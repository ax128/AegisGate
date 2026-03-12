"""FastAPI app entry."""

from __future__ import annotations

import hmac
import hashlib
import ipaddress
import os
import re
import secrets
import tempfile
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from aegisgate.adapters.openai_compat.router import (
    clear_pending_confirmations_on_startup,
    close_semantic_async_client,
    prune_pending_confirmations,
    router as openai_router,
)
from aegisgate.adapters.openai_compat.upstream import close_upstream_async_client
from aegisgate.adapters.relay_compat.router import router as relay_router
from aegisgate.adapters.v2_proxy.router import close_v2_async_client, router as v2_proxy_router
from aegisgate.config.settings import settings
from aegisgate.core.audit import shutdown_audit_worker
from aegisgate.core.confirmation_cache_task import ConfirmationCacheTask
from aegisgate.core.hot_reload import HotReloader, build_watcher
from aegisgate.core.gw_tokens import (
    find_token as gw_tokens_find_token,
    get as gw_tokens_get,
    list_tokens as gw_tokens_list,
    load as gw_tokens_load,
    register as gw_tokens_register,
    unregister as gw_tokens_unregister,
    update as gw_tokens_update,
)
from aegisgate.init_config import assert_security_bootstrap_ready, ensure_config_dir
from aegisgate.core.security_boundary import (
    build_nonce_cache,
    build_signature_payload,
    now_ts,
    verify_hmac_signature,
)
from aegisgate.util.logger import logger
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys

# /v1/__gw__/t/{token}/chat/completions -> /v1/chat/completions
# /v2/__gw__/t/{token}/proxy -> /v2/proxy
_GW_TOKEN_PATH_RE = re.compile(r"^/(v1|v2)/__gw__/t/([^/]+)(?:/(.*))?$")

_confirmation_cache_task: ConfirmationCacheTask | None = None
_hot_reloader: HotReloader | None = None

# ---------------------------------------------------------------------------
# Gateway key auto-generation
# ---------------------------------------------------------------------------
_GENERATED_KEY_FILE = "aegis_gateway.key"


def _ensure_gateway_key() -> str:
    """Return the effective gateway_key; auto-generate if empty."""
    key = (settings.gateway_key or "").strip()
    if key:
        return key

    # Try loading persisted auto-generated key
    from pathlib import Path
    key_path = (Path.cwd() / "config" / _GENERATED_KEY_FILE).resolve()
    if key_path.is_file():
        stored = key_path.read_text(encoding="utf-8").strip()
        if stored:
            settings.gateway_key = stored
            logger.info("gateway_key loaded from %s", key_path)
            return stored

    # Generate new key
    new_key = secrets.token_urlsafe(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(new_key, encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    settings.gateway_key = new_key
    logger.warning(
        "gateway_key was empty — auto-generated and saved to %s. "
        "Set AEGIS_GATEWAY_KEY env var to use your own key.",
        key_path,
    )
    return new_key


# ---------------------------------------------------------------------------
# Internal proxy token auto-generation (Caddy ↔ AegisGate auto-pairing)
# ---------------------------------------------------------------------------
_PROXY_TOKEN_FILE = "aegis_proxy_token.key"
_PROXY_TOKEN_HEADER = "x-aegis-proxy-token"
_proxy_token_value: str = ""


def _ensure_proxy_token() -> str:
    """Auto-generate an internal proxy token for Caddy ↔ AegisGate trust."""
    global _proxy_token_value
    from pathlib import Path

    key_path = (Path.cwd() / "config" / _PROXY_TOKEN_FILE).resolve()
    if key_path.is_file():
        stored = key_path.read_text(encoding="utf-8").strip()
        if stored:
            _proxy_token_value = stored
            logger.info("proxy_token loaded from %s", key_path)
            return stored

    new_token = secrets.token_urlsafe(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(new_token, encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    _proxy_token_value = new_token
    logger.info("proxy_token auto-generated and saved to %s", key_path)
    return new_token


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter for admin endpoints
# ---------------------------------------------------------------------------
class _AdminRateLimiter:
    def __init__(self, max_per_minute: int = 30) -> None:
        self._max = max(1, max_per_minute)
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            bucket = self._buckets[client_ip]
            # Prune old entries
            self._buckets[client_ip] = [t for t in bucket if t > cutoff]
            if len(self._buckets[client_ip]) >= self._max:
                return False
            self._buckets[client_ip].append(now)
            return True


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    # --- startup ---
    try:
        ensure_config_dir()
        assert_security_bootstrap_ready()
        logger.info("security policy bootstrap ready")
    except Exception as exc:  # pragma: no cover
        logger.error("init_config on startup failed: %s", exc)
        raise

    _ensure_gateway_key()
    _ensure_proxy_token()

    # Log key config so operators can verify the right compose overlay is active.
    upstream = (settings.upstream_base_url or "").strip()
    logger.info(
        "gateway config: upstream=%s security_level=%s enforce_loopback=%s v2_proxy=%s",
        upstream or "(none — token path required)",
        settings.security_level,
        settings.enforce_loopback_only,
        settings.enable_v2_proxy,
    )

    try:
        gw_tokens_load()
    except Exception as exc:  # pragma: no cover
        logger.warning("gw_tokens load on startup failed: %s", exc)
    if settings.clear_pending_on_startup:
        try:
            n = clear_pending_confirmations_on_startup()
            if n:
                logger.info("cleared %d pending confirmation(s) on startup", n)
        except Exception as exc:  # pragma: no cover
            logger.warning("clear pending confirmations on startup failed: %s", exc)
    global _confirmation_cache_task, _hot_reloader
    if settings.enable_pending_prune_task and _confirmation_cache_task is None:
        _confirmation_cache_task = ConfirmationCacheTask(prune_func=prune_pending_confirmations)
        await _confirmation_cache_task.start()

    # Start hot-reload file watcher
    if _hot_reloader is None:
        _hot_reloader = build_watcher()
        await _hot_reloader.start()

    yield

    # --- shutdown ---
    if _hot_reloader is not None:
        await _hot_reloader.stop()
        _hot_reloader = None
    if _confirmation_cache_task is not None:
        await _confirmation_cache_task.stop()
        _confirmation_cache_task = None
    await close_upstream_async_client()
    await close_v2_async_client()
    await close_semantic_async_client()
    shutdown_audit_worker()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(openai_router, prefix="/v1")
if settings.enable_v2_proxy:
    app.include_router(v2_proxy_router)
if settings.enable_relay_endpoint:
    app.include_router(relay_router, prefix="/relay")
_WWW_DIR = (Path(__file__).resolve().parents[2] / "www").resolve()
_UI_ASSETS_DIR = (_WWW_DIR / "assets").resolve()
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_README_PATH = (_PROJECT_ROOT / "README.md").resolve()
# docs/ 目录为本地私有文档，不在 UI 中展示，也不上传 git。
# 根目录下这些文件属于本地内部文件，同样不在 UI 中展示。
_EXCLUDED_ROOT_DOCS: frozenset[str] = frozenset(
    {
        "AGENTS.md",
        "CHANGELOG.md",
        "PRODUCTION_READINESS_TEST_REPORT.md",
        "OPEN_SOURCE_CHECKLIST.md",
        "PR_DESCRIPTION_2026-02-26-security-hardening.md",
    }
)
_ENV_PATH = (Path.cwd() / "config" / ".env").resolve()
_UI_SESSION_COOKIE = "aegis_ui_session"
_UI_LOGIN_RATE_LIMITER = _AdminRateLimiter(max_per_minute=settings.local_ui_login_rate_limit_per_minute)
if _UI_ASSETS_DIR.is_dir():
    app.mount("/__ui__/assets", StaticFiles(directory=str(_UI_ASSETS_DIR)), name="ui-assets")
_nonce_cache = build_nonce_cache()
_admin_rate_limiter = _AdminRateLimiter(max_per_minute=settings.admin_rate_limit_per_minute)
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_ADMIN_ENDPOINTS = frozenset({"/__gw__/register", "/__gw__/lookup", "/__gw__/unregister", "/__gw__/add", "/__gw__/remove"})
# Paths that bypass security boundary and go directly to route handlers.
_PASSTHROUGH_PATHS = frozenset({"/", "/health", "/robots.txt", "/favicon.ico"})

# ---------------------------------------------------------------------------
# Trusted proxy handling
# ---------------------------------------------------------------------------
_trusted_proxy_exact: set[str] | None = None
_trusted_proxy_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None


def _parse_trusted_proxy_ips() -> None:
    """Parse AEGIS_TRUSTED_PROXY_IPS into exact IPs and CIDR networks."""
    global _trusted_proxy_exact, _trusted_proxy_networks
    exact: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    raw = (settings.trusted_proxy_ips or "").strip()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            try:
                networks.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                logger.warning("trusted_proxy_ips: invalid CIDR %s, skipped", token)
        else:
            exact.add(token)
    _trusted_proxy_exact = exact
    _trusted_proxy_networks = networks


def _is_trusted_proxy(ip_str: str) -> bool:
    """Check if an IP is in the trusted proxy list (exact match or CIDR)."""
    global _trusted_proxy_exact, _trusted_proxy_networks
    if _trusted_proxy_exact is None:
        _parse_trusted_proxy_ips()
    assert _trusted_proxy_exact is not None and _trusted_proxy_networks is not None
    if not _trusted_proxy_exact and not _trusted_proxy_networks:
        return False
    if ip_str in _trusted_proxy_exact:
        return True
    if _trusted_proxy_networks:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in _trusted_proxy_networks)
        except ValueError:
            pass
    return False


def _real_client_ip(request: Request) -> str:
    """
    Determine the real client IP.
    Only trust X-Forwarded-For when the direct connection comes from a trusted proxy.
    """
    direct_ip = (request.client.host if request.client else "").strip()
    if not _is_trusted_proxy(direct_ip):
        # Not from trusted proxy — use direct connection IP (ignore XFF).
        return direct_ip
    # From trusted proxy — take the leftmost (original client) IP from XFF.
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        return xff.split(",", 1)[0].strip()
    return direct_ip


class GWTokenRewriteMiddleware:
    """
    在路由匹配前重写 token 路径，避免 /v1/__gw__/t/{token}/... 被 generic 路由误接管。
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "/")
        matched = _GW_TOKEN_PATH_RE.match(path)
        if not matched:
            await self.app(scope, receive, send)
            return

        version, token, rest = matched.group(1), matched.group(2), matched.group(3)
        mapping = gw_tokens_get(token)
        if not mapping:
            logger.warning("gw_token not found token=%s path=%s", token, path)
            response = JSONResponse(
                status_code=404,
                content={"error": "token_not_found", "detail": "token invalid or expired"},
            )
            await response(scope, receive, send)
            return

        new_path = f"/{version}/{rest}" if rest else f"/{version}"
        logger.info("gw_token_rewrite path=%s -> %s token=%s", path, new_path, token)

        ub = mapping["upstream_base"]
        gk = mapping["gateway_key"]
        wk = normalize_whitelist_keys(mapping.get("whitelist_key"))
        new_scope = dict(scope)
        new_scope["path"] = new_path
        new_scope["root_path"] = ""
        new_scope["raw_path"] = new_path.encode("utf-8")
        new_scope["aegis_token_authenticated"] = True
        new_scope["aegis_gateway_token"] = token
        new_scope["aegis_upstream_base"] = ub
        new_scope["aegis_gateway_key"] = gk
        new_scope["aegis_redaction_whitelist_keys"] = wk

        headers = list(new_scope.get("headers") or [])
        # token 访问时移除客户端携带的网关内部头，避免冲突。
        ub_name = settings.upstream_base_header.encode("latin-1")
        gk_name = settings.gateway_key_header.encode("latin-1")
        rk_name = b"x-aegis-redaction-whitelist"
        ub_alt = settings.upstream_base_header.replace("-", "_").encode("latin-1")
        gk_alt = settings.gateway_key_header.replace("-", "_").encode("latin-1")
        skip = (ub_name.lower(), gk_name.lower(), rk_name.lower(), ub_alt.lower(), gk_alt.lower())
        headers = [(k, v) for k, v in headers if k.lower() not in skip]
        new_scope["headers"] = headers

        await self.app(new_scope, receive, send)


def _blocked_response(status_code: int, reason: str, detail: str | None = None) -> JSONResponse:
    # Sanitize detail: never expose internal exception info to client.
    safe_detail = reason
    if detail:
        safe = detail.strip()
        # Only use detail if it doesn't look like an internal traceback/exception.
        if not any(marker in safe for marker in ("Traceback", "File ", "line ", "Error:", "Exception:")):
            safe_detail = safe
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": safe_detail,
                "type": "aegisgate_error",
                "code": reason,
            },
            "error_code": reason,
            "detail": safe_detail,
            "aegisgate": {
                "action": "block",
                "risk_score": 1.0,
                "reasons": [reason],
            },
        },
    )


def _is_loopback_ip(host: str) -> bool:
    if not host:
        return False
    if host in _LOOPBACK_HOSTS:
        return True
    normalized = host
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return ip.is_loopback


def _is_internal_ip(host: str) -> bool:
    if not host:
        return False
    if host in _LOOPBACK_HOSTS:
        return True
    normalized = host
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _verify_admin_gateway_key(body: dict) -> bool:
    """Constant-time comparison of gateway_key from request body against configured key."""
    provided = str(body.get("gateway_key") or "").strip()
    expected = (settings.gateway_key or "").strip()
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _is_passthrough_read_path(path: str) -> bool:
    return path == "/__ui__" or path.startswith("/__ui__/")


def _is_public_ui_path(path: str) -> bool:
    return path in {
        "/__ui__/login",
        "/__ui__/health",
        "/__ui__/api/login",
    } or path.startswith("/__ui__/assets/")


def _apply_ui_security_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


def _ui_client_fingerprint(request: Request) -> str:
    client_ip = _real_client_ip(request)
    user_agent = (request.headers.get("user-agent") or "").strip()[:200]
    raw = f"{client_ip}|{user_agent}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _ui_session_signature(issued_at: int, fingerprint: str) -> str:
    secret = _ensure_gateway_key().encode("utf-8")
    payload = f"ui:{issued_at}:{fingerprint}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _create_ui_session_token(request: Request) -> str:
    issued_at = int(time.time())
    fingerprint = _ui_client_fingerprint(request)
    return f"{issued_at}.{_ui_session_signature(issued_at, fingerprint)}"


def _ui_csrf_token(session_token: str) -> str:
    secret = _ensure_gateway_key().encode("utf-8")
    return hmac.new(secret, f"csrf:{session_token}".encode("utf-8"), hashlib.sha256).hexdigest()


def _is_valid_ui_session(token: str, request: Request) -> bool:
    value = (token or "").strip()
    if not value or "." not in value:
        return False
    issued_at_str, signature = value.split(".", 1)
    try:
        issued_at = int(issued_at_str)
    except ValueError:
        return False
    if issued_at <= 0:
        return False
    if time.time() - issued_at > settings.local_ui_session_ttl_seconds:
        return False
    expected = _ui_session_signature(issued_at, _ui_client_fingerprint(request))
    return hmac.compare_digest(signature, expected)


def _is_ui_authenticated(request: Request) -> bool:
    return _is_valid_ui_session(request.cookies.get(_UI_SESSION_COOKIE, ""), request)


def _verify_ui_csrf(request: Request) -> bool:
    session_token = request.cookies.get(_UI_SESSION_COOKIE, "")
    if not _is_valid_ui_session(session_token, request):
        return False
    presented = (request.headers.get("x-aegis-ui-csrf") or "").strip()
    if not presented:
        return False
    expected = _ui_csrf_token(session_token)
    return hmac.compare_digest(presented, expected)


def _docs_catalog() -> list[dict[str, str]]:
    """返回 UI 文档目录：README.md 置顶，其次是根目录中允许展示的 .md 文件。
    docs/ 子目录为本地私有文档，不纳入展示范围。
    """
    docs: list[dict[str, str]] = []
    if _README_PATH.is_file():
        docs.append({"id": "README.md", "title": "README", "path": "README.md"})
    for doc_path in sorted(_PROJECT_ROOT.glob("*.md")):
        if doc_path.name in _EXCLUDED_ROOT_DOCS:
            continue
        if doc_path.resolve() == _README_PATH:
            continue  # 已在首位添加
        docs.append(
            {
                "id": doc_path.name,
                "title": doc_path.stem.replace("-", " ").replace("_", " "),
                "path": doc_path.name,
            }
        )
    return docs


def _resolve_doc_path(doc_id: str) -> Path | None:
    safe_id = Path(doc_id).name
    if safe_id != doc_id:
        return None
    if safe_id in _EXCLUDED_ROOT_DOCS:
        return None
    candidate = (_PROJECT_ROOT / safe_id).resolve()
    # 只允许读取项目根目录下的 .md 文件，不允许遍历子目录
    if candidate.is_file() and candidate.suffix == ".md" and candidate.parent == _PROJECT_ROOT:
        return candidate
    return None


_UI_CONFIG_FIELDS: tuple[dict[str, object], ...] = (
    {
        "env": "AEGIS_HOST",
        "field": "host",
        "label": "Host",
        "type": "string",
        "section": "general",
    },
    {
        "env": "AEGIS_PORT",
        "field": "port",
        "label": "Port",
        "type": "int",
        "section": "general",
    },
    {
        "env": "AEGIS_UPSTREAM_BASE_URL",
        "field": "upstream_base_url",
        "label": "Upstream Base URL",
        "type": "string",
        "section": "general",
    },
    {
        "env": "AEGIS_LOG_LEVEL",
        "field": "log_level",
        "label": "Log Level",
        "type": "enum",
        "section": "general",
        "options": ["debug", "info", "warning", "error"],
    },
    {
        "env": "AEGIS_STORAGE_BACKEND",
        "field": "storage_backend",
        "label": "Storage Backend",
        "type": "enum",
        "section": "general",
        "options": ["sqlite", "redis", "postgres"],
    },
    {
        "env": "AEGIS_SECURITY_LEVEL",
        "field": "security_level",
        "label": "Security Level",
        "type": "enum",
        "section": "security",
        "options": ["low", "medium", "high"],
    },
    {
        "env": "AEGIS_MAX_REQUEST_BODY_BYTES",
        "field": "max_request_body_bytes",
        "label": "Max Request Body Bytes",
        "type": "int",
        "section": "security",
    },
    {
        "env": "AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK",
        "field": "require_confirmation_on_block",
        "label": "Require Confirmation On Block",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "AEGIS_STRICT_COMMAND_BLOCK_ENABLED",
        "field": "strict_command_block_enabled",
        "label": "Strict Command Block",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "AEGIS_ENFORCE_LOOPBACK_ONLY",
        "field": "enforce_loopback_only",
        "label": "Loopback Only",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "AEGIS_ENABLE_SEMANTIC_MODULE",
        "field": "enable_semantic_module",
        "label": "Semantic Module",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "AEGIS_ENABLE_V2_PROXY",
        "field": "enable_v2_proxy",
        "label": "Enable v2 Proxy",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "AEGIS_V2_ENABLE_REQUEST_REDACTION",
        "field": "v2_enable_request_redaction",
        "label": "v2 Request Redaction",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "AEGIS_V2_ENABLE_RESPONSE_COMMAND_FILTER",
        "field": "v2_enable_response_command_filter",
        "label": "v2 Response Filter",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "AEGIS_V2_RESPONSE_FILTER_OBVIOUS_ONLY",
        "field": "v2_response_filter_obvious_only",
        "label": "v2 Obvious Only",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "AEGIS_V2_BLOCK_INTERNAL_TARGETS",
        "field": "v2_block_internal_targets",
        "label": "v2 Block Internal Targets",
        "type": "bool",
        "section": "v2",
    },
)


def _ui_config_field_map() -> dict[str, dict[str, object]]:
    return {str(item["field"]): dict(item) for item in _UI_CONFIG_FIELDS}


def _field_default(field_name: str) -> object:
    field_info = settings.__class__.model_fields[field_name]
    return field_info.default


def _serialize_env_value(kind: str, value: object) -> str:
    if kind == "bool":
        return "true" if bool(value) else "false"
    return str(value)


def _parse_bool_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def _coerce_config_value(meta: dict[str, object], raw_value: object) -> object:
    kind = str(meta["type"])
    if kind == "bool":
        return _parse_bool_value(raw_value)
    if kind == "int":
        try:
            return int(str(raw_value).strip())
        except ValueError as exc:
            raise ValueError(f"invalid integer for {meta['field']}") from exc
    value = str(raw_value or "").strip()
    if kind == "enum":
        raw_options = meta.get("options")
        options = {str(item) for item in raw_options} if isinstance(raw_options, list) else set()
        if value not in options:
            raise ValueError(f"invalid option for {meta['field']}")
    return value


def _read_env_lines() -> list[str]:
    if not _ENV_PATH.exists():
        return []
    return _ENV_PATH.read_text(encoding="utf-8").splitlines()


def _write_env_updates(updates: dict[str, str]) -> None:
    existing_lines = _read_env_lines()
    consumed: set[str] = set()
    new_lines: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue
        key, _, _value = line.partition("=")
        key = key.strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            consumed.add(key)
        else:
            new_lines.append(line)
    if new_lines and new_lines[-1].strip():
        new_lines.append("")
    for key in updates:
        if key not in consumed:
            new_lines.append(f"{key}={updates[key]}")
    _ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(_ENV_PATH.parent)) as tmp:
        tmp.write("\n".join(new_lines).rstrip() + "\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(_ENV_PATH)


def _ui_config_payload() -> dict[str, object]:
    items: list[dict[str, object]] = []
    for meta in _UI_CONFIG_FIELDS:
        field_name = str(meta["field"])
        current_value = getattr(settings, field_name)
        default_value = _field_default(field_name)
        items.append(
            {
                **meta,
                "value": current_value,
                "default": default_value,
            }
        )
    return {"items": items}


@app.middleware("http")
async def security_boundary_middleware(request: Request, call_next):
    boundary = {
        "loopback_only": settings.enforce_loopback_only,
        "auth_required": settings.enable_request_hmac_auth,
        "auth_verified": False,
        "replay_checked": False,
        "max_request_body_bytes": settings.max_request_body_bytes,
    }
    request.state.security_boundary = boundary

    if request.url.path.startswith("/__ui__"):
        client_ip = _real_client_ip(request)
        if not _is_internal_ip(client_ip):
            boundary["rejected_reason"] = "local_ui_network_restricted"
            logger.warning("boundary reject local ui host=%s path=%s", client_ip, request.url.path)
            return _apply_ui_security_headers(_blocked_response(
                status_code=403,
                reason="local_ui_network_restricted",
                detail="local ui only allowed from internal network",
            ))
        if request.url.path == "/__ui__/api/login" and request.method.upper() == "POST":
            if not _UI_LOGIN_RATE_LIMITER.is_allowed(client_ip):
                boundary["rejected_reason"] = "ui_login_rate_limited"
                return _apply_ui_security_headers(
                    JSONResponse(status_code=429, content={"error": "ui_login_rate_limited", "detail": "too many login attempts"})
                )
        if _is_public_ui_path(request.url.path):
            response = await call_next(request)
            return _apply_ui_security_headers(response)
        if not _is_ui_authenticated(request):
            if request.url.path.startswith("/__ui__/api/"):
                return _apply_ui_security_headers(JSONResponse(status_code=401, content={"error": "ui_auth_required"}))
            return _apply_ui_security_headers(RedirectResponse(url="/__ui__/login", status_code=303))
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"} and request.url.path.startswith("/__ui__/api/"):
            if request.url.path != "/__ui__/api/login" and not _verify_ui_csrf(request):
                return _apply_ui_security_headers(
                    JSONResponse(status_code=403, content={"error": "ui_csrf_invalid", "detail": "missing or invalid csrf token"})
                )
        response = await call_next(request)
        return _apply_ui_security_headers(response)

    # Passthrough: only safe read-only methods (GET/HEAD) on info endpoints.
    # POST/PUT/DELETE to these paths still go through the full security boundary.
    if request.url.path in _PASSTHROUGH_PATHS and request.method.upper() in {"GET", "HEAD"}:
        return await call_next(request)

    logger.debug("boundary enter method=%s path=%s", request.method, request.url.path)

    # --- Admin endpoint protection ---
    if request.url.path in _ADMIN_ENDPOINTS and request.method.upper() == "POST":
        client_ip = _real_client_ip(request)

        # Rate limiting
        if not _admin_rate_limiter.is_allowed(client_ip):
            await request.body()
            boundary["rejected_reason"] = "admin_rate_limited"
            logger.warning("boundary reject admin rate limit host=%s path=%s", client_ip, request.url.path)
            return _blocked_response(status_code=429, reason="admin_rate_limited", detail="too many requests")

        # Network restriction: require loopback or internal IP
        if not _is_internal_ip(client_ip):
            await request.body()
            boundary["rejected_reason"] = "admin_endpoint_network_restricted"
            logger.warning(
                "boundary reject admin endpoint from non-internal host=%s path=%s",
                client_ip,
                request.url.path,
            )
            return _blocked_response(
                status_code=403,
                reason="admin_endpoint_network_restricted",
                detail="admin endpoint only allowed from internal network",
            )

    protected_v1 = request.url.path == "/v1" or request.url.path.startswith("/v1/")
    protected_v2 = request.url.path == "/v2" or request.url.path.startswith("/v2/")

    # --- Internal proxy token: Caddy ↔ AegisGate auto-pairing ---
    # If the request carries a valid X-Aegis-Proxy-Token, authenticate it
    # with the default upstream automatically (no token path needed).
    if not bool(request.scope.get("aegis_token_authenticated")) and (protected_v1 or protected_v2):
        proxy_token = (request.headers.get(_PROXY_TOKEN_HEADER) or "").strip()
        if proxy_token and _proxy_token_value and hmac.compare_digest(proxy_token, _proxy_token_value):
            default_base = (settings.upstream_base_url or "").strip()
            if default_base:
                request.scope["aegis_upstream_base"] = default_base
                request.scope["aegis_token_authenticated"] = True
                boundary["auth_verified"] = True

    if protected_v1 and not bool(request.scope.get("aegis_token_authenticated")):
        # 若配置了默认上游（如 AEGIS_UPSTREAM_BASE_URL=http://cli-proxy-api:8317/v1），
        # 则 v1 可直接转发到该上游，无需 token 注册。
        # CLIProxyAPI 自行负责 API key 校验。
        default_base = (settings.upstream_base_url or "").strip()
        if default_base:
            request.scope["aegis_upstream_base"] = default_base
            request.scope["aegis_token_authenticated"] = True
            logger.debug("using default upstream for v1 path=%s", request.url.path)
        else:
            await request.body()
            boundary["rejected_reason"] = "token_route_required"
            client_ip = _real_client_ip(request)
            logger.warning(
                "boundary reject non-token request path=%s client=%s hint=set AEGIS_UPSTREAM_BASE_URL or use token path",
                request.url.path, client_ip,
            )
            return _blocked_response(
                status_code=403,
                reason="token_route_required",
                detail="no default upstream configured; use /v1/__gw__/t/<token>/... or set AEGIS_UPSTREAM_BASE_URL",
            )

    if protected_v2 and not bool(request.scope.get("aegis_token_authenticated")):
        await request.body()
        boundary["rejected_reason"] = "token_route_required"
        logger.warning("boundary reject non-token v2 request path=%s", request.url.path)
        return _blocked_response(
            status_code=403,
            reason="token_route_required",
            detail="use /v2/__gw__/t/<token>/... routes for v2 proxy access",
        )

    cached_body: bytes | None = None
    content_length_header = request.headers.get("content-length", "").strip()
    if settings.max_request_body_bytes > 0 and request.method.upper() in {"POST", "PUT", "PATCH"} and content_length_header:
        try:
            content_length = int(content_length_header)
        except ValueError:
            await request.body()
            boundary["rejected_reason"] = "invalid_content_length"
            logger.warning("boundary reject invalid content-length path=%s", request.url.path)
            return _blocked_response(status_code=400, reason="invalid_content_length")
        if content_length > settings.max_request_body_bytes:
            await request.body()
            boundary["rejected_reason"] = "request_body_too_large"
            logger.warning(
                "boundary reject oversize request content_length=%s max=%s path=%s",
                content_length,
                settings.max_request_body_bytes,
                request.url.path,
            )
            return _blocked_response(status_code=413, reason="request_body_too_large")
    elif settings.max_request_body_bytes > 0 and request.method.upper() in {"POST", "PUT", "PATCH"}:
        cached_body = await request.body()
        if len(cached_body) > settings.max_request_body_bytes:
            boundary["rejected_reason"] = "request_body_too_large"
            logger.warning(
                "boundary reject oversize request actual_size=%s max=%s path=%s",
                len(cached_body),
                settings.max_request_body_bytes,
                request.url.path,
            )
            return _blocked_response(status_code=413, reason="request_body_too_large")

    if settings.enforce_loopback_only:
        client_host = request.client.host if request.client else ""
        if client_host not in _LOOPBACK_HOSTS:
            await request.body()
            boundary["rejected_reason"] = "loopback_only_reject"
            logger.warning("boundary reject non-loopback host=%s path=%s", client_host, request.url.path)
            return _blocked_response(status_code=403, reason="loopback_only_reject")

    if settings.enable_request_hmac_auth:
        secret = settings.request_hmac_secret
        if not secret:
            logger.error("request hmac auth enabled but secret is empty")
            return _blocked_response(status_code=500, reason="hmac_misconfigured")

        signature = request.headers.get(settings.request_signature_header)
        timestamp = request.headers.get(settings.request_timestamp_header)
        nonce = request.headers.get(settings.request_nonce_header)
        if not signature or not timestamp or not nonce:
            boundary["rejected_reason"] = "hmac_header_missing"
            return _blocked_response(status_code=401, reason="hmac_header_missing")

        try:
            ts_int = int(timestamp)
        except ValueError:
            boundary["rejected_reason"] = "hmac_timestamp_invalid"
            return _blocked_response(status_code=401, reason="hmac_timestamp_invalid")

        current_ts = now_ts()
        if abs(current_ts - ts_int) > settings.request_replay_window_seconds:
            boundary["rejected_reason"] = "hmac_timestamp_out_of_window"
            return _blocked_response(status_code=401, reason="hmac_timestamp_out_of_window")

        replayed = _nonce_cache.check_and_store(
            nonce=nonce,
            now_ts=current_ts,
            window_seconds=settings.request_replay_window_seconds,
        )
        boundary["replay_checked"] = True
        if replayed:
            boundary["rejected_reason"] = "replay_nonce_detected"
            return _blocked_response(status_code=409, reason="replay_nonce_detected")

        body = cached_body if cached_body is not None else await request.body()
        payload = build_signature_payload(timestamp=timestamp, nonce=nonce, body=body)
        if not verify_hmac_signature(secret=secret, payload=payload, presented=signature):
            boundary["rejected_reason"] = "hmac_signature_invalid"
            return _blocked_response(status_code=401, reason="hmac_signature_invalid")

        boundary["auth_verified"] = True
        logger.info("boundary hmac verified path=%s", request.url.path)

    try:
        response = await call_next(request)
    except Exception as exc:  # pragma: no cover - fail-safe
        logger.exception("gateway unhandled exception path=%s", request.url.path)
        boundary["rejected_reason"] = "gateway_internal_error"
        return _blocked_response(
            status_code=500,
            reason="gateway_internal_error",
            detail="an internal error occurred",  # Never expose exc details
        )
    if boundary.get("auth_verified"):
        response.headers["x-aegis-auth-verified"] = "true"
    logger.debug(
        "boundary pass method=%s path=%s auth_verified=%s",
        request.method,
        request.url.path,
        bool(boundary.get("auth_verified")),
    )
    return response


# 注册时禁止使用的示例/占位 upstream_base，避免用户未替换就提交
_FORBIDDEN_UPSTREAM_BASE_EXAMPLES = frozenset(
    u.rstrip("/").lower()
    for u in (
        "https://your-upstream.example.com/v1",
        "http://your-upstream.example.com/v1",
    )
)


def _sanitize_public_host(raw_host: str) -> str:
    host = (raw_host or "").strip()
    if not host:
        return f"127.0.0.1:{settings.port}"
    if re.search(r"[^A-Za-z0-9.\-:\[\]]", host):
        return f"127.0.0.1:{settings.port}"
    lowered = host.lower()
    if lowered in {"0.0.0.0", "::", "[::]"}:
        return f"127.0.0.1:{settings.port}"
    if lowered.startswith("0.0.0.0:"):
        return f"127.0.0.1:{host.split(':', 1)[1]}"
    if lowered.startswith("[::]:"):
        return f"127.0.0.1:{host.split(':', 1)[1]}"
    return host


def _public_base_url(request: Request) -> str:
    # Only trust forwarded headers from trusted proxies.
    direct_ip = (request.client.host if request.client else "").strip()
    if _is_trusted_proxy(direct_ip):
        forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    else:
        forwarded_proto = ""
        forwarded_host = ""
    scheme = forwarded_proto if forwarded_proto in {"http", "https"} else request.url.scheme or "http"
    host_header = (request.headers.get("host") or "").strip()
    host = _sanitize_public_host(forwarded_host or host_header or f"{settings.host}:{settings.port}")
    return f"{scheme}://{host}"


def _string_field(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalize_required_whitelist_list(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    return normalize_whitelist_keys(value)


@app.post("/__gw__/register")
async def gw_register(request: Request) -> JSONResponse:
    """一次性注册：返回短 token 与 baseUrl，映射写入 config/gw_tokens.json。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = _string_field(body.get("upstream_base"))
    gateway_key = _string_field(body.get("gateway_key"))
    whitelist_present = "whitelist_key" in body
    requested_whitelist = normalize_whitelist_keys(body.get("whitelist_key")) if whitelist_present else None
    if not upstream_base or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "upstream_base and gateway_key required"},
        )

    # Authenticate: gateway_key must match the configured key.
    if not _verify_admin_gateway_key(body):
        logger.warning("register rejected: gateway_key mismatch")
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match the configured key"},
        )

    upstream_normalized = upstream_base.rstrip("/").lower()
    if upstream_normalized in _FORBIDDEN_UPSTREAM_BASE_EXAMPLES:
        return JSONResponse(
            status_code=400,
            content={
                "error": "example_upstream_forbidden",
                "detail": "upstream_base 不能使用文档中的示例地址，请替换为你的真实上游地址后再注册。",
            },
        )
    upstream_base_normalized = upstream_base.rstrip("/")
    if whitelist_present:
        token, already_registered = gw_tokens_register(
            upstream_base_normalized,
            gateway_key,
            requested_whitelist,
        )
    else:
        token, already_registered = gw_tokens_register(
            upstream_base_normalized,
            gateway_key,
        )
    stored = gw_tokens_get(token) or {}
    effective_whitelist = (
        normalize_whitelist_keys(stored.get("whitelist_key"))
        if stored
        else (requested_whitelist or [])
    )
    base_url = f"{_public_base_url(request)}/v1/__gw__/t/{token}"
    if already_registered:
        return JSONResponse(
            content={
                "already_registered": True,
                "detail": "该 upstream_base + gateway_key 已注册过，返回已有 token。",
                "token": token,
                "baseUrl": base_url,
                "whitelist_key": effective_whitelist,
            },
        )
    return JSONResponse(content={"token": token, "baseUrl": base_url, "whitelist_key": effective_whitelist})


@app.post("/__gw__/add")
async def gw_add(request: Request) -> JSONResponse:
    """对指定 token 追加 whitelist_key；可选替换 upstream_base。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    token = _string_field(body.get("token"))
    gateway_key = _string_field(body.get("gateway_key"))
    whitelist_add = _normalize_required_whitelist_list(body.get("whitelist_key"))
    if not token or not gateway_key or whitelist_add is None or not whitelist_add:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "token, gateway_key and whitelist_key(list) required"},
        )
    # Authenticate: gateway_key must match the configured key.
    if not _verify_admin_gateway_key(body):
        return JSONResponse(status_code=403, content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"})
    upstream_base_input = _string_field(body.get("upstream_base"))
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    mapped_gateway_key = _string_field(mapping.get("gateway_key"))
    if mapped_gateway_key != gateway_key:
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_mismatch", "detail": "token and gateway_key not matched"},
        )
    current_upstream_base = _string_field(mapping.get("upstream_base")).rstrip("/")
    next_upstream_base = current_upstream_base
    if upstream_base_input:
        normalized_upstream = upstream_base_input.rstrip("/")
        normalized_lower = normalized_upstream.lower()
        if normalized_lower in _FORBIDDEN_UPSTREAM_BASE_EXAMPLES:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "example_upstream_forbidden",
                    "detail": "upstream_base 不能使用文档中的示例地址，请替换为你的真实上游地址后再更新。",
                },
            )
        existing = gw_tokens_find_token(normalized_upstream, gateway_key)
        if existing is not None and existing != token:
            return JSONResponse(
                status_code=409,
                content={"error": "upstream_pair_conflict", "detail": "target upstream_base + gateway_key already bound"},
            )
        next_upstream_base = normalized_upstream

    current = normalize_whitelist_keys(mapping.get("whitelist_key"))
    current_set = set(current)
    added = [k for k in whitelist_add if k not in current_set]
    next_whitelist = current + added
    updated = gw_tokens_update(
        token,
        upstream_base=next_upstream_base,
        gateway_key=gateway_key,
        whitelist_key=next_whitelist,
    )
    if not updated:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    latest = (gw_tokens_get(token) or {}).get("whitelist_key", current)
    base_url = f"{_public_base_url(request)}/v1/__gw__/t/{token}"
    return JSONResponse(
        content={
            "token": token,
            "gateway_key": gateway_key,
            "upstream_base": next_upstream_base,
            "baseUrl": base_url,
            "whitelist_key": normalize_whitelist_keys(latest),
            "added": added,
        }
    )


@app.post("/__gw__/remove")
async def gw_remove(request: Request) -> JSONResponse:
    """仅对指定 token 移除 whitelist_key。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    token = _string_field(body.get("token"))
    gateway_key = _string_field(body.get("gateway_key"))
    whitelist_remove = _normalize_required_whitelist_list(body.get("whitelist_key"))
    if not token or not gateway_key or whitelist_remove is None or not whitelist_remove:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "token, gateway_key and whitelist_key(list) required"},
        )
    # Authenticate
    if not _verify_admin_gateway_key(body):
        return JSONResponse(status_code=403, content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"})
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    mapped_gateway_key = _string_field(mapping.get("gateway_key"))
    if mapped_gateway_key != gateway_key:
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_mismatch", "detail": "token and gateway_key not matched"},
        )
    upstream_base = _string_field(mapping.get("upstream_base")).rstrip("/")
    current = normalize_whitelist_keys(mapping.get("whitelist_key"))
    remove_set = set(whitelist_remove)
    removed = [k for k in current if k in remove_set]
    next_whitelist = [k for k in current if k not in remove_set]
    updated = gw_tokens_update(
        token,
        upstream_base=upstream_base,
        gateway_key=gateway_key,
        whitelist_key=next_whitelist,
    )
    if not updated:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    latest = (gw_tokens_get(token) or {}).get("whitelist_key", current)
    base_url = f"{_public_base_url(request)}/v1/__gw__/t/{token}"
    return JSONResponse(
        content={
            "token": token,
            "gateway_key": gateway_key,
            "baseUrl": base_url,
            "whitelist_key": normalize_whitelist_keys(latest),
            "removed": removed,
        }
    )


@app.post("/__gw__/lookup")
async def gw_lookup(request: Request) -> JSONResponse:
    """根据 upstream_base + gateway_key 查询已注册的 token，避免忘记。不存在返回 404。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = _string_field(body.get("upstream_base"))
    gateway_key = _string_field(body.get("gateway_key"))
    if not upstream_base or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "upstream_base and gateway_key required"},
        )
    # Authenticate
    if not _verify_admin_gateway_key(body):
        return JSONResponse(status_code=403, content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"})
    upstream_normalized = upstream_base.rstrip("/").lower()
    if upstream_normalized in _FORBIDDEN_UPSTREAM_BASE_EXAMPLES:
        return JSONResponse(
            status_code=400,
            content={
                "error": "example_upstream_forbidden",
                "detail": "upstream_base 不能使用文档中的示例地址。",
            },
        )
    token = gw_tokens_find_token(upstream_base, gateway_key)
    if token is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "detail": "该 upstream_base + gateway_key 未注册，请先调用 /__gw__/register 注册。",
            },
        )
    base_url = f"{_public_base_url(request)}/v1/__gw__/t/{token}"
    mapping = gw_tokens_get(token) or {}
    whitelist_key = normalize_whitelist_keys(mapping.get("whitelist_key"))
    return JSONResponse(content={"token": token, "baseUrl": base_url, "whitelist_key": whitelist_key})


@app.post("/__gw__/unregister")
async def gw_unregister(request: Request) -> JSONResponse:
    """删除 token 映射：body 传 token，删除后写回 config。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    token = _string_field(body.get("token"))
    gateway_key = _string_field(body.get("gateway_key"))
    if not token or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "token and gateway_key required"},
        )
    # Authenticate
    if not _verify_admin_gateway_key(body):
        return JSONResponse(status_code=403, content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"})
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    mapped_gateway_key = _string_field(mapping.get("gateway_key"))
    if mapped_gateway_key != gateway_key:
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_mismatch", "detail": "token and gateway_key not matched"},
        )
    if gw_tokens_unregister(token):
        return JSONResponse(content={"ok": True, "message": "token removed"})
    return JSONResponse(status_code=404, content={"error": "token_not_found"})


# ---------------------------------------------------------------------------
# Info / health / liveness endpoints
# ---------------------------------------------------------------------------

_BOOT_TIME = time.time()


def _ui_bootstrap_payload(request: Request | None = None) -> dict[str, object]:
    session_token = request.cookies.get(_UI_SESSION_COOKIE, "") if request is not None else ""
    return {
        "app_name": settings.app_name,
        "status": "ok",
        "uptime_seconds": int(time.time() - _BOOT_TIME),
        "server": {
            "host": settings.host,
            "port": settings.port,
        },
        "upstream_base_url": (settings.upstream_base_url or "").strip(),
        "security": {
            "level": settings.security_level,
            "confirmation_on_block": settings.require_confirmation_on_block,
            "strict_command_block": settings.strict_command_block_enabled,
        },
        "v2": {
            "enabled": settings.enable_v2_proxy,
            "request_redaction": settings.v2_enable_request_redaction,
            "response_filter": settings.v2_enable_response_command_filter,
        },
        "ui": {
            "session_ttl_seconds": settings.local_ui_session_ttl_seconds,
            "csrf_token": _ui_csrf_token(session_token) if session_token else "",
        },
        "docs": _docs_catalog(),
        "config_sections": {
            "general": "基础设置",
            "security": "安全设置",
            "v2": "v2 代理",
        },
    }


@app.get("/__ui__/login")
def local_ui_login_page() -> Response:
    login_path = (_WWW_DIR / "login.html").resolve()
    if not login_path.is_file():
        return PlainTextResponse("local ui login assets not found", status_code=404)
    return FileResponse(login_path, media_type="text/html; charset=utf-8")


@app.get("/__ui__")
def local_ui_index() -> Response:
    index_path = (_WWW_DIR / "index.html").resolve()
    if not index_path.is_file():
        return PlainTextResponse("local ui assets not found", status_code=404)
    return FileResponse(index_path, media_type="text/html; charset=utf-8")


@app.get("/__ui__/health")
def local_ui_health() -> dict[str, object]:
    return {"status": "ok", "ui": True, "uptime_seconds": int(time.time() - _BOOT_TIME)}


@app.get("/__ui__/api/bootstrap")
def local_ui_bootstrap(request: Request) -> dict[str, object]:
    return _ui_bootstrap_payload(request)


@app.get("/__ui__/api/docs")
def local_ui_docs_list() -> dict[str, object]:
    return {"items": _docs_catalog()}


@app.get("/__ui__/api/config")
def local_ui_config() -> dict[str, object]:
    return _ui_config_payload()


@app.post("/__ui__/api/config")
async def local_ui_update_config(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    raw_values = body.get("values")
    if not isinstance(raw_values, dict):
        return JSONResponse(status_code=400, content={"error": "invalid_values"})

    field_map = _ui_config_field_map()
    env_updates: dict[str, str] = {}
    updated_fields: dict[str, object] = {}
    for field_name, raw_value in raw_values.items():
        meta = field_map.get(str(field_name))
        if meta is None:
            return JSONResponse(status_code=400, content={"error": "invalid_field", "detail": str(field_name)})
        try:
            coerced = _coerce_config_value(meta, raw_value)
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_field_value", "detail": str(exc)})
        env_updates[str(meta["env"])] = _serialize_env_value(str(meta["type"]), coerced)
        updated_fields[str(field_name)] = coerced

    _write_env_updates(env_updates)
    from aegisgate.core.hot_reload import reload_settings

    reload_settings()
    return JSONResponse(content={"ok": True, "updated": updated_fields, "config": _ui_config_payload()})


@app.get("/__ui__/api/docs/{doc_id}")
def local_ui_doc_content(doc_id: str) -> JSONResponse:
    doc_path = _resolve_doc_path(doc_id)
    if doc_path is None:
        return JSONResponse(status_code=404, content={"error": "doc_not_found"})
    return JSONResponse(
        content={
            "id": doc_id,
            "title": doc_path.stem.replace("-", " "),
            "content": doc_path.read_text(encoding="utf-8"),
            "path": doc_path.name,
        }
    )


@app.post("/__ui__/api/login")
async def local_ui_login(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    password = _string_field(body.get("password"))
    gateway_key = _ensure_gateway_key()
    if not password or not hmac.compare_digest(password.encode("utf-8"), gateway_key.encode("utf-8")):
        return JSONResponse(status_code=403, content={"error": "ui_login_failed", "detail": "invalid password"})
    response = JSONResponse(content={"ok": True})
    response.set_cookie(
        key=_UI_SESSION_COOKIE,
        value=_create_ui_session_token(request),
        max_age=settings.local_ui_session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.local_ui_secure_cookie,
    )
    return response


@app.post("/__ui__/api/logout")
def local_ui_logout() -> JSONResponse:
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(_UI_SESSION_COOKIE)
    return response


@app.get("/__ui__/api/tokens")
def local_ui_tokens_list() -> JSONResponse:
    """列出所有已注册 Token（隐藏 gateway_key 明文）。"""
    raw = gw_tokens_list()
    items = []
    for token, m in raw.items():
        gk = m.get("gateway_key") or ""
        items.append(
            {
                "token": token,
                "upstream_base": m.get("upstream_base", ""),
                "gateway_key_hint": (gk[:6] + "…" + gk[-3:]) if len(gk) > 9 else ("*" * len(gk) if gk else ""),
                "whitelist_keys": m.get("whitelist_key") or [],
            }
        )
    return JSONResponse(content={"items": items})


@app.post("/__ui__/api/tokens")
async def local_ui_tokens_register(request: Request) -> JSONResponse:
    """通过 UI 注册新 Token。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = _string_field(body.get("upstream_base"))
    gateway_key = _string_field(body.get("gateway_key"))
    if not upstream_base or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "upstream_base 和 gateway_key 均为必填"},
        )
    upstream_normalized = upstream_base.rstrip("/").lower()
    if upstream_normalized in _FORBIDDEN_UPSTREAM_BASE_EXAMPLES:
        return JSONResponse(
            status_code=400,
            content={"error": "example_upstream_forbidden", "detail": "请替换为真实上游地址"},
        )
    raw_whitelist = body.get("whitelist_key")
    whitelist = normalize_whitelist_keys(raw_whitelist) if raw_whitelist is not None else []
    try:
        token, already = gw_tokens_register(upstream_base.rstrip("/"), gateway_key, whitelist)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": "invalid_params", "detail": str(exc)})
    base_url = f"{_public_base_url(request)}/v1/__gw__/t/{token}"
    return JSONResponse(
        status_code=200 if already else 201,
        content={"ok": True, "token": token, "already_registered": already, "base_url": base_url},
    )


@app.delete("/__ui__/api/tokens/{token}")
def local_ui_tokens_delete(token: str) -> JSONResponse:
    """注销指定 Token。"""
    token = token.strip()
    if not token:
        return JSONResponse(status_code=400, content={"error": "missing_token"})
    if gw_tokens_unregister(token):
        return JSONResponse(content={"ok": True})
    return JSONResponse(status_code=404, content={"error": "token_not_found"})


@app.get("/health")
@app.head("/health")
def health() -> dict:
    """Liveness probe — lightweight, no logging."""
    return {"status": "ok"}


@app.api_route("/", methods=["GET", "HEAD"])
def gateway_root(request: Request) -> dict:
    """Gateway info — used by Caddy / ALB health checks and humans."""
    from aegisgate import __version__

    routes_summary = ["/v1/*"]
    if settings.enable_v2_proxy:
        routes_summary.append("/v2/*")
    if settings.enable_relay_endpoint:
        routes_summary.append("/relay/*")
    return {
        "name": settings.app_name,
        "version": __version__,
        "status": "ok",
        "uptime_seconds": int(time.time() - _BOOT_TIME),
        "routes": routes_summary,
    }


@app.get("/robots.txt")
def robots_txt() -> PlainTextResponse:
    """Block crawlers — this is an API gateway, not a website."""
    return PlainTextResponse("User-agent: *\nDisallow: /\n", media_type="text/plain")


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


# Token 重写必须最先执行：用 ASGI middleware 在路由匹配前直接改写 scope.path。
app.add_middleware(GWTokenRewriteMiddleware)
