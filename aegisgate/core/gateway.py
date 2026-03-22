"""FastAPI app entry — assembly module.

This file imports from sub-modules and wires the application together.
The actual logic lives in:
- gateway_keys.py     — key & proxy token management
- gateway_network.py  — trusted proxy, loopback, internal IP checks
- gateway_auth.py     — UI session, CSRF, admin auth, blocked response
- gateway_ui_config.py — config field data, docs catalog, env helpers
- gateway_ui_routes.py — UI / keys / rules / compose endpoints
"""

from __future__ import annotations

import hmac
import re
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from aegisgate.adapters.openai_compat.router import (
    clear_pending_confirmations_on_startup,
    close_runtime_dependencies,
    close_semantic_async_client,
    prune_pending_confirmations,
    reload_runtime_dependencies,
    router as openai_router,
)
from aegisgate.adapters.openai_compat.offload import shutdown_payload_transform_executor
from aegisgate.adapters.openai_compat.upstream import close_upstream_async_client
from aegisgate.adapters.relay_compat.router import router as relay_router
from aegisgate.adapters.v2_proxy.router import close_v2_async_client, router as v2_proxy_router
from aegisgate.config.settings import settings
from aegisgate.core.audit import shutdown_audit_worker
from aegisgate.core.dangerous_response_log import shutdown_dangerous_response_log_worker
from aegisgate.core.confirmation_cache_task import ConfirmationCacheTask
from aegisgate.core.hot_reload import HotReloader, build_watcher

# --- Re-exports from sub-modules (backward compatibility) ---
from aegisgate.core.gateway_keys import (  # noqa: F401
    _FORBIDDEN_UPSTREAM_BASE_EXAMPLES,
    _GATEWAY_KEY_FILE,
    _is_forbidden_upstream_base_example,
    _normalize_input_upstream_base,
    _PROXY_TOKEN_FILE,
    _PROXY_TOKEN_HEADER,
    _ensure_gateway_key,
    _ensure_proxy_token,
    _gateway_key_cached,
    _normalize_required_whitelist_list,
    get_proxy_token_value,
)
from aegisgate.core.gateway_network import (  # noqa: F401
    _LOOPBACK_HOSTS,
    _is_internal_ip,
    _is_loopback_ip,
    _is_trusted_proxy,
    _parse_trusted_proxy_ips,
    _real_client_ip,
)
import aegisgate.core.gateway_network as _gw_net  # noqa: F401 — used by tests
from aegisgate.core.gateway_auth import (  # noqa: F401
    _UI_SESSION_COOKIE,
    _apply_ui_security_headers,
    _blocked_response,
    _create_ui_session_token,
    _gateway_token_base_url,
    _is_passthrough_read_path,
    _is_public_ui_path,
    _is_ui_authenticated,
    _is_valid_ui_session,
    _public_base_url,
    _sanitize_public_host,
    _string_field,
    _ui_client_fingerprint,
    _ui_csrf_token,
    _ui_session_signature,
    _verify_admin_gateway_key,
    _verify_ui_csrf,
)
from aegisgate.core.gateway_ui_config import (  # noqa: F401
    _coerce_config_value,
    _docs_catalog,
    _field_default,
    _parse_bool_value,
    _read_env_lines,
    _resolve_doc_path,
    _serialize_env_value,
    _ui_config_field_map,
    _ui_config_payload,
    _write_env_updates,
    _UI_CONFIG_FIELDS,
)
from aegisgate.core.gateway_ui_routes import (  # noqa: F401
    register_ui_routes,
    _ui_bootstrap_payload,
)

from aegisgate.core.gw_tokens import (
    find_token as gw_tokens_find_token,
    get as gw_tokens_get,
    inject_docker_upstreams as gw_tokens_inject_docker_upstreams,
    load as gw_tokens_load,
    register as gw_tokens_register,
    unregister as gw_tokens_unregister,
    update as gw_tokens_update,
)
from aegisgate.init_config import assert_security_bootstrap_ready, ensure_config_dir
from aegisgate.storage.crypto import ensure_key as _ensure_fernet_key
from aegisgate.core.security_boundary import (
    build_nonce_cache,
    build_signature_payload,
    now_ts,
    verify_hmac_signature,
)
from aegisgate.storage.offload import run_store_io, shutdown_store_io_executor
from aegisgate.util.logger import logger
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys

# /v1/__gw__/t/{token}/chat/completions -> /v1/chat/completions
# /v1/__gw__/t/{token}__redact/chat/completions -> redact-only mode
# /v1/__gw__/t/{token}__passthrough/chat/completions -> passthrough mode
# /v2/__gw__/t/{token}/proxy -> /v2/proxy
_GW_TOKEN_PATH_RE = re.compile(r"^/(v1|v2)/__gw__/t/([^/]+?)(?:__([a-z]+))?(?:/(.*))?$")
_VALID_FILTER_MODES = frozenset({"redact", "passthrough"})

_confirmation_cache_task: ConfirmationCacheTask | None = None
_hot_reloader: HotReloader | None = None


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter for admin endpoints
# ---------------------------------------------------------------------------
class _AdminRateLimiter:
    _EVICT_INTERVAL = 300.0  # 每 5 分钟清理一次过期 bucket

    def __init__(self, max_per_minute: int = 30) -> None:
        self._max = max(1, max_per_minute)
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._last_evict: float = 0.0

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            # Periodically evict stale buckets to prevent unbounded memory growth
            if now - self._last_evict > self._EVICT_INTERVAL:
                self._buckets = defaultdict(list, {
                    k: v for k, v in self._buckets.items() if v and v[-1] > cutoff
                })
                self._last_evict = now
            bucket = self._buckets[client_ip]
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
    _ensure_fernet_key()
    # Rebuild runtime dependencies at startup so test lifespans and hot-reload
    # shutdowns never reuse a store backend that has already been closed.
    reload_runtime_dependencies()

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
    try:
        gw_tokens_inject_docker_upstreams()
    except Exception as exc:  # pragma: no cover
        logger.warning("docker_upstreams inject failed: %s", exc)
    if settings.clear_pending_on_startup:
        try:
            n = await run_store_io(clear_pending_confirmations_on_startup)
            if n:
                logger.info("cleared %d pending confirmation(s) on startup", n)
        except Exception as exc:  # pragma: no cover
            logger.warning("clear pending confirmations on startup failed: %s", exc)
    global _confirmation_cache_task, _hot_reloader
    if settings.enable_pending_prune_task and _confirmation_cache_task is None:
        _confirmation_cache_task = ConfirmationCacheTask(prune_func=prune_pending_confirmations)
        await _confirmation_cache_task.start()

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
    close_runtime_dependencies()
    shutdown_store_io_executor()
    shutdown_payload_transform_executor()
    await close_upstream_async_client()
    await close_v2_async_client()
    await close_semantic_async_client()
    shutdown_audit_worker()
    shutdown_dangerous_response_log_worker()
    from aegisgate.core.stats import flush as flush_stats
    flush_stats()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(openai_router, prefix="/v1")
if settings.enable_v2_proxy:
    app.include_router(v2_proxy_router)
if settings.enable_relay_endpoint:
    app.include_router(relay_router, prefix="/relay")
_WWW_DIR = (Path(__file__).resolve().parents[2] / "www").resolve()
_UI_ASSETS_DIR = (_WWW_DIR / "assets").resolve()
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_UI_LOGIN_RATE_LIMITER = _AdminRateLimiter(max_per_minute=settings.local_ui_login_rate_limit_per_minute)
if _UI_ASSETS_DIR.is_dir():
    app.mount("/__ui__/assets", StaticFiles(directory=str(_UI_ASSETS_DIR)), name="ui-assets")
_nonce_cache = build_nonce_cache()
_admin_rate_limiter = _AdminRateLimiter(max_per_minute=settings.admin_rate_limit_per_minute)
_ADMIN_ENDPOINTS = frozenset({"/__gw__/register", "/__gw__/lookup", "/__gw__/unregister", "/__gw__/add", "/__gw__/remove"})
_PASSTHROUGH_PATHS = frozenset({"/", "/health", "/robots.txt", "/favicon.ico"})


# ---------------------------------------------------------------------------
# GWTokenRewriteMiddleware
# ---------------------------------------------------------------------------
class GWTokenRewriteMiddleware:
    """在路由匹配前重写 token 路径。"""

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

        version, token, filter_mode, rest = (
            matched.group(1), matched.group(2), matched.group(3), matched.group(4),
        )
        # 验证 filter_mode
        if filter_mode and filter_mode not in _VALID_FILTER_MODES:
            response = JSONResponse(
                status_code=400,
                content={"error": "invalid_filter_mode", "detail": f"unknown mode '{filter_mode}', valid: {sorted(_VALID_FILTER_MODES)}"},
            )
            await response(scope, receive, send)
            return

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
        logger.debug("gw_token_rewrite path=%s -> %s token=%s… mode=%s", path, new_path, token[:6], filter_mode or "default")

        ub = mapping["upstream_base"]
        wk = normalize_whitelist_keys(mapping.get("whitelist_key"))
        new_scope = dict(scope)
        new_scope["path"] = new_path
        new_scope["root_path"] = ""
        new_scope["raw_path"] = new_path.encode("utf-8")
        new_scope["aegis_token_authenticated"] = True
        new_scope["aegis_gateway_token"] = token
        new_scope["aegis_upstream_base"] = ub
        new_scope["aegis_redaction_whitelist_keys"] = wk
        new_scope["aegis_filter_mode"] = filter_mode  # None | "redact" | "passthrough"

        headers = list(new_scope.get("headers") or [])
        ub_name = settings.upstream_base_header.encode("latin-1")
        gk_name = settings.gateway_key_header.encode("latin-1")
        rk_name = b"x-aegis-redaction-whitelist"
        ub_alt = settings.upstream_base_header.replace("-", "_").encode("latin-1")
        gk_alt = settings.gateway_key_header.replace("-", "_").encode("latin-1")
        skip = (ub_name.lower(), gk_name.lower(), rk_name.lower(), ub_alt.lower(), gk_alt.lower())
        headers = [(k, v) for k, v in headers if k.lower() not in skip]
        new_scope["headers"] = headers

        await self.app(new_scope, receive, send)


# ---------------------------------------------------------------------------
# Security boundary middleware
# ---------------------------------------------------------------------------

async def _drain_and_reject(
    request: Request,
    boundary: dict[str, object],
    reason: str,
    status_code: int,
    detail: str | None = None,
) -> JSONResponse:
    """Consume request body (prevent Starlette warnings) and return a blocked response."""
    await request.body()
    boundary["rejected_reason"] = reason
    return _blocked_response(status_code=status_code, reason=reason, detail=detail)


@app.middleware("http")
async def security_boundary_middleware(request: Request, call_next):
    boundary: dict[str, object] = {
        "loopback_only": settings.enforce_loopback_only,
        "auth_required": settings.enable_request_hmac_auth,
        "auth_verified": False,
        "replay_checked": False,
        "max_request_body_bytes": settings.max_request_body_bytes,
    }
    request.state.security_boundary = boundary

    # --- UI branch (internal network only) ---
    if request.url.path.startswith("/__ui__"):
        client_ip = _real_client_ip(request)
        ui_allowed = _is_internal_ip(client_ip) if settings.local_ui_allow_internal_network else _is_loopback_ip(client_ip)
        if not ui_allowed:
            boundary["rejected_reason"] = "local_ui_network_restricted"
            logger.warning("boundary reject local ui host=%s path=%s", client_ip, request.url.path)
            detail = (
                "local ui only allowed from internal network"
                if settings.local_ui_allow_internal_network
                else "local ui only allowed from loopback"
            )
            return _apply_ui_security_headers(_blocked_response(
                status_code=403,
                reason="local_ui_network_restricted",
                detail=detail,
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
            from fastapi.responses import RedirectResponse
            return _apply_ui_security_headers(RedirectResponse(url="/__ui__/login", status_code=303))
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"} and request.url.path.startswith("/__ui__/api/"):
            if request.url.path != "/__ui__/api/login" and not _verify_ui_csrf(request):
                return _apply_ui_security_headers(
                    JSONResponse(status_code=403, content={"error": "ui_csrf_invalid", "detail": "missing or invalid csrf token"})
                )
        response = await call_next(request)
        return _apply_ui_security_headers(response)

    # --- Passthrough (health, root, robots, favicon) ---
    if request.url.path in _PASSTHROUGH_PATHS and request.method.upper() in {"GET", "HEAD"}:
        return await call_next(request)

    logger.debug("boundary enter method=%s path=%s", request.method, request.url.path)

    # --- Loopback enforcement (reject early, before any auth/body processing) ---
    if settings.enforce_loopback_only:
        client_host = request.client.host if request.client else ""
        if client_host not in _LOOPBACK_HOSTS:
            logger.warning("boundary reject non-loopback host=%s path=%s", client_host, request.url.path)
            return await _drain_and_reject(request, boundary, "loopback_only_reject", 403)

    # --- Admin endpoint guards ---
    if request.url.path in _ADMIN_ENDPOINTS and request.method.upper() == "POST":
        client_ip = _real_client_ip(request)
        if not _admin_rate_limiter.is_allowed(client_ip):
            logger.warning("boundary reject admin rate limit host=%s path=%s", client_ip, request.url.path)
            return await _drain_and_reject(request, boundary, "admin_rate_limited", 429, "too many requests")
        if not _is_internal_ip(client_ip):
            logger.warning("boundary reject admin endpoint from non-internal host=%s path=%s", client_ip, request.url.path)
            return await _drain_and_reject(
                request, boundary, "admin_endpoint_network_restricted", 403,
                "admin endpoint only allowed from internal network",
            )

    # --- v1/v2 token authentication ---
    protected_v1 = request.url.path == "/v1" or request.url.path.startswith("/v1/")
    protected_v2 = request.url.path == "/v2" or request.url.path.startswith("/v2/")

    if not bool(request.scope.get("aegis_token_authenticated")) and (protected_v1 or protected_v2):
        proxy_token = (request.headers.get(_PROXY_TOKEN_HEADER) or "").strip()
        proxy_token_value = get_proxy_token_value()
        if proxy_token and proxy_token_value and hmac.compare_digest(proxy_token, proxy_token_value):
            default_base = (settings.upstream_base_url or "").strip()
            if default_base:
                request.scope["aegis_upstream_base"] = default_base
                request.scope["aegis_token_authenticated"] = True
                boundary["auth_verified"] = True

    if protected_v1 and not bool(request.scope.get("aegis_token_authenticated")):
        default_base = (settings.upstream_base_url or "").strip()
        if default_base:
            request.scope["aegis_upstream_base"] = default_base
            request.scope["aegis_token_authenticated"] = True
            logger.debug("using default upstream for v1 path=%s", request.url.path)
        else:
            client_ip = _real_client_ip(request)
            logger.warning(
                "boundary reject non-token request path=%s client=%s hint=set AEGIS_UPSTREAM_BASE_URL or use token path",
                request.url.path, client_ip,
            )
            return await _drain_and_reject(
                request, boundary, "token_route_required", 403,
                "no default upstream configured; use /v1/__gw__/t/<token>/... or set AEGIS_UPSTREAM_BASE_URL",
            )

    if protected_v2 and not bool(request.scope.get("aegis_token_authenticated")):
        logger.warning("boundary reject non-token v2 request path=%s", request.url.path)
        return await _drain_and_reject(
            request, boundary, "token_route_required", 403,
            "use /v2/__gw__/t/<token>/... routes for v2 proxy access",
        )

    # --- Request body size check ---
    cached_body: bytes | None = None
    content_length_header = request.headers.get("content-length", "").strip()
    if settings.max_request_body_bytes > 0 and request.method.upper() in {"POST", "PUT", "PATCH"} and content_length_header:
        try:
            content_length = int(content_length_header)
        except ValueError:
            logger.warning("boundary reject invalid content-length path=%s", request.url.path)
            return await _drain_and_reject(request, boundary, "invalid_content_length", 400)
        if content_length > settings.max_request_body_bytes:
            logger.warning(
                "boundary reject oversize request content_length=%s max=%s path=%s",
                content_length, settings.max_request_body_bytes, request.url.path,
            )
            return await _drain_and_reject(request, boundary, "request_body_too_large", 413)
        boundary["request_body_size"] = content_length
    elif settings.max_request_body_bytes > 0 and request.method.upper() in {"POST", "PUT", "PATCH"}:
        cached_body = await request.body()
        boundary["request_body_size"] = len(cached_body)
        if len(cached_body) > settings.max_request_body_bytes:
            boundary["rejected_reason"] = "request_body_too_large"
            logger.warning(
                "boundary reject oversize request actual_size=%s max=%s path=%s",
                len(cached_body), settings.max_request_body_bytes, request.url.path,
            )
            return _blocked_response(status_code=413, reason="request_body_too_large")

    # --- HMAC authentication ---
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
        boundary["request_body_size"] = len(body)
        payload = build_signature_payload(timestamp=timestamp, nonce=nonce, body=body)
        if not verify_hmac_signature(secret=secret, payload=payload, presented=signature):
            boundary["rejected_reason"] = "hmac_signature_invalid"
            return _blocked_response(status_code=401, reason="hmac_signature_invalid")

        boundary["auth_verified"] = True
        logger.info("boundary hmac verified path=%s", request.url.path)

    try:
        response = await call_next(request)
    except Exception:  # pragma: no cover - fail-safe
        logger.exception("gateway unhandled exception path=%s", request.url.path)
        boundary["rejected_reason"] = "gateway_internal_error"
        return _blocked_response(
            status_code=500,
            reason="gateway_internal_error",
            detail="an internal error occurred",
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


# ---------------------------------------------------------------------------
# Admin API endpoints (register / add / remove / lookup / unregister)
# ---------------------------------------------------------------------------

@app.post("/__gw__/register")
async def gw_register(request: Request) -> JSONResponse:
    """一次性注册：返回短 token 与 baseUrl，映射写入 config/gw_tokens.json。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = _normalize_input_upstream_base(body.get("upstream_base"))
    gateway_key = _string_field(body.get("gateway_key"))
    whitelist_present = "whitelist_key" in body
    requested_whitelist = normalize_whitelist_keys(body.get("whitelist_key")) if whitelist_present else None
    if not upstream_base or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "upstream_base and gateway_key required"},
        )
    if not _verify_admin_gateway_key(body):
        logger.warning("register rejected: gateway_key mismatch")
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match the configured key"},
        )
    if _is_forbidden_upstream_base_example(upstream_base):
        return JSONResponse(
            status_code=400,
            content={"error": "example_upstream_forbidden", "detail": "upstream_base 不能使用文档中的示例地址，请替换为你的真实上游地址后再注册。"},
        )
    if whitelist_present:
        token, already_registered = gw_tokens_register(upstream_base, whitelist_key=requested_whitelist)
    else:
        token, already_registered = gw_tokens_register(upstream_base)
    stored = gw_tokens_get(token) or {}
    effective_whitelist = normalize_whitelist_keys(stored.get("whitelist_key")) if stored else (requested_whitelist or [])
    base_url = _gateway_token_base_url(request, token)
    if already_registered:
        return JSONResponse(content={
            "already_registered": True,
            "detail": "该 upstream_base + gateway_key 已注册过，返回已有 token。",
            "token": token,
            "baseUrl": base_url,
            "whitelist_key": effective_whitelist,
        })
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
    if not _verify_admin_gateway_key(body):
        return JSONResponse(status_code=403, content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"})
    upstream_base_input = _normalize_input_upstream_base(body.get("upstream_base"))
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    current_upstream_base = _normalize_input_upstream_base(mapping.get("upstream_base"))
    next_upstream_base = current_upstream_base
    if upstream_base_input:
        if _is_forbidden_upstream_base_example(upstream_base_input):
            return JSONResponse(status_code=400, content={"error": "example_upstream_forbidden", "detail": "upstream_base 不能使用文档中的示例地址，请替换为你的真实上游地址后再更新。"})
        existing = gw_tokens_find_token(upstream_base_input)
        if existing is not None and existing != token:
            return JSONResponse(status_code=409, content={"error": "upstream_pair_conflict", "detail": "target upstream_base already bound"})
        next_upstream_base = upstream_base_input
    current = normalize_whitelist_keys(mapping.get("whitelist_key"))
    current_set = set(current)
    added = [k for k in whitelist_add if k not in current_set]
    next_whitelist = current + added
    updated = gw_tokens_update(token, upstream_base=next_upstream_base, whitelist_key=next_whitelist)
    if not updated:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    latest = (gw_tokens_get(token) or {}).get("whitelist_key", current)
    base_url = _gateway_token_base_url(request, token)
    return JSONResponse(content={
        "token": token, "upstream_base": next_upstream_base,
        "baseUrl": base_url, "whitelist_key": normalize_whitelist_keys(latest), "added": added,
    })


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
    if not _verify_admin_gateway_key(body):
        return JSONResponse(status_code=403, content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"})
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    upstream_base = _normalize_input_upstream_base(mapping.get("upstream_base"))
    current = normalize_whitelist_keys(mapping.get("whitelist_key"))
    remove_set = set(whitelist_remove)
    removed = [k for k in current if k in remove_set]
    next_whitelist = [k for k in current if k not in remove_set]
    updated = gw_tokens_update(token, upstream_base=upstream_base, whitelist_key=next_whitelist)
    if not updated:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    latest = (gw_tokens_get(token) or {}).get("whitelist_key", current)
    base_url = _gateway_token_base_url(request, token)
    return JSONResponse(content={
        "token": token, "baseUrl": base_url,
        "whitelist_key": normalize_whitelist_keys(latest), "removed": removed,
    })


@app.post("/__gw__/lookup")
async def gw_lookup(request: Request) -> JSONResponse:
    """根据 upstream_base 查询已注册的 token。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = _normalize_input_upstream_base(body.get("upstream_base"))
    gateway_key = _string_field(body.get("gateway_key"))
    if not upstream_base or not gateway_key:
        return JSONResponse(status_code=400, content={"error": "missing_params", "detail": "upstream_base and gateway_key required"})
    if not _verify_admin_gateway_key(body):
        return JSONResponse(status_code=403, content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"})
    if _is_forbidden_upstream_base_example(upstream_base):
        return JSONResponse(status_code=400, content={"error": "example_upstream_forbidden", "detail": "upstream_base 不能使用文档中的示例地址。"})
    token = gw_tokens_find_token(upstream_base)
    if token is None:
        return JSONResponse(status_code=404, content={"error": "not_found", "detail": "该 upstream_base 未注册，请先调用 /__gw__/register 注册。"})
    base_url = _gateway_token_base_url(request, token)
    mapping = gw_tokens_get(token) or {}
    whitelist_key = normalize_whitelist_keys(mapping.get("whitelist_key"))
    return JSONResponse(content={"token": token, "baseUrl": base_url, "whitelist_key": whitelist_key})


@app.post("/__gw__/unregister")
async def gw_unregister(request: Request) -> JSONResponse:
    """删除 token 映射。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    token = _string_field(body.get("token"))
    gateway_key = _string_field(body.get("gateway_key"))
    if not token or not gateway_key:
        return JSONResponse(status_code=400, content={"error": "missing_params", "detail": "token and gateway_key required"})
    if not _verify_admin_gateway_key(body):
        return JSONResponse(status_code=403, content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"})
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    if gw_tokens_unregister(token):
        return JSONResponse(content={"ok": True, "message": "token removed"})
    return JSONResponse(status_code=404, content={"error": "token_not_found"})


# ---------------------------------------------------------------------------
# Register UI routes
# ---------------------------------------------------------------------------
register_ui_routes(app)


# Backward-compat aliases for functions that tests call directly.
def local_ui_bootstrap(request: Request) -> dict[str, object]:
    return _ui_bootstrap_payload(request)


def local_ui_index() -> Response:
    index_path = (_WWW_DIR / "index.html").resolve()
    if not index_path.is_file():
        return PlainTextResponse("local ui assets not found", status_code=404)
    from fastapi.responses import FileResponse
    return FileResponse(index_path, media_type="text/html; charset=utf-8")

# ---------------------------------------------------------------------------
# Info / health / liveness endpoints
# ---------------------------------------------------------------------------
_BOOT_TIME = time.time()


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
