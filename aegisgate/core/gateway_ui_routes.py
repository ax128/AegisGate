"""UI, key management, security rules CRUD, and compose file endpoints.

All endpoints are registered via ``register_ui_routes(app)`` called from
the main ``gateway.py`` module.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import signal
import tempfile
import time
import yaml
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response

from aegisgate.config.settings import settings
from aegisgate.core.gateway_auth import (
    _create_ui_session_token,
    _gateway_token_base_url,
    _string_field,
    _ui_csrf_token,
    _UI_SESSION_COOKIE,
)
from aegisgate.core.gateway_keys import (
    _ensure_gateway_key,
    _is_forbidden_upstream_base_example,
    _normalize_input_upstream_base,
)
from aegisgate.core.gateway_ui_config import (
    _coerce_config_value,
    _docs_catalog,
    _resolve_doc_path,
    _restart_required_fields,
    _serialize_env_value,
    _UI_CONFIG_SECTIONS,
    _ui_config_field_map,
    _ui_config_payload,
    _write_env_updates,
)
from aegisgate.core.rules_editor import RuleEdit
from aegisgate.core.gw_tokens import (
    list_tokens as gw_tokens_list,
    register as gw_tokens_register,
    unregister as gw_tokens_unregister,
    update_and_rename as gw_tokens_update_and_rename,
)
from aegisgate.util.logger import logger
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys
from aegisgate.core.audit import write_audit
import hmac

_WWW_DIR = (Path(__file__).resolve().parents[2] / "www").resolve()
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def register_ui_routes(app: FastAPI) -> None:
    """Register all UI, key management, rules CRUD, and compose endpoints on *app*."""

    # ------------------------------------------------------------------
    # UI pages
    # ------------------------------------------------------------------

    @app.get("/__ui__/login")
    async def local_ui_login_page() -> Response:
        login_path = (_WWW_DIR / "login.html").resolve()
        if not login_path.is_file():
            return PlainTextResponse("local ui login assets not found", status_code=404)
        return FileResponse(login_path, media_type="text/html; charset=utf-8")

    @app.get("/__ui__")
    async def local_ui_index() -> Response:
        index_path = (_WWW_DIR / "index.html").resolve()
        if not index_path.is_file():
            return PlainTextResponse("local ui assets not found", status_code=404)
        return FileResponse(index_path, media_type="text/html; charset=utf-8")

    @app.get("/__ui__/health")
    async def local_ui_health() -> dict[str, object]:
        from aegisgate.core.gateway import _BOOT_TIME
        return {"status": "ok", "ui": True, "uptime_seconds": int(time.time() - _BOOT_TIME)}

    # ------------------------------------------------------------------
    # Bootstrap / config / docs
    # ------------------------------------------------------------------

    @app.get("/__ui__/api/bootstrap")
    async def local_ui_bootstrap(request: Request) -> dict[str, object]:
        return _ui_bootstrap_payload(request)

    @app.get("/__ui__/api/docs")
    async def local_ui_docs_list() -> dict[str, object]:
        return {"items": _docs_catalog()}

    @app.get("/__ui__/api/stats")
    async def local_ui_stats() -> JSONResponse:
        from aegisgate.core.stats import snapshot
        return JSONResponse(content=snapshot())

    @app.delete("/__ui__/api/stats")
    async def local_ui_stats_clear() -> JSONResponse:
        from aegisgate.core.stats import clear
        clear()
        return JSONResponse(content={"ok": True})

    @app.get("/__ui__/api/config")
    async def local_ui_config() -> dict[str, object]:
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
            # Secrets are never echoed to the browser, so an empty submission
            # means "keep the stored value" rather than "clear it".
            if meta.get("sensitive") and not str(raw_value or "").strip():
                continue
            try:
                coerced = _coerce_config_value(meta, raw_value)
            except ValueError as exc:
                return JSONResponse(status_code=400, content={"error": "invalid_field_value", "detail": str(exc)})
            env_updates[str(meta["env"])] = _serialize_env_value(str(meta["type"]), coerced)
            updated_fields[str(field_name)] = coerced
        if not env_updates:
            return JSONResponse(content={"ok": True, "updated": {}, "restart_required": [], "config": _ui_config_payload()})
        try:
            _write_env_updates(env_updates)
        except RuntimeError as exc:
            return JSONResponse(status_code=500, content={"error": "env_write_failed", "detail": str(exc)})
        from aegisgate.core.hot_reload import reload_settings
        reload_settings()
        # Fields pinned by hot_reload._IMMUTABLE_FIELDS were written to .env but
        # are NOT live in this process. Tell the client so it can say so instead
        # of reporting a hot reload that did not happen.
        restart_fields = _restart_required_fields()
        restart_required = sorted(f for f in updated_fields if f in restart_fields)
        # H-20: Audit every successful configuration change for traceability.
        write_audit({
            "event": "config_updated",
            "route": "/__ui__/api/config",
            "actor_ip": request.client.host if request.client else "unknown",
            "updated_fields": {
                str(k): ("***" if field_map.get(str(k), {}).get("sensitive") else str(v))
                for k, v in updated_fields.items()
            },
            "restart_required": restart_required,
        })
        return JSONResponse(content={
            "ok": True,
            "updated": {
                k: ("***" if field_map.get(str(k), {}).get("sensitive") else v)
                for k, v in updated_fields.items()
            },
            "restart_required": restart_required,
            "config": _ui_config_payload(),
        })

    @app.get("/__ui__/api/docs/{doc_id}")
    async def local_ui_doc_content(doc_id: str) -> JSONResponse:
        doc_path = _resolve_doc_path(doc_id)
        if doc_path is None:
            return JSONResponse(status_code=404, content={"error": "doc_not_found"})
        return JSONResponse(content={
            "id": doc_id,
            "title": doc_path.stem.replace("-", " "),
            "content": doc_path.read_text(encoding="utf-8"),
            "path": doc_path.name,
        })

    # ------------------------------------------------------------------
    # Login / logout
    # ------------------------------------------------------------------

    @app.post("/__ui__/api/login")
    async def local_ui_login(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        password = _string_field(body.get("password"))
        gateway_key = _ensure_gateway_key()
        key_ok = bool(password) and hmac.compare_digest(password.encode("utf-8"), gateway_key.encode("utf-8"))
        if not key_ok:
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
    async def local_ui_logout() -> JSONResponse:
        response = JSONResponse(content={"ok": True})
        response.delete_cookie(_UI_SESSION_COOKIE)
        return response

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    @app.get("/__ui__/api/tokens")
    async def local_ui_tokens_list() -> JSONResponse:
        raw = gw_tokens_list()
        items = []
        for token, m in raw.items():
            items.append({
                "token": token,
                "upstream_base": m.get("upstream_base", ""),
                "whitelist_keys": m.get("whitelist_key") or [],
            })
        return JSONResponse(content={"items": items})

    @app.post("/__ui__/api/tokens")
    async def local_ui_tokens_register(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        upstream_base = _normalize_input_upstream_base(body.get("upstream_base"))
        if not upstream_base:
            return JSONResponse(status_code=400, content={"error": "missing_params", "detail": "upstream_base 为必填"})
        if _is_forbidden_upstream_base_example(upstream_base):
            return JSONResponse(status_code=400, content={"error": "example_upstream_forbidden", "detail": "请替换为真实上游地址"})
        raw_whitelist = body.get("whitelist_key")
        whitelist = normalize_whitelist_keys(raw_whitelist) if raw_whitelist is not None else []
        try:
            token, already = gw_tokens_register(upstream_base, whitelist_key=whitelist)
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_params", "detail": str(exc)})
        except OSError as exc:
            logger.warning("ui token register persistence failed error=%s", exc)
            return JSONResponse(status_code=500, content={"error": "token_persistence_failed"})
        base_url = _gateway_token_base_url(request, token)
        return JSONResponse(
            status_code=200 if already else 201,
            content={"ok": True, "token": token, "already_registered": already, "base_url": base_url},
        )

    @app.patch("/__ui__/api/tokens/{token}")
    async def local_ui_tokens_update(token: str, request: Request) -> JSONResponse:
        token = token.strip()
        if not token:
            return JSONResponse(status_code=400, content={"error": "missing_token"})
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        kwargs: dict = {}
        new_token_val: str | None = None
        if "upstream_base" in body:
            upstream_base = _normalize_input_upstream_base(body["upstream_base"])
            if not upstream_base:
                return JSONResponse(status_code=400, content={"error": "invalid_params", "detail": "upstream_base 不能为空"})
            if _is_forbidden_upstream_base_example(upstream_base):
                return JSONResponse(status_code=400, content={"error": "example_upstream_forbidden", "detail": "请替换为真实上游地址"})
            kwargs["upstream_base"] = upstream_base
        if "whitelist_key" in body:
            kwargs["whitelist_key"] = body["whitelist_key"]
        if "new_token" in body:
            new_token_val = _string_field(body["new_token"])
            if not new_token_val:
                return JSONResponse(status_code=400, content={"error": "invalid_params", "detail": "new_token 不能为空"})
        if not kwargs and new_token_val is None:
            return JSONResponse(status_code=400, content={"error": "no_fields", "detail": "未提供任何可更新字段"})
        active_token = new_token_val if (new_token_val and new_token_val != token) else token
        try:
            updated = gw_tokens_update_and_rename(
                token,
                new_token=new_token_val if new_token_val != token else None,
                **kwargs,
            )
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_params", "detail": str(exc)})
        except OSError as exc:
            logger.warning("ui token update persistence failed token=%s error=%s", token, exc)
            return JSONResponse(status_code=500, content={"error": "token_persistence_failed"})
        if not updated:
            return JSONResponse(status_code=404, content={"error": "token_not_found"})
        base_url = _gateway_token_base_url(request, active_token)
        return JSONResponse(content={"ok": True, "token": active_token, "base_url": base_url})

    @app.delete("/__ui__/api/tokens/{token}")
    async def local_ui_tokens_delete(token: str) -> JSONResponse:
        token = token.strip()
        if not token:
            return JSONResponse(status_code=400, content={"error": "missing_token"})
        try:
            removed = gw_tokens_unregister(token)
        except OSError as exc:
            logger.warning("ui token delete persistence failed token=%s error=%s", token, exc)
            return JSONResponse(status_code=500, content={"error": "token_persistence_failed"})
        if removed:
            return JSONResponse(content={"ok": True})
        return JSONResponse(status_code=404, content={"error": "token_not_found"})

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    _KEY_FILES: dict[str, str] = {
        "gateway": "aegis_gateway.key",
        "proxy_token": "aegis_proxy_token.key",
        "fernet": "aegis_fernet.key",
    }

    def _key_path(key_type: str) -> Path:
        return (Path.cwd() / "config").resolve() / _KEY_FILES[key_type]

    def _key_fallback_path(key_type: str) -> Path:
        return Path("/tmp/aegisgate") / _KEY_FILES[key_type]

    def _is_regular_key_file(path: Path) -> bool:
        try:
            return path.is_file() and not path.is_symlink()
        except OSError:
            return False

    def _read_key_file(key_type: str) -> str | None:
        for candidate in (_key_path(key_type), _key_fallback_path(key_type)):
            if candidate.is_symlink():
                logger.warning("ignoring symlinked key file path=%s", candidate)
                continue
            if _is_regular_key_file(candidate):
                v = candidate.read_text(encoding="utf-8").strip()
                if v:
                    return v
        return None

    def _key_fingerprint(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    def _mask_key(value: str) -> str:
        secret = str(value or "")
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}***{secret[-3:]}"

    def _write_key_file_safe(path: Path, value: str) -> None:
        """Atomically write a key file without following an existing symlink."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                delete=False,
                dir=str(path.parent),
                suffix=".tmp",
            ) as tmp:
                tmp.write(value)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = Path(tmp.name)
            os.chmod(tmp_path, 0o600)
            tmp_path.replace(path)
        except Exception:
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise

    def _write_key_file(key_type: str, value: str) -> None:
        primary = _key_path(key_type)
        try:
            _write_key_file_safe(primary, value)
        except PermissionError:
            fallback = _key_fallback_path(key_type)
            _write_key_file_safe(fallback, value)
            logger.warning(
                "key file written to fallback path=%s (primary %s not writable)",
                fallback, primary,
            )

    @app.get("/__ui__/api/keys")
    async def local_ui_keys_list() -> JSONResponse:
        result = []
        for key_type, filename in _KEY_FILES.items():
            primary = _key_path(key_type)
            fallback = _key_fallback_path(key_type)
            exists = _is_regular_key_file(primary) or _is_regular_key_file(fallback)
            result.append({"type": key_type, "filename": filename, "exists": exists})
        return JSONResponse(content={"items": result})

    @app.get("/__ui__/api/keys/{key_type}")
    async def local_ui_key_get(key_type: str, request: Request) -> JSONResponse:
        if key_type not in _KEY_FILES:
            return JSONResponse(status_code=404, content={"error": "unknown_key_type"})
        value = _read_key_file(key_type)
        if value is None:
            return JSONResponse(status_code=404, content={"error": "key_not_found"})
        write_audit({
            "event": "ui_key_read",
            "route": f"/__ui__/api/keys/{key_type}",
            "actor_ip": request.client.host if request.client else "unknown",
            "key_type": key_type,
            "key_fingerprint": _key_fingerprint(value),
        })
        return JSONResponse(
            content={
                "ok": True,
                "type": key_type,
                "masked_value": _mask_key(value),
                "key_fingerprint": _key_fingerprint(value),
            }
        )

    @app.post("/__ui__/api/keys/{key_type}/rotate")
    async def local_ui_key_rotate(key_type: str, request: Request) -> JSONResponse:
        if key_type not in _KEY_FILES:
            return JSONResponse(status_code=404, content={"error": "unknown_key_type"})
        if key_type == "fernet":
            from cryptography.fernet import Fernet
            from aegisgate.storage import crypto as _crypto_mod
            # H-17: Save current key to history before rotation so existing
            # ciphertext remains decodable via MultiFernet during the transition.
            current_raw = _read_key_file("fernet")
            if current_raw:
                _crypto_mod.save_prev_key(current_raw.encode("utf-8"))
            new_key = Fernet.generate_key().decode("utf-8")
            _write_key_file(key_type, new_key)
            _crypto_mod._fernet_instance = None
            write_audit({
                "event": "ui_key_rotated",
                "route": f"/__ui__/api/keys/{key_type}/rotate",
                "actor_ip": request.client.host if request.client else "unknown",
                "key_type": key_type,
                "key_fingerprint": _key_fingerprint(new_key),
            })
            return JSONResponse(content={"ok": True, "type": key_type, "rotated": True})
        new_key = secrets.token_urlsafe(32)
        _write_key_file(key_type, new_key)
        if key_type == "gateway":
            import aegisgate.core.gateway_keys as _keys_mod
            _keys_mod._gateway_key_cached = new_key
            settings.gateway_key = new_key
            # Re-issue session so the user stays authenticated after key rotation.
            # The old session was signed with the old key and would immediately 401.
            new_session = _create_ui_session_token(request)
            new_csrf = _ui_csrf_token(new_session)
            response = JSONResponse(content={
                "ok": True, "type": key_type, "rotated": True,
                "csrf_token": new_csrf,
            })
            response.set_cookie(
                key=_UI_SESSION_COOKIE,
                value=new_session,
                max_age=settings.local_ui_session_ttl_seconds,
                httponly=True,
                samesite="lax",
                secure=settings.local_ui_secure_cookie,
            )
            write_audit({
                "event": "ui_key_rotated",
                "route": f"/__ui__/api/keys/{key_type}/rotate",
                "actor_ip": request.client.host if request.client else "unknown",
                "key_type": key_type,
                "key_fingerprint": _key_fingerprint(new_key),
            })
            return response
        write_audit({
            "event": "ui_key_rotated",
            "route": f"/__ui__/api/keys/{key_type}/rotate",
            "actor_ip": request.client.host if request.client else "unknown",
            "key_type": key_type,
            "key_fingerprint": _key_fingerprint(new_key),
        })
        return JSONResponse(content={"ok": True, "type": key_type, "rotated": True})

    # ------------------------------------------------------------------
    # Security rules YAML CRUD
    # ------------------------------------------------------------------

    # Every editable rule group in security_filters.yaml, addressed by its dotted
    # path. Discovery below picks up anything not listed here, so a new group in
    # the YAML shows up in the console without a code change; the seed exists so
    # a group whose last rule was deleted keeps its label and stays editable.
    _RULE_SECTION_LABELS: dict[str, str] = {
        "redaction.pii_patterns": "PII 脱敏规则",
        "restoration.suspicious_context_patterns": "还原可疑上下文",
        "untrusted_content_guard.instructional_patterns": "不可信内容指令",
        "injection_detector.direct_patterns": "直接注入规则",
        "injection_detector.system_exfil_patterns": "提示词窃取规则",
        "injection_detector.html_markdown_patterns": "HTML/Markdown 注入",
        "injection_detector.remote_content_patterns": "远程内容注入",
        "injection_detector.indirect_injection_patterns": "间接注入规则",
        "injection_detector.remote_content_instruction_patterns": "远程内容指令",
        "injection_detector.tool_call_injection_patterns": "工具调用注入规则",
        "injection_detector.spam_noise_patterns": "垃圾噪声规则",
        "rag_poison_guard.ingestion_poison_patterns": "RAG 入库投毒",
        "rag_poison_guard.retrieval_poison_patterns": "RAG 检索投毒",
        "rag_poison_guard.propagation_patterns": "RAG 扩散传播",
        "privilege_guard.blocked_patterns": "越权阻断规则",
        "anomaly_detector.command_patterns": "异常命令规则",
        "request_sanitizer.strong_intent_patterns": "请求强意图规则",
        "request_sanitizer.leak_check_patterns": "请求泄露检查",
        "request_sanitizer.shape_anomaly_patterns": "请求形态异常",
        "request_sanitizer.command_patterns": "请求命令规则",
        "request_sanitizer.encoded_payload_patterns": "请求编码载荷",
        "sanitizer.command_patterns": "响应命令规则",
        "sanitizer.force_block_command_patterns": "强制阻断命令",
        "sanitizer.encoded_payload_patterns": "响应编码载荷",
        "sanitizer.system_leak_patterns": "系统信息泄露",
        "sanitizer.unsafe_markup_patterns": "不安全标记",
        "sanitizer.unsafe_uri_patterns": "不安全 URI",
        "tool_call_guard.parameter_rules": "工具参数规则",
        "tool_call_guard.dangerous_param_patterns": "危险参数规则",
        "tool_call_guard.semantic_approval_patterns": "语义放行规则",
        "post_restore_guard.lure_patterns": "还原后诱导规则",
        "post_restore_guard.secret_patterns": "还原后密钥规则",
    }

    _RULE_FILTER_LABELS: dict[str, str] = {
        "redaction": "脱敏",
        "restoration": "还原",
        "untrusted_content_guard": "不可信内容防护",
        "injection_detector": "注入检测",
        "rag_poison_guard": "RAG 投毒防护",
        "privilege_guard": "越权防护",
        "anomaly_detector": "异常检测",
        "request_sanitizer": "请求净化",
        "sanitizer": "响应净化",
        "tool_call_guard": "工具调用防护",
        "post_restore_guard": "还原后检查",
    }

    # Section ids the console used before dotted paths existed. Kept so bookmarked
    # URLs and existing API clients keep working.
    _LEGACY_SECTION_ALIASES: dict[str, str] = {
        "pii_patterns": "redaction.pii_patterns",
        "tool_injection": "injection_detector.tool_call_injection_patterns",
        "command_patterns": "anomaly_detector.command_patterns",
        "direct_patterns": "injection_detector.direct_patterns",
        "system_exfil_patterns": "injection_detector.system_exfil_patterns",
    }

    # Groups whose items are keyed by something other than `id` (parameter_rules
    # uses tool+param), so the id-based CRUD below cannot address them. Listed and
    # viewable, not editable.
    _READONLY_SECTIONS: frozenset[str] = frozenset({"tool_call_guard.parameter_rules"})

    # Per-rule metadata the editor may write besides id/regex. Anything else in an
    # existing rule is preserved untouched on update.
    _RULE_EXTRA_STRING_FIELDS: frozenset[str] = frozenset({"kind", "category", "tool", "param"})

    def _looks_like_rule_list(value: object) -> bool:
        if not isinstance(value, list) or not value:
            return False
        return all(isinstance(entry, dict) for entry in value) and any(
            "regex" in entry or "id" in entry for entry in value
        )

    def _discover_rule_sections(data: dict) -> dict[str, dict[str, Any]]:
        """Map every editable rule group in *data* to its dotted section id.

        Walks the YAML instead of hard-coding a list, so adding a rule group to
        security_filters.yaml surfaces it in the console with no code change. The
        returned ids are the only values the CRUD routes accept, so a dotted path
        from a request can never reach an arbitrary node.
        """
        found: dict[str, dict[str, Any]] = {}

        def walk(node: object, path: list[str]) -> None:
            if not isinstance(node, dict):
                return
            for key, value in node.items():
                key = str(key)
                current = path + [key]
                if _looks_like_rule_list(value):
                    found[".".join(current)] = {"path": current, "count": len(value)}
                elif isinstance(value, dict):
                    walk(value, current)

        walk(data, [])
        # Seed known groups so one whose rules were all deleted does not vanish.
        for section_id in _RULE_SECTION_LABELS:
            found.setdefault(section_id, {"path": section_id.split("."), "count": 0})

        for section_id, info in found.items():
            filter_key = info["path"][0]
            info["id"] = section_id
            info["label"] = _RULE_SECTION_LABELS.get(
                section_id, section_id.rsplit(".", 1)[-1].replace("_", " ")
            )
            info["filter"] = filter_key
            info["filter_label"] = _RULE_FILTER_LABELS.get(filter_key, filter_key)
            info["readonly"] = section_id in _READONLY_SECTIONS
        return found

    def _resolve_rules_file() -> Path:
        p = Path(settings.security_rules_path)
        if not p.is_absolute():
            p = Path.cwd() / p
        return p.resolve()

    def _load_rules_yaml() -> dict:
        path = _resolve_rules_file()
        if not path.is_file():
            return {}
        with path.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _write_rules_text(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=str(path.parent), suffix=".tmp"
        ) as tmp:
            tmp.write(text)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
        try:
            from aegisgate.core.hot_reload import reload_security_rules
            reload_security_rules()
        except Exception:
            pass

    def _save_rules_yaml(data: dict, edit: "RuleEdit | None" = None) -> None:
        """Persist *data*, keeping the file's comments when *edit* describes the change.

        A plain dump would drop all 80 comment lines in security_filters.yaml —
        the file documents the security policy, so the edit is applied as a text
        patch instead, verified against *data* before it is written.
        """
        path = _resolve_rules_file()
        if edit is not None and path.is_file():
            from aegisgate.core.rules_editor import render_rules_yaml

            original = path.read_text(encoding="utf-8")
            _write_rules_text(path, render_rules_yaml(original, data, edit))
            return
        _write_rules_text(
            path,
            yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False),
        )

    def _save_action_map_yaml(data: dict, updates: list[tuple[list[str], object]]) -> None:
        path = _resolve_rules_file()
        if path.is_file():
            from aegisgate.core.rules_editor import render_scalar_updates

            original = path.read_text(encoding="utf-8")
            _write_rules_text(path, render_scalar_updates(original, data, updates))
            return
        _write_rules_text(
            path,
            yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False),
        )

    def _section_info(data: dict, section: str) -> dict[str, Any] | None:
        """Resolve a section id (dotted or legacy alias) against *data*."""
        sections = _discover_rule_sections(data)
        resolved = _LEGACY_SECTION_ALIASES.get(section, section)
        return sections.get(resolved)

    def _get_section_list(data: dict, path: list[str]) -> list:
        node: Any = data
        for key in path:
            if not isinstance(node, dict):
                return []
            node = node.get(key) or []
        return node if isinstance(node, list) else []

    def _set_section_list(data: dict, path: list[str], items: list) -> None:
        node = data
        for key in path[:-1]:
            if key not in node or not isinstance(node[key], dict):
                node[key] = {}
            node = node[key]
        node[path[-1]] = items

    def _required_rule_regex(body: dict[str, Any]) -> str | None:
        regex = _string_field(body.get("regex"))
        return regex or None

    def _invalid_regex_response(regex: str) -> JSONResponse | None:
        try:
            re.compile(regex)
        except re.error as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_regex", "detail": str(exc)},
            )
        return None

    def _unknown_section_response(section: str) -> JSONResponse:
        return JSONResponse(
            status_code=404, content={"error": "unknown_section", "detail": section}
        )

    def _readonly_section_response(section: str) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={
                "error": "section_readonly",
                "detail": f"规则组 '{section}' 以 tool+param 为标识，暂不支持通过控制台编辑",
            },
        )

    def _apply_rule_extras(target: dict, body: dict[str, Any]) -> dict[str, Any]:
        """Copy the editable metadata fields present in *body* onto *target*.

        Returns just the fields it wrote, so an update can hand the comment-
        preserving writer the exact change set instead of the whole rule.
        """
        applied: dict[str, Any] = {}
        for key in _RULE_EXTRA_STRING_FIELDS:
            if key in body:
                target[key] = str(body[key])
                applied[key] = target[key]
        if isinstance(body.get("patterns"), list):
            target["patterns"] = body["patterns"]
            applied["patterns"] = target["patterns"]
        return applied

    @app.get("/__ui__/api/rules")
    async def local_ui_rules_sections() -> JSONResponse:
        data = _load_rules_yaml()
        discovered = _discover_rule_sections(data)
        sections = [
            {
                "id": info["id"],
                "label": info["label"],
                "filter": info["filter"],
                "filter_label": info["filter_label"],
                "count": len(_get_section_list(data, info["path"])),
                "readonly": info["readonly"],
            }
            for info in discovered.values()
        ]
        sections.sort(key=lambda s: (s["filter"], s["id"]))
        return JSONResponse(content={
            "sections": sections,
            "total_rules": sum(s["count"] for s in sections),
            "aliases": dict(_LEGACY_SECTION_ALIASES),
        })

    @app.get("/__ui__/api/rules/{section}")
    async def local_ui_rules_get(section: str) -> JSONResponse:
        data = _load_rules_yaml()
        info = _section_info(data, section)
        if info is None:
            return _unknown_section_response(section)
        items = _get_section_list(data, info["path"])
        return JSONResponse(content={
            "section": info["id"],
            "label": info["label"],
            "readonly": info["readonly"],
            "items": items,
        })

    @app.post("/__ui__/api/rules/{section}")
    async def local_ui_rules_add(section: str, request: Request) -> JSONResponse:
        data = _load_rules_yaml()
        info = _section_info(data, section)
        if info is None:
            return _unknown_section_response(section)
        if info["readonly"]:
            return _readonly_section_response(info["id"])
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        rule_id = _string_field(body.get("id"))
        if not rule_id:
            return JSONResponse(status_code=400, content={"error": "missing_id"})
        regex = _required_rule_regex(body)
        if regex is None:
            return JSONResponse(status_code=400, content={"error": "missing_regex"})
        invalid_regex = _invalid_regex_response(regex)
        if invalid_regex is not None:
            return invalid_regex
        items = _get_section_list(data, info["path"])
        if any(str(item.get("id", "")) == rule_id for item in items):
            return JSONResponse(status_code=409, content={"error": "id_exists", "detail": f"规则 id '{rule_id}' 已存在"})
        new_item: dict = {"id": rule_id, "regex": regex}
        _apply_rule_extras(new_item, body)
        items.append(new_item)
        _set_section_list(data, info["path"], items)
        _save_rules_yaml(
            data,
            RuleEdit(
                path=list(info["path"]),
                op="add",
                rule_id=rule_id,
                fields={k: v for k, v in new_item.items() if k != "id"},
            ),
        )
        return JSONResponse(status_code=201, content={"ok": True, "section": info["id"], "item": new_item})

    @app.patch("/__ui__/api/rules/{section}/{rule_id}")
    async def local_ui_rules_update(section: str, rule_id: str, request: Request) -> JSONResponse:
        data = _load_rules_yaml()
        info = _section_info(data, section)
        if info is None:
            return _unknown_section_response(section)
        if info["readonly"]:
            return _readonly_section_response(info["id"])
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        items = _get_section_list(data, info["path"])
        changed: dict[str, object] = {}
        for item in items:
            if str(item.get("id", "")) == rule_id:
                if "regex" in body:
                    regex = _required_rule_regex(body)
                    if regex is None:
                        return JSONResponse(status_code=400, content={"error": "missing_regex"})
                    invalid_regex = _invalid_regex_response(regex)
                    if invalid_regex is not None:
                        return invalid_regex
                    item["regex"] = regex
                    changed["regex"] = regex
                changed.update(_apply_rule_extras(item, body))
                _set_section_list(data, info["path"], items)
                _save_rules_yaml(
                    data,
                    RuleEdit(
                        path=list(info["path"]),
                        op="update",
                        rule_id=rule_id,
                        fields=changed,
                    ),
                )
                return JSONResponse(content={"ok": True, "section": info["id"], "item": item})
        return JSONResponse(status_code=404, content={"error": "rule_not_found"})

    @app.delete("/__ui__/api/rules/{section}/{rule_id}")
    async def local_ui_rules_delete(section: str, rule_id: str) -> JSONResponse:
        data = _load_rules_yaml()
        info = _section_info(data, section)
        if info is None:
            return _unknown_section_response(section)
        if info["readonly"]:
            return _readonly_section_response(info["id"])
        items = _get_section_list(data, info["path"])
        new_items = [item for item in items if str(item.get("id", "")) != rule_id]
        if len(new_items) == len(items):
            return JSONResponse(status_code=404, content={"error": "rule_not_found"})
        _set_section_list(data, info["path"], new_items)
        _save_rules_yaml(
            data,
            RuleEdit(path=list(info["path"]), op="delete", rule_id=rule_id),
        )
        return JSONResponse(content={"ok": True, "section": info["id"]})

    @app.post("/__ui__/api/rules_test")
    async def local_ui_rules_test(request: Request) -> JSONResponse:
        """Run a candidate regex against sample text and report the hit spans.

        Matching happens in a killable child process: a pattern typed here is a
        very plausible source of catastrophic backtracking, and reporting the
        timeout is more useful to the author than hanging a worker.
        """
        from aegisgate.core.regex_probe import (
            ProbeInputError,
            normalize_probe_input,
            probe,
        )

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        try:
            regex, samples = normalize_probe_input(body.get("regex"), body.get("samples"))
        except ProbeInputError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_probe_input", "detail": str(exc)})

        outcome = await asyncio.to_thread(probe, regex, samples)
        if outcome.get("error"):
            return JSONResponse(status_code=400, content={"error": "probe_failed", "detail": outcome["error"]})
        if outcome.get("timed_out"):
            return JSONResponse(content={
                "ok": True,
                "timed_out": True,
                "timeout_seconds": outcome["timeout_seconds"],
                "detail": (
                    f"正则在 {outcome['timeout_seconds']} 秒内未跑完，极可能存在灾难性回溯，"
                    "不建议保存"
                ),
                "results": [],
            })
        return JSONResponse(content={"ok": True, "timed_out": False, "results": outcome["results"]})

    @app.get("/__ui__/api/rules_action_map")
    async def local_ui_action_map_get() -> JSONResponse:
        data = _load_rules_yaml()
        return JSONResponse(content={"action_map": data.get("action_map") or {}})

    @app.patch("/__ui__/api/rules_action_map")
    async def local_ui_action_map_update(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        allowed_actions = {"block", "review", "sanitize", "pass"}
        data = _load_rules_yaml()
        action_map = data.get("action_map") or {}
        updates: list[tuple[list[str], object]] = []
        for category, threats in body.items():
            if not isinstance(threats, dict):
                continue
            if category not in action_map:
                action_map[category] = {}
            for threat, action in threats.items():
                if str(action) not in allowed_actions:
                    return JSONResponse(
                        status_code=400,
                        content={"error": "invalid_action", "detail": f"'{action}' 不是有效动作"},
                    )
                if action_map[category].get(threat) != str(action):
                    updates.append((["action_map", str(category), str(threat)], str(action)))
                action_map[category][threat] = str(action)
        data["action_map"] = action_map
        _save_action_map_yaml(data, updates)
        return JSONResponse(content={"ok": True, "action_map": action_map})

    # ------------------------------------------------------------------
    # Exact-value redaction management
    # ------------------------------------------------------------------

    _REDACT_VALUES_DESCRIPTION = (
        "精确值脱敏：配置的字符串若出现在请求/响应体中会被自动替换为 [REDACTED:EXACT_VALUE]。"
        "最少 10 个字符，适合保护 API Key、密钥等敏感数据。V1/V2 均适用。"
    )

    def _mask_value(val: str) -> str:
        if len(val) <= 10:
            return val[:2] + "*" * (len(val) - 2)
        return val[:4] + "****" + val[-3:]

    @app.get("/__ui__/api/redact_values")
    async def local_ui_redact_values_list() -> JSONResponse:
        from aegisgate.config.redact_values import load_redact_values

        values = load_redact_values()
        items = [{"masked": _mask_value(v), "length": len(v)} for v in values]
        return JSONResponse(content={
            "items": items,
            "count": len(items),
            "description": _REDACT_VALUES_DESCRIPTION,
        })

    @app.post("/__ui__/api/redact_values")
    async def local_ui_redact_values_add(request: Request) -> JSONResponse:
        from aegisgate.config.redact_values import load_redact_values, save_redact_values

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        value = body.get("value", "")
        if not isinstance(value, str) or not value.strip():
            return JSONResponse(status_code=400, content={"error": "value_required"})
        value = value.strip()
        if len(value) < 10:
            return JSONResponse(status_code=400, content={"error": "value_too_short", "detail": "至少 10 个字符"})
        values = load_redact_values()
        if value in values:
            return JSONResponse(status_code=409, content={"error": "duplicate", "detail": "该值已存在"})
        values.append(value)
        try:
            save_redact_values(values)
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": "validation_error", "detail": str(exc)})
        return JSONResponse(content={"ok": True, "count": len(values)})

    @app.delete("/__ui__/api/redact_values/{index}")
    async def local_ui_redact_values_delete(index: int) -> JSONResponse:
        from aegisgate.config.redact_values import load_redact_values, save_redact_values

        values = load_redact_values()
        if index < 0 or index >= len(values):
            return JSONResponse(status_code=404, content={"error": "index_out_of_range"})
        values.pop(index)
        save_redact_values(values)
        return JSONResponse(content={"ok": True, "count": len(values)})

    # ------------------------------------------------------------------
    # Docker compose file editor
    # ------------------------------------------------------------------

    _COMPOSE_FILES_ALLOWED = frozenset({
        "docker-compose.yml",
    })

    def _compose_file_path(filename: str) -> Path:
        # AEGIS_COMPOSE_DIR: explicit mount path (e.g. /app/project pointing to host project root).
        # Empty → default to config/compose/ (volume-mounted, host-accessible).
        if settings.compose_dir:
            base = Path(settings.compose_dir)
        else:
            base = Path.cwd() / "config" / "compose"
        return (base / filename).resolve()

    @app.get("/__ui__/api/compose")
    async def local_ui_compose_list() -> JSONResponse:
        items = []
        for name in sorted(_COMPOSE_FILES_ALLOWED):
            path = _compose_file_path(name)
            items.append({"filename": name, "exists": path.is_file()})
        return JSONResponse(content={"items": items})

    @app.get("/__ui__/api/compose/{filename:path}")
    async def local_ui_compose_get(filename: str) -> JSONResponse:
        if filename not in _COMPOSE_FILES_ALLOWED:
            return JSONResponse(status_code=404, content={"error": "not_allowed"})
        path = _compose_file_path(filename)
        if not path.is_file():
            return JSONResponse(status_code=404, content={"error": "file_not_found"})
        return JSONResponse(content={"filename": filename, "content": path.read_text(encoding="utf-8")})

    @app.put("/__ui__/api/compose/{filename:path}")
    async def local_ui_compose_put(filename: str, request: Request) -> JSONResponse:
        if filename not in _COMPOSE_FILES_ALLOWED:
            return JSONResponse(status_code=404, content={"error": "not_allowed"})
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        content = body.get("content", "")
        if not isinstance(content, str):
            return JSONResponse(status_code=400, content={"error": "content_must_be_string"})
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_yaml", "detail": str(exc)})
        path = _compose_file_path(filename)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(path.parent), suffix=".tmp") as tmp:
                tmp.write(content)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)
        except OSError:
            return JSONResponse(status_code=500, content={"error": "write_failed", "detail": "无法写入文件"})
        return JSONResponse(content={"ok": True, "filename": filename, "save_path": str(path)})

    # ------------------------------------------------------------------
    # Audit log explorer
    # ------------------------------------------------------------------

    _AUDIT_CSV_COLUMNS: tuple[str, ...] = (
        "ts", "request_id", "session_id", "tenant_id", "route", "event",
        "risk_score", "risk_threshold", "requires_human_review",
        "request_disposition", "response_disposition",
        "disposition_reasons", "security_tags", "enforcement_actions",
    )
    # Excel and friends execute a cell whose text starts with one of these.
    _CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

    def _audit_filter_from_query(request: Request):
        from aegisgate.core.audit_query import AuditFilter, parse_timestamp

        params = request.query_params
        raw_min_risk = params.get("min_risk", "").strip()
        try:
            min_risk = float(raw_min_risk) if raw_min_risk else None
        except ValueError:
            min_risk = None
        return AuditFilter(
            since=parse_timestamp(params.get("since")),
            until=parse_timestamp(params.get("until")),
            route=params.get("route", "").strip(),
            disposition=params.get("disposition", "").strip(),
            min_risk=min_risk,
            tag=params.get("tag", "").strip(),
            event=params.get("event", "").strip(),
            text=params.get("q", "").strip(),
        )

    def _audit_paging(request: Request, default_limit: int, max_limit: int) -> tuple[int | None, int]:
        params = request.query_params
        raw_cursor = params.get("cursor", "").strip()
        try:
            cursor = int(raw_cursor) if raw_cursor else None
        except ValueError:
            cursor = None
        try:
            limit = int(params.get("limit", default_limit))
        except ValueError:
            limit = default_limit
        return cursor, max(1, min(limit, max_limit))

    def _audit_unavailable() -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={
                "error": "audit_log_disabled",
                "detail": "AEGIS_AUDIT_LOG_PATH 为空，审计文件未启用",
            },
        )

    def _csv_cell(value: object) -> str:
        if isinstance(value, (list, tuple)):
            text = " | ".join(str(item) for item in value)
        elif value is None:
            text = ""
        else:
            text = str(value)
        if text.startswith(_CSV_FORMULA_PREFIXES):
            text = "'" + text
        return text

    @app.get("/__ui__/api/audit")
    async def local_ui_audit_query(request: Request) -> JSONResponse:
        """Page backwards through the audit log, newest record first."""
        from aegisgate.core.audit_query import (
            DEFAULT_LIMIT,
            MAX_LIMIT,
            query_log,
            resolve_audit_path,
        )

        path = resolve_audit_path()
        if path is None:
            return _audit_unavailable()
        cursor, limit = _audit_paging(request, DEFAULT_LIMIT, MAX_LIMIT)
        criteria = _audit_filter_from_query(request)
        result = await asyncio.to_thread(
            query_log, path, criteria, cursor=cursor, limit=limit
        )
        return JSONResponse(content={
            "items": result.items,
            "next_cursor": result.next_cursor,
            "reached_start": result.reached_start,
            "budget_exhausted": result.budget_exhausted,
            "scanned_bytes": result.scanned_bytes,
            "file_size": result.file_size,
            "malformed_lines": result.malformed_lines,
            "path": str(path),
            "exists": path.is_file(),
        })

    @app.get("/__ui__/api/audit/summary")
    async def local_ui_audit_summary(request: Request) -> JSONResponse:
        from aegisgate.core.audit_query import resolve_audit_path, summarize_log

        path = resolve_audit_path()
        if path is None:
            return _audit_unavailable()
        criteria = _audit_filter_from_query(request)
        summary = await asyncio.to_thread(summarize_log, path, criteria)
        return JSONResponse(content=summary)

    @app.get("/__ui__/api/audit/record/{request_id}")
    async def local_ui_audit_record(request_id: str) -> JSONResponse:
        from aegisgate.core.audit_query import AuditFilter, query_log, resolve_audit_path

        path = resolve_audit_path()
        if path is None:
            return _audit_unavailable()
        result = await asyncio.to_thread(
            query_log, path, AuditFilter(request_id=request_id.strip()), limit=20
        )
        if not result.items:
            return JSONResponse(status_code=404, content={"error": "record_not_found"})
        return JSONResponse(content={"request_id": request_id, "items": result.items})

    @app.get("/__ui__/api/audit/export")
    async def local_ui_audit_export(request: Request) -> Response:
        """Export the current filter as JSONL or CSV, capped at MAX_EXPORT_LIMIT rows."""
        import csv
        import io

        from aegisgate.core.audit_query import (
            MAX_EXPORT_LIMIT,
            query_log,
            resolve_audit_path,
        )

        path = resolve_audit_path()
        if path is None:
            return _audit_unavailable()
        fmt = request.query_params.get("format", "jsonl").strip().lower()
        if fmt not in {"jsonl", "csv"}:
            return JSONResponse(status_code=400, content={"error": "invalid_format"})
        cursor, limit = _audit_paging(request, MAX_EXPORT_LIMIT, MAX_EXPORT_LIMIT)
        criteria = _audit_filter_from_query(request)
        result = await asyncio.to_thread(
            query_log, path, criteria, cursor=cursor, limit=limit
        )

        if fmt == "jsonl":
            body = "".join(
                json.dumps({k: v for k, v in item.items() if k != "_offset"}, ensure_ascii=False) + "\n"
                for item in result.items
            )
            media_type = "application/x-ndjson"
            filename = "aegisgate-audit.jsonl"
        else:
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(_AUDIT_CSV_COLUMNS)
            for item in result.items:
                writer.writerow([_csv_cell(item.get(column)) for column in _AUDIT_CSV_COLUMNS])
            body = buffer.getvalue()
            media_type = "text/csv; charset=utf-8"
            filename = "aegisgate-audit.csv"

        return Response(
            content=body,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Aegis-Export-Rows": str(len(result.items)),
                "X-Aegis-Export-Truncated": "1" if result.next_cursor is not None else "0",
            },
        )

    # ------------------------------------------------------------------
    # Dangerous response samples
    # ------------------------------------------------------------------

    @app.get("/__ui__/api/dangerous_samples/dates")
    async def local_ui_dangerous_sample_dates() -> JSONResponse:
        from aegisgate.core.audit_query import list_dangerous_sample_dates

        return JSONResponse(content={
            "items": list_dangerous_sample_dates(),
            "enabled": bool(settings.enable_dangerous_response_log),
        })

    @app.get("/__ui__/api/dangerous_samples")
    async def local_ui_dangerous_samples(request: Request) -> JSONResponse:
        from aegisgate.core.audit_query import (
            DEFAULT_LIMIT,
            MAX_LIMIT,
            query_log,
            resolve_dangerous_sample_path,
        )

        date_str = request.query_params.get("date", "").strip()
        path = resolve_dangerous_sample_path(date_str)
        if path is None:
            return JSONResponse(
                status_code=404,
                content={"error": "sample_file_not_found", "detail": date_str},
            )
        cursor, limit = _audit_paging(request, DEFAULT_LIMIT, MAX_LIMIT)
        criteria = _audit_filter_from_query(request)
        result = await asyncio.to_thread(
            query_log, path, criteria, cursor=cursor, limit=limit
        )
        return JSONResponse(content={
            "date": date_str,
            "items": result.items,
            "next_cursor": result.next_cursor,
            "reached_start": result.reached_start,
            "budget_exhausted": result.budget_exhausted,
            "file_size": result.file_size,
        })

    # ------------------------------------------------------------------
    # Gateway restart
    # ------------------------------------------------------------------

    @app.post("/__ui__/api/restart")
    async def local_ui_restart(request: Request) -> JSONResponse:
        write_audit({
            "event": "ui_restart_requested",
            "route": "/__ui__/api/restart",
            "actor_ip": request.client.host if request.client else "unknown",
        })
        async def _do_restart() -> None:
            await asyncio.sleep(1.5)
            os.kill(os.getpid(), signal.SIGTERM)
        asyncio.ensure_future(_do_restart())
        return JSONResponse(content={"ok": True, "message": "gateway will restart in ~1.5s"})


# ---------------------------------------------------------------------------
# Helpers used by register_ui_routes closures
# ---------------------------------------------------------------------------

def _get_boot_time() -> float:
    """Late import to avoid circular dependency with gateway.py."""
    from aegisgate.core.gateway import _BOOT_TIME
    return _BOOT_TIME


def _ui_bootstrap_payload(request: Request | None = None) -> dict[str, object]:
    session_token = request.cookies.get(_UI_SESSION_COOKIE, "") if request is not None else ""
    return {
        "app_name": settings.app_name,
        "status": "running",
        "uptime_seconds": int(time.time() - _get_boot_time()),
        "server": {"host": settings.host, "port": settings.port},
        "upstream_base_url": (settings.upstream_base_url or "").strip(),
        "security": {
            "level": settings.security_level,
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
        "config_sections": [dict(section) for section in _UI_CONFIG_SECTIONS],
    }
