"""UI, key management, security rules CRUD, and compose file endpoints.

All endpoints are registered via ``register_ui_routes(app)`` called from
the main ``gateway.py`` module.
"""

from __future__ import annotations

import asyncio
import os
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
    _serialize_env_value,
    _ui_config_field_map,
    _ui_config_payload,
    _write_env_updates,
)
from aegisgate.core.gw_tokens import (
    list_tokens as gw_tokens_list,
    register as gw_tokens_register,
    unregister as gw_tokens_unregister,
    update_and_rename as gw_tokens_update_and_rename,
)
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys
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
            try:
                coerced = _coerce_config_value(meta, raw_value)
            except ValueError as exc:
                return JSONResponse(status_code=400, content={"error": "invalid_field_value", "detail": str(exc)})
            env_updates[str(meta["env"])] = _serialize_env_value(str(meta["type"]), coerced)
            updated_fields[str(field_name)] = coerced
        try:
            _write_env_updates(env_updates)
        except RuntimeError as exc:
            return JSONResponse(status_code=500, content={"error": "env_write_failed", "detail": str(exc)})
        from aegisgate.core.hot_reload import reload_settings
        reload_settings()
        return JSONResponse(content={"ok": True, "updated": updated_fields, "config": _ui_config_payload()})

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
        if not updated:
            return JSONResponse(status_code=404, content={"error": "token_not_found"})
        base_url = _gateway_token_base_url(request, active_token)
        return JSONResponse(content={"ok": True, "token": active_token, "base_url": base_url})

    @app.delete("/__ui__/api/tokens/{token}")
    async def local_ui_tokens_delete(token: str) -> JSONResponse:
        token = token.strip()
        if not token:
            return JSONResponse(status_code=400, content={"error": "missing_token"})
        if gw_tokens_unregister(token):
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
        return (Path.cwd() / "config" / _KEY_FILES[key_type]).resolve()

    def _key_fallback_path(key_type: str) -> Path:
        return Path("/tmp/aegisgate") / _KEY_FILES[key_type]

    def _read_key_file(key_type: str) -> str | None:
        for candidate in (_key_path(key_type), _key_fallback_path(key_type)):
            if candidate.is_file():
                v = candidate.read_text(encoding="utf-8").strip()
                if v:
                    return v
        return None

    def _write_key_file(key_type: str, value: str) -> None:
        primary = _key_path(key_type)
        try:
            primary.parent.mkdir(parents=True, exist_ok=True)
            primary.write_text(value, encoding="utf-8")
            try:
                os.chmod(primary, 0o600)
            except OSError:
                pass
        except PermissionError:
            fallback = _key_fallback_path(key_type)
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(value, encoding="utf-8")
            try:
                os.chmod(fallback, 0o600)
            except OSError:
                pass

    @app.get("/__ui__/api/keys")
    async def local_ui_keys_list() -> JSONResponse:
        result = []
        for key_type, filename in _KEY_FILES.items():
            primary = _key_path(key_type)
            fallback = _key_fallback_path(key_type)
            exists = primary.is_file() or fallback.is_file()
            active_path = str(primary) if primary.is_file() else (str(fallback) if fallback.is_file() else str(primary))
            result.append({"type": key_type, "filename": filename, "exists": exists})
        return JSONResponse(content={"items": result})

    @app.get("/__ui__/api/keys/{key_type}")
    async def local_ui_key_get(key_type: str) -> JSONResponse:
        if key_type not in _KEY_FILES:
            return JSONResponse(status_code=404, content={"error": "unknown_key_type"})
        value = _read_key_file(key_type)
        if value is None:
            return JSONResponse(status_code=404, content={"error": "key_not_found"})
        return JSONResponse(content={"ok": True, "type": key_type, "value": value})

    @app.post("/__ui__/api/keys/{key_type}/rotate")
    async def local_ui_key_rotate(key_type: str, request: Request) -> JSONResponse:
        if key_type not in _KEY_FILES:
            return JSONResponse(status_code=404, content={"error": "unknown_key_type"})
        if key_type == "fernet":
            from cryptography.fernet import Fernet
            from aegisgate.storage import crypto as _crypto_mod
            new_key = Fernet.generate_key().decode("utf-8")
            _write_key_file(key_type, new_key)
            _crypto_mod._fernet_instance = None
            return JSONResponse(content={"ok": True, "type": key_type, "value": new_key})
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
                "ok": True, "type": key_type, "value": new_key,
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
            return response
        return JSONResponse(content={"ok": True, "type": key_type, "value": new_key})

    # ------------------------------------------------------------------
    # Security rules YAML CRUD
    # ------------------------------------------------------------------

    _RULES_SECTIONS: dict[str, list[str]] = {
        "pii_patterns": ["redaction", "pii_patterns"],
        "tool_injection": ["injection_detector", "tool_call_injection_patterns"],
        "command_patterns": ["anomaly_detector", "command_patterns"],
        "direct_patterns": ["injection_detector", "direct_patterns"],
        "system_exfil_patterns": ["injection_detector", "system_exfil_patterns"],
    }

    _RULES_SECTION_LABELS: dict[str, str] = {
        "pii_patterns": "PII 脱敏规则",
        "tool_injection": "工具调用注入规则",
        "command_patterns": "异常命令规则",
        "direct_patterns": "直接注入规则",
        "system_exfil_patterns": "提示词窃取规则",
    }

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

    def _save_rules_yaml(data: dict) -> None:
        path = _resolve_rules_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(path.parent), suffix=".tmp") as tmp:
            yaml.dump(data, tmp, allow_unicode=True, default_flow_style=False, sort_keys=False)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
        try:
            from aegisgate.core.hot_reload import reload_security_rules
            reload_security_rules()
        except Exception:
            pass

    def _get_section_list(data: dict, section_key: str) -> list:
        keys = _RULES_SECTIONS[section_key]
        node: Any = data
        for k in keys:
            if not isinstance(node, dict):
                return []
            node = node.get(k) or []
        return node if isinstance(node, list) else []

    def _set_section_list(data: dict, section_key: str, items: list) -> None:
        keys = _RULES_SECTIONS[section_key]
        node = data
        for k in keys[:-1]:
            if k not in node:
                node[k] = {}
            node = node[k]
        node[keys[-1]] = items

    @app.get("/__ui__/api/rules")
    async def local_ui_rules_sections() -> JSONResponse:
        sections = [{"id": k, "label": v} for k, v in _RULES_SECTION_LABELS.items()]
        return JSONResponse(content={"sections": sections})

    @app.get("/__ui__/api/rules/{section}")
    async def local_ui_rules_get(section: str) -> JSONResponse:
        if section not in _RULES_SECTIONS:
            return JSONResponse(status_code=404, content={"error": "unknown_section"})
        data = _load_rules_yaml()
        items = _get_section_list(data, section)
        return JSONResponse(content={"section": section, "items": items})

    @app.post("/__ui__/api/rules/{section}")
    async def local_ui_rules_add(section: str, request: Request) -> JSONResponse:
        if section not in _RULES_SECTIONS:
            return JSONResponse(status_code=404, content={"error": "unknown_section"})
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        rule_id = _string_field(body.get("id"))
        if not rule_id:
            return JSONResponse(status_code=400, content={"error": "missing_id"})
        data = _load_rules_yaml()
        items = _get_section_list(data, section)
        if any(str(item.get("id", "")) == rule_id for item in items):
            return JSONResponse(status_code=409, content={"error": "id_exists", "detail": f"规则 id '{rule_id}' 已存在"})
        new_item: dict = {"id": rule_id}
        if "regex" in body:
            new_item["regex"] = str(body["regex"])
        if "kind" in body:
            new_item["kind"] = str(body["kind"])
        if "patterns" in body and isinstance(body["patterns"], list):
            new_item["patterns"] = body["patterns"]
        items.append(new_item)
        _set_section_list(data, section, items)
        _save_rules_yaml(data)
        return JSONResponse(status_code=201, content={"ok": True, "item": new_item})

    @app.patch("/__ui__/api/rules/{section}/{rule_id}")
    async def local_ui_rules_update(section: str, rule_id: str, request: Request) -> JSONResponse:
        if section not in _RULES_SECTIONS:
            return JSONResponse(status_code=404, content={"error": "unknown_section"})
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})
        data = _load_rules_yaml()
        items = _get_section_list(data, section)
        for item in items:
            if str(item.get("id", "")) == rule_id:
                if "regex" in body:
                    item["regex"] = str(body["regex"])
                if "kind" in body:
                    item["kind"] = str(body["kind"])
                if "patterns" in body and isinstance(body["patterns"], list):
                    item["patterns"] = body["patterns"]
                _set_section_list(data, section, items)
                _save_rules_yaml(data)
                return JSONResponse(content={"ok": True, "item": item})
        return JSONResponse(status_code=404, content={"error": "rule_not_found"})

    @app.delete("/__ui__/api/rules/{section}/{rule_id}")
    async def local_ui_rules_delete(section: str, rule_id: str) -> JSONResponse:
        if section not in _RULES_SECTIONS:
            return JSONResponse(status_code=404, content={"error": "unknown_section"})
        data = _load_rules_yaml()
        items = _get_section_list(data, section)
        new_items = [item for item in items if str(item.get("id", "")) != rule_id]
        if len(new_items) == len(items):
            return JSONResponse(status_code=404, content={"error": "rule_not_found"})
        _set_section_list(data, section, new_items)
        _save_rules_yaml(data)
        return JSONResponse(content={"ok": True})

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
                action_map[category][threat] = str(action)
        data["action_map"] = action_map
        _save_rules_yaml(data)
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
    # Gateway restart
    # ------------------------------------------------------------------

    @app.post("/__ui__/api/restart")
    async def local_ui_restart(request: Request) -> JSONResponse:
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
        "config_sections": {
            "general": "基础设置",
            "security": "安全设置",
            "v2": "v2 代理",
        },
    }
