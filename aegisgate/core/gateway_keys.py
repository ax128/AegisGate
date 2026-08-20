"""Gateway key and proxy token file management."""

from __future__ import annotations

import os
import secrets
import threading
from pathlib import Path

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys

# ---------------------------------------------------------------------------
# Gateway key  (file-based)
# ---------------------------------------------------------------------------
_GATEWAY_KEY_FILE = "aegis_gateway.key"

_gateway_key_cached: str | None = None
_gateway_key_lock = threading.Lock()


def _ensure_gateway_key() -> str:
    """Return the gateway key from config/aegis_gateway.key (auto-created on first run)."""
    global _gateway_key_cached

    with _gateway_key_lock:
        # If settings.gateway_key was set externally (e.g. tests / monkeypatch), honour it.
        current = (settings.gateway_key or "").strip()
        if current and current != _gateway_key_cached:
            _gateway_key_cached = current
            return current
        if _gateway_key_cached:
            return _gateway_key_cached

        key_path = (Path.cwd() / "config" / _GATEWAY_KEY_FILE).resolve()
        if key_path.is_file():
            stored = key_path.read_text(encoding="utf-8").strip()
            if stored:
                settings.gateway_key = stored
                _gateway_key_cached = stored
                logger.info("gateway_key loaded from %s", key_path)
                return stored

        # Auto-generate and persist (first run)
        new_key = secrets.token_urlsafe(32)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, new_key.encode("utf-8"))
            finally:
                os.close(fd)
            try:
                os.chmod(str(key_path), 0o600)
            except OSError:
                pass
            logger.info("gateway_key auto-generated and saved to %s", key_path)
        except PermissionError as exc:
            raise RuntimeError(
                f"gateway_key: could not write required key file at {key_path}; refusing insecure fallback"
            ) from exc
        settings.gateway_key = new_key
        _gateway_key_cached = new_key
        return new_key


# ---------------------------------------------------------------------------
# Internal proxy token auto-generation (Caddy ↔ AegisGate auto-pairing)
# ---------------------------------------------------------------------------
_PROXY_TOKEN_FILE = "aegis_proxy_token.key"
_PROXY_TOKEN_HEADER = "x-aegis-proxy-token"
_proxy_token_value: str = ""
_proxy_token_lock = threading.Lock()


def _ensure_proxy_token() -> str:
    """Auto-generate an internal proxy token for Caddy ↔ AegisGate trust."""
    global _proxy_token_value

    with _proxy_token_lock:
        key_path = (Path.cwd() / "config" / _PROXY_TOKEN_FILE).resolve()
        if key_path.is_file():
            stored = key_path.read_text(encoding="utf-8").strip()
            if stored:
                _proxy_token_value = stored
                logger.info("proxy_token loaded from %s", key_path)
                return stored

        new_token = secrets.token_urlsafe(32)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, new_token.encode("utf-8"))
            finally:
                os.close(fd)
            try:
                os.chmod(str(key_path), 0o600)
            except OSError:
                pass
            logger.info("proxy_token auto-generated and saved to %s", key_path)
        except PermissionError as exc:
            raise RuntimeError(
                f"proxy_token: could not write required token file at {key_path}; refusing insecure fallback"
            ) from exc
        _proxy_token_value = new_token
        return new_token


def get_proxy_token_value() -> str:
    """Return the current proxy token value."""
    with _proxy_token_lock:
        return _proxy_token_value


# ---------------------------------------------------------------------------
# Shared validation constants (used by gateway.py and gateway_ui_routes.py)
# ---------------------------------------------------------------------------
_FORBIDDEN_UPSTREAM_BASE_EXAMPLES = frozenset(
    u.rstrip("/").lower()
    for u in (
        "https://your-upstream.example.com/v1",
        "http://your-upstream.example.com/v1",
    )
)


def _normalize_input_upstream_base(value: object) -> str:
    return value.strip().rstrip("/") if isinstance(value, str) else ""


def _is_forbidden_upstream_base_example(value: object) -> bool:
    normalized = _normalize_input_upstream_base(value).lower()
    return bool(normalized) and normalized in _FORBIDDEN_UPSTREAM_BASE_EXAMPLES


# The forwarder already refuses a malformed upstream — but only at request time,
# via adapters.openai_compat.upstream._normalize_upstream_base. Registering one
# through the console therefore "succeeded" and then failed on the first real
# request with nothing in the UI to explain it. These messages are checked
# against that same function rather than restating its rules, so the console can
# never accept a base the forwarder will refuse.
_UPSTREAM_BASE_ERRORS: dict[str, str] = {
    "invalid_upstream_scheme": "上游地址必须以 http:// 或 https:// 开头",
    "invalid_upstream_host": "上游地址缺少主机名",
    "invalid_upstream_query_fragment": "上游地址不能带查询参数或 # 片段",
}


def upstream_base_error(value: object) -> str | None:
    """Return why *value* is unusable as an upstream base, or ``None`` if it is fine."""
    candidate = _normalize_input_upstream_base(value)
    if not candidate:
        return "上游地址为必填"
    # Imported here: the adapter package pulls in the forwarding stack, which
    # imports this module back.
    from urllib.parse import urlparse

    from aegisgate.adapters.openai_compat.upstream import _normalize_upstream_base

    try:
        _normalize_upstream_base(candidate)
    except ValueError as exc:
        return _UPSTREAM_BASE_ERRORS.get(str(exc), f"上游地址无效：{exc}")
    # Stricter than the forwarder on purpose: credentials in the URL end up in
    # every log line that records the upstream, and an upstream key belongs in a
    # header. Refusing them here narrows what can be stored, never widens it.
    if "@" in urlparse(candidate).netloc:
        return "上游地址不能包含用户名或密码，请改用请求头传递凭据"
    return None


def _normalize_required_whitelist_list(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    return normalize_whitelist_keys(value)
