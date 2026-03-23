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
            key_path.write_text(new_key, encoding="utf-8")
            try:
                os.chmod(key_path, 0o600)
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
            key_path.write_text(new_token, encoding="utf-8")
            try:
                os.chmod(key_path, 0o600)
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


def _normalize_required_whitelist_list(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    return normalize_whitelist_keys(value)
