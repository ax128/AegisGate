"""Reversible encryption for redaction mappings using Fernet (AES-128-CBC + HMAC).

Encryption key is loaded from AEGIS_ENCRYPTION_KEY env var.  When absent the
module auto-generates a persistent key file at ``<config_dir>/aegis_fernet.key``
on first use.  The key file is created with owner-only permissions (0o600).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from aegisgate.util.logger import logger

import threading

_fernet_instance: Fernet | None = None
_fernet_lock = threading.Lock()
_FERNET_KEY_FILE = "aegis_fernet.key"
_PENDING_PAYLOAD_PREFIX = "encjson:v1:"


def _config_dir() -> Path:
    """Resolve config directory (same logic as init_config)."""
    env = os.environ.get("AEGIS_CONFIG_DIR", "").strip()
    if env:
        return Path(env).resolve()
    return (Path.cwd() / "config").resolve()


def _load_or_generate_key() -> bytes:
    """Return Fernet key bytes, creating a new key file if needed."""
    # 1. Prefer explicit env var
    env_key = os.environ.get("AEGIS_ENCRYPTION_KEY", "").strip()
    if env_key:
        return env_key.encode("utf-8")

    primary_path = _config_dir() / _FERNET_KEY_FILE
    if primary_path.is_file():
        raw = primary_path.read_text(encoding="utf-8").strip()
        if raw:
            logger.info("crypto: loaded Fernet key from %s", primary_path)
            return raw.encode("utf-8")

    # 3. Auto-generate
    key = Fernet.generate_key()
    primary_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        primary_path.write_text(key.decode("utf-8"), encoding="utf-8")
        try:
            os.chmod(primary_path, 0o600)
        except OSError:
            pass
        logger.info("crypto: generated new Fernet key at %s", primary_path)
    except PermissionError as exc:
        raise RuntimeError(
            "crypto: could not write Fernet key file at "
            f"{primary_path}; refusing insecure fallback and requiring a writable config dir or explicit AEGIS_ENCRYPTION_KEY"
        ) from exc
    return key


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        with _fernet_lock:
            if _fernet_instance is None:
                _fernet_instance = Fernet(_load_or_generate_key())
    return _fernet_instance


def ensure_key() -> None:
    """Eagerly load or generate the Fernet key. Call at startup to surface errors early."""
    _get_fernet()


def encrypt_mapping(mapping: dict[str, str]) -> str:
    raw = json.dumps(mapping, ensure_ascii=False).encode("utf-8")
    return _get_fernet().encrypt(raw).decode("utf-8")


def decrypt_mapping(payload: str) -> dict[str, str]:
    try:
        raw = _get_fernet().decrypt(payload.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except InvalidToken:
        logger.warning(
            "crypto: decrypt_mapping failed with InvalidToken; "
            "rejecting payload (base64 plaintext fallback removed for security)"
        )
        raise


def encrypt_pending_payload(payload: dict[str, Any]) -> str:
    raw = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    token = _get_fernet().encrypt(raw).decode("utf-8")
    return f"{_PENDING_PAYLOAD_PREFIX}{token}"


def decrypt_pending_payload(payload: str) -> dict[str, Any]:
    raw_payload = str(payload or "")
    if not raw_payload:
        return {}
    if not raw_payload.startswith(_PENDING_PAYLOAD_PREFIX):
        loaded = json.loads(raw_payload)
        if isinstance(loaded, dict):
            return loaded
        return {}
    token = raw_payload[len(_PENDING_PAYLOAD_PREFIX) :]
    try:
        raw = _get_fernet().decrypt(token.encode("utf-8"))
    except InvalidToken:
        logger.warning("crypto: decrypt_pending_payload failed with InvalidToken")
        raise
    loaded = json.loads(raw.decode("utf-8"))
    if isinstance(loaded, dict):
        return loaded
    return {}
