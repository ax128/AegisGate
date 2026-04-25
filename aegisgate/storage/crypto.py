"""Reversible encryption for redaction mappings using Fernet (AES-128-CBC + HMAC).

Encryption key is loaded from AEGIS_ENCRYPTION_KEY env var.  When absent the
module auto-generates a persistent key file at ``<config_dir>/aegis_fernet.key``
on first use.  The key file is created with owner-only permissions (0o600).

Key rotation is supported via MultiFernet: the previous key is kept in
``<config_dir>/aegis_fernet_prev.key`` so that existing ciphertext encrypted
with the old key remains decodable during the transition window.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Union

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from aegisgate.util.logger import logger

import threading

# _fernet_instance may be a bare Fernet or a MultiFernet (key rotation window).
_fernet_instance: Union[Fernet, MultiFernet, None] = None
_fernet_lock = threading.Lock()
_FERNET_KEY_FILE = "aegis_fernet.key"
_FERNET_PREV_KEY_FILE = "aegis_fernet_prev.key"
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


def _get_fernet() -> Union[Fernet, MultiFernet]:
    global _fernet_instance
    if _fernet_instance is None:
        with _fernet_lock:
            if _fernet_instance is None:
                current = Fernet(_load_or_generate_key())
                prev_raw = _load_prev_key()
                if prev_raw:
                    try:
                        _fernet_instance = MultiFernet([current, Fernet(prev_raw)])
                        logger.info("crypto: MultiFernet initialized (current + prev key)")
                    except Exception:
                        logger.warning("crypto: failed to load prev key for MultiFernet; falling back to single key")
                        _fernet_instance = current
                else:
                    _fernet_instance = current
    return _fernet_instance


def _load_prev_key() -> bytes | None:
    """Load the previous Fernet key (kept for rotation window decryption)."""
    prev_path = _config_dir() / _FERNET_PREV_KEY_FILE
    if prev_path.is_file():
        raw = prev_path.read_text(encoding="utf-8").strip()
        if raw:
            return raw.encode("utf-8")
    return None


def save_prev_key(key_bytes: bytes) -> None:
    """Persist the current key as the previous key before rotation.

    Called by the UI key-rotation endpoint before writing the new key.
    """
    prev_path = _config_dir() / _FERNET_PREV_KEY_FILE
    try:
        prev_path.write_text(key_bytes.decode("utf-8"), encoding="utf-8")
        try:
            os.chmod(prev_path, 0o600)
        except OSError:
            pass
        logger.info("crypto: saved previous Fernet key to %s", prev_path)
    except Exception as exc:
        logger.warning("crypto: failed to save previous key: %s", exc)


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


_WHITELIST_KEY_PREFIX = "encwk:v1:"


def encrypt_whitelist_key(value: str) -> str:
    if not value:
        return value
    token = _get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")
    return f"{_WHITELIST_KEY_PREFIX}{token}"


def decrypt_whitelist_key(value: str) -> str:
    if not value or not value.startswith(_WHITELIST_KEY_PREFIX):
        return value
    token = value[len(_WHITELIST_KEY_PREFIX):]
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.warning("crypto: decrypt_whitelist_key failed with InvalidToken")
        return ""


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
        # H-18: Plaintext JSON fallback removed — records without the encryption
        # prefix are rejected to prevent attackers from injecting forged payloads
        # directly into the database.
        logger.warning(
            "crypto: decrypt_pending_payload rejected non-prefixed payload (possible injection attempt)"
        )
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
