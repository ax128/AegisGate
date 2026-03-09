"""Reversible encryption for redaction mappings using Fernet (AES-128-CBC + HMAC).

Encryption key is loaded from AEGIS_ENCRYPTION_KEY env var.  When absent the
module auto-generates a persistent key file at ``<config_dir>/aegis_fernet.key``
on first use.  The key file is created with owner-only permissions (0o600).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from aegisgate.util.logger import logger

_fernet_instance: Fernet | None = None


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

    # 2. Try persistent key file
    key_path = _config_dir() / "aegis_fernet.key"
    if key_path.is_file():
        raw = key_path.read_text(encoding="utf-8").strip()
        if raw:
            return raw.encode("utf-8")

    # 3. Auto-generate
    key = Fernet.generate_key()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(key.decode("utf-8"), encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    logger.info("crypto: generated new Fernet key at %s", key_path)
    return key


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        _fernet_instance = Fernet(_load_or_generate_key())
    return _fernet_instance


def encrypt_mapping(mapping: dict[str, str]) -> str:
    raw = json.dumps(mapping, ensure_ascii=False).encode("utf-8")
    return _get_fernet().encrypt(raw).decode("utf-8")


def decrypt_mapping(payload: str) -> dict[str, str]:
    try:
        raw = _get_fernet().decrypt(payload.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except InvalidToken:
        # Backwards compat: try base64 decode for pre-encryption data
        import base64
        try:
            raw = base64.b64decode(payload.encode("utf-8"))
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise
