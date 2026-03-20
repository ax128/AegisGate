"""Tests for aegisgate.storage.crypto — Fernet encryption for redaction mappings."""

from __future__ import annotations

import json
import threading

import pytest

from aegisgate.storage import crypto


@pytest.fixture(autouse=True)
def _reset_fernet_singleton(monkeypatch):
    """Ensure each test gets a fresh Fernet instance."""
    monkeypatch.setattr(crypto, "_fernet_instance", None)
    monkeypatch.setattr(crypto, "_fernet_lock", threading.Lock())


# ---------- _config_dir ----------

def test_config_dir_uses_env_when_set(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(tmp_path / "custom_cfg"))
    result = crypto._config_dir()
    assert result == (tmp_path / "custom_cfg").resolve()


def test_config_dir_defaults_to_cwd_config(monkeypatch):
    monkeypatch.delenv("AEGIS_CONFIG_DIR", raising=False)
    result = crypto._config_dir()
    assert result.name == "config"


# ---------- _load_or_generate_key ----------

def test_load_key_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", "test-key-32-chars-for-fernet-ok!")
    key = crypto._load_or_generate_key()
    assert key == b"test-key-32-chars-for-fernet-ok!"


def test_load_key_from_file(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet

    monkeypatch.delenv("AEGIS_ENCRYPTION_KEY", raising=False)
    key_bytes = Fernet.generate_key()
    key_file = tmp_path / "aegis_fernet.key"
    key_file.write_text(key_bytes.decode("utf-8"), encoding="utf-8")

    monkeypatch.setattr(crypto, "_config_dir", lambda: tmp_path)
    result = crypto._load_or_generate_key()
    assert result == key_bytes


def test_auto_generate_key_when_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("AEGIS_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(crypto, "_config_dir", lambda: tmp_path)
    monkeypatch.setattr(crypto, "_FERNET_FALLBACK_DIR", tmp_path / "fallback")

    key = crypto._load_or_generate_key()
    assert len(key) > 0

    # Key file should have been written
    key_file = tmp_path / "aegis_fernet.key"
    assert key_file.exists()


def test_auto_generate_key_fallback_on_permission_error(monkeypatch, tmp_path):
    from pathlib import Path

    monkeypatch.delenv("AEGIS_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(crypto, "_config_dir", lambda: tmp_path / "readonly")
    fallback_dir = tmp_path / "fallback"
    monkeypatch.setattr(crypto, "_FERNET_FALLBACK_DIR", fallback_dir)

    # Make primary path raise PermissionError on write
    original_write = Path.write_text

    def _raise_perm(self, *args, **kwargs):
        if "readonly" in str(self):
            raise PermissionError("read-only")
        return original_write(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _raise_perm)

    key = crypto._load_or_generate_key()
    assert len(key) > 0
    assert (fallback_dir / "aegis_fernet.key").exists()


# ---------- ensure_key ----------

def test_ensure_key_initializes_fernet(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", key.decode("utf-8"))
    crypto.ensure_key()
    assert crypto._fernet_instance is not None


# ---------- encrypt / decrypt roundtrip ----------

def test_encrypt_decrypt_roundtrip(monkeypatch):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", key.decode("utf-8"))

    mapping = {"placeholder_1": "secret_value_1", "placeholder_2": "secret_value_2"}
    encrypted = crypto.encrypt_mapping(mapping)
    assert encrypted != json.dumps(mapping)

    decrypted = crypto.decrypt_mapping(encrypted)
    assert decrypted == mapping


# ---------- decrypt backwards-compat (base64 fallback) ----------

def test_decrypt_mapping_base64_fallback(monkeypatch):
    import base64
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", key.decode("utf-8"))

    mapping = {"k": "v"}
    b64_payload = base64.b64encode(json.dumps(mapping).encode("utf-8")).decode("utf-8")
    result = crypto.decrypt_mapping(b64_payload)
    assert result == mapping


def test_decrypt_mapping_invalid_data_raises(monkeypatch):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", key.decode("utf-8"))

    with pytest.raises(Exception):
        crypto.decrypt_mapping("not-valid-encrypted-or-base64!!!")
