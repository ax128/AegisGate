"""Tests for aegisgate.config.redact_values — exact-value redaction management."""

from __future__ import annotations

import json

import pytest

from aegisgate.config import redact_values


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch):
    """Reset module-level cache between tests."""
    monkeypatch.setattr(redact_values, "_cached_values", None)
    monkeypatch.setattr(redact_values, "_cached_mtime_ns", 0)


# ---------- load_redact_values ----------

def test_load_returns_empty_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(redact_values, "_config_path", lambda: tmp_path / "nonexistent.enc.json")
    result = redact_values.load_redact_values()
    assert result == []


def test_load_returns_cached_when_mtime_unchanged(monkeypatch, tmp_path):
    # Pre-populate cache
    monkeypatch.setattr(redact_values, "_cached_values", ["secret1234"])
    path = tmp_path / "redact_values.enc.json"
    path.write_text("placeholder", encoding="utf-8")
    mtime_ns = path.stat().st_mtime_ns
    monkeypatch.setattr(redact_values, "_cached_mtime_ns", mtime_ns)
    monkeypatch.setattr(redact_values, "_config_path", lambda: path)

    result = redact_values.load_redact_values()
    assert result == ["secret1234"]


def test_load_returns_empty_on_stat_oserror(monkeypatch, tmp_path):
    from pathlib import Path

    monkeypatch.setattr(redact_values, "_cached_values", ["fallback_v"])
    path = tmp_path / "redact_values.enc.json"
    path.write_text("data", encoding="utf-8")
    monkeypatch.setattr(redact_values, "_config_path", lambda: path)

    original_stat = Path.stat
    call_count = 0

    def _raise_on_second(self, *a, **kw):
        nonlocal call_count
        if "redact_values" in str(self):
            call_count += 1
            if call_count > 1:
                raise OSError("stat failed")
        return original_stat(self, *a, **kw)

    monkeypatch.setattr(Path, "stat", _raise_on_second)
    result = redact_values.load_redact_values()
    assert result == ["fallback_v"]


def test_load_decrypts_values(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    f = Fernet(key)
    values = {"values": ["sensitive_value_123"]}
    encrypted = f.encrypt(json.dumps(values).encode("utf-8")).decode("utf-8")

    path = tmp_path / "redact_values.enc.json"
    path.write_text(encrypted, encoding="utf-8")
    monkeypatch.setattr(redact_values, "_config_path", lambda: path)
    monkeypatch.setattr("aegisgate.config.redact_values._get_fernet", lambda: f)

    result = redact_values.load_redact_values()
    assert result == ["sensitive_value_123"]


def test_load_returns_empty_on_decrypt_failure(monkeypatch, tmp_path):
    path = tmp_path / "redact_values.enc.json"
    path.write_text("corrupt-data-here", encoding="utf-8")
    monkeypatch.setattr(redact_values, "_config_path", lambda: path)

    from cryptography.fernet import Fernet
    monkeypatch.setattr("aegisgate.config.redact_values._get_fernet", lambda: Fernet(Fernet.generate_key()))

    result = redact_values.load_redact_values()
    assert result == []


def test_load_handles_empty_file(monkeypatch, tmp_path):
    path = tmp_path / "redact_values.enc.json"
    path.write_text("   ", encoding="utf-8")
    monkeypatch.setattr(redact_values, "_config_path", lambda: path)

    result = redact_values.load_redact_values()
    assert result == []


# ---------- save_redact_values ----------

def test_save_validates_min_length(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet
    f = Fernet(Fernet.generate_key())
    monkeypatch.setattr("aegisgate.config.redact_values._get_fernet", lambda: f)
    monkeypatch.setattr(redact_values, "_config_path", lambda: tmp_path / "out.enc.json")

    with pytest.raises(ValueError, match="至少"):
        redact_values.save_redact_values(["short"])


def test_save_deduplicates_values(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet
    f = Fernet(Fernet.generate_key())
    monkeypatch.setattr("aegisgate.config.redact_values._get_fernet", lambda: f)

    path = tmp_path / "out.enc.json"
    monkeypatch.setattr(redact_values, "_config_path", lambda: path)

    redact_values.save_redact_values([
        "long_enough_value_1",
        "long_enough_value_1",  # duplicate
        "long_enough_value_2",
    ])

    # Verify file was written
    assert path.exists()
    # Decrypt and check
    encrypted = path.read_text(encoding="utf-8")
    raw = f.decrypt(encrypted.encode("utf-8"))
    data = json.loads(raw)
    assert len(data["values"]) == 2
    assert data["values"][0] == "long_enough_value_1"


def test_save_skips_non_string_values(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet
    f = Fernet(Fernet.generate_key())
    monkeypatch.setattr("aegisgate.config.redact_values._get_fernet", lambda: f)

    path = tmp_path / "out.enc.json"
    monkeypatch.setattr(redact_values, "_config_path", lambda: path)

    redact_values.save_redact_values([
        "valid_string_value_long",
        123,  # non-string, should be skipped
    ])

    encrypted = path.read_text(encoding="utf-8")
    raw = f.decrypt(encrypted.encode("utf-8"))
    data = json.loads(raw)
    assert len(data["values"]) == 1


# ---------- replace_exact_values ----------

def test_replace_exact_values_replaces_matches(monkeypatch):
    monkeypatch.setattr(redact_values, "load_redact_values", lambda: ["my_secret_key_12345"])

    text = "The key is my_secret_key_12345 end."
    result, count = redact_values.replace_exact_values(text)
    assert count == 1
    assert "my_secret_key_12345" not in result
    assert "[REDACTED:EXACT_VALUE]" in result


def test_replace_exact_values_returns_zero_when_no_values(monkeypatch):
    monkeypatch.setattr(redact_values, "load_redact_values", lambda: [])

    text = "nothing to replace"
    result, count = redact_values.replace_exact_values(text)
    assert count == 0
    assert result == text


def test_replace_exact_values_longest_first(monkeypatch):
    monkeypatch.setattr(redact_values, "load_redact_values", lambda: [
        "secret_token",
        "secret_token_extended",
    ])

    text = "has secret_token_extended here"
    result, count = redact_values.replace_exact_values(text)
    assert count == 1
    assert "[REDACTED:EXACT_VALUE]" in result


def test_replace_exact_values_multiple_occurrences(monkeypatch):
    monkeypatch.setattr(redact_values, "load_redact_values", lambda: ["password_abcdef"])

    text = "password_abcdef and again password_abcdef"
    result, count = redact_values.replace_exact_values(text)
    assert count == 2
