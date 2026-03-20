"""Tests for aegisgate.util.debug_excerpt — log-safe content truncation."""

from __future__ import annotations

from aegisgate.util.debug_excerpt import (
    _resolve_max_len,
    debug_log_original,
    excerpt_for_debug,
    info_log_sanitized,
)


# ---------- _resolve_max_len ----------

def test_resolve_max_len_default():
    assert _resolve_max_len(500) == 500


def test_resolve_max_len_env_override(monkeypatch):
    monkeypatch.setenv("AEGIS_DEBUG_EXCERPT_MAX_LEN", "200")
    assert _resolve_max_len(500) == 200


def test_resolve_max_len_env_zero(monkeypatch):
    monkeypatch.setenv("AEGIS_DEBUG_EXCERPT_MAX_LEN", "0")
    assert _resolve_max_len(500) == 0


def test_resolve_max_len_env_invalid(monkeypatch):
    monkeypatch.setenv("AEGIS_DEBUG_EXCERPT_MAX_LEN", "not_a_number")
    assert _resolve_max_len(500) == 500


# ---------- excerpt_for_debug ----------

def test_excerpt_empty_string():
    assert excerpt_for_debug("") == ""


def test_excerpt_short_text():
    assert excerpt_for_debug("hello", max_len=100) == "hello"


def test_excerpt_truncates_long_text():
    text = "a" * 1000
    result = excerpt_for_debug(text, max_len=50)
    assert len(result) < 200
    assert "truncated" in result
    assert "1000 chars" in result


def test_excerpt_no_truncation_when_maxlen_zero():
    text = "a" * 1000
    result = excerpt_for_debug(text, max_len=0)
    assert result == text


def test_excerpt_strips_whitespace():
    result = excerpt_for_debug("  hello  ", max_len=100)
    assert result == "hello"


# ---------- debug_log_original ----------

def test_debug_log_original_skips_when_not_debug(monkeypatch):
    from aegisgate.util import logger as logger_mod

    monkeypatch.setattr(logger_mod.logger, "isEnabledFor", lambda level: False)
    # Should not raise
    debug_log_original("test_label", "original text", reason="test reason")


def test_debug_log_original_logs_with_reason(monkeypatch):
    from aegisgate.util import logger as logger_mod

    logged = []
    monkeypatch.setattr(logger_mod.logger, "isEnabledFor", lambda level: True)
    monkeypatch.setattr(logger_mod.logger, "debug", lambda *args: logged.append(args))

    debug_log_original("blocked", "dangerous text", reason="injection")
    assert len(logged) == 1
    assert "reason" in logged[0][0]


def test_debug_log_original_logs_without_reason(monkeypatch):
    from aegisgate.util import logger as logger_mod

    logged = []
    monkeypatch.setattr(logger_mod.logger, "isEnabledFor", lambda level: True)
    monkeypatch.setattr(logger_mod.logger, "debug", lambda *args: logged.append(args))

    debug_log_original("blocked", "text")
    assert len(logged) == 1
    assert "reason" not in logged[0][0]


# ---------- info_log_sanitized ----------

def test_info_log_sanitized_skips_when_not_info(monkeypatch):
    from aegisgate.util import logger as logger_mod

    monkeypatch.setattr(logger_mod.logger, "isEnabledFor", lambda level: False)
    info_log_sanitized("test", "text")


def test_info_log_sanitized_with_reason(monkeypatch):
    from aegisgate.util import logger as logger_mod

    logged = []
    monkeypatch.setattr(logger_mod.logger, "isEnabledFor", lambda level: True)
    monkeypatch.setattr(logger_mod.logger, "info", lambda *args: logged.append(args))

    info_log_sanitized("sanitized", "clean text", request_id="r-1", reason="pii")
    assert len(logged) == 1
    assert "reason" in logged[0][0]


def test_info_log_sanitized_without_reason(monkeypatch):
    from aegisgate.util import logger as logger_mod

    logged = []
    monkeypatch.setattr(logger_mod.logger, "isEnabledFor", lambda level: True)
    monkeypatch.setattr(logger_mod.logger, "info", lambda *args: logged.append(args))

    info_log_sanitized("sanitized", "clean text", request_id="r-1")
    assert len(logged) == 1
    assert "reason" not in logged[0][0]
