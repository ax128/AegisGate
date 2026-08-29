"""AEGIS_LOG_JSON has to reach the logger this app actually logs through."""

from __future__ import annotations

import json
import logging

import pytest

from aegisgate.config.settings import settings
from aegisgate.observability.logging import JSONFormatter, configure_logging


@pytest.fixture
def _restore_aegis_formatters():
    from aegisgate.util.logger import logger as aegis_logger

    saved = [(handler, handler.formatter) for handler in aegis_logger.handlers]
    yield
    for handler, formatter in saved:
        handler.setFormatter(formatter)


def test_json_format_applies_to_the_app_logger(_restore_aegis_formatters) -> None:
    """root is not where this app logs: the aegisgate logger sets propagate=False."""
    from aegisgate.util.logger import logger as aegis_logger

    configure_logging("info", json_format=True)
    assert aegis_logger.handlers, "the app logger has no handler to format"
    for handler in aegis_logger.handlers:
        assert isinstance(handler.formatter, JSONFormatter)
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "hello %s", ("world",), None
    )
    payload = json.loads(aegis_logger.handlers[0].formatter.format(record))
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"


def test_json_format_false_restores_the_human_formatter(
    _restore_aegis_formatters,
) -> None:
    """The two modes must stop leaking into each other across hot reloads."""
    from aegisgate.util.logger import logger as aegis_logger

    configure_logging("info", json_format=True)
    configure_logging("info", json_format=False)
    for handler in aegis_logger.handlers:
        assert not isinstance(handler.formatter, JSONFormatter)
        assert "%(levelname)s" in handler.formatter._fmt


def test_gateway_passes_log_json_to_configure_logging(monkeypatch) -> None:
    """Patch the name gateway actually calls, not the module it came from.

    gateway.py imports configure_logging at module scope, so the callable is
    bound into gateway's namespace at import time — patching
    observability.logging would not intercept it and the test would pass while
    the wiring was still missing.
    """
    from aegisgate.core import gateway

    seen: list[tuple] = []
    monkeypatch.setattr(gateway, "configure_logging", lambda *a, **kw: seen.append((a, kw)))
    monkeypatch.setattr(gateway, "init_tracing", lambda *a, **kw: None)
    monkeypatch.setattr(settings, "log_json", True)
    gateway._initialize_observability()
    assert seen and seen[0][1].get("json_format") is True


def test_hot_reload_passes_log_json_to_configure_logging(monkeypatch) -> None:
    """hot_reload imports configure_logging inside reload_settings, so the patch
    target is the source module here — the opposite of the test above.

    reload_settings swallows its own exceptions, so a failure inside it would
    look like "configure_logging was never called". Everything it reaches after
    the logging call is stubbed out for that reason.
    """
    import aegisgate.observability.logging as obs_logging
    from aegisgate.core import hot_reload

    seen: list[tuple] = []
    monkeypatch.setattr(
        obs_logging, "configure_logging", lambda *a, **kw: seen.append((a, kw))
    )
    monkeypatch.setattr(settings, "log_json", True)
    monkeypatch.setattr(hot_reload, "_settings_from_runtime_env_file", lambda: settings)
    monkeypatch.setattr(
        "aegisgate.config.feature_flags.refresh_feature_flags", lambda: None
    )
    monkeypatch.setattr(
        "aegisgate.init_config.ensure_runtime_storage_paths", lambda: None
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.pipeline_runtime.reload_runtime_dependencies",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.upstream.schedule_close_upstream_async_client",
        lambda: None,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.reload_semantic_client_settings",
        lambda: None,
    )

    hot_reload.reload_settings()

    assert seen, "reload_settings never reached configure_logging"
    assert seen[-1][1].get("json_format") is True


def test_log_json_is_hot_reloadable() -> None:
    """It changes no security decision, so it must not be pinned at startup."""
    from aegisgate.core.hot_reload import _IMMUTABLE_FIELDS

    assert "log_json" not in _IMMUTABLE_FIELDS
