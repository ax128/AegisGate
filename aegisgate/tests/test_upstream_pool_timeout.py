"""Pool wait must not inherit the long upstream read timeout."""

from __future__ import annotations

from aegisgate.adapters.openai_compat.upstream import _upstream_http_timeout
from aegisgate.config.settings import settings


def test_pool_timeout_is_a_small_separate_value_when_max_connections_is_one(
    monkeypatch,
) -> None:
    """Turning the connection cap down to 1 must not stretch the pool wait.

    Acquiring a connection is a separate, short budget. The read timeout stays
    at the configured upstream timeout so a response already in flight can
    finish. The timeout helper does not consult the cap, so this setting is
    the case the bug report asked to check.
    """
    monkeypatch.setattr(settings, "upstream_max_connections", 1)
    monkeypatch.setattr(settings, "upstream_timeout_seconds", 600.0)

    timeout = _upstream_http_timeout()

    assert timeout.pool == 10.0
    assert timeout.read == 600.0
    assert timeout.write == 600.0
    assert timeout.connect == 30.0
    assert timeout.pool < timeout.read


def test_pool_timeout_does_not_exceed_a_short_configured_read_timeout(
    monkeypatch,
) -> None:
    """A configured timeout under 10s must not grow a longer pool wait."""
    monkeypatch.setattr(settings, "upstream_max_connections", 1)
    monkeypatch.setattr(settings, "upstream_timeout_seconds", 4.0)

    timeout = _upstream_http_timeout()

    assert timeout.read == 4.0
    assert timeout.pool == 4.0
    assert timeout.pool <= 10.0
