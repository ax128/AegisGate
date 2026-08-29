"""The stream probe interval is configurable; the window and holdback are not."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisgate.adapters.openai_compat import router
from aegisgate.config.settings import Settings, settings
from aegisgate.core import gateway


def test_holdback_is_derived_at_every_stream_loop() -> None:
    """H-15's invariant survives configuration: holdback is never independent.

    Asserting `_resolve_holdback(n) == n * 2` against a one-line function that
    returns `interval * 2` proves nothing a reader of that line does not already
    see. What can actually rot is a *use site*: four loops read the holdback and
    someone reintroducing a literal 8 in one of them would keep this file green
    while breaking the invariant on one protocol only. So pin the source text of
    the loops, not the helper.
    """
    src = Path(router.__file__).read_text(encoding="utf-8")
    # Matched on the loop header, not on the bare comparison: the looser form
    # counts any prose that quotes the expression, so a comment explaining the
    # invariant would break the test that enforces it. A use site rewritten
    # away from `while` still drops the count below four and still fails.
    holdback_lines = [
        line for line in src.splitlines() if "while len(pending_frames) >" in line
    ]
    assert len(holdback_lines) == 4, holdback_lines
    for line in holdback_lines:
        assert "_resolve_holdback(" in line, line
    # ...and the helper itself still derives rather than reads a setting.
    assert "stream_scan_holdback" not in src
    for interval in (1, 2, 4, 16):
        assert router._resolve_holdback(interval) == interval * 2


def test_stream_scan_interval_is_pinned_at_startup() -> None:
    """A detection-sensitivity knob that moves at runtime makes the forensic
    story worse, not better — which is the thing this change exists to fix."""
    from aegisgate.core.hot_reload import _IMMUTABLE_FIELDS

    assert "stream_scan_interval_chunks" in _IMMUTABLE_FIELDS


def test_scan_window_stays_a_constant() -> None:
    """The window is deliberately NOT configurable: coverage needs
    window >= interval * max_chunk_chars, and the right-hand side is set by the
    upstream, so no static validator can enforce it. Guard against a later
    "just add the setting too"."""
    assert "stream_scan_window_chars" not in Settings.model_fields
    assert "stream_scan_holdback_events" not in Settings.model_fields
    assert isinstance(router._STREAM_WINDOW_MAX_CHARS, int)


def test_the_interval_is_read_at_use_time_not_import_time() -> None:
    """A module-level `interval = settings.x` would freeze the value at import
    and make every monkeypatch in the streaming tests a no-op."""
    src = Path(router.__file__).read_text(encoding="utf-8")
    assert "_STREAM_FILTER_CHECK_INTERVAL" not in src
    assert "_STREAM_BLOCK_HOLDBACK_EVENTS" not in src
    assert src.count("settings.stream_scan_interval_chunks") >= 4


@pytest.mark.parametrize("bad", [0, -1, 17, 100])
def test_out_of_range_intervals_are_rejected(bad: int) -> None:
    """interval=0 would reach `chunk_count % 0` and raise ZeroDivisionError on
    the streaming path — a crash a config file could cause."""
    with pytest.raises(Exception):
        Settings(stream_scan_interval_chunks=bad)


def test_an_illegal_value_is_not_applied_by_hot_reload(monkeypatch) -> None:
    """The reload path builds a whole Settings, so an illegal value makes the
    entire reload raise; reload_settings logs and swallows it and the running
    value stays put. Fail-safe, but pin it rather than assume it."""
    from aegisgate.core import hot_reload

    before = settings.stream_scan_interval_chunks
    monkeypatch.setattr(
        hot_reload,
        "_parse_runtime_env_values",
        lambda: {"AEGIS_STREAM_SCAN_INTERVAL_CHUNKS": "0"},
    )
    hot_reload.reload_settings()
    assert settings.stream_scan_interval_chunks == before


def test_effective_values_are_logged_at_startup(monkeypatch) -> None:
    """The forensic surface this change exists for. Logs, not /ready.

    Not caplog: the aegisgate logger sets propagate = False and caplog's handler
    lives on root, so it would see nothing and this test would fail for a reason
    unrelated to what it checks. The repo already met this and settled on a
    recorder — see test_process_identity.py and test_redact_values_load_guard.py.
    """
    recorded: list[str] = []

    class _Recorder:
        def info(self, message: str, *args: object) -> None:
            recorded.append(str(message) % args if args else str(message))

        def __getattr__(self, name: str):  # pragma: no cover - unused levels
            return lambda *a, **kw: None

    monkeypatch.setattr(gateway, "logger", _Recorder())
    gateway._log_stream_scan_config()
    line = "\n".join(recorded)
    # Read the constant rather than the literal 8000: this pins that the value
    # is *reported*, not what it is. test_scan_window_stays_a_constant pins that
    # it stays a constant, which is the property that matters.
    assert f"window_chars={router._STREAM_WINDOW_MAX_CHARS}" in line
    assert f"interval_chunks={settings.stream_scan_interval_chunks}" in line
    assert f"holdback_events={settings.stream_scan_interval_chunks * 2}" in line


def test_ready_does_not_publish_the_scan_cadence() -> None:
    """/ready is in _PASSTHROUGH_PATHS and the boundary short-circuits GET/HEAD
    on it, so anything added to that body is unauthenticated. The three
    quantities this change refuses to make configurable *because misconfiguring
    them silently weakens detection* must not be handed out there either."""
    src = Path(gateway.__file__).read_text(encoding="utf-8")
    ready_body = src.split('@app.get("/ready")')[1].split("@app.api_route")[0]
    assert "stream_scan" not in ready_body
    assert "_STREAM_WINDOW_MAX_CHARS" not in ready_body
    assert "_resolve_holdback" not in ready_body
