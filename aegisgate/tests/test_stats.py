"""Tests for aegisgate.core.stats module."""

from __future__ import annotations

import threading
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from aegisgate.core.context import RequestContext
from aegisgate.core.stats import StatsCollector, _hour_key


def _make_ctx(
    *,
    redaction_replacements: int = 0,
    exact_redaction_replacements: int = 0,
    danger_hit: bool = False,
    blocked: bool = False,
    passthrough: bool = False,
) -> RequestContext:
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions")
    if redaction_replacements:
        ctx.report_items.append({"filter": "redaction", "hit": True, "replacements": redaction_replacements})
    if exact_redaction_replacements:
        ctx.report_items.append({"filter": "exact_value_redaction", "hit": True, "replacements": exact_redaction_replacements})
    if danger_hit:
        ctx.report_items.append({"filter": "injection_detector", "hit": True, "replacements": 0})
    if blocked:
        ctx.request_disposition = "block"
    if passthrough:
        ctx.security_tags.add("filter_mode:passthrough")
    return ctx


def test_empty_snapshot():
    c = StatsCollector()
    snap = c.snapshot()
    assert snap["totals"]["requests"] == 0
    assert snap["hourly"] == []
    assert snap["daily"] == []


def test_basic_record():
    c = StatsCollector()
    ctx = _make_ctx(redaction_replacements=3, exact_redaction_replacements=2)
    c.record(ctx)

    snap = c.snapshot()
    assert snap["totals"]["requests"] == 1
    assert snap["totals"]["redactions"] == 5
    assert snap["totals"]["blocked"] == 0
    assert len(snap["hourly"]) == 1
    assert snap["hourly"][0]["redactions"] == 5


def test_blocked_count():
    c = StatsCollector()
    c.record(_make_ctx(blocked=True))
    c.record(_make_ctx(blocked=False))

    snap = c.snapshot()
    assert snap["totals"]["requests"] == 2
    assert snap["totals"]["blocked"] == 1


def test_passthrough_count():
    c = StatsCollector()
    c.record(_make_ctx(passthrough=True))
    c.record(_make_ctx(passthrough=False))

    snap = c.snapshot()
    assert snap["totals"]["passthrough"] == 1


def test_dangerous_count():
    c = StatsCollector()
    c.record(_make_ctx(danger_hit=True))
    c.record(_make_ctx(danger_hit=False))

    snap = c.snapshot()
    assert snap["totals"]["dangerous_replaced"] == 1


def test_daily_aggregation():
    c = StatsCollector()
    now = datetime.now(timezone.utc)
    hour1 = now.replace(hour=10, minute=0, second=0, microsecond=0)
    hour2 = now.replace(hour=14, minute=0, second=0, microsecond=0)

    with patch("aegisgate.core.stats.datetime") as mock_dt:
        mock_dt.now.return_value = hour1
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        c.record(_make_ctx(redaction_replacements=2))

        mock_dt.now.return_value = hour2
        c.record(_make_ctx(redaction_replacements=3))

    snap = c.snapshot()
    assert len(snap["daily"]) == 1
    assert snap["daily"][0]["redactions"] == 5
    assert len(snap["hourly"]) == 2


def test_prune_old_buckets():
    c = StatsCollector()
    old_key = _hour_key(datetime.now(timezone.utc) - timedelta(hours=200))
    c._hourly[old_key] = {"requests": 1, "redactions": 0, "dangerous_replaced": 0, "blocked": 0, "passthrough": 0}

    c.record(_make_ctx())

    assert old_key not in c._hourly
    snap = c.snapshot()
    assert len(snap["hourly"]) == 1


def test_thread_safety():
    c = StatsCollector()
    errors = []

    def worker():
        try:
            for _ in range(100):
                c.record(_make_ctx(redaction_replacements=1))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    snap = c.snapshot()
    assert snap["totals"]["requests"] == 400
    assert snap["totals"]["redactions"] == 400


def test_hour_key_format():
    dt = datetime(2026, 3, 18, 14, 30, 0, tzinfo=timezone.utc)
    assert _hour_key(dt) == "2026-03-18T14"
