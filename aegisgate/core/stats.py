"""
请求统计收集器：线程安全的内存计数，按小时分桶，保留 7 天。
进程重启后清零（审计 JSONL 提供持久记录）。
"""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from aegisgate.core.context import RequestContext

_RETENTION_HOURS = 168  # 7 days
_BOOT_TIME = datetime.now(timezone.utc)

_EMPTY_BUCKET = {"requests": 0, "redactions": 0, "dangerous_replaced": 0, "blocked": 0, "passthrough": 0}
_REDACTION_FILTERS = frozenset({"redaction", "exact_value_redaction"})
_DANGER_FILTERS = frozenset({
    "anomaly_detector", "injection_detector", "privilege_guard",
    "tool_call_guard", "rag_poison_guard", "untrusted_content_guard",
    "output_sanitizer", "post_restore_guard",
})


def _hour_key(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H")


def _date_key(hour_key: str) -> str:
    return hour_key[:10]


class StatsCollector:
    """线程安全的请求统计收集器。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._totals = dict(_EMPTY_BUCKET)
        self._hourly: dict[str, dict[str, int]] = defaultdict(lambda: dict(_EMPTY_BUCKET))

    def record(self, ctx: RequestContext) -> None:
        """从已完成的请求上下文中提取计数并累加。"""
        redactions = 0
        dangerous = 0
        for item in ctx.report_items:
            fname = item.get("filter", "")
            if fname in _REDACTION_FILTERS:
                redactions += item.get("replacements", 0)
            if fname in _DANGER_FILTERS and item.get("hit"):
                dangerous += 1

        action = _resolve_action(ctx)
        blocked = 1 if action == "block" else 0
        passthrough = 1 if "filter_mode:passthrough" in ctx.security_tags else 0

        hour = _hour_key(datetime.now(timezone.utc))

        with self._lock:
            self._totals["requests"] += 1
            self._totals["redactions"] += redactions
            self._totals["dangerous_replaced"] += dangerous
            self._totals["blocked"] += blocked
            self._totals["passthrough"] += passthrough

            bucket = self._hourly[hour]
            bucket["requests"] += 1
            bucket["redactions"] += redactions
            bucket["dangerous_replaced"] += dangerous
            bucket["blocked"] += blocked
            bucket["passthrough"] += passthrough

            self._prune()

    def snapshot(self) -> dict[str, Any]:
        """返回当前统计快照。"""
        with self._lock:
            totals = dict(self._totals)
            hourly_raw = {k: dict(v) for k, v in sorted(self._hourly.items())}

        # 按小时
        hourly = [{"hour": k, **v} for k, v in hourly_raw.items()]

        # 按天汇总
        daily_agg: dict[str, dict[str, int]] = defaultdict(lambda: dict(_EMPTY_BUCKET))
        for k, v in hourly_raw.items():
            day = _date_key(k)
            for field in _EMPTY_BUCKET:
                daily_agg[day][field] += v[field]
        daily = [{"date": k, **v} for k, v in sorted(daily_agg.items())]

        return {
            "since": _BOOT_TIME.isoformat(),
            "totals": totals,
            "hourly": hourly,
            "daily": daily,
        }

    def _prune(self) -> None:
        """删除超过 7 天的小时桶（需在锁内调用）。"""
        cutoff = _hour_key(datetime.now(timezone.utc) - timedelta(hours=_RETENTION_HOURS))
        stale = [k for k in self._hourly if k < cutoff]
        for k in stale:
            del self._hourly[k]


def _resolve_action(ctx: RequestContext) -> str:
    if ctx.request_disposition == "block" or ctx.response_disposition == "block":
        return "block"
    if ctx.request_disposition == "sanitize" or ctx.response_disposition == "sanitize":
        return "sanitize"
    return "allow"


# ── 模块级单例 ──

_collector = StatsCollector()


def record(ctx: RequestContext) -> None:
    """记录一次请求的统计数据。"""
    _collector.record(ctx)


def snapshot() -> dict[str, Any]:
    """获取当前统计快照。"""
    return _collector.snapshot()
