"""
请求统计收集器：线程安全的内存计数，按小时分桶，保留 7 天。
数据持久化到 config/stats.json，重启后自动恢复。
"""

from __future__ import annotations

import json
import tempfile
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from aegisgate.core.context import RequestContext
from aegisgate.util.logger import logger

_RETENTION_HOURS = 168  # 7 days
_PERSIST_INTERVAL = 30  # 每 30 次 record 写一次磁盘
_STATS_FILE = (Path.cwd() / "config" / "stats.json").resolve()
_STATS_FALLBACK = Path("/tmp/aegisgate/stats.json")

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


def _resolve_stats_path() -> Path:
    """返回可写的持久化路径，优先 config/stats.json，不可写时 fallback。"""
    for idx, candidate in enumerate((_STATS_FILE, _STATS_FALLBACK)):
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            # 测试可写
            test_path = candidate.parent / ".stats_write_test"
            test_path.write_text("ok", encoding="utf-8")
            test_path.unlink(missing_ok=True)
            if idx > 0:
                logger.warning(
                    "stats path not writable, switched to fallback configured=%s fallback=%s",
                    _STATS_FILE, candidate,
                )
            return candidate
        except OSError:
            continue
    return _STATS_FILE  # 返回默认，写入时会静默失败


class StatsCollector:
    """线程安全的请求统计收集器，支持持久化。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._totals = dict(_EMPTY_BUCKET)
        self._hourly: dict[str, dict[str, int]] = defaultdict(lambda: dict(_EMPTY_BUCKET))
        self._since: str = datetime.now(timezone.utc).isoformat()
        self._record_count = 0
        self._persist_path = _resolve_stats_path()
        self._load()

    def _load(self) -> None:
        """启动时从磁盘加载持久化数据。"""
        for candidate in (self._persist_path, _STATS_FILE, _STATS_FALLBACK):
            if not candidate.is_file():
                continue
            try:
                raw = json.loads(candidate.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    continue
                # 恢复 totals
                saved_totals = raw.get("totals")
                if isinstance(saved_totals, dict):
                    for key in _EMPTY_BUCKET:
                        if key in saved_totals and isinstance(saved_totals[key], (int, float)):
                            self._totals[key] = int(saved_totals[key])
                # 恢复 hourly
                saved_hourly = raw.get("hourly")
                if isinstance(saved_hourly, dict):
                    for hour_key, bucket in saved_hourly.items():
                        if not isinstance(bucket, dict):
                            continue
                        restored: dict[str, int] = dict(_EMPTY_BUCKET)
                        for field in _EMPTY_BUCKET:
                            if field in bucket and isinstance(bucket[field], (int, float)):
                                restored[field] = int(bucket[field])
                        self._hourly[str(hour_key)] = restored
                # 恢复 since
                saved_since = raw.get("since")
                if isinstance(saved_since, str) and saved_since:
                    self._since = saved_since
                self._prune()
                logger.info("stats loaded from %s totals.requests=%d", candidate, self._totals.get("requests", 0))
                return
            except (json.JSONDecodeError, OSError, ValueError) as exc:
                logger.warning("stats load failed path=%s error=%s", candidate, exc)
                continue
        logger.info("stats no persisted data found, starting fresh")

    def _save(self) -> None:
        """将当前数据写入磁盘（原子写入）。"""
        data = {
            "since": self._since,
            "totals": dict(self._totals),
            "hourly": {k: dict(v) for k, v in self._hourly.items()},
        }
        path = self._persist_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", delete=False, dir=str(path.parent), suffix=".tmp"
            ) as tmp:
                json.dump(data, tmp, ensure_ascii=False)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)
        except OSError as exc:
            logger.warning("stats persist failed path=%s error=%s", path, exc)

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
            self._record_count += 1
            if self._record_count >= _PERSIST_INTERVAL:
                self._record_count = 0
                self._save()

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
            "since": self._since,
            "totals": totals,
            "hourly": hourly,
            "daily": daily,
        }

    def clear(self) -> None:
        """清除所有统计数据并删除持久化文件。"""
        with self._lock:
            self._totals = dict(_EMPTY_BUCKET)
            self._hourly = defaultdict(lambda: dict(_EMPTY_BUCKET))
            self._since = datetime.now(timezone.utc).isoformat()
            self._record_count = 0
        # 删除持久化文件
        for path in (self._persist_path, _STATS_FILE, _STATS_FALLBACK):
            try:
                if path.is_file():
                    path.unlink()
            except OSError:
                pass
        logger.info("stats cleared")

    def flush(self) -> None:
        """强制写盘（用于优雅关闭）。"""
        with self._lock:
            self._save()

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


def clear() -> None:
    """清除所有统计数据和持久化文件。"""
    _collector.clear()


def flush() -> None:
    """强制将统计数据写入磁盘。"""
    _collector.flush()
