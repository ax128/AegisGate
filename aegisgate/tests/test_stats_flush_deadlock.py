"""A4 / P6: stats persist-queue overflow must not hang flush()/join()."""

from __future__ import annotations

import queue
import threading
from pathlib import Path

import pytest

from aegisgate.core import stats as stats_mod
from aegisgate.core.stats import StatsCollector


def test_flush_returns_after_queue_overflow_discards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    persist = tmp_path / "stats.json"
    fallback = tmp_path / "stats-fallback.json"
    monkeypatch.setattr(stats_mod, "_STATS_FILE", persist)
    monkeypatch.setattr(stats_mod, "_STATS_FALLBACK", fallback)

    collector = StatsCollector()
    collector._persist_path = persist
    collector._persist_atexit_registered = True
    collector._persist_queue = queue.Queue(maxsize=2)

    started = threading.Event()
    release = threading.Event()
    original_save = collector._save_payload

    def blocked_save(data: dict) -> None:
        started.set()
        assert release.wait(timeout=5), "worker save was not released"
        original_save(data)

    collector._save_payload = blocked_save  # type: ignore[method-assign]

    collector._persist_async({"seq": 0})
    assert started.wait(timeout=2), "stats worker did not pick up the first snapshot"

    for seq in range(1, 20):
        collector._persist_async({"seq": seq})

    release.set()

    finished = threading.Event()
    errors: list[BaseException] = []

    def run_flush() -> None:
        try:
            collector.flush()
        except BaseException as exc:  # noqa: BLE001 — surface in the parent thread
            errors.append(exc)
        finally:
            finished.set()

    flusher = threading.Thread(target=run_flush, name="stats-flush-test")
    flusher.start()
    completed = finished.wait(timeout=2.0)
    flusher.join(timeout=1.0)
    collector.shutdown_worker(timeout_seconds=1.0)

    assert not errors, f"flush() raised {errors[0]!r}"
    assert completed, (
        "flush() hung for >2s after overflow discards; discarded items are "
        "likely missing task_done() so Queue.join() never returns"
    )
