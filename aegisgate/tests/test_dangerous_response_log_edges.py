import queue
import threading
from pathlib import Path

import pytest

from aegisgate.config.settings import settings
from aegisgate.core import dangerous_response_log as danger_log


@pytest.fixture(autouse=True)
def _reset_dangerous_log_state(monkeypatch):
    monkeypatch.setattr(danger_log, "_LOG_QUEUE", queue.Queue(maxsize=10000))
    monkeypatch.setattr(danger_log, "_LOG_WORKER", None)
    monkeypatch.setattr(danger_log, "_LOG_WORKER_LOCK", threading.Lock())
    monkeypatch.setattr(danger_log, "_LOG_ATEXIT_REGISTERED", False)
    monkeypatch.setattr(danger_log, "_LOG_PATH", None)
    monkeypatch.setattr(danger_log, "_LOG_PATH_CONFIG", None)
    monkeypatch.setattr(danger_log, "_LOG_PATH_DATE", None)
    monkeypatch.setattr(danger_log, "_LOG_PATH_LOCK", threading.Lock())


def test_resolve_log_path_returns_none_when_path_empty(monkeypatch):
    monkeypatch.setattr(settings, "dangerous_response_log_path", "   ")
    monkeypatch.setattr(danger_log, "_current_log_date", lambda: "2026-03-20")

    resolved = danger_log._resolve_log_path()

    assert resolved is None
    assert danger_log._LOG_PATH is None
    assert danger_log._LOG_PATH_CONFIG == ""
    assert danger_log._LOG_PATH_DATE == "2026-03-20"


def test_resolve_log_path_switches_to_fallback_when_configured_path_not_writable(monkeypatch, tmp_path):
    configured = tmp_path / "custom.jsonl"
    fallback = tmp_path / "fallback.jsonl"
    prune_calls: list[Path] = []

    monkeypatch.setattr(settings, "dangerous_response_log_path", str(configured))
    monkeypatch.setattr(danger_log, "_current_log_date", lambda: "2026-03-20")
    monkeypatch.setattr(danger_log, "_FALLBACK_LOG_PATH", fallback)
    monkeypatch.setattr(danger_log, "_prune_old_log_files", lambda path, current_date: prune_calls.append(path))

    def fake_can_append(path: Path) -> bool:
        return path == fallback.with_name("fallback-2026-03-20.jsonl")

    monkeypatch.setattr(danger_log, "_can_append_file", fake_can_append)

    resolved = danger_log._resolve_log_path()

    assert resolved == fallback.with_name("fallback-2026-03-20.jsonl")
    assert prune_calls == [configured, fallback]


def test_append_payload_handles_oserror(monkeypatch, tmp_path):
    target = tmp_path / "danger.jsonl"
    monkeypatch.setattr(danger_log, "_resolve_log_path", lambda: target)

    class BrokenOpen:
        def __call__(self, *args, **kwargs):
            raise OSError("disk full")

    monkeypatch.setattr(Path, "open", BrokenOpen())

    danger_log._append_payload({"request_id": "r-1"})


def test_write_dangerous_response_sample_falls_back_to_sync_write_when_queue_full(monkeypatch):
    calls: list[str] = []
    payloads: list[dict] = []

    class FullQueue:
        def put_nowait(self, item):
            raise queue.Full

    monkeypatch.setattr(settings, "enable_dangerous_response_log", True)
    monkeypatch.setattr(danger_log, "_ensure_worker", lambda: calls.append("ensure_worker"))
    monkeypatch.setattr(danger_log, "_append_payload", lambda payload: payloads.append(payload))
    monkeypatch.setattr(danger_log, "_LOG_QUEUE", FullQueue())

    danger_log.write_dangerous_response_sample({"request_id": "r-queue", "source": "unit-test"})

    assert calls == ["ensure_worker"]
    assert len(payloads) == 1
    assert payloads[0]["request_id"] == "r-queue"
    assert payloads[0]["source"] == "unit-test"
    assert "ts" in payloads[0]


def test_shutdown_dangerous_response_log_worker_resets_cache_without_worker(monkeypatch):
    monkeypatch.setattr(danger_log, "_LOG_PATH", Path("/tmp/cached.jsonl"))
    monkeypatch.setattr(danger_log, "_LOG_PATH_CONFIG", "cached")
    monkeypatch.setattr(danger_log, "_LOG_PATH_DATE", "2026-03-20")

    danger_log.shutdown_dangerous_response_log_worker()

    assert danger_log._LOG_WORKER is None
    assert danger_log._LOG_PATH is None
    assert danger_log._LOG_PATH_CONFIG is None
    assert danger_log._LOG_PATH_DATE is None
