"""Tests for aegisgate.core.audit — async queue-based audit logging."""

from __future__ import annotations

import json
import queue
import threading

import pytest

from aegisgate.core import audit


@pytest.fixture(autouse=True)
def _reset_audit_state(monkeypatch):
    """Reset audit module state between tests."""
    monkeypatch.setattr(audit, "_AUDIT_QUEUE", queue.Queue(maxsize=10000))
    monkeypatch.setattr(audit, "_AUDIT_WORKER", None)
    monkeypatch.setattr(audit, "_AUDIT_LOCK", threading.Lock())
    monkeypatch.setattr(audit, "_AUDIT_ATEXIT_REGISTERED", False)


# ---------- _append_payload ----------

def test_append_payload_writes_to_file(monkeypatch, tmp_path):
    log_file = tmp_path / "audit.log"
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "audit_log_path", str(log_file))

    payload = {"event": "test", "detail": "hello"}
    audit._append_payload(payload)

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["event"] == "test"


def test_append_payload_noop_when_path_empty(monkeypatch):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "audit_log_path", "")

    # Should not raise
    audit._append_payload({"event": "test"})


def test_append_payload_handles_oserror(monkeypatch, tmp_path):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "audit_log_path", "/nonexistent/path/audit.log")

    from pathlib import Path

    def _raise_os(self, *a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "mkdir", _raise_os)

    # Should not raise, just log warning
    audit._append_payload({"event": "test"})


# ---------- write_audit ----------

def test_write_audit_queues_event(monkeypatch, tmp_path):
    from aegisgate.config.settings import settings
    log_file = tmp_path / "audit.log"
    monkeypatch.setattr(settings, "audit_log_path", str(log_file))

    audit.write_audit({"request_id": "r-1", "action": "test"})

    # Wait for worker to process
    audit.shutdown_audit_worker(timeout_seconds=2.0)

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["request_id"] == "r-1"
    assert "ts" in data


def test_write_audit_multiple_events(monkeypatch, tmp_path):
    from aegisgate.config.settings import settings
    log_file = tmp_path / "audit.log"
    monkeypatch.setattr(settings, "audit_log_path", str(log_file))

    for i in range(5):
        audit.write_audit({"request_id": f"r-{i}"})

    audit.shutdown_audit_worker(timeout_seconds=2.0)

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 5


# ---------- shutdown_audit_worker ----------

def test_shutdown_noop_when_no_worker():
    audit.shutdown_audit_worker(timeout_seconds=0.1)


def test_shutdown_sends_sentinel(monkeypatch, tmp_path):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "audit_log_path", str(tmp_path / "audit.log"))

    audit.write_audit({"request_id": "r-1"})
    assert audit._AUDIT_WORKER is not None

    audit.shutdown_audit_worker(timeout_seconds=2.0)
    assert audit._AUDIT_WORKER is None


def test_shutdown_preserves_live_worker_when_queue_is_full(monkeypatch):
    class FullQueue:
        def __init__(self) -> None:
            self.calls: list[tuple[object | None, float | None]] = []

        def put(self, item, timeout=None):
            self.calls.append((item, timeout))
            raise queue.Full

    class LiveWorker:
        def __init__(self) -> None:
            self.join_calls: list[float | None] = []

        def join(self, timeout=None) -> None:
            self.join_calls.append(timeout)

        def is_alive(self) -> bool:
            return True

    fake_queue = FullQueue()
    fake_worker = LiveWorker()
    monkeypatch.setattr(audit, "_AUDIT_QUEUE", fake_queue)
    monkeypatch.setattr(audit, "_AUDIT_WORKER", fake_worker)

    audit.shutdown_audit_worker(timeout_seconds=0.2)

    assert fake_queue.calls == [(None, 0.2)]
    assert fake_worker.join_calls == [0.2]
    assert audit._AUDIT_WORKER is fake_worker


# ---------- _ensure_worker (double-checked locking) ----------

def test_ensure_worker_idempotent(monkeypatch, tmp_path):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "audit_log_path", str(tmp_path / "audit.log"))

    audit._ensure_worker()
    worker1 = audit._AUDIT_WORKER
    audit._ensure_worker()
    worker2 = audit._AUDIT_WORKER
    assert worker1 is worker2

    audit.shutdown_audit_worker(timeout_seconds=2.0)


def test_ensure_worker_registers_atexit_once(monkeypatch):
    calls: list[object] = []

    class FakeThread:
        def __init__(self, *args, **kwargs) -> None:
            self.started = False

        def start(self) -> None:
            self.started = True

        def is_alive(self) -> bool:
            return self.started

    monkeypatch.setattr(audit.atexit, "register", lambda fn: calls.append(fn))
    monkeypatch.setattr(audit.threading, "Thread", FakeThread)

    audit._ensure_worker()
    audit._ensure_worker()

    assert calls == [audit.shutdown_audit_worker]
    assert isinstance(audit._AUDIT_WORKER, FakeThread)
    assert audit._AUDIT_WORKER.started is True
