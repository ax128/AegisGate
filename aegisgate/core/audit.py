"""Audit record handling."""

from __future__ import annotations

import json
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisgate.util.logger import logger


AUDIT_PATH = Path("logs") / "audit.jsonl"
_AUDIT_QUEUE: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=10000)
_AUDIT_WORKER: threading.Thread | None = None
_AUDIT_LOCK = threading.Lock()


def _append_payload(payload: dict[str, Any]) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _worker_loop() -> None:
    while True:
        item = _AUDIT_QUEUE.get()
        try:
            if item is None:
                break
            _append_payload(item)
        except Exception as exc:  # pragma: no cover - operational safeguard
            logger.warning("audit worker write failed: %s", exc)
        finally:
            _AUDIT_QUEUE.task_done()


def _ensure_worker() -> None:
    global _AUDIT_WORKER
    if _AUDIT_WORKER is not None and _AUDIT_WORKER.is_alive():
        return
    with _AUDIT_LOCK:
        if _AUDIT_WORKER is not None and _AUDIT_WORKER.is_alive():
            return
        _AUDIT_WORKER = threading.Thread(target=_worker_loop, name="aegisgate-audit-writer", daemon=True)
        _AUDIT_WORKER.start()


def write_audit(event: dict[str, Any]) -> None:
    payload = {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        **event,
    }
    _ensure_worker()
    try:
        _AUDIT_QUEUE.put_nowait(payload)
    except queue.Full:  # pragma: no cover - overload safeguard
        _append_payload(payload)
        logger.warning("audit queue full, fallback to sync write request_id=%s", event.get("request_id", "unknown"))
    logger.info("audit event queued: request_id=%s", event.get("request_id", "unknown"))


def shutdown_audit_worker(timeout_seconds: float = 1.0) -> None:
    global _AUDIT_WORKER
    if _AUDIT_WORKER is None:
        return
    try:
        _AUDIT_QUEUE.put_nowait(None)
    except queue.Full:
        pass
    worker = _AUDIT_WORKER
    worker.join(timeout=timeout_seconds)
    _AUDIT_WORKER = None
