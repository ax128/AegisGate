"""Audit record handling."""

from __future__ import annotations

import atexit
import json
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisgate.core.background_worker import ensure_worker_thread, run_queue_worker, shutdown_queue_worker
from aegisgate.config.settings import settings
from aegisgate.util.logger import logger


_AUDIT_QUEUE: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=10000)
_AUDIT_WORKER: threading.Thread | None = None
_AUDIT_LOCK = threading.Lock()
_AUDIT_ATEXIT_REGISTERED = False


def _append_payload(payload: dict[str, Any]) -> None:
    path_str = (settings.audit_log_path or "").strip()
    if not path_str:
        return
    path = Path(path_str)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning("audit worker write failed: %s", exc)


def _worker_loop() -> None:
    run_queue_worker(
        _AUDIT_QUEUE,
        _append_payload,
        on_error=lambda exc: logger.warning("audit worker write failed: %s", exc),
    )


def _register_shutdown_handler() -> None:
    global _AUDIT_ATEXIT_REGISTERED
    if _AUDIT_ATEXIT_REGISTERED:
        return
    atexit.register(shutdown_audit_worker)
    _AUDIT_ATEXIT_REGISTERED = True


def _ensure_worker() -> None:
    global _AUDIT_WORKER
    _register_shutdown_handler()
    _AUDIT_WORKER = ensure_worker_thread(
        _AUDIT_WORKER,
        lock=_AUDIT_LOCK,
        build_thread=lambda: threading.Thread(
            target=_worker_loop,
            name="aegisgate-audit-writer",
            daemon=False,
        ),
    )


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
    _AUDIT_WORKER = shutdown_queue_worker(
        _AUDIT_WORKER,
        work_queue=_AUDIT_QUEUE,
        timeout_seconds=timeout_seconds,
        on_queue_full=lambda: logger.warning("audit shutdown: queue full, sentinel could not be sent"),
        on_timeout=lambda timeout: logger.warning("audit worker did not stop within %.2fs", timeout),
    )
