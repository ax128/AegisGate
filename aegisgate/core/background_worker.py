"""Shared helpers for queue-backed background worker threads."""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import Any, TypeVar


T = TypeVar("T")


def run_queue_worker(
    work_queue: queue.Queue[T | None],
    handler: Callable[[T], None],
    *,
    on_error: Callable[[Exception], None],
) -> None:
    """Drain a queue until a ``None`` sentinel is received."""
    while True:
        item = work_queue.get()
        try:
            if item is None:
                break
            handler(item)
        except Exception as exc:  # pragma: no cover - operational safeguard
            on_error(exc)
        finally:
            work_queue.task_done()


def ensure_worker_thread(
    worker: threading.Thread | None,
    *,
    lock: threading.Lock,
    build_thread: Callable[[], threading.Thread],
) -> threading.Thread:
    """Start a worker thread once using double-checked locking."""
    if worker is not None and worker.is_alive():
        return worker
    with lock:
        if worker is not None and worker.is_alive():
            return worker
        worker = build_thread()
        worker.start()
        return worker


def shutdown_queue_worker(
    worker: threading.Thread | None,
    *,
    work_queue: queue.Queue[Any],
    timeout_seconds: float,
    on_queue_full: Callable[[], None],
    on_timeout: Callable[[float], None],
) -> threading.Thread | None:
    """Stop a worker thread and return the remaining live worker, if any."""
    if worker is None:
        return None
    timeout = max(0.01, float(timeout_seconds))
    try:
        work_queue.put(None, timeout=timeout)
    except queue.Full:
        on_queue_full()
    worker.join(timeout=timeout)
    if worker.is_alive():
        on_timeout(timeout)
        return worker
    return None
