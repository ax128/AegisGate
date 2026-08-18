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
    get_worker: Callable[[], threading.Thread | None],
    set_worker: Callable[[threading.Thread], None],
    *,
    lock: threading.Lock,
    build_thread: Callable[[], threading.Thread],
) -> threading.Thread:
    """Start a worker thread once using double-checked locking.

    The previous signature took ``worker`` by value, so the in-lock recheck
    still saw the stale local copy from before the lock. Concurrent first
    starts could then spawn two non-daemon threads; shutdown only sent one
    sentinel and the leftover thread blocked on ``queue.get()`` forever.

    ``get_worker`` / ``set_worker`` read and publish the live holder *inside*
    the lock so the assignment is visible to the next waiter before we
    release. ``set_worker`` must run after ``start()``: a not-yet-started
    thread reports ``is_alive() is False`` and would look like a dead worker.
    """
    worker = get_worker()
    if worker is not None and worker.is_alive():
        return worker
    with lock:
        worker = get_worker()
        if worker is not None and worker.is_alive():
            return worker
        worker = build_thread()
        worker.start()
        set_worker(worker)
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
