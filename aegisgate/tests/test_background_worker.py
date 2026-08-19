"""A5 / P9: concurrent ensure_worker_thread must start only one live worker."""

from __future__ import annotations

import queue
import threading

from aegisgate.core.background_worker import (
    ensure_worker_thread,
    run_queue_worker,
    shutdown_queue_worker,
)


def test_ensure_worker_thread_starts_only_one_thread_under_concurrency() -> None:
    hold = threading.Event()
    lock = threading.Lock()
    holder: dict[str, threading.Thread | None] = {"worker": None}
    built: list[threading.Thread] = []

    def worker_loop() -> None:
        hold.wait(timeout=5)

    def build_thread() -> threading.Thread:
        thread = threading.Thread(
            target=worker_loop,
            name="aegisgate-ensure-worker-test",
            daemon=True,
        )
        built.append(thread)
        return thread

    barrier = threading.Barrier(32)

    def race() -> None:
        barrier.wait(timeout=5)
        ensure_worker_thread(
            lambda: holder["worker"],
            lambda worker: holder.update(worker=worker),
            lock=lock,
            build_thread=build_thread,
        )

    threads = [threading.Thread(target=race) for _ in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    hold.set()
    live = holder["worker"]
    if live is not None:
        live.join(timeout=2)

    assert len(built) == 1, f"expected one worker thread, started {len(built)}"
    assert holder["worker"] is built[0]


def test_shutdown_queue_worker_joins_nondaemon_thread() -> None:
    work_queue: queue.Queue[object | None] = queue.Queue()
    lock = threading.Lock()
    holder: dict[str, threading.Thread | None] = {"worker": None}

    def loop() -> None:
        run_queue_worker(
            work_queue,
            lambda _item: None,
            on_error=lambda _exc: None,
        )

    worker = ensure_worker_thread(
        lambda: holder["worker"],
        lambda started: holder.update(worker=started),
        lock=lock,
        build_thread=lambda: threading.Thread(
            target=loop,
            name="aegisgate-shutdown-worker-test",
            daemon=False,
        ),
    )
    remaining = shutdown_queue_worker(
        worker,
        work_queue=work_queue,
        timeout_seconds=2.0,
        on_queue_full=lambda: None,
        on_timeout=lambda _timeout: None,
    )

    assert remaining is None
    assert not worker.is_alive()
    assert not any(
        thread.is_alive() and thread.name == "aegisgate-shutdown-worker-test"
        for thread in threading.enumerate()
    )
