"""Executor helpers for the filter pipeline, plus the inline payload transform."""

from __future__ import annotations

import atexit
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Any, Callable, TypeVar


T = TypeVar("T")

_FILTER_PIPELINE_EXECUTOR: ThreadPoolExecutor | None = None
_FILTER_PIPELINE_LOCK = Lock()
_FILTER_PIPELINE_MAX_WORKERS = max(8, min(32, (os.cpu_count() or 4) * 2))


def _get_filter_pipeline_executor() -> ThreadPoolExecutor:
    global _FILTER_PIPELINE_EXECUTOR
    executor = _FILTER_PIPELINE_EXECUTOR
    if executor is not None:
        return executor
    with _FILTER_PIPELINE_LOCK:
        executor = _FILTER_PIPELINE_EXECUTOR
        if executor is None:
            executor = ThreadPoolExecutor(
                max_workers=_FILTER_PIPELINE_MAX_WORKERS,
                thread_name_prefix="aegisgate-filter-pipeline",
            )
            _FILTER_PIPELINE_EXECUTOR = executor
        return executor


async def run_payload_transform_offloop(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run lightweight payload mapping work on the calling thread.

    There is no executor behind this and there has not been one for a while:
    this repo runs on Python 3.13 in CI/dev, and repeated thread-offload
    submissions can deadlock in practice (observed via pytest-timeout in compat
    redirect flows and security-view preparation). Payload transforms are
    intentionally lightweight, so we run them inline to keep correctness and
    avoid event loop stalls.

    The ``async def`` stays: every call site awaits it, and the signature is the
    seam that made the inline switch a one-line change rather than a caller
    audit.
    """
    return func(*args, **kwargs)


async def run_filter_pipeline_offloop(
    func: Callable[..., T], *args: Any, **kwargs: Any
) -> T:
    """Run the request/response filter pipeline off the event loop thread.

    This does **not** buy parallelism. CPython's ``re`` holds the GIL for the
    whole match, so the worker thread and the loop thread still take turns at
    the interpreter's switch interval — what this buys is that the loop gets
    those turns at all, instead of being pinned for the length of a full
    pipeline run.

    The same fact bounds ``filter_pipeline_timeout_s``: the timeout can only
    fire at an ``await`` point, so a single catastrophic pattern inside one
    filter is not interruptible by it. That guarantee comes from the static
    ReDoS budget in ``tests/test_redos_guard.py``, not from this function.
    """
    loop = asyncio.get_running_loop()
    executor = _get_filter_pipeline_executor()
    future = executor.submit(func, *args, **kwargs)
    return await asyncio.wrap_future(future, loop=loop)


def shutdown_filter_pipeline_executor() -> None:
    """Release filter-pipeline worker threads during app shutdown."""
    global _FILTER_PIPELINE_EXECUTOR
    with _FILTER_PIPELINE_LOCK:
        executor = _FILTER_PIPELINE_EXECUTOR
        _FILTER_PIPELINE_EXECUTOR = None
    if executor is not None:
        executor.shutdown(wait=True, cancel_futures=False)


atexit.register(shutdown_filter_pipeline_executor)
