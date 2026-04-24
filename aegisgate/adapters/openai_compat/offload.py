"""Dedicated executor helpers for protocol payload transforms."""

from __future__ import annotations

import atexit
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Any, Callable, TypeVar


T = TypeVar("T")

_PAYLOAD_TRANSFORM_EXECUTOR: ThreadPoolExecutor | None = None
_PAYLOAD_TRANSFORM_LOCK = Lock()
_PAYLOAD_TRANSFORM_MAX_WORKERS = 4
_FILTER_PIPELINE_EXECUTOR: ThreadPoolExecutor | None = None
_FILTER_PIPELINE_LOCK = Lock()
_FILTER_PIPELINE_MAX_WORKERS = max(8, min(32, (os.cpu_count() or 4) * 2))


def _get_payload_transform_executor() -> ThreadPoolExecutor:
    global _PAYLOAD_TRANSFORM_EXECUTOR
    executor = _PAYLOAD_TRANSFORM_EXECUTOR
    if executor is not None:
        return executor
    with _PAYLOAD_TRANSFORM_LOCK:
        executor = _PAYLOAD_TRANSFORM_EXECUTOR
        if executor is None:
            executor = ThreadPoolExecutor(
                max_workers=_PAYLOAD_TRANSFORM_MAX_WORKERS,
                thread_name_prefix="aegisgate-payload-transform",
            )
            _PAYLOAD_TRANSFORM_EXECUTOR = executor
        return executor


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
    """Run lightweight payload mapping work on a dedicated executor.

    NOTE: This repo runs on Python 3.13 in CI/dev, and repeated thread-offload
    submissions can deadlock in practice (observed via pytest-timeout in compat
    redirect flows and security-view preparation). Payload transforms are
    intentionally lightweight, so we run them inline to keep correctness and
    avoid event loop stalls.
    """
    return func(*args, **kwargs)


async def run_filter_pipeline_offloop(
    func: Callable[..., T], *args: Any, **kwargs: Any
) -> T:
    """Run CPU-heavy request/response filter pipelines on a dedicated executor."""
    loop = asyncio.get_running_loop()
    executor = _get_filter_pipeline_executor()
    future = executor.submit(func, *args, **kwargs)
    return await asyncio.wrap_future(future, loop=loop)


def shutdown_payload_transform_executor() -> None:
    """Release payload transform workers during app shutdown."""
    global _PAYLOAD_TRANSFORM_EXECUTOR
    with _PAYLOAD_TRANSFORM_LOCK:
        executor = _PAYLOAD_TRANSFORM_EXECUTOR
        _PAYLOAD_TRANSFORM_EXECUTOR = None
    if executor is not None:
        executor.shutdown(wait=True, cancel_futures=False)


def shutdown_filter_pipeline_executor() -> None:
    """Release filter-pipeline worker threads during app shutdown."""
    global _FILTER_PIPELINE_EXECUTOR
    with _FILTER_PIPELINE_LOCK:
        executor = _FILTER_PIPELINE_EXECUTOR
        _FILTER_PIPELINE_EXECUTOR = None
    if executor is not None:
        executor.shutdown(wait=True, cancel_futures=False)


atexit.register(shutdown_payload_transform_executor)
atexit.register(shutdown_filter_pipeline_executor)
