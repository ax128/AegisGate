"""Dedicated executor helpers for blocking store I/O."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from threading import Lock
from typing import Any, Callable, TypeVar


T = TypeVar("T")

_STORE_IO_EXECUTOR: ThreadPoolExecutor | None = None
_STORE_IO_LOCK = Lock()
_STORE_IO_MAX_WORKERS = 4


def _get_store_io_executor() -> ThreadPoolExecutor:
    global _STORE_IO_EXECUTOR
    executor = _STORE_IO_EXECUTOR
    if executor is not None:
        return executor
    with _STORE_IO_LOCK:
        executor = _STORE_IO_EXECUTOR
        if executor is None:
            executor = ThreadPoolExecutor(
                max_workers=_STORE_IO_MAX_WORKERS,
                thread_name_prefix="aegisgate-store-io",
            )
            _STORE_IO_EXECUTOR = executor
        return executor


async def run_store_io(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run blocking store work outside the event loop."""
    loop = asyncio.get_running_loop()
    call = partial(func, *args, **kwargs)
    return await loop.run_in_executor(_get_store_io_executor(), call)


def shutdown_store_io_executor() -> None:
    """Release store I/O worker threads during app shutdown."""
    global _STORE_IO_EXECUTOR
    with _STORE_IO_LOCK:
        executor = _STORE_IO_EXECUTOR
        _STORE_IO_EXECUTOR = None
    if executor is not None:
        executor.shutdown(wait=True, cancel_futures=False)
