"""Dedicated executor helpers for protocol payload transforms."""

from __future__ import annotations

import atexit
import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from threading import Lock
from typing import Any, Callable, TypeVar


T = TypeVar("T")

_PAYLOAD_TRANSFORM_EXECUTOR: ThreadPoolExecutor | None = None
_PAYLOAD_TRANSFORM_LOCK = Lock()
_PAYLOAD_TRANSFORM_MAX_WORKERS = 4


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


async def run_payload_transform_offloop(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run lightweight payload mapping work outside the event loop."""
    loop = asyncio.get_running_loop()
    call = partial(func, *args, **kwargs)
    return await loop.run_in_executor(_get_payload_transform_executor(), call)


def shutdown_payload_transform_executor() -> None:
    """Release payload transform workers during app shutdown."""
    global _PAYLOAD_TRANSFORM_EXECUTOR
    with _PAYLOAD_TRANSFORM_LOCK:
        executor = _PAYLOAD_TRANSFORM_EXECUTOR
        _PAYLOAD_TRANSFORM_EXECUTOR = None
    if executor is not None:
        executor.shutdown(wait=True, cancel_futures=False)


atexit.register(shutdown_payload_transform_executor)
