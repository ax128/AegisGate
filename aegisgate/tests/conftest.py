from __future__ import annotations

import asyncio
import concurrent.futures.thread as thread_runtime

import pytest

from aegisgate.adapters.openai_compat.offload import (
    shutdown_filter_pipeline_executor,
    shutdown_payload_transform_executor,
)
from aegisgate.adapters.openai_compat.router import (
    close_runtime_dependencies,
    close_semantic_async_client,
)
from aegisgate.adapters.openai_compat.upstream import close_upstream_async_client
from aegisgate.adapters.v2_proxy.router import close_v2_async_client
from aegisgate.core.audit import shutdown_audit_worker
from aegisgate.core.dangerous_response_log import shutdown_dangerous_response_log_worker
from aegisgate.storage.offload import shutdown_store_io_executor


def _run_async_cleanup(coro_factory) -> None:
    try:
        asyncio.run(coro_factory())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(coro_factory())
        finally:
            loop.close()


@pytest.fixture(scope="session", autouse=True)
def _shutdown_background_runtime_after_tests():
    yield
    close_runtime_dependencies()
    shutdown_store_io_executor()
    shutdown_filter_pipeline_executor()
    shutdown_payload_transform_executor()
    shutdown_audit_worker()
    shutdown_dangerous_response_log_worker()
    _run_async_cleanup(close_upstream_async_client)
    _run_async_cleanup(close_v2_async_client)
    _run_async_cleanup(close_semantic_async_client)
    python_exit = getattr(thread_runtime, "_python_exit", None)
    if callable(python_exit):
        python_exit()
