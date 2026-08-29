"""The payload-transform path runs inline, and there is no pool behind it."""

from __future__ import annotations

import asyncio
import threading

from aegisgate.adapters.openai_compat.offload import run_payload_transform_offloop


def test_payload_transform_stays_inline() -> None:
    """It runs on the caller's thread — no executor, no thread hop."""
    caller = threading.get_ident()
    seen: list[int] = []
    asyncio.run(run_payload_transform_offloop(lambda: seen.append(threading.get_ident())))
    assert seen == [caller]


def test_no_payload_transform_executor_symbol() -> None:
    """Guards the removal: a pool that is never created is pure upkeep.

    This fails if anyone reintroduces the executor "while they are in there",
    which is how the last one outlived the code path that used it.
    """
    import aegisgate.adapters.openai_compat.offload as mod

    assert not hasattr(mod, "_get_payload_transform_executor")
    assert not hasattr(mod, "shutdown_payload_transform_executor")
    assert not hasattr(mod, "_PAYLOAD_TRANSFORM_EXECUTOR")
    assert not hasattr(mod, "_PAYLOAD_TRANSFORM_LOCK")
    assert not hasattr(mod, "_PAYLOAD_TRANSFORM_MAX_WORKERS")


def test_the_filter_pipeline_pool_is_untouched() -> None:
    """Only the payload-transform pool goes; the pipeline one is load-bearing."""
    import aegisgate.adapters.openai_compat.offload as mod

    assert hasattr(mod, "_get_filter_pipeline_executor")
    assert hasattr(mod, "shutdown_filter_pipeline_executor")
