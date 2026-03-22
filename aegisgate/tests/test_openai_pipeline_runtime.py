from __future__ import annotations

from aegisgate.adapters.openai_compat import pipeline_runtime


def test_get_pipeline_reuses_cached_instance_for_current_thread() -> None:
    pipeline_runtime.reset_pipeline_cache()

    first = pipeline_runtime._get_pipeline()
    second = pipeline_runtime._get_pipeline()

    assert first is second


def test_reset_pipeline_cache_invalidates_cached_pipeline() -> None:
    pipeline_runtime.reset_pipeline_cache()
    first = pipeline_runtime._get_pipeline()

    pipeline_runtime.reset_pipeline_cache()
    second = pipeline_runtime._get_pipeline()

    assert first is not second
