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


def test_pipeline_includes_system_prompt_guard_in_request_filters() -> None:
    pipeline_runtime.reset_pipeline_cache()

    pipeline = pipeline_runtime._get_pipeline()

    assert [plugin.name for plugin in pipeline.request_filters] == [
        "exact_value_redaction",
        "redaction",
        "system_prompt_guard",
        "untrusted_content_guard",
        "request_sanitizer",
        "rag_poison_guard",
    ]
