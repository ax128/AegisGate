from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from fastapi.responses import StreamingResponse

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.core import pipeline as pipeline_module


def _seed_policy(ctx, policy_name: str = "default") -> dict[str, object]:
    ctx.enabled_filters = {"redaction", "anomaly_detector"}
    ctx.risk_threshold = 0.85
    return {"enabled_filters": set(ctx.enabled_filters), "threshold": ctx.risk_threshold}


def _raise_unexpected(*args, **kwargs):
    raise AssertionError("passthrough 模式不应触发过滤/摘录逻辑")


async def _raise_unexpected_async(*args, **kwargs):
    raise AssertionError("passthrough 模式不应触发过滤/摘录逻辑")


async def _collect_stream_body(response: StreamingResponse) -> bytes:
    chunks: list[bytes] = []
    async for chunk in response.body_iterator:
        chunks.append(chunk if isinstance(chunk, bytes) else chunk.encode("utf-8"))
    return b"".join(chunks)


def _install_common_passthrough_mocks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    audit_calls: list[str] = []
    monkeypatch.setattr(openai_router.policy_engine, "resolve", _seed_policy)
    monkeypatch.setattr(openai_router, "_resolve_upstream_base", lambda headers: "http://upstream.test")
    monkeypatch.setattr(openai_router, "_build_upstream_url", lambda path, base: f"{base}{path}")
    monkeypatch.setattr(openai_router, "_build_forward_headers", lambda headers: {"x-forwarded-for": "test"})
    monkeypatch.setattr(openai_router, "_run_request_pipeline", _raise_unexpected_async)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", _raise_unexpected_async)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", _raise_unexpected_async)
    monkeypatch.setattr(openai_router, "debug_log_original", _raise_unexpected)
    monkeypatch.setattr(
        openai_router,
        "_write_audit_event",
        lambda ctx, boundary=None: audit_calls.append(ctx.request_id),
    )
    return audit_calls


def test_responses_stream_debug_log_filter() -> None:
    assert openai_router._should_log_responses_stream_event("response.created") is False
    assert openai_router._should_log_responses_stream_event("response.completed") is False
    assert openai_router._should_log_responses_stream_event("response.output_text.delta") is False
    assert openai_router._should_log_responses_stream_event("response.failed") is True


def test_filter_done_debug_log_only_when_filter_hits() -> None:
    assert pipeline_module._should_log_filter_done(phase="request", is_stream=False, report={"hit": False}) is False
    assert pipeline_module._should_log_filter_done(phase="request", is_stream=False, report={"hit": True}) is True
    assert pipeline_module._should_log_filter_done(phase="response", is_stream=True, report={"hit": True}) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("execute_fn", "payload", "request_path", "expected_forward_payload", "expected_body"),
    [
        (
            openai_router._execute_chat_once,
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "hello"}],
                "request_id": "chat-pass",
                "session_id": "chat-pass",
                "policy": "default",
            },
            "/v1/chat/completions",
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "hello"}],
            },
            {"id": "chat-1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        ),
        (
            openai_router._execute_responses_once,
            {
                "model": "gpt-5.4",
                "input": "hello",
                "request_id": "resp-pass",
                "session_id": "resp-pass",
                "metadata": {"trace": "x"},
            },
            "/v1/responses",
            {
                "model": "gpt-5.4",
                "input": "hello",
            },
            {"id": "resp-1", "output_text": "ok"},
        ),
    ],
)
async def test_passthrough_json_endpoints_skip_all_filters(
    monkeypatch: pytest.MonkeyPatch,
    execute_fn,
    payload: dict[str, object],
    request_path: str,
    expected_forward_payload: dict[str, object],
    expected_body: dict[str, object],
) -> None:
    audit_calls = _install_common_passthrough_mocks(monkeypatch)

    async def fake_forward_json(url: str, forwarded_payload: dict[str, object], headers: dict[str, str]):
        assert forwarded_payload == expected_forward_payload
        assert url == f"http://upstream.test{request_path}"
        return 200, expected_body

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await execute_fn(
        payload=payload,
        request_headers={"x-aegis-filter-mode": "passthrough"},
        request_path=request_path,
        boundary={},
        tenant_id="default",
    )

    assert result == expected_body
    assert audit_calls == [str(payload["request_id"])]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("execute_fn", "payload", "request_path", "expected_forward_payload", "expected_chunks"),
    [
        (
            openai_router._execute_chat_stream_once,
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
                "request_id": "chat-stream-pass",
                "session_id": "chat-stream-pass",
                "policy": "default",
            },
            "/v1/chat/completions",
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
            [b"data: chat-1\n\n", b"data: [DONE]\n\n"],
        ),
        (
            openai_router._execute_responses_stream_once,
            {
                "model": "gpt-5.4",
                "input": "hello",
                "stream": True,
                "request_id": "resp-stream-pass",
                "session_id": "resp-stream-pass",
                "metadata": {"trace": "x"},
            },
            "/v1/responses",
            {
                "model": "gpt-5.4",
                "input": "hello",
                "stream": True,
            },
            [b"data: resp-1\n\n", b"data: [DONE]\n\n"],
        ),
    ],
)
async def test_passthrough_stream_endpoints_skip_all_filters(
    monkeypatch: pytest.MonkeyPatch,
    execute_fn,
    payload: dict[str, object],
    request_path: str,
    expected_forward_payload: dict[str, object],
    expected_chunks: list[bytes],
) -> None:
    audit_calls = _install_common_passthrough_mocks(monkeypatch)

    async def fake_forward_stream_lines(
        url: str,
        forwarded_payload: dict[str, object],
        headers: dict[str, str],
    ) -> AsyncGenerator[bytes, None]:
        assert forwarded_payload == expected_forward_payload
        assert url == f"http://upstream.test{request_path}"
        for chunk in expected_chunks:
            yield chunk

    monkeypatch.setattr(openai_router, "_forward_stream_lines", fake_forward_stream_lines)

    response = await execute_fn(
        payload=payload,
        request_headers={"x-aegis-filter-mode": "passthrough"},
        request_path=request_path,
        boundary={},
        tenant_id="default",
    )

    assert isinstance(response, StreamingResponse)
    assert await _collect_stream_body(response) == b"".join(expected_chunks)
    assert audit_calls == [str(payload["request_id"])]
