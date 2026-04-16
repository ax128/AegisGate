from __future__ import annotations

import asyncio
import io
import logging
from collections.abc import AsyncGenerator

import pytest
from fastapi.responses import JSONResponse, StreamingResponse

from aegisgate.adapters.openai_compat.router import (
    _UPSTREAM_EOF_RECOVERY_NOTICE,
    _coerce_responses_stream_to_chat_stream,
    _execute_chat_stream_once,
    _execute_messages_stream_once,
    _execute_responses_stream_once,
    _extract_sse_data_payload,
    _iter_forward_stream_with_pinning,
    _run_request_pipeline,
    _run_response_pipeline,
    _stream_block_reason,
    _stream_block_sse_chunk,
)
from aegisgate.adapters.openai_compat.stream_utils import (
    _extract_sse_data_payload_from_chunk,
    _extract_stream_event_type,
    _extract_stream_text_from_event,
    _iter_sse_frames,
    _stream_error_sse_chunk,
)
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.util.logger import logger as aegis_logger


async def _async_resolve_upstream_example(headers):
    return ("https://upstream.example.com", (), "")


@pytest.fixture(autouse=True)
def _patch_upstream_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_resolve(headers):
        base = str(
            headers.get("X-Upstream-Base")
            or headers.get("x-upstream-base")
            or "https://upstream.example.com/v1"
        )
        return (base, (), "")

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._resolve_upstream_base",
        _fake_resolve,
    )


def _to_bytes(value: bytes | str | memoryview[int]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return value.tobytes()


def _install_inline_payload_transform(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_payload_transform",
        fake_run_payload_transform,
    )


def _install_identity_stream_pipelines(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        return resp

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )


async def _collect_execute_stream(
    response: StreamingResponse | JSONResponse | AsyncGenerator[bytes, None],
) -> bytes:
    chunks: list[bytes] = []
    if isinstance(response, JSONResponse):
        raise AssertionError("expected streaming response")
    if isinstance(response, StreamingResponse):
        async for chunk in response.body_iterator:
            chunks.append(_to_bytes(chunk))
        return b"".join(chunks)
    async for chunk in response:
        chunks.append(chunk)
    return b"".join(chunks)


def test_extract_sse_data_payload() -> None:
    assert _extract_sse_data_payload(b"data: [DONE]\n\n") == "[DONE]"
    assert _extract_sse_data_payload(b"event: message\n") is None


def test_run_request_pipeline_uses_dedicated_offload_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[str] = []

    async def fake_run_filter_pipeline_offloop(func, *args, **kwargs):
        called.append(getattr(func, "__name__", "<unknown>"))
        return func(*args, **kwargs)

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.run_filter_pipeline_offloop",
        fake_run_filter_pipeline_offloop,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.filter_pipeline_timeout_s",
        0.0,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline_sync",
        lambda req, ctx: req,
    )

    req = object()
    ctx = RequestContext(
        request_id="rq-1", session_id="sq-1", route="/v1/chat/completions"
    )

    assert asyncio.run(_run_request_pipeline(None, req, ctx)) is req
    assert len(called) == 1


def test_run_response_pipeline_uses_dedicated_offload_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[str] = []

    async def fake_run_filter_pipeline_offloop(func, *args, **kwargs):
        called.append(getattr(func, "__name__", "<unknown>"))
        return func(*args, **kwargs)

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.run_filter_pipeline_offloop",
        fake_run_filter_pipeline_offloop,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.filter_pipeline_timeout_s",
        0.0,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline_sync",
        lambda resp, ctx: resp,
    )

    resp = InternalResponse(
        request_id="rq-2",
        session_id="sq-2",
        model="test-model",
        output_text="hello",
    )
    ctx = RequestContext(request_id="rq-2", session_id="sq-2", route="/v1/responses")

    assert asyncio.run(_run_response_pipeline(None, resp, ctx)) is resp
    assert len(called) == 1


def test_iter_sse_frames_reassembles_split_chunks() -> None:
    async def chunks() -> AsyncGenerator[bytes, None]:
        yield b'data: {"type":"response.output_text.delta",'
        yield b'"delta":"hello"}\n'
        yield b"\n"

    async def run_case() -> list[bytes]:
        return [frame async for frame in _iter_sse_frames(chunks())]

    frames = asyncio.run(run_case())

    assert len(frames) == 1
    assert (
        _extract_sse_data_payload_from_chunk(frames[0])
        == '{"type":"response.output_text.delta","delta":"hello"}'
    )


def test_coerce_responses_stream_to_chat_stream_handles_split_frames() -> None:
    async def responses_stream() -> AsyncGenerator[bytes, None]:
        yield b'data: {"type":"response.output_text.delta",'
        yield b'"delta":"hello"}\n'
        yield b"\n"
        yield b"data: [DO"
        yield b"NE]\n\n"

    response = StreamingResponse(responses_stream(), media_type="text/event-stream")
    coerced = _coerce_responses_stream_to_chat_stream(
        response,
        request_id="req-1",
        model="test-model",
    )

    async def run_case() -> bytes:
        chunks: list[bytes] = []
        async for chunk in coerced.body_iterator:
            chunks.append(
                chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8")
            )
        return b"".join(chunks)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert '"object": "chat.completion.chunk"' in body
    assert '"content": "hello"' in body
    assert "data: [DONE]" in body


def test_coerce_responses_stream_incremental_tool_calls() -> None:
    """Tool calls streamed via incremental Responses API events are converted
    to Chat Completions tool_calls delta chunks."""
    import json as _json

    async def responses_stream() -> AsyncGenerator[bytes, None]:
        # 1. output_item.added with type=function_call
        yield (
            b'data: {"type":"response.output_item.added","output_index":0,'
            b'"item":{"type":"function_call","id":"fc_001","call_id":"call_abc",'
            b'"name":"read_file","arguments":""}}\n\n'
        )
        # 2. argument deltas
        yield (
            b'data: {"type":"response.function_call_arguments.delta",'
            b'"output_index":0,"delta":"{\\"path\\":"}\n\n'
        )
        yield (
            b'data: {"type":"response.function_call_arguments.delta",'
            b'"output_index":0,"delta":"\\"a.txt\\"}"}\n\n'
        )
        # 3. arguments done (no new data)
        yield (
            b'data: {"type":"response.function_call_arguments.done",'
            b'"output_index":0,"arguments":"{\\"path\\":\\"a.txt\\"}"}\n\n'
        )
        # 4. output_item.done
        yield (
            b'data: {"type":"response.output_item.done","output_index":0,'
            b'"item":{"type":"function_call","id":"fc_001","call_id":"call_abc",'
            b'"name":"read_file","arguments":"{\\"path\\":\\"a.txt\\"}"}}\n\n'
        )
        # 5. response.completed with minimal output (no full array)
        yield (
            b'data: {"type":"response.completed","response":{"id":"resp_1",'
            b'"model":"gpt-4","status":"completed","output":[]}}\n\n'
        )
        yield b"data: [DONE]\n\n"

    response = StreamingResponse(responses_stream(), media_type="text/event-stream")
    coerced = _coerce_responses_stream_to_chat_stream(
        response,
        request_id="req-tc",
        model="test-model",
    )

    async def run_case() -> bytes:
        chunks: list[bytes] = []
        async for chunk in coerced.body_iterator:
            chunks.append(
                chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8")
            )
        return b"".join(chunks)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    # Parse all SSE data lines
    payloads = []
    for line in body.split("\n"):
        if line.startswith("data: ") and line.strip() != "data: [DONE]":
            payloads.append(_json.loads(line[6:]))

    # First chunk: initial tool call with role, id, name, empty arguments
    first = payloads[0]
    assert first["object"] == "chat.completion.chunk"
    tc0 = first["choices"][0]["delta"]["tool_calls"][0]
    assert tc0["index"] == 0
    assert tc0["id"] == "call_abc"
    assert tc0["type"] == "function"
    assert tc0["function"]["name"] == "read_file"
    assert tc0["function"]["arguments"] == ""
    assert first["choices"][0]["delta"].get("role") == "assistant"

    # Middle chunks: argument deltas
    arg_chunks = [
        p["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
        for p in payloads[1:]
        if p["choices"][0].get("delta", {}).get("tool_calls")
        and p["choices"][0]["delta"]["tool_calls"][0].get("function", {}).get(
            "arguments"
        )
        is not None
        and p["choices"][0].get("finish_reason") is None
    ]
    combined_args = "".join(arg_chunks)
    assert combined_args == '{"path":"a.txt"}'

    # Final chunk: finish_reason = "tool_calls"
    finish_payloads = [
        p for p in payloads if p["choices"][0].get("finish_reason") == "tool_calls"
    ]
    assert len(finish_payloads) == 1

    # DONE sentinel
    assert "data: [DONE]" in body


def test_coerce_responses_stream_output_item_done_fallback() -> None:
    """When no output_item.added is received, output_item.done emits the full
    tool call as a fallback (some proxies skip incremental events)."""
    import json as _json

    async def responses_stream() -> AsyncGenerator[bytes, None]:
        # Only output_item.done, no prior added/delta events
        yield (
            b'data: {"type":"response.output_item.done","output_index":0,'
            b'"item":{"type":"function_call","id":"fc_002","call_id":"call_xyz",'
            b'"name":"write_file","arguments":"{\\"content\\":\\"hi\\"}"}}\n\n'
        )
        yield (
            b'data: {"type":"response.completed","response":{"id":"resp_2",'
            b'"model":"gpt-4","status":"completed","output":[]}}\n\n'
        )
        yield b"data: [DONE]\n\n"

    response = StreamingResponse(responses_stream(), media_type="text/event-stream")
    coerced = _coerce_responses_stream_to_chat_stream(
        response,
        request_id="req-fb",
        model="test-model",
    )

    async def run_case() -> bytes:
        chunks: list[bytes] = []
        async for chunk in coerced.body_iterator:
            chunks.append(
                chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8")
            )
        return b"".join(chunks)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    payloads = []
    for line in body.split("\n"):
        if line.startswith("data: ") and line.strip() != "data: [DONE]":
            payloads.append(_json.loads(line[6:]))

    # Should have the full tool call from output_item.done fallback
    tc = payloads[0]["choices"][0]["delta"]["tool_calls"][0]
    assert tc["id"] == "call_xyz"
    assert tc["function"]["name"] == "write_file"
    assert tc["function"]["arguments"] == '{"content":"hi"}'

    # finish_reason = "tool_calls"
    finish = [p for p in payloads if p["choices"][0].get("finish_reason") == "tool_calls"]
    assert len(finish) == 1


def test_stream_block_reason_uses_response_disposition_first() -> None:
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions")
    ctx.response_disposition = "sanitize"

    assert _stream_block_reason(ctx) == "response_sanitized"


def test_stream_block_reason_high_risk_command_tag_requires_confirmation() -> None:
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions")
    ctx.security_tags.add("response_anomaly_high_risk_command")

    assert _stream_block_reason(ctx) == "response_high_risk_command"


def test_stream_block_sse_chunk_for_responses_route() -> None:
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/responses")
    chunk = _stream_block_sse_chunk(
        ctx, "test-model", "response_high_risk", "/v1/responses"
    )
    payload = chunk.decode("utf-8")

    assert '"object": "response.chunk"' in payload
    assert "response_high_risk" in payload


def test_stream_error_sse_chunk_uses_structured_error_payload() -> None:
    payload = _stream_error_sse_chunk(
        "upstream_unreachable: dns", code="upstream_unreachable"
    ).decode("utf-8")

    assert '"type": "error"' in payload
    assert '"code": "upstream_unreachable"' in payload
    assert "dns" in payload


def test_extract_stream_text_from_responses_delta_only() -> None:
    delta = _extract_stream_text_from_event(
        '{"type":"response.output_text.delta","delta":"hello"}'
    )
    summary = _extract_stream_text_from_event(
        '{"type":"response.reasoning_summary_text.delta","delta":"hello"}'
    )
    done = _extract_stream_text_from_event(
        '{"type":"response.output_text.done","text":"hello"}'
    )
    completed = _extract_stream_text_from_event(
        '{"type":"response.completed","response":{"output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]}]}}'
    )

    assert delta == "hello"
    assert summary == ""
    assert done == ""
    assert completed == ""


def test_extract_stream_event_type_normalizes_type() -> None:
    assert (
        _extract_stream_event_type('{"type":"response.completed"}')
        == "response.completed"
    )
    assert (
        _extract_stream_event_type('{"type":" Response.Output_Text.Delta "}')
        == "response.output_text.delta"
    )
    assert _extract_stream_event_type('{"x":1}') == ""


def test_openai_forward_headers_strip_connection_scoped_header() -> None:
    from aegisgate.adapters.openai_compat.upstream import _build_forward_headers

    headers = _build_forward_headers(
        {
            "Connection": "x-drop-me, keep-alive",
            "X-Drop-Me": "secret",
            "X-Extra": "keep-me",
        }
    )

    assert headers == {"X-Extra": "keep-me", "Content-Type": "application/json"}


def test_v2_forward_headers_strip_connection_scoped_header() -> None:
    from fastapi import Request

    from aegisgate.adapters.v2_proxy.router import _build_forward_headers

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v2",
            "headers": [
                (b"host", b"gateway.test"),
                (b"connection", b"x-internal-trace"),
                (b"x-internal-trace", b"leak"),
                (b"x-target-url", b"https://upstream.example.com/v2"),
                (b"x-extra", b"keep-me"),
            ],
            "query_string": b"",
            "scheme": "https",
            "server": ("gateway.test", 443),
            "client": ("127.0.0.1", 12345),
        }
    )

    headers = _build_forward_headers(request)
    assert headers == {"x-extra": "keep-me"}


def test_v2_client_response_headers_strip_connection_scoped_header() -> None:
    from aegisgate.adapters.v2_proxy.router import _build_client_response_headers

    headers = _build_client_response_headers(
        {
            "Connection": "x-upstream-trace",
            "X-Upstream-Trace": "should-drop",
            "X-Extra": "keep-me",
        }
    )

    assert headers == {"X-Extra": "keep-me"}


@pytest.mark.asyncio
async def test_iter_forward_stream_retries_before_first_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def fake_forward_stream_lines(url, payload, headers):
        del url, payload, headers
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("upstream_unreachable: bootstrap timeout")
        yield b"data: ok\n\n"

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.stream_bootstrap_retries", 1
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    chunks = [
        chunk
        async for chunk in _iter_forward_stream_with_pinning(
            url="https://upstream.example.com/v1/responses",
            payload={"stream": True},
            headers={"x-aegis-request-id": "rq-bootstrap-retry"},
            connect_urls=(),
            host_header="",
        )
    ]

    assert attempts == 2
    assert chunks == [b"data: ok\n\n"]


@pytest.mark.asyncio
async def test_iter_forward_stream_retries_before_first_chunk_with_pinning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def fake_forward_stream_lines_pinned(
        *, url, payload, headers, connect_urls, host_header
    ):
        del url, payload, headers, connect_urls, host_header
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("upstream_unreachable: bootstrap timeout")
        yield b"data: pinned-ok\n\n"

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.stream_bootstrap_retries", 1
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines_pinned",
        fake_forward_stream_lines_pinned,
    )

    chunks = [
        chunk
        async for chunk in _iter_forward_stream_with_pinning(
            url="https://upstream.example.com/v1/responses",
            payload={"stream": True},
            headers={"x-aegis-request-id": "rq-bootstrap-retry-pinned"},
            connect_urls=("https://93.184.216.34/v1/responses",),
            host_header="upstream.example.com",
        )
    ]

    assert attempts == 2
    assert chunks == [b"data: pinned-ok\n\n"]


@pytest.mark.asyncio
async def test_iter_forward_stream_does_not_retry_after_first_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def fake_forward_stream_lines(url, payload, headers):
        del url, payload, headers
        nonlocal attempts
        attempts += 1
        yield b"data: partial\n\n"
        raise RuntimeError("upstream_unreachable: after-first-byte")

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.stream_bootstrap_retries", 3
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    chunks: list[bytes] = []
    with pytest.raises(RuntimeError, match="after-first-byte"):
        async for chunk in _iter_forward_stream_with_pinning(
            url="https://upstream.example.com/v1/chat/completions",
            payload={"stream": True},
            headers={"x-aegis-request-id": "rq-bootstrap-no-retry"},
            connect_urls=(),
            host_header="",
        ):
            chunks.append(chunk)

    assert attempts == 1
    assert chunks == [b"data: partial\n\n"]


@pytest.mark.asyncio
async def test_iter_forward_stream_does_not_retry_non_retryable_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def fake_forward_stream_lines(url, payload, headers):
        del url, payload, headers
        nonlocal attempts
        attempts += 1
        raise RuntimeError("upstream_http_error:400:bad_request")
        yield b""  # pragma: no cover

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.stream_bootstrap_retries", 3
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    with pytest.raises(RuntimeError, match="upstream_http_error:400:bad_request"):
        async for _ in _iter_forward_stream_with_pinning(
            url="https://upstream.example.com/v1/chat/completions",
            payload={"stream": True},
            headers={"x-aegis-request-id": "rq-bootstrap-no-retry-400"},
            connect_urls=(),
            host_header="",
        ):
            pass

    assert attempts == 1


def test_messages_stream_harness_avoids_offload_timeout_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transform_calls: list[str] = []
    audit_calls: list[str] = []

    async def fake_payload_transform(func, *args, **kwargs):
        transform_calls.append(getattr(func, "__name__", "<unknown>"))
        return func(*args, **kwargs)

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        return resp

    async def fake_semantic_review(*args, **kwargs):
        return None

    async def fake_forward_stream_lines(url, payload, headers):
        yield (
            b"event: message_start\n"
            b'data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4.5","content":[]}}\n\n'
        )
        yield (
            b"event: content_block_start\n"
            b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
        )
        yield (
            b"event: content_block_delta\n"
            b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}\n\n'
        )
        yield (
            b"event: content_block_stop\n"
            b'data: {"type":"content_block_stop","index":0}\n\n'
        )
        yield b'event: message_stop\ndata: {"type":"message_stop"}\n\n'

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._resolve_upstream_base",
        _async_resolve_upstream_example,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_upstream_url",
        lambda path, base: f"{base}{path}",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_forward_headers",
        lambda headers: {"x-forwarded-for": "test"},
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_payload_transform",
        fake_payload_transform,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._apply_semantic_review",
        fake_semantic_review,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._write_audit_event",
        lambda ctx, boundary=None: audit_calls.append(ctx.request_id),
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.debug_log_original",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.policy_engine.resolve",
        lambda ctx, policy_name="default": {
            "enabled_filters": {"sanitizer"},
            "threshold": 0.85,
        },
    )

    payload = {
        "request_id": "messages-stream-harness",
        "session_id": "messages-stream-harness",
        "model": "claude-sonnet-4.5",
        "stream": True,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_messages_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com"},
            request_path="/v1/messages",
            boundary={},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert transform_calls == [
        "to_internal_messages",
        "_build_messages_upstream_payload",
    ]
    assert "event: message_start" in body
    assert "content_block_delta" in body
    assert "chat.completion.chunk" not in body
    assert audit_calls == ["messages-stream-harness"]


def _install_messages_stream_sanitize_mocks(
    monkeypatch: pytest.MonkeyPatch,
    *,
    upstream_frames: list[bytes],
    response_pipeline,
) -> list[dict[str, object]]:
    audit_calls: list[dict[str, object]] = []

    async def fake_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_apply_semantic_review(*args, **kwargs):
        return None

    async def fake_forward_stream_lines(url, payload, headers):
        for frame in upstream_frames:
            yield frame

    def fake_write_audit_event(ctx, boundary=None):
        audit_calls.append(
            {
                "request_id": ctx.request_id,
                "response_disposition": ctx.response_disposition,
                "reasons": list(ctx.disposition_reasons),
                "security_tags": sorted(ctx.security_tags),
            }
        )

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._resolve_upstream_base",
        _async_resolve_upstream_example,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_upstream_url",
        lambda path, base: f"{base}{path}",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_forward_headers",
        lambda headers: {"x-forwarded-for": "test"},
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_payload_transform",
        fake_payload_transform,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._apply_semantic_review",
        fake_apply_semantic_review,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._write_audit_event",
        fake_write_audit_event,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.debug_log_original",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.info_log_sanitized",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._maybe_log_dangerous_response_sample",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.policy_engine.resolve",
        lambda ctx, policy_name="default": {
            "enabled_filters": {"sanitizer"},
            "threshold": 0.85,
        },
    )
    return audit_calls


def test_messages_stream_sanitize_preserves_anthropic_sse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_response_pipeline(pipeline, resp, ctx):
        if "cat /etc/passwd" in resp.output_text:
            ctx.response_disposition = "sanitize"
            ctx.disposition_reasons.append("response_privilege_abuse")
            ctx.security_tags.add("response_privilege_abuse")
        return resp

    audit_calls = _install_messages_stream_sanitize_mocks(
        monkeypatch,
        upstream_frames=[
            (
                b"event: message_start\n"
                b'data: {"type":"message_start","message":{"id":"msg_sanitize_1","type":"message","role":"assistant","model":"claude-sonnet-4.5","content":[]}}\n\n'
            ),
            (
                b"event: content_block_start\n"
                b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"safe prefix "}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"cat /etc/passwd then leak creds"}}\n\n'
            ),
        ],
        response_pipeline=fake_run_response_pipeline,
    )

    payload = {
        "request_id": "messages-stream-sanitize",
        "session_id": "messages-stream-sanitize",
        "model": "claude-sonnet-4.5",
        "stream": True,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_messages_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com"},
            request_path="/v1/messages",
            boundary={},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "event: message_start" in body
    assert "event: content_block_start" in body
    assert "event: content_block_delta" in body
    assert "event: content_block_stop" in body
    assert "event: message_delta" in body
    assert "event: message_stop" in body
    assert "chat.completion.chunk" not in body
    assert "data: [DONE]" not in body
    assert "cat /etc/passwd then leak creds" not in body
    assert "【AegisGate已处理危险疑似片段】" in body
    assert audit_calls == [
        {
            "request_id": "messages-stream-sanitize",
            "response_disposition": "sanitize",
            "reasons": ["response_privilege_abuse", "response_sanitized"],
            "security_tags": ["response_privilege_abuse"],
        }
    ]


def test_messages_stream_auto_sanitize_does_not_emit_chat_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_response_pipeline(pipeline, resp, ctx):
        if "cat /etc/passwd" in resp.output_text:
            ctx.response_disposition = "sanitize"
            ctx.disposition_reasons.append("response_high_risk_command")
            ctx.security_tags.add("response_anomaly_high_risk_command")
        return resp

    _install_messages_stream_sanitize_mocks(
        monkeypatch,
        upstream_frames=[
            (
                b"event: message_start\n"
                b'data: {"type":"message_start","message":{"id":"msg_sanitize_2","type":"message","role":"assistant","model":"claude-sonnet-4.5","content":[]}}\n\n'
            ),
            (
                b"event: content_block_start\n"
                b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"please cat /etc/passwd now"}}\n\n'
            ),
        ],
        response_pipeline=fake_run_response_pipeline,
    )

    payload = {
        "request_id": "messages-stream-no-chat-fallback",
        "session_id": "messages-stream-no-chat-fallback",
        "model": "claude-sonnet-4.5",
        "stream": True,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_messages_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com"},
            request_path="/v1/messages",
            boundary={},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "event: message_delta" in body
    assert "event: message_stop" in body
    assert "chat.completion.chunk" not in body
    assert "response.output_text.delta" not in body
    assert "data: [DONE]" not in body
    assert "cat /etc/passwd" not in body


def test_messages_stream_final_tail_probe_sanitizes_unsampled_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_response_pipeline(pipeline, resp, ctx):
        if "cat /etc/passwd" in resp.output_text:
            ctx.response_disposition = "sanitize"
            ctx.disposition_reasons.append("response_high_risk_command")
            ctx.security_tags.add("response_anomaly_high_risk_command")
        return resp

    _install_messages_stream_sanitize_mocks(
        monkeypatch,
        upstream_frames=[
            (
                b"event: message_start\n"
                b'data: {"type":"message_start","message":{"id":"msg_tail_1","type":"message","role":"assistant","model":"claude-sonnet-4.5","content":[]}}\n\n'
            ),
            (
                b"event: content_block_start\n"
                b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"one "}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"two "}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"three "}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"four "}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"cat /etc/passwd now"}}\n\n'
            ),
            (
                b"event: content_block_stop\n"
                b'data: {"type":"content_block_stop","index":0}\n\n'
            ),
            b'event: message_stop\ndata: {"type":"message_stop"}\n\n',
        ],
        response_pipeline=fake_run_response_pipeline,
    )

    payload = {
        "request_id": "messages-stream-tail",
        "session_id": "messages-stream-tail",
        "model": "claude-sonnet-4.5",
        "stream": True,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_messages_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com"},
            request_path="/v1/messages",
            boundary={},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "event: message_stop" in body
    assert "cat /etc/passwd now" not in body
    assert "【AegisGate已处理危险疑似片段】" in body
    assert "data: [DONE]" not in body


def test_messages_stream_runtime_error_uses_anthropic_error_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        return resp

    async def fake_semantic_review(*args, **kwargs):
        return None

    async def fake_forward_stream_lines(url, payload, headers):
        if False:
            yield b""
        raise RuntimeError("upstream_unreachable: dns failure")

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._resolve_upstream_base",
        _async_resolve_upstream_example,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_upstream_url",
        lambda path, base: f"{base}{path}",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_forward_headers",
        lambda headers: {"x-forwarded-for": "test"},
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_payload_transform",
        fake_payload_transform,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._apply_semantic_review",
        fake_semantic_review,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._write_audit_event",
        lambda ctx, boundary=None: None,
    )

    payload = {
        "request_id": "messages-stream-error",
        "session_id": "messages-stream-error",
        "model": "claude-sonnet-4.5",
        "stream": True,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_messages_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com"},
            request_path="/v1/messages",
            boundary={},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "event: error" in body
    assert '"type": "error"' in body or '"type":"error"' in body
    assert "dns failure" in body
    assert "data: [DONE]" not in body


def test_messages_stream_passthrough_runtime_error_uses_anthropic_error_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        if False:
            yield b""
        raise RuntimeError("upstream_unreachable: dns failure")

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._write_audit_event",
        lambda ctx, boundary=None: None,
    )

    payload = {
        "request_id": "messages-stream-pass-error",
        "session_id": "messages-stream-pass-error",
        "model": "claude-sonnet-4.5",
        "stream": True,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_messages_stream_once(
            payload=payload,
            request_headers={
                "X-Upstream-Base": "https://upstream.example.com",
                "x-aegis-filter-mode": "passthrough",
            },
            request_path="/v1/messages",
            boundary={},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "event: error" in body
    assert "dns failure" in body
    assert "data: [DONE]" not in body


def test_messages_stream_sanitized_outputs_use_aegisgate_metadata_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_response_pipeline(pipeline, resp, ctx):
        if "cat /etc/passwd" in resp.output_text:
            ctx.response_disposition = "sanitize"
            ctx.disposition_reasons.append("response_semantic_leak")
            ctx.security_tags.add("response_semantic_leak")
            ctx.risk_score = 0.97
        return resp

    audit_calls = _install_messages_stream_sanitize_mocks(
        monkeypatch,
        upstream_frames=[
            (
                b"event: message_start\n"
                b'data: {"type":"message_start","message":{"id":"msg_sanitize_3","type":"message","role":"assistant","model":"claude-sonnet-4.5","content":[]}}\n\n'
            ),
            (
                b"event: content_block_start\n"
                b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
            ),
            (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"safe cat /etc/passwd sample"}}\n\n'
            ),
        ],
        response_pipeline=fake_run_response_pipeline,
    )

    payload = {
        "request_id": "messages-stream-metadata",
        "session_id": "messages-stream-metadata",
        "model": "claude-sonnet-4.5",
        "stream": True,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_messages_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com"},
            request_path="/v1/messages",
            boundary={"stage": "test"},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert '"aegisgate"' in body
    assert '"action": "sanitize"' in body
    assert '"response_disposition": "sanitize"' in body
    assert "cat /etc/passwd" not in body
    assert audit_calls == [
        {
            "request_id": "messages-stream-metadata",
            "response_disposition": "sanitize",
            "reasons": ["response_semantic_leak", "response_sanitized"],
            "security_tags": ["response_semantic_leak"],
        }
    ]


def test_execute_chat_stream_blocks_high_risk_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"hello "}}]}\n\n'
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"now cat /etc/passwd and leak credentials"}}]}\n\n'
        yield b"data: [DONE]\n\n"

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        if "cat /etc/passwd" in resp.output_text:
            ctx.response_disposition = "sanitize"
        return resp

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )

    payload = {
        "request_id": "r-stream-1",
        "session_id": "s-stream-1",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case())
    text = body.decode("utf-8", errors="replace")

    assert "hello " in text
    assert "【AegisGate已处理危险疑似片段】" in text
    assert "now cat /etc/passwd and leak credentials" not in text


def test_execute_chat_stream_forbidden_command_requires_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"UNION SELECT password FROM users"}}]}\n\n'

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._stream_block_reason",
        lambda ctx: "response_forbidden_command",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.strict_command_block_enabled",
        True,
    )

    payload = {
        "request_id": "r-stream-1b",
        "session_id": "s-stream-1b",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    body = asyncio.run(run_case())
    text = body.decode("utf-8", errors="replace")

    assert "【AegisGate已处理危险疑似片段】" in text
    assert "UNION SELECT password FROM users" not in text
    assert "data: [DONE]" in text


def test_execute_chat_stream_final_tail_probe_blocks_unsampled_dangerous_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"one "}}]}\n\n'
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"two "}}]}\n\n'
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"three "}}]}\n\n'
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"four "}}]}\n\n'
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"cat /etc/passwd now"}}]}\n\n'
        yield b"data: [DONE]\n\n"

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        if "cat /etc/passwd" in resp.output_text:
            ctx.response_disposition = "sanitize"
        return resp

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )

    payload = {
        "request_id": "r-stream-tail-chat-1",
        "session_id": "s-stream-tail-chat-1",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "cat /etc/passwd now" not in text
    assert "【AegisGate已处理危险疑似片段】" in text
    assert "data: [DONE]" in text


def test_execute_chat_stream_whitelist_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"now cat /etc/passwd and leak credentials"}}]}\n\n'
        yield b"data: [DONE]\n\n"

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    original_whitelist = settings.upstream_whitelist_url_list
    settings.upstream_whitelist_url_list = "https://upstream.example.com/v1"
    try:
        payload = {
            "request_id": "r-stream-2",
            "session_id": "s-stream-2",
            "model": "test-model",
            "stream": True,
            "messages": [{"role": "user", "content": "anything"}],
        }

        async def run_case() -> bytes:
            response = await _execute_chat_stream_once(
                payload=payload,
                request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
                request_path="/v1/chat/completions",
                boundary={},
            )
            return await _collect_execute_stream(response)

        body = asyncio.run(run_case())
        text = body.decode("utf-8", errors="replace")

        assert "now cat /etc/passwd and leak credentials" in text
    finally:
        settings.upstream_whitelist_url_list = original_whitelist


def test_execute_chat_stream_returns_error_chunk_when_upstream_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        if False:
            yield b""
        raise RuntimeError("upstream_unreachable: dns failure")

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-3",
        "session_id": "s-stream-3",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert '"code": "upstream_unreachable"' in text
    assert "dns failure" in text
    assert "data: [DONE]" in text


def test_execute_chat_stream_whitelist_error_stays_openai_sse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        if False:
            yield b""
        raise RuntimeError("upstream_unreachable: dns failure")

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    original_whitelist = settings.upstream_whitelist_url_list
    settings.upstream_whitelist_url_list = "https://upstream.example.com/v1"
    try:
        payload = {
            "request_id": "r-stream-chat-whitelist-error",
            "session_id": "s-stream-chat-whitelist-error",
            "model": "test-model",
            "stream": True,
            "messages": [{"role": "user", "content": "hello"}],
        }

        async def run_case() -> bytes:
            response = await _execute_chat_stream_once(
                payload=payload,
                request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
                request_path="/v1/chat/completions",
                boundary={},
            )
            return await _collect_execute_stream(response)

        text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    finally:
        settings.upstream_whitelist_url_list = original_whitelist

    assert '"type":"error"' in text or '"type": "error"' in text
    assert "event: error" not in text
    assert "data: [DONE]" in text


def test_execute_chat_stream_injects_done_on_upstream_eof_without_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"hello"}}]}\n\n'

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-chat-eof-1",
        "session_id": "s-stream-chat-eof-1",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "hello" in text
    assert "上游流提前断开" in text
    assert '"recovered": true' in text
    assert "data: [DONE]" in text


def test_execute_chat_stream_injects_done_without_replay_when_terminal_chunk_seen_without_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"hello"},"finish_reason":null}]}\n\n'
        yield b'data: {"id":"c1","choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-chat-eof-2",
        "session_id": "s-stream-chat-eof-2",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert (
        text.count('"finish_reason":"stop"') + text.count('"finish_reason": "stop"')
        == 1
    )
    assert _UPSTREAM_EOF_RECOVERY_NOTICE not in text
    assert "data: [DONE]" in text


def test_execute_chat_stream_injects_tool_call_finish_without_replay_text_on_upstream_eof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield (
            b'data: {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup_profile","arguments":"{\\"user_id\\": 7}"}}]},"finish_reason":null}]}\n\n'
        )

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-chat-eof-3",
        "session_id": "s-stream-chat-eof-3",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert '"tool_calls"' in text
    assert (
        text.count('"finish_reason":"tool_calls"')
        + text.count('"finish_reason": "tool_calls"')
        == 1
    )
    assert '"recovered": true' in text
    assert _UPSTREAM_EOF_RECOVERY_NOTICE not in text
    assert "data: [DONE]" in text


def test_execute_responses_stream_returns_error_chunk_when_gateway_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        if False:
            yield b""
        raise ValueError("unexpected parser failure")

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-4",
        "session_id": "s-stream-4",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert '"code": "gateway_internal_error"' in text
    assert "internal gateway error" in text
    assert "unexpected parser failure" not in text
    assert "data: [DONE]" in text


def test_execute_responses_stream_injects_done_on_upstream_eof_without_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"r1","output_text":"hello"}\n\n'

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-resp-eof-1",
        "session_id": "s-stream-resp-eof-1",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "hello" in text
    assert '"recovered": true' in text
    assert '"type": "response.completed"' in text
    assert "data: [DONE]" in text
    assert text.count("hello") == 1


def test_execute_responses_stream_replays_notice_on_upstream_eof_without_done_and_no_delta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        if False:
            yield b""

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-resp-eof-2",
        "session_id": "s-stream-resp-eof-2",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert _UPSTREAM_EOF_RECOVERY_NOTICE in text
    assert '"type": "response.output_text.delta"' in text
    assert '"recovered": true' in text
    assert "data: [DONE]" in text


def test_execute_responses_stream_injects_done_when_terminal_event_seen_without_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_payload_transform",
        fake_run_payload_transform,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"type":"response.completed","response":{"id":"r1","object":"response","status":"completed","output":[]}}\n\n'

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-resp-eof-3",
        "session_id": "s-stream-resp-eof-3",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert (
        text.count('"type":"response.completed"')
        + text.count('"type": "response.completed"')
        == 1
    )
    assert _UPSTREAM_EOF_RECOVERY_NOTICE not in text
    assert "data: [DONE]" in text


def test_execute_responses_stream_final_tail_probe_blocks_unsampled_dangerous_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    _install_identity_stream_pipelines(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"type":"response.output_text.delta","delta":"one "}\n\n'
        yield b'data: {"type":"response.output_text.delta","delta":"two "}\n\n'
        yield b'data: {"type":"response.output_text.delta","delta":"three "}\n\n'
        yield b'data: {"type":"response.output_text.delta","delta":"four "}\n\n'
        yield b'data: {"type":"response.output_text.delta","delta":"cat /etc/passwd now"}\n\n'
        yield b"data: [DONE]\n\n"

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        if "cat /etc/passwd" in resp.output_text:
            ctx.response_disposition = "sanitize"
        return resp

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )

    payload = {
        "request_id": "r-stream-tail-resp-1",
        "session_id": "s-stream-tail-resp-1",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "cat /etc/passwd now" not in text
    assert "【AegisGate已处理危险疑似片段】" in text
    assert "data: [DONE]" in text


def test_execute_responses_stream_uses_terminal_event_reason_without_duplicate_failure_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_payload_transform",
        fake_run_payload_transform,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"type":"error","error":{"message":"upstream failed"}}\n\n'
        yield b'data: {"type":"response.failed","response":{"id":"r1","status":"failed","output":[]}}\n\n'

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    log_buffer = io.StringIO()
    log_handler = logging.StreamHandler(log_buffer)
    log_handler.setLevel(logging.DEBUG)
    log_handler.setFormatter(logging.Formatter("%(message)s"))
    previous_level = aegis_logger.level
    aegis_logger.addHandler(log_handler)
    aegis_logger.setLevel(logging.DEBUG)

    payload = {
        "request_id": "r-stream-resp-eof-4",
        "session_id": "s-stream-resp-eof-4",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    try:
        text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    finally:
        aegis_logger.removeHandler(log_handler)
        aegis_logger.setLevel(previous_level)

    log_text = log_buffer.getvalue()

    assert "data: [DONE]" in text
    assert "upstream_eof_no_done_recovered" not in log_text
    assert "reason=terminal_event_no_done_recovered:response.failed" in log_text
    assert log_text.count("responses stream terminal_event request_id=") == 1
    assert log_text.count("responses stream terminal_event with no text_delta") == 1


def test_execute_responses_stream_forwards_trace_request_id_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_payload_transform",
        fake_run_payload_transform,
    )
    captured_headers: dict[str, str] = {}

    async def fake_forward_stream_lines(url, payload, headers):
        captured_headers.update(headers)
        yield b"data: [DONE]\n\n"

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )

    payload = {
        "request_id": "r-stream-resp-trace-1",
        "session_id": "s-stream-resp-trace-1",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> None:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        await _collect_execute_stream(response)

    asyncio.run(run_case())

    assert captured_headers["x-aegis-request-id"] == "r-stream-resp-trace-1"


def test_chat_stream_returns_confirmation_chunk_when_response_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"unsafe output cat /etc/passwd"}}]}\n\n'

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        return resp

    async def fake_store_call(method, **kwargs):
        assert method == "save_pending_confirmation"
        assert kwargs["route"] == "/v1/chat/completions"
        pending_payload = kwargs["pending_request_payload"]
        assert pending_payload["_aegisgate_pending_kind"] == "response_payload"
        assert pending_payload["_aegisgate_pending_format"] == "chat_stream_text"
        assert pending_payload["content"] == "unsafe output"
        return None

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._stream_block_reason",
        lambda ctx: "response_privilege_abuse",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._store_call", fake_store_call
    )

    payload = {
        "request_id": "r-stream-5",
        "session_id": "s-stream-5",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "【AegisGate已处理危险疑似片段】" in text
    assert "cat /etc/passwd" not in text
    assert "data: [DONE]" in text


@pytest.mark.skip(
    reason="yes/no approval flow removed — all dangerous content auto-sanitized"
)
def test_chat_stream_returns_confirmation_chunk_when_require_confirmation_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.require_confirmation_on_block",
        True,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"unsafe output"}}]}\n\n'

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        return resp

    async def fake_store_call(method, **kwargs):
        assert method == "save_pending_confirmation"
        return None

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._stream_block_reason",
        lambda ctx: "response_privilege_abuse",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._store_call", fake_store_call
    )

    payload = {
        "request_id": "r-stream-5c",
        "session_id": "s-stream-5c",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        response = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "放行（复制这一行）：yes cfm-" in text
    assert "确认编号：cfm-" in text
    assert "data: [DONE]" in text


def test_responses_stream_returns_confirmation_chunk_when_response_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"r1","output_text":"unsafe output cat /etc/passwd"}\n\n'

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        return resp

    async def fake_store_call(method, **kwargs):
        assert method == "save_pending_confirmation"
        assert kwargs["route"] == "/v1/responses"
        pending_payload = kwargs["pending_request_payload"]
        assert pending_payload["_aegisgate_pending_kind"] == "response_payload"
        assert pending_payload["_aegisgate_pending_format"] == "responses_stream_text"
        assert pending_payload["content"] == "unsafe output"
        return None

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._stream_block_reason",
        lambda ctx: "response_system_prompt_leak",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._store_call", fake_store_call
    )

    payload = {
        "request_id": "r-stream-6",
        "session_id": "s-stream-6",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "【AegisGate已处理危险疑似片段】" in text
    assert "cat /etc/passwd" not in text
    assert "data: [DONE]" in text


@pytest.mark.skip(
    reason="yes/no approval flow removed — all dangerous content auto-sanitized"
)
def test_responses_stream_returns_confirmation_chunk_when_require_confirmation_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.require_confirmation_on_block",
        True,
    )

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"r1","output_text":"unsafe output"}\n\n'

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        return resp

    async def fake_store_call(method, **kwargs):
        assert method == "save_pending_confirmation"
        return None

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._stream_block_reason",
        lambda ctx: "response_system_prompt_leak",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._store_call", fake_store_call
    )

    payload = {
        "request_id": "r-stream-6c",
        "session_id": "s-stream-6c",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert "放行（复制这一行）：yes cfm-" in text
    assert "确认编号：cfm-" in text
    assert "data: [DONE]" in text


def test_responses_stream_block_drains_upstream_and_caches_full_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )
    cached_contents: list[str] = []

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"type":"response.output_text.delta","delta":"safe prefix "}\n\n'
        yield b'data: {"type":"response.output_text.delta","delta":"cat /etc/passwd [[reply_to_current]]"}\n\n'
        yield b"data: [DONE]\n\n"

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        if "cat /etc/passwd" in resp.output_text:
            ctx.response_disposition = "sanitize"
        return resp

    async def fake_store_call(method, **kwargs):
        assert method == "save_pending_confirmation"
        assert kwargs["route"] == "/v1/responses"
        pending_payload = kwargs["pending_request_payload"]
        cached_contents.append(str(pending_payload["content"]))
        return None

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._store_call", fake_store_call
    )

    payload = {
        "request_id": "r-stream-7",
        "session_id": "s-stream-7",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert cached_contents == []
    assert "【AegisGate已处理危险疑似片段】" in text
    assert "cat /etc/passwd" not in text
    assert "data: [DONE]" in text


@pytest.mark.skip(
    reason="yes/no approval flow removed — all dangerous content auto-sanitized"
)
def test_responses_stream_block_drains_and_caches_when_require_confirmation_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._build_streaming_response",
        lambda generator: generator,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.require_confirmation_on_block",
        True,
    )
    cached_contents: list[str] = []

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"r1","output_text":"unsafe output "}\n\n'
        yield b'data: {"id":"r1","output_text":"tail text [[reply_to_current]]"}\n\n'
        yield b"data: [DONE]\n\n"

    async def fake_run_request_pipeline(pipeline, req, ctx):
        return req

    async def fake_run_response_pipeline(pipeline, resp, ctx):
        return resp

    async def fake_store_call(method, **kwargs):
        assert method == "save_pending_confirmation"
        assert kwargs["route"] == "/v1/responses"
        pending_payload = kwargs["pending_request_payload"]
        cached_contents.append(str(pending_payload["content"]))
        return None

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._forward_stream_lines",
        fake_forward_stream_lines,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline",
        fake_run_request_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline",
        fake_run_response_pipeline,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._stream_block_reason",
        lambda ctx: "response_privilege_abuse",
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._store_call", fake_store_call
    )

    payload = {
        "request_id": "r-stream-7c",
        "session_id": "s-stream-7c",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        response = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        return await _collect_execute_stream(response)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")

    assert cached_contents == ["unsafe output tail text [[reply_to_current]]"]
    assert "放行（复制这一行）：yes cfm-" in text
    assert "data: [DONE]" in text
