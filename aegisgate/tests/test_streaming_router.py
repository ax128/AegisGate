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
    _execute_responses_stream_once,
    _extract_sse_data_payload,
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
from aegisgate.util.logger import logger as aegis_logger


def _to_bytes(value: bytes | str | memoryview[int]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return value.tobytes()


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


def test_execute_chat_stream_blocks_high_risk_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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


def test_execute_chat_stream_whitelist_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_execute_chat_stream_injects_done_on_upstream_eof_without_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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


def test_execute_responses_stream_returns_error_chunk_when_gateway_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    assert "unexpected parser failure" in text
    assert "data: [DONE]" in text


def test_execute_responses_stream_injects_done_on_upstream_eof_without_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
