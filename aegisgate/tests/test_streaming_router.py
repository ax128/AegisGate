import asyncio
from collections.abc import AsyncGenerator

from aegisgate.adapters.openai_compat.router import (
    _execute_chat_stream_once,
    _execute_responses_stream_once,
    _extract_sse_data_payload,
    _stream_block_reason,
    _stream_block_sse_chunk,
)
from aegisgate.adapters.openai_compat.stream_utils import _extract_stream_text_from_event, _stream_error_sse_chunk
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext


def test_extract_sse_data_payload():
    assert _extract_sse_data_payload(b"data: [DONE]\n\n") == "[DONE]"
    assert _extract_sse_data_payload(b"event: message\n") is None


def test_stream_block_reason_uses_response_disposition_first():
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions")
    ctx.response_disposition = "sanitize"
    assert _stream_block_reason(ctx) == "response_sanitized"


def test_stream_block_reason_high_risk_command_tag_requires_confirmation():
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions")
    ctx.security_tags.add("response_anomaly_high_risk_command")
    assert _stream_block_reason(ctx) == "response_high_risk_command"


def test_stream_block_sse_chunk_for_responses_route():
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/responses")
    chunk = _stream_block_sse_chunk(ctx, "test-model", "response_high_risk", "/v1/responses")
    payload = chunk.decode("utf-8")
    assert '"object": "response.chunk"' in payload
    assert "response_high_risk" in payload


def test_stream_error_sse_chunk_uses_structured_error_payload():
    payload = _stream_error_sse_chunk("upstream_unreachable: dns", code="upstream_unreachable").decode("utf-8")
    assert '"type": "error"' in payload
    assert '"code": "upstream_unreachable"' in payload
    assert "dns" in payload


def test_extract_stream_text_from_responses_delta_only():
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


def test_execute_chat_stream_blocks_high_risk_chunk(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"hello "}}]}\n\n'
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"please run shell bash command now"}}]}\n\n'
        yield b"data: [DONE]\n\n"

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)

    payload = {
        "request_id": "r-stream-1",
        "session_id": "s-stream-1",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }
    async def run_case() -> bytes:
        resp = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        assert hasattr(resp, "__aiter__")
        out: list[bytes] = []
        async for chunk in resp:
            out.append(chunk)
        return b"".join(out)

    body = asyncio.run(run_case())
    text = body.decode("utf-8", errors="replace")

    assert "hello " in text
    assert "response_privilege_abuse" in text
    assert "please run shell bash command now" not in text


def test_execute_chat_stream_whitelist_bypass(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"please run shell bash command now"}}]}\n\n'
        yield b"data: [DONE]\n\n"

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)
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
            resp = await _execute_chat_stream_once(
                payload=payload,
                request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
                request_path="/v1/chat/completions",
                boundary={},
            )
            assert isinstance(resp, AsyncGenerator)
            out: list[bytes] = []
            async for chunk in resp:
                out.append(chunk)
            return b"".join(out)

        body = asyncio.run(run_case())
        text = body.decode("utf-8", errors="replace")
        assert "please run shell bash command now" in text
    finally:
        settings.upstream_whitelist_url_list = original_whitelist


def test_execute_chat_stream_returns_error_chunk_when_upstream_runtime_error(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        if False:  # pragma: no cover - keeps async generator type
            yield b""
        raise RuntimeError("upstream_unreachable: dns failure")

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)

    payload = {
        "request_id": "r-stream-3",
        "session_id": "s-stream-3",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        resp = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        out: list[bytes] = []
        async for chunk in resp:
            out.append(chunk)
        return b"".join(out)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    assert '"code": "upstream_unreachable"' in text
    assert "dns failure" in text
    assert "data: [DONE]" in text


def test_execute_chat_stream_injects_done_on_upstream_eof_without_done(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"hello"}}]}\n\n'

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)

    payload = {
        "request_id": "r-stream-chat-eof-1",
        "session_id": "s-stream-chat-eof-1",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        resp = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        out: list[bytes] = []
        async for chunk in resp:
            out.append(chunk)
        return b"".join(out)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    assert "hello" in text
    assert "上游流提前断开" in text
    assert '"recovered": true' in text
    assert "data: [DONE]" in text


def test_execute_responses_stream_returns_error_chunk_when_gateway_internal_error(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        if False:  # pragma: no cover - keeps async generator type
            yield b""
        raise ValueError("unexpected parser failure")

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)

    payload = {
        "request_id": "r-stream-4",
        "session_id": "s-stream-4",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        resp = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        out: list[bytes] = []
        async for chunk in resp:
            out.append(chunk)
        return b"".join(out)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    assert '"code": "gateway_internal_error"' in text
    assert "unexpected parser failure" in text
    assert "data: [DONE]" in text


def test_execute_responses_stream_injects_done_on_upstream_eof_without_done(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"r1","output_text":"hello"}\n\n'

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)

    payload = {
        "request_id": "r-stream-resp-eof-1",
        "session_id": "s-stream-resp-eof-1",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        resp = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        out: list[bytes] = []
        async for chunk in resp:
            out.append(chunk)
        return b"".join(out)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    assert "hello" in text
    assert '"recovered": true' in text
    assert '"type": "response.completed"' in text
    assert "data: [DONE]" in text
    assert text.count("hello") == 1


def test_chat_stream_returns_confirmation_chunk_when_response_blocked(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"c1","choices":[{"delta":{"content":"unsafe output"}}]}\n\n'

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

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._run_request_pipeline", fake_run_request_pipeline)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._run_response_pipeline", fake_run_response_pipeline)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._stream_block_reason", lambda ctx: "response_privilege_abuse")
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._store_call", fake_store_call)

    payload = {
        "request_id": "r-stream-5",
        "session_id": "s-stream-5",
        "model": "test-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
    }

    async def run_case() -> bytes:
        resp = await _execute_chat_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/chat/completions",
            boundary={},
        )
        out: list[bytes] = []
        async for chunk in resp:
            out.append(chunk)
        return b"".join(out)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    assert "放行（复制这一行）：yes cfm-" in text
    assert "确认编号：cfm-" in text
    assert "data: [DONE]" in text


def test_responses_stream_returns_confirmation_chunk_when_response_blocked(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"r1","output_text":"unsafe output"}\n\n'

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

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._run_request_pipeline", fake_run_request_pipeline)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._run_response_pipeline", fake_run_response_pipeline)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._stream_block_reason", lambda ctx: "response_system_prompt_leak")
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._store_call", fake_store_call)

    payload = {
        "request_id": "r-stream-6",
        "session_id": "s-stream-6",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        resp = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        out: list[bytes] = []
        async for chunk in resp:
            out.append(chunk)
        return b"".join(out)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    assert "放行（复制这一行）：yes cfm-" in text
    assert "确认编号：cfm-" in text
    assert "data: [DONE]" in text


def test_responses_stream_block_drains_upstream_and_caches_full_text(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)
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

    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._forward_stream_lines", fake_forward_stream_lines)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._run_request_pipeline", fake_run_request_pipeline)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._run_response_pipeline", fake_run_response_pipeline)
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._stream_block_reason", lambda ctx: "response_privilege_abuse")
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._store_call", fake_store_call)

    payload = {
        "request_id": "r-stream-7",
        "session_id": "s-stream-7",
        "model": "test-model",
        "stream": True,
        "input": "hello",
    }

    async def run_case() -> bytes:
        resp = await _execute_responses_stream_once(
            payload=payload,
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
        out: list[bytes] = []
        async for chunk in resp:
            out.append(chunk)
        return b"".join(out)

    text = asyncio.run(run_case()).decode("utf-8", errors="replace")
    assert cached_contents == ["unsafe output tail text [[reply_to_current]]"]
    assert "放行（复制这一行）：yes cfm-" in text
    assert "data: [DONE]" in text
