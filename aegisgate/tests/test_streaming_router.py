import asyncio
from collections.abc import AsyncGenerator

from aegisgate.adapters.openai_compat.router import (
    _execute_chat_stream_once,
    _extract_sse_data_payload,
    _stream_block_reason,
    _stream_block_sse_chunk,
)
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext


def test_extract_sse_data_payload():
    assert _extract_sse_data_payload(b"data: [DONE]\n\n") == "[DONE]"
    assert _extract_sse_data_payload(b"event: message\n") is None


def test_stream_block_reason_uses_response_disposition_first():
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions")
    ctx.response_disposition = "sanitize"
    assert _stream_block_reason(ctx) == "response_sanitized"


def test_stream_block_sse_chunk_for_responses_route():
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/responses")
    chunk = _stream_block_sse_chunk(ctx, "test-model", "response_high_risk", "/v1/responses")
    payload = chunk.decode("utf-8")
    assert '"object": "response.chunk"' in payload
    assert "response_high_risk" in payload


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
