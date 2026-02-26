import json

import pytest
from starlette.requests import Request

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.config.settings import settings


def _build_request(
    headers: dict[str, str] | None = None,
    path: str = "/v1/messages",
    query_string: str = "",
) -> Request:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": query_string.encode("latin-1"),
        "headers": raw_headers,
        "client": ("127.0.0.1", 54321),
        "server": ("testserver", 80),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    request.state.security_boundary = {}
    return request


@pytest.mark.asyncio
async def test_generic_provider_proxy_forwards_claude_style_payload(monkeypatch):
    captured: dict[str, str] = {}

    async def fake_forward_json(url, payload, headers):
        captured["url"] = url
        return 200, {
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "hello"}],
        }

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)
    original_loopback = settings.enforce_loopback_only
    try:
        settings.enforce_loopback_only = False
        request = _build_request(
            headers={
                "X-Upstream-Base": "https://upstream.example.com/v1",
                "gateway-key": settings.gateway_key,
            }
        )
        response = await openai_router.generic_provider_proxy(
            "messages",
            {
                "model": "generic-model",
                "messages": [{"role": "user", "content": "hi"}],
            },
            request,
        )
        assert response.status_code == 200
        body = json.loads(response.body.decode("utf-8"))
        assert body["type"] == "message"
        assert captured["url"] == "https://upstream.example.com/v1/messages"
    finally:
        settings.enforce_loopback_only = original_loopback


@pytest.mark.asyncio
async def test_generic_provider_proxy_requires_gateway_headers():
    original_loopback = settings.enforce_loopback_only
    try:
        settings.enforce_loopback_only = False
        request = _build_request(headers={})
        response = await openai_router.generic_provider_proxy("messages", {"model": "generic-model"}, request)
        assert response.status_code == 400
        body = json.loads(response.body.decode("utf-8"))
        assert body["error"]["code"] == "invalid_parameters"
        assert "missing" in body["error"]["message"].lower()
    finally:
        settings.enforce_loopback_only = original_loopback


@pytest.mark.asyncio
async def test_generic_provider_proxy_preserves_query_string(monkeypatch):
    captured: dict[str, str] = {}

    async def fake_forward_json(url, payload, headers):
        captured["url"] = url
        return 200, {"ok": True}

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)
    original_loopback = settings.enforce_loopback_only
    try:
        settings.enforce_loopback_only = False
        request = _build_request(
            path="/v1/messages",
            query_string="anthropic-version=2023-06-01",
            headers={
                "X-Upstream-Base": "https://upstream.example.com/v1",
                "gateway-key": settings.gateway_key,
            },
        )
        response = await openai_router.generic_provider_proxy(
            "messages",
            {"model": "claude-3-5-sonnet-latest", "messages": [{"role": "user", "content": "hi"}]},
            request,
        )
        assert response.status_code == 200
        assert captured["url"] == "https://upstream.example.com/v1/messages?anthropic-version=2023-06-01"
    finally:
        settings.enforce_loopback_only = original_loopback


@pytest.mark.asyncio
async def test_generic_provider_proxy_streaming_for_claude_payload(monkeypatch):
    async def fake_forward_stream_lines(url, payload, headers):
        yield b'event: content_block_delta\n'
        yield b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}\n\n'
        yield b'event: message_stop\n'
        yield b'data: {"type":"message_stop"}\n\n'

    monkeypatch.setattr(openai_router, "_forward_stream_lines", fake_forward_stream_lines)
    original_loopback = settings.enforce_loopback_only
    try:
        settings.enforce_loopback_only = False
        request = _build_request(
            headers={
                "X-Upstream-Base": "https://upstream.example.com/v1",
                "gateway-key": settings.gateway_key,
            }
        )
        response = await openai_router.generic_provider_proxy(
            "messages",
            {
                "model": "claude-3-5-sonnet-latest",
                "stream": True,
                "messages": [{"role": "user", "content": "hello"}],
            },
            request,
        )
        assert response.status_code == 200
        chunks: list[bytes] = []
        async for chunk in response.body_iterator:
            chunks.append(chunk)
        body = b"".join(chunks)
        assert b"content_block_delta" in body
        assert b"message_stop" in body
    finally:
        settings.enforce_loopback_only = original_loopback


@pytest.mark.asyncio
async def test_generic_provider_proxy_streaming_returns_error_chunk_when_upstream_fails(monkeypatch):
    monkeypatch.setattr("aegisgate.adapters.openai_compat.router._build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        if False:  # pragma: no cover - keeps async generator type
            yield b""
        raise RuntimeError("upstream_unreachable: dns resolution failed")

    monkeypatch.setattr(openai_router, "_forward_stream_lines", fake_forward_stream_lines)
    original_loopback = settings.enforce_loopback_only
    try:
        settings.enforce_loopback_only = False
        request = _build_request(
            headers={
                "X-Upstream-Base": "https://upstream.example.com/v1",
                "gateway-key": settings.gateway_key,
            }
        )
        response = await openai_router.generic_provider_proxy(
            "messages",
            {
                "model": "claude-3-5-sonnet-latest",
                "stream": True,
                "messages": [{"role": "user", "content": "hello"}],
            },
            request,
        )
        assert hasattr(response, "__aiter__")
        chunks: list[bytes] = []
        async for chunk in response:
            chunks.append(chunk)
        body = b"".join(chunks).decode("utf-8", errors="replace")
        assert '"code": "upstream_unreachable"' in body
        assert "dns resolution failed" in body
        assert "data: [DONE]" in body
    finally:
        settings.enforce_loopback_only = original_loopback
