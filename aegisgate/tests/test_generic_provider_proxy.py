import json

import pytest
from starlette.requests import Request

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.config.settings import settings


def _build_request(headers: dict[str, str] | None = None, path: str = "/v1/messages") -> Request:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
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
        assert body["error"] == "invalid_parameters"
    finally:
        settings.enforce_loopback_only = original_loopback
