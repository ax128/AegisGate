import json

import pytest
from starlette.requests import Request

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.config.settings import settings


def _build_request(headers: dict[str, str] | None = None, path: str = "/v1/chat/completions") -> Request:
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
async def test_chat_completions_returns_structured_error_when_upstream_unreachable(monkeypatch):
    async def fake_forward_json(url, payload, headers):
        raise RuntimeError("upstream_unreachable: dns lookup failed")

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)
    original_loopback = settings.enforce_loopback_only
    try:
        settings.enforce_loopback_only = False
        request = _build_request(
            headers={
                "X-Upstream-Base": "https://upstream.example.com/v1",
                "gateway-key": settings.gateway_key,
            },
            path="/v1/chat/completions",
        )
        response = await openai_router.chat_completions(
            {
                "request_id": "chat-error-1",
                "session_id": "s1",
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "hello"}],
            },
            request,
        )
        assert response.status_code == 502
        body = json.loads(response.body.decode("utf-8"))
        assert body["error"]["code"] == "upstream_unreachable"
        assert "dns lookup failed" in body["error"]["message"]
    finally:
        settings.enforce_loopback_only = original_loopback


@pytest.mark.asyncio
async def test_responses_returns_structured_error_when_upstream_unreachable(monkeypatch):
    async def fake_forward_json(url, payload, headers):
        raise RuntimeError("upstream_unreachable: dns lookup failed")

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)
    original_loopback = settings.enforce_loopback_only
    try:
        settings.enforce_loopback_only = False
        request = _build_request(
            headers={
                "X-Upstream-Base": "https://upstream.example.com/v1",
                "gateway-key": settings.gateway_key,
            },
            path="/v1/responses",
        )
        response = await openai_router.responses(
            {
                "request_id": "responses-error-1",
                "session_id": "s1",
                "model": "gpt-test",
                "input": "hello",
            },
            request,
        )
        assert response.status_code == 502
        body = json.loads(response.body.decode("utf-8"))
        assert body["error"]["code"] == "upstream_unreachable"
        assert "dns lookup failed" in body["error"]["message"]
    finally:
        settings.enforce_loopback_only = original_loopback
