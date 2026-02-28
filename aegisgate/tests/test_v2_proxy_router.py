import json
import logging

import httpx
import pytest
from starlette.requests import Request

from aegisgate.adapters.v2_proxy import router as v2_router
from aegisgate.config.settings import settings


def _build_request(
    *,
    path: str = "/v2/proxy",
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> Request:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 54321),
        "server": ("testserver", 80),
        "aegis_token_authenticated": True,
    }
    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


@pytest.mark.asyncio
async def test_v2_proxy_redacts_request_body_before_forward(monkeypatch):
    captured: dict[str, object] = {}

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["content"] = content
            return httpx.Response(
                status_code=200,
                content=b'{"ok":true}',
                headers={"content-type": "application/json"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_redaction = settings.v2_enable_request_redaction
    settings.v2_enable_request_redaction = True
    try:
        body = json.dumps({"api_key": "sk-abcdeABCDE1234567890xyz"}).encode("utf-8")
        request = _build_request(
            headers={
                "content-type": "application/json",
                "x-original-url": "https://upstream.example.com/path",
            },
            body=body,
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_request_redaction = original_redaction

    assert response.status_code == 200
    assert captured["method"] == "POST"
    assert captured["url"] == "https://upstream.example.com/path"
    forwarded = json.loads((captured["content"] or b"{}").decode("utf-8"))
    assert forwarded["api_key"] != "sk-abcdeABCDE1234567890xyz"
    assert str(forwarded["api_key"]).startswith("[REDACTED:")


@pytest.mark.asyncio
async def test_v2_proxy_blocks_dangerous_response_command(monkeypatch):
    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content="payload probe: UNION SELECT username, password FROM users".encode("utf-8"),
                headers={"content-type": "text/plain; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    settings.v2_enable_response_command_filter = True
    try:
        request = _build_request(
            headers={"x-original-url": "https://upstream.example.com/path"},
            body=b"{}",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter

    assert response.status_code == 403
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["error"]["code"] == "v2_response_http_attack_blocked"
    assert "该请求已被安全网关拦截" in payload["error"]["message"]
    assert payload["error"]["details"]
    assert payload["aegisgate_v2"]["matched_rules"]


@pytest.mark.asyncio
async def test_v2_proxy_can_disable_response_command_filter(monkeypatch):
    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content="UNION SELECT credit_card FROM payment_cards".encode("utf-8"),
                headers={"content-type": "text/plain; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    settings.v2_enable_response_command_filter = False
    try:
        request = _build_request(
            headers={"x-original-url": "https://upstream.example.com/path"},
            body=b"{}",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter

    assert response.status_code == 200
    assert response.body == b"UNION SELECT credit_card FROM payment_cards"


@pytest.mark.asyncio
async def test_v2_proxy_does_not_block_docker_text_when_http_attack_filter_enabled(monkeypatch):
    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content="docker compose logs -f web".encode("utf-8"),
                headers={"content-type": "text/plain; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    settings.v2_enable_response_command_filter = True
    try:
        request = _build_request(
            headers={"x-original-url": "https://upstream.example.com/path"},
            body=b"{}",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter

    assert response.status_code == 200
    assert response.body == b"docker compose logs -f web"


@pytest.mark.asyncio
async def test_v2_proxy_requires_original_url_header():
    request = _build_request(headers={}, body=b"{}")
    response = await v2_router.proxy_v2(request)
    assert response.status_code == 400
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["error"]["code"] == "invalid_original_url_header"


@pytest.mark.asyncio
async def test_v2_proxy_accepts_x_target_url_header(monkeypatch):
    captured: dict[str, object] = {}

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            captured["url"] = url
            return httpx.Response(
                status_code=200,
                content=b"ok",
                headers={"content-type": "text/plain; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    request = _build_request(
        headers={"x-target-url": "https://upstream.example.com/path"},
        body=b"{}",
    )
    response = await v2_router.proxy_v2(request)
    assert response.status_code == 200
    assert captured["url"] == "https://upstream.example.com/path"


@pytest.mark.asyncio
async def test_v2_proxy_logs_request_body_when_debug_and_flag_enabled(monkeypatch):
    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content=b'{"ok":true}',
                headers={"content-type": "application/json"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    monkeypatch.setattr(v2_router.logger, "isEnabledFor", lambda level: level <= logging.DEBUG)
    debug_messages: list[str] = []

    def _capture_debug(msg: str, *args, **kwargs):
        rendered = msg % args if args else msg
        debug_messages.append(rendered)

    monkeypatch.setattr(v2_router.logger, "debug", _capture_debug)
    original_log_full = settings.log_full_request_body
    settings.log_full_request_body = True

    try:
        request = _build_request(
            headers={
                "content-type": "application/json",
                "x-target-url": "https://upstream.example.com/path",
            },
            body=b'{"message":"hello-v2-debug"}',
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.log_full_request_body = original_log_full

    assert response.status_code == 200
    assert any("incoming v2 request body" in message for message in debug_messages)
    assert any("hello-v2-debug" in message for message in debug_messages)
