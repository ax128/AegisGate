import asyncio
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
    raw_headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
) -> Request:
    encoded_headers: list[tuple[bytes, bytes]] = []
    if headers:
        encoded_headers.extend((k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items())
    if raw_headers:
        encoded_headers.extend((k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in raw_headers)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": encoded_headers,
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
                "x-target-url": "https://upstream.example.com/path",
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
async def test_v2_proxy_redaction_keeps_encrypted_and_ip_content(monkeypatch):
    captured: dict[str, object] = {}

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
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
        token = "sk-abcdeABCDE1234567890xyz"
        encrypted_blob = "9xQeWvG816bUx9EPjHmaT23yvVMZbrrpQ9e3Qk6nQJ2J"
        body = json.dumps(
            {
                "encrypted_content": encrypted_blob,
                "output": f"node=2001:db8::1 token={token}",
            }
        ).encode("utf-8")
        request = _build_request(
            headers={
                "content-type": "application/json",
                "x-target-url": "https://upstream.example.com/path",
            },
            body=body,
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_request_redaction = original_redaction

    assert response.status_code == 200
    forwarded = json.loads((captured["content"] or b"{}").decode("utf-8"))
    assert forwarded["encrypted_content"] == encrypted_blob
    assert "2001:db8::1" in str(forwarded["output"])
    assert token not in str(forwarded["output"])
    assert "[REDACTED:" in str(forwarded["output"])


@pytest.mark.asyncio
async def test_v2_proxy_redaction_text_body_does_not_replace_ip(monkeypatch):
    captured: dict[str, object] = {}

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
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
        token = "sk-abcdeABCDE1234567890xyz"
        body = f"ip=2001:db8::1 token={token}".encode("utf-8")
        request = _build_request(
            headers={
                "content-type": "text/plain; charset=utf-8",
                "x-target-url": "https://upstream.example.com/path",
            },
            body=body,
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_request_redaction = original_redaction

    assert response.status_code == 200
    forwarded = (captured["content"] or b"").decode("utf-8")
    assert "2001:db8::1" in forwarded
    assert token not in forwarded
    assert "[REDACTED:" in forwarded


@pytest.mark.asyncio
async def test_v2_proxy_allows_non_protocol_payload_in_strict_mode(monkeypatch):
    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content="payload probe: UNION SELECT username FROM users && curl http://evil.test".encode("utf-8"),
                headers={"content-type": "text/plain; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    original_obvious_only = settings.v2_response_filter_obvious_only
    settings.v2_enable_response_command_filter = True
    settings.v2_response_filter_obvious_only = False
    try:
        request = _build_request(
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"{}",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter
        settings.v2_response_filter_obvious_only = original_obvious_only

    assert response.status_code == 200
    assert b"UNION SELECT username FROM users" in response.body


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
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"{}",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter

    assert response.status_code == 200
    assert response.body == b"UNION SELECT credit_card FROM payment_cards"


@pytest.mark.asyncio
async def test_v2_proxy_allows_single_low_conf_signal_in_obvious_only_mode(monkeypatch):
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
    original_obvious_only = settings.v2_response_filter_obvious_only
    settings.v2_enable_response_command_filter = True
    settings.v2_response_filter_obvious_only = True
    try:
        request = _build_request(
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter
        settings.v2_response_filter_obvious_only = original_obvious_only

    assert response.status_code == 200
    assert b"UNION SELECT" in response.body


@pytest.mark.asyncio
async def test_v2_proxy_allows_normal_html_with_script_tags(monkeypatch):
    html = b"""<!doctype html>
<html><head><script src="/assets/app.js"></script></head>
<body><h1>ACM Digital Library</h1><script>window.appBoot = true;</script></body></html>"""

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content=html,
                headers={"content-type": "text/html; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    settings.v2_enable_response_command_filter = True
    try:
        request = _build_request(
            method="GET",
            headers={"x-target-url": "https://upstream.example.com/page"},
            body=b"",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter

    assert response.status_code == 200
    assert b"ACM Digital Library" in response.body


@pytest.mark.asyncio
async def test_v2_proxy_allows_xss_payload_in_strict_mode_with_minimal_http_rule_set(monkeypatch):
    xss_html = b"""<html><body>payload:<img src=x onerror=alert(1)></body></html>"""

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content=xss_html,
                headers={"content-type": "text/html; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    original_obvious_only = settings.v2_response_filter_obvious_only
    settings.v2_enable_response_command_filter = True
    settings.v2_response_filter_obvious_only = False
    try:
        request = _build_request(
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter
        settings.v2_response_filter_obvious_only = original_obvious_only

    assert response.status_code == 200
    assert b"onerror=alert(1)" in response.body


@pytest.mark.asyncio
async def test_v2_proxy_allows_onload_fetch_in_obvious_only_mode(monkeypatch):
    html = b"""<html><body onload="fetch('/api/bootstrap')">ok</body></html>"""

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content=html,
                headers={"content-type": "text/html; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    original_obvious_only = settings.v2_response_filter_obvious_only
    settings.v2_enable_response_command_filter = True
    settings.v2_response_filter_obvious_only = True
    try:
        request = _build_request(
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter
        settings.v2_response_filter_obvious_only = original_obvious_only

    assert response.status_code == 200
    assert b"fetch('/api/bootstrap')" in response.body


@pytest.mark.asyncio
async def test_v2_proxy_allows_high_confidence_xss_in_obvious_only_mode(monkeypatch):
    xss_html = b"""<html><body>payload:<img src=x onerror=alert(1)></body></html>"""

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content=xss_html,
                headers={"content-type": "text/html; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    original_obvious_only = settings.v2_response_filter_obvious_only
    settings.v2_enable_response_command_filter = True
    settings.v2_response_filter_obvious_only = True
    try:
        request = _build_request(
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter
        settings.v2_response_filter_obvious_only = original_obvious_only

    assert response.status_code == 200
    assert b"onerror=alert(1)" in response.body


@pytest.mark.asyncio
async def test_v2_proxy_allows_bypassed_host_even_when_xss_rule_matches(monkeypatch):
    xss_html = b"""<html><body>payload:<img src=x onerror=alert(1)></body></html>"""

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content=xss_html,
                headers={"content-type": "text/html; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    original_bypass = settings.v2_response_filter_bypass_hosts
    settings.v2_enable_response_command_filter = True
    settings.v2_response_filter_bypass_hosts = "moltbook.com,.trusted.example"
    try:
        request = _build_request(
            headers={"x-target-url": "https://www.moltbook.com/u/test"},
            body=b"",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter
        settings.v2_response_filter_bypass_hosts = original_bypass

    assert response.status_code == 200
    assert b"payload" in response.body


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
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"{}",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter

    assert response.status_code == 200
    assert response.body == b"docker compose logs -f web"


@pytest.mark.asyncio
async def test_v2_proxy_requires_target_url_header():
    request = _build_request(headers={}, body=b"{}")
    response = await v2_router.proxy_v2(request)
    assert response.status_code == 400
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["error"]["code"] == "missing_target_url_header"


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


@pytest.mark.asyncio
async def test_v2_proxy_passes_request_with_cl_and_te_headers(monkeypatch):
    """请求侧不再做 framing 检测，CL+TE 同时存在的合法请求应能正常透传。"""
    captured: dict[str, object] = {}

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            captured["url"] = url
            return httpx.Response(
                status_code=200,
                content=b"ok",
                headers={"content-type": "text/plain"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    request = _build_request(
        raw_headers=[
            ("x-target-url", "https://upstream.example.com/path"),
            ("content-length", "8"),
            ("transfer-encoding", "chunked"),
        ],
        body=b'{"k":1}',
    )
    response = await v2_router.proxy_v2(request)
    assert response.status_code == 200
    assert captured["url"] == "https://upstream.example.com/path"


@pytest.mark.asyncio
async def test_v2_proxy_passes_response_with_cl_and_te_headers(monkeypatch):
    """响应侧不再做 header 层 framing 检测，CL+TE 并存的 CDN/Nginx 正常响应应能透传。"""

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content=b"safe-body",
                headers=[
                    ("content-type", "text/plain; charset=utf-8"),
                    ("content-length", "9"),
                    ("transfer-encoding", "chunked"),
                ],
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    settings.v2_enable_response_command_filter = True
    try:
        request = _build_request(
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter

    assert response.status_code == 200
    assert response.body == b"safe-body"


@pytest.mark.asyncio
async def test_v2_proxy_blocks_response_smuggling_signature(monkeypatch):
    body = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n\r\n"
    ).encode("utf-8")

    class FakeClient:
        async def request(self, *, method: str, url: str, headers: dict[str, str], content: bytes):
            return httpx.Response(
                status_code=200,
                content=body,
                headers={"content-type": "text/plain; charset=utf-8"},
            )

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    original_filter = settings.v2_enable_response_command_filter
    settings.v2_enable_response_command_filter = True
    try:
        request = _build_request(
            headers={"x-target-url": "https://upstream.example.com/path"},
            body=b"",
        )
        response = await v2_router.proxy_v2(request)
    finally:
        settings.v2_enable_response_command_filter = original_filter

    assert response.status_code == 403
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["error"]["code"] == "v2_response_http_attack_blocked"
    assert any("http_smuggling" in str(rule) for rule in payload["aegisgate_v2"]["matched_rules"])


@pytest.mark.asyncio
async def test_v2_proxy_streaming_injects_done_when_upstream_eof_without_done(monkeypatch):
    class FakeStreamResponse:
        def __init__(self):
            self.status_code = 200
            self.headers = {"content-type": "text/event-stream"}

        async def aiter_bytes(self):
            yield b'data: {"type":"response.output_text.delta","delta":"hello"}\n\n'

    class FakeStreamContext:
        async def __aenter__(self):
            return FakeStreamResponse()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClient:
        def stream(self, method: str, url: str, *, headers: dict[str, str], content: bytes):
            return FakeStreamContext()

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)
    request = _build_request(
        headers={
            "content-type": "application/json",
            "accept": "text/event-stream",
            "x-target-url": "https://upstream.example.com/path",
        },
        body=b'{"stream": true, "input":"hello"}',
    )

    response = await v2_router.proxy_v2(request)
    assert response.status_code == 200
    chunks: list[bytes] = []
    async for chunk in response.body_iterator:
        chunks.append(chunk)
    body = b"".join(chunks).decode("utf-8", errors="replace")
    assert '"response.output_text.delta"' in body
    assert "data: [DONE]" in body


@pytest.mark.asyncio
async def test_v2_proxy_streaming_handles_high_concurrency(monkeypatch):
    class FakeStreamResponse:
        def __init__(self, idx: str):
            self.status_code = 200
            self.headers = {"content-type": "text/event-stream"}
            self._idx = idx

        async def aiter_bytes(self):
            await asyncio.sleep(0)
            yield f'data: {{"type":"response.output_text.delta","delta":"ok-{self._idx}"}}\n\n'.encode("utf-8")
            yield b"data: [DONE]\n\n"

    class FakeStreamContext:
        def __init__(self, idx: str):
            self._response = FakeStreamResponse(idx)

        async def __aenter__(self):
            return self._response

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClient:
        def __init__(self):
            self.inflight = 0
            self.max_inflight = 0
            self._lock = asyncio.Lock()

        def stream(self, method: str, url: str, *, headers: dict[str, str], content: bytes):
            idx = url.rsplit("/", 1)[-1]
            client = self
            base_context = FakeStreamContext(idx)

            class _TrackedContext:
                async def __aenter__(self_inner):
                    async with client._lock:
                        client.inflight += 1
                        client.max_inflight = max(client.max_inflight, client.inflight)
                    return await base_context.__aenter__()

                async def __aexit__(self_inner, exc_type, exc, tb):
                    try:
                        return await base_context.__aexit__(exc_type, exc, tb)
                    finally:
                        async with client._lock:
                            client.inflight = max(0, client.inflight - 1)

            return _TrackedContext()

    fake_client = FakeClient()

    async def fake_get_client():
        return fake_client

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_client)

    async def _one_call(i: int) -> str:
        request = _build_request(
            headers={
                "content-type": "application/json",
                "accept": "text/event-stream",
                "x-target-url": f"https://upstream.example.com/path/{i}",
            },
            body=b'{"stream": true, "input":"hello"}',
        )
        response = await v2_router.proxy_v2(request)
        chunks: list[bytes] = []
        async for chunk in response.body_iterator:
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")

    total = 40
    results = await asyncio.gather(*(_one_call(i) for i in range(total)))
    assert len(results) == total
    for i, body in enumerate(results):
        assert f"ok-{i}" in body
        assert "data: [DONE]" in body
    assert fake_client.max_inflight > 1
