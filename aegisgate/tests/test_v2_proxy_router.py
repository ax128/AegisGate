from __future__ import annotations

import asyncio
import ipaddress
import json
import socket

import httpx
import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse

from aegisgate.adapters.v2_proxy.router import proxy_v2
from aegisgate.config.settings import settings


def _make_request(
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"{}",
    path: str = "/v2",
    method: str = "POST",
) -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "root_path": "",
        "query_string": b"",
        "headers": [
            (key.lower().encode("latin-1"), value.encode("latin-1"))
            for key, value in (headers or {}).items()
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 18080),
    }

    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(scope, receive)
    request.state.security_boundary = {}
    return request


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        content: bytes = b"",
        text: str | None = None,
    ):
        self.status_code = status_code
        self.headers = headers or {"content-type": "application/json"}
        self.content = content
        self.text = (
            text if text is not None else content.decode("utf-8", errors="replace")
        )

    def json(self):
        return json.loads(self.content.decode("utf-8"))

    async def aiter_bytes(self):
        if self.content:
            yield self.content


class _FakeRequestClient:
    def __init__(self, response: _FakeResponse | Exception):
        self.response = response

    async def request(self, **kwargs):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _FakeStreamResponse:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ):
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/event-stream"}
        self._chunks = list(chunks)

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


class _FakeStreamContext:
    def __init__(self, response: _FakeStreamResponse | Exception):
        self.response = response

    async def __aenter__(self):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeStreamClient:
    def __init__(self, response: _FakeStreamResponse | Exception):
        self.response = response

    def stream(self, method, target_url, headers=None, content=None):
        del method, target_url, headers, content
        return _FakeStreamContext(self.response)


def _patch_client(monkeypatch: pytest.MonkeyPatch, client) -> None:
    async def fake_get_v2_async_client():
        return client

    monkeypatch.setattr(
        "aegisgate.adapters.v2_proxy.router._get_v2_async_client",
        fake_get_v2_async_client,
    )


def _patch_resolve(
    monkeypatch: pytest.MonkeyPatch, values: list[str] | Exception
) -> None:
    async def fake_resolve(hostname: str):
        del hostname
        if isinstance(values, Exception):
            raise values
        return {ipaddress.ip_address(value) for value in values}

    monkeypatch.setattr(
        "aegisgate.adapters.v2_proxy.router._resolve_target_ips", fake_resolve
    )


def _to_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


def _response_json(response) -> dict:
    return json.loads(_to_bytes(response.body).decode("utf-8"))


async def _collect_stream_body(response: StreamingResponse) -> bytes:
    chunks: list[bytes] = []
    async for chunk in response.body_iterator:
        chunks.append(_to_bytes(chunk))
    return b"".join(chunks)


def test_proxy_rejects_missing_target_header() -> None:
    response = asyncio.run(proxy_v2(_make_request()))

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "x-target-url" in body["error"]["message"]


def test_proxy_rejects_invalid_target_url() -> None:
    response = asyncio.run(
        proxy_v2(_make_request(headers={"x-target-url": "not-a-url"}))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "scheme must be http/https" in body["error"]["message"]


def test_proxy_rejects_non_http_scheme() -> None:
    response = asyncio.run(
        proxy_v2(_make_request(headers={"x-target-url": "ftp://example.com/resource"}))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "scheme must be http/https" in body["error"]["message"]


def test_proxy_rejects_private_ipv4_target() -> None:
    response = asyncio.run(
        proxy_v2(_make_request(headers={"x-target-url": "http://127.0.0.1/secret"}))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "SSRF protection" in body["error"]["message"]


def test_proxy_rejects_metadata_hostname_target() -> None:
    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "http://metadata.google.internal/computeMetadata/v1"
                }
            )
        )
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "SSRF protection" in body["error"]["message"]


def test_proxy_rejects_internal_ipv6_target() -> None:
    response = asyncio.run(
        proxy_v2(_make_request(headers={"x-target-url": "http://[::1]/secret"}))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "SSRF protection" in body["error"]["message"]


def test_proxy_blocks_dns_rebinding_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_resolve(monkeypatch, ["10.0.0.5"])

    response = asyncio.run(
        proxy_v2(
            _make_request(headers={"x-target-url": "https://public.example.com/api"})
        )
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "SSRF protection" in body["error"]["message"]


def test_proxy_blocks_dns_lookup_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, socket.gaierror("dns timeout"))

    response = asyncio.run(
        proxy_v2(_make_request(headers={"x-target-url": "https://example.com/api"}))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "SSRF protection" in body["error"]["message"]


def test_proxy_rejects_target_not_in_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "v2_target_allowlist", "api.example.com")

    response = asyncio.run(
        proxy_v2(
            _make_request(headers={"x-target-url": "https://other.example.com/api"})
        )
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _response_json(response)
    assert body["error"]["code"] == "missing_target_url_header"
    assert "allowlist" in body["error"]["message"]


def test_proxy_allows_target_matching_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "v2_target_allowlist", "api.example.com")
    _patch_resolve(monkeypatch, ["93.184.216.34"])
    _patch_client(
        monkeypatch, _FakeRequestClient(_FakeResponse(content=b'{"ok":true}'))
    )

    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "https://api.example.com/resource",
                    "content-type": "application/json",
                },
                body=b'{"ping":true}',
            )
        )
    )

    assert response.status_code == 200
    assert _response_json(response) == {"ok": True}


def test_proxy_allows_public_ipv6_target(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, ["2001:4860:4860::8888"])
    _patch_client(
        monkeypatch,
        _FakeRequestClient(
            _FakeResponse(
                content=b'{"ok":true}',
                headers={"content-type": "application/json", "x-extra": "1"},
            )
        ),
    )

    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "https://[2001:4860:4860::8888]/resource",
                    "content-type": "application/json",
                },
                body=b'{"ping":true}',
            )
        )
    )

    assert response.status_code == 200
    assert response.headers["x-extra"] == "1"
    assert _response_json(response) == {"ok": True}


def test_proxy_allows_public_hostname_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_resolve(monkeypatch, ["93.184.216.34"])
    _patch_client(
        monkeypatch, _FakeRequestClient(_FakeResponse(content=b'{"ok":true}'))
    )

    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "https://example.com/api",
                    "content-type": "application/json",
                },
                body=b'{"ping":true}',
            )
        )
    )

    assert response.status_code == 200
    assert _response_json(response) == {"ok": True}


def test_proxy_forwards_json_response(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(
        monkeypatch,
        _FakeRequestClient(
            _FakeResponse(
                status_code=201,
                headers={"content-type": "application/json", "x-extra": "1"},
                content=b'{"ok":true}',
            )
        ),
    )

    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "https://example.com/api",
                    "content-type": "application/json",
                },
                body=b'{"hello":"world"}',
            )
        )
    )

    assert response.status_code == 201
    assert response.headers["x-extra"] == "1"
    assert _response_json(response) == {"ok": True}


def test_proxy_blocks_non_streaming_dangerous_text_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dangerous = b"Content-Length: 1\r\nTransfer-Encoding: chunked"
    _patch_client(
        monkeypatch,
        _FakeRequestClient(
            _FakeResponse(
                headers={"content-type": "text/plain; charset=utf-8"}, content=dangerous
            )
        ),
    )

    response = asyncio.run(
        proxy_v2(_make_request(headers={"x-target-url": "https://example.com/plain"}))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "v2_response_http_attack_blocked"
    assert body["aegisgate_v2"]["response_command_filter_enabled"] is True


def test_proxy_bypasses_non_streaming_filter_for_bypass_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = settings.v2_response_filter_bypass_hosts
    settings.v2_response_filter_bypass_hosts = "example.com"
    try:
        dangerous = b"Content-Length: 1\r\nTransfer-Encoding: chunked"
        _patch_client(
            monkeypatch,
            _FakeRequestClient(
                _FakeResponse(
                    headers={"content-type": "text/plain; charset=utf-8"},
                    content=dangerous,
                )
            ),
        )

        response = asyncio.run(
            proxy_v2(
                _make_request(headers={"x-target-url": "https://example.com/plain"})
            )
        )

        assert response.status_code == 200
        assert response.body == dangerous
    finally:
        settings.v2_response_filter_bypass_hosts = original


def test_proxy_preserves_binary_response(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(
        monkeypatch,
        _FakeRequestClient(
            _FakeResponse(
                status_code=202,
                headers={"content-type": "application/octet-stream", "x-extra": "1"},
                content=b"\x00\x01\x02",
                text="",
            )
        ),
    )

    response = asyncio.run(
        proxy_v2(_make_request(headers={"x-target-url": "https://example.com/blob"}))
    )

    assert response.status_code == 202
    assert response.headers["x-extra"] == "1"
    assert response.body == b"\x00\x01\x02"


def test_proxy_maps_httpx_error_to_upstream_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = httpx.ConnectError(
        "boom", request=httpx.Request("POST", "https://example.com/api")
    )
    _patch_client(monkeypatch, _FakeRequestClient(error))

    response = asyncio.run(
        proxy_v2(_make_request(headers={"x-target-url": "https://example.com/api"}))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 502
    body = _response_json(response)
    assert body["error"]["code"] == "upstream_unreachable"


def test_proxy_blocks_streaming_dangerous_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_client(
        monkeypatch,
        _FakeStreamClient(
            _FakeStreamResponse(
                [b"Content-Length: 1\r\nTransfer-Encoding: chunked"],
                headers={"content-type": "text/event-stream"},
            )
        ),
    )

    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "https://example.com/stream",
                    "accept": "text/event-stream",
                },
                body=b'{"stream":true}',
            )
        )
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "v2_response_http_attack_blocked"


def test_proxy_blocks_streaming_dangerous_probe_split_across_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_resolve(monkeypatch, ["93.184.216.34"])
    _patch_client(
        monkeypatch,
        _FakeStreamClient(
            _FakeStreamResponse(
                [b"Content-Length: 1\r\n", b"Transfer-Encoding: chunked"],
                headers={"content-type": "text/event-stream"},
            )
        ),
    )

    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "https://example.com/stream",
                    "accept": "text/event-stream",
                },
                body=b'{"stream":true}',
            )
        )
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "v2_response_http_attack_blocked"


def test_proxy_streaming_bypass_host_allows_original_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = settings.v2_response_filter_bypass_hosts
    settings.v2_response_filter_bypass_hosts = "example.com"
    try:
        _patch_client(
            monkeypatch,
            _FakeStreamClient(
                _FakeStreamResponse(
                    [
                        b"data: hello\n\n",
                        b"data: Content-Length: 1\r\nTransfer-Encoding: chunked\n\n",
                    ],
                    headers={"content-type": "text/event-stream"},
                )
            ),
        )

        response = asyncio.run(
            proxy_v2(
                _make_request(
                    headers={
                        "x-target-url": "https://example.com/stream",
                        "accept": "text/event-stream",
                    },
                    body=b'{"stream":true}',
                )
            )
        )

        assert isinstance(response, StreamingResponse)
        body = asyncio.run(_collect_stream_body(response)).decode(
            "utf-8", errors="replace"
        )
        assert "Content-Length: 1" in body
        assert "data: [DONE]" in body
    finally:
        settings.v2_response_filter_bypass_hosts = original


def test_proxy_streaming_injects_done_when_upstream_ends_without_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_resolve(monkeypatch, ["93.184.216.34"])
    _patch_client(
        monkeypatch,
        _FakeStreamClient(
            _FakeStreamResponse(
                [b"data: hello\n\n"], headers={"content-type": "text/event-stream"}
            )
        ),
    )

    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "https://stream.example.com/feed",
                    "accept": "text/event-stream",
                },
                body=b'{"stream":true}',
            )
        )
    )

    assert isinstance(response, StreamingResponse)
    body = asyncio.run(_collect_stream_body(response)).decode("utf-8", errors="replace")
    assert "data: hello" in body
    assert body.endswith("data: [DONE]\n\n")


def test_proxy_streaming_maps_httpx_error_to_upstream_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = httpx.ReadTimeout(
        "boom", request=httpx.Request("POST", "https://example.com/stream")
    )
    _patch_client(monkeypatch, _FakeStreamClient(error))

    response = asyncio.run(
        proxy_v2(
            _make_request(
                headers={
                    "x-target-url": "https://example.com/stream",
                    "accept": "text/event-stream",
                },
                body=b'{"stream":true}',
            )
        )
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 502
    body = _response_json(response)
    assert body["error"]["code"] == "upstream_unreachable"
