import json

import pytest
from starlette.requests import Request

from aegisgate.core import gateway


def _build_request(path: str, body: dict, headers: dict[str, str] | None = None) -> Request:
    payload = json.dumps(body).encode("utf-8")
    raw_headers = [(b"content-type", b"application/json")]
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
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
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 18080),
    }

    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": payload, "more_body": False}

    req = Request(scope, receive)
    req.state.security_boundary = {}
    return req


@pytest.mark.asyncio
async def test_gw_register_base_url_prefers_request_host(monkeypatch):
    monkeypatch.setattr(gateway, "gw_tokens_register", lambda upstream, key: ("token123", False))
    request = _build_request(
        "/__gw__/register",
        {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent"},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_register(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert body["baseUrl"] == "http://127.0.0.1:18080/v1/__gw__/t/token123"


@pytest.mark.asyncio
async def test_gw_register_base_url_uses_forwarded_headers(monkeypatch):
    monkeypatch.setattr(gateway, "gw_tokens_register", lambda upstream, key: ("token123", False))
    request = _build_request(
        "/__gw__/register",
        {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent"},
        headers={
            "host": "internal:18080",
            "x-forwarded-host": "gw.example.com",
            "x-forwarded-proto": "https",
        },
    )
    resp = await gateway.gw_register(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert body["baseUrl"] == "https://gw.example.com/v1/__gw__/t/token123"


def test_sanitize_public_host_replaces_zero_host():
    assert gateway._sanitize_public_host("0.0.0.0:18080") == "127.0.0.1:18080"
