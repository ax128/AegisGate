import json

import pytest
from fastapi.responses import JSONResponse
from starlette.requests import Request

from aegisgate.core import gateway


def _build_request(
    path: str,
    *,
    method: str = "POST",
    client_host: str = "127.0.0.1",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    token_authenticated: bool = False,
) -> Request:
    payload = json.dumps(body or {}).encode("utf-8")
    raw_headers = [(b"content-type", b"application/json")]
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
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
        "client": (client_host, 50000),
        "server": ("127.0.0.1", 18080),
        "aegis_token_authenticated": token_authenticated,
    }

    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": payload, "more_body": False}

    return Request(scope, receive)


async def _allow_next(_request: Request):
    return JSONResponse(status_code=200, content={"ok": True})


@pytest.mark.asyncio
async def test_boundary_blocks_non_token_v1_requests():
    request = _build_request("/v1/responses", token_authenticated=False, body={"input": "hello"})
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "token_route_required"


@pytest.mark.asyncio
async def test_boundary_allows_token_authenticated_v1_requests():
    request = _build_request("/v1/responses", token_authenticated=True, body={"input": "hello"})
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_blocks_admin_endpoints_from_public_ip():
    request = _build_request(
        "/__gw__/register",
        client_host="8.8.8.8",
        body={"upstream_base": "https://upstream.example.com/v1", "gateway_key": "agent"},
    )
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "admin_endpoint_network_restricted"


@pytest.mark.asyncio
async def test_boundary_allows_admin_endpoints_from_private_ip():
    original_loopback_only = gateway.settings.enforce_loopback_only
    gateway.settings.enforce_loopback_only = False
    request = _build_request(
        "/__gw__/lookup",
        client_host="10.0.0.8",
        body={"upstream_base": "https://upstream.example.com/v1", "gateway_key": "agent"},
    )
    try:
        response = await gateway.security_boundary_middleware(request, _allow_next)
        assert response.status_code == 200
    finally:
        gateway.settings.enforce_loopback_only = original_loopback_only
