from __future__ import annotations

import json

import pytest
from fastapi.responses import JSONResponse
from starlette.requests import Request

from aegisgate.core import gateway
from aegisgate.core import gateway_network


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
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode("latin-1"), value.encode("latin-1")))
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


async def _allow_next(_request: Request) -> JSONResponse:
    return JSONResponse(status_code=200, content={"ok": True})


@pytest.mark.asyncio
async def test_boundary_blocks_non_token_v1_requests() -> None:
    request = _build_request("/v1/responses", token_authenticated=False, body={"input": "hello"})

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "token_route_required"


@pytest.mark.asyncio
async def test_boundary_allows_token_authenticated_v1_requests() -> None:
    request = _build_request("/v1/responses", token_authenticated=True, body={"input": "hello"})

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200
    assert request.state.security_boundary["request_body_size"] > 0


@pytest.mark.asyncio
async def test_boundary_blocks_non_token_v2_requests() -> None:
    request = _build_request(
        "/v2/proxy",
        token_authenticated=False,
        headers={"x-target-url": "https://example.com/api"},
        body={"hello": "world"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "token_route_required"


@pytest.mark.asyncio
async def test_boundary_allows_non_token_v1_when_default_upstream_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1")
    request = _build_request("/v1/responses", token_authenticated=False, body={"input": "hello"})
    captured: dict[str, object] = {}

    async def _capture_next(req: Request) -> JSONResponse:
        captured["aegis_token_authenticated"] = req.scope.get("aegis_token_authenticated")
        captured["aegis_upstream_base"] = req.scope.get("aegis_upstream_base")
        return JSONResponse(status_code=200, content={"ok": True})

    response = await gateway.security_boundary_middleware(request, _capture_next)

    assert response.status_code == 200
    assert captured["aegis_token_authenticated"] is True
    assert captured["aegis_upstream_base"] == "http://cli-proxy-api:8317/v1"


@pytest.mark.asyncio
async def test_boundary_blocks_non_token_v2_when_default_upstream_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1")
    request = _build_request(
        "/v2/proxy",
        token_authenticated=False,
        headers={"x-target-url": "https://example.com/api"},
        body={"hello": "world"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "token_route_required"


@pytest.mark.asyncio
async def test_boundary_allows_token_authenticated_v2_requests() -> None:
    request = _build_request(
        "/v2/proxy",
        token_authenticated=True,
        headers={"x-target-url": "https://example.com/api"},
        body={"hello": "world"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_blocks_admin_endpoints_from_public_ip() -> None:
    request = _build_request(
        "/__gw__/register",
        client_host="8.8.8.8",
        body={"upstream_base": "https://upstream.example.com/v1", "gateway_key": "agent"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "loopback_only_reject"


@pytest.mark.asyncio
async def test_boundary_blocks_admin_endpoints_from_public_ip_loopback_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
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
async def test_boundary_ignores_xff_from_untrusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    request = _build_request(
        "/__gw__/register",
        client_host="172.18.0.4",
        headers={"x-forwarded-for": "8.8.8.8"},
        body={"upstream_base": "https://upstream.example.com/v1", "gateway_key": "agent"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_blocks_xff_public_when_trusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "172.18.0.4")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/__gw__/register",
        client_host="172.18.0.4",
        headers={"x-forwarded-for": "8.8.8.8"},
        body={"upstream_base": "https://upstream.example.com/v1", "gateway_key": "agent"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "admin_endpoint_network_restricted"


@pytest.mark.asyncio
async def test_boundary_blocks_add_endpoint_from_public_ip() -> None:
    request = _build_request(
        "/__gw__/add",
        client_host="8.8.8.8",
        body={"token": "tok123", "gateway_key": "agent", "whitelist_key": ["okx_key"]},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "loopback_only_reject"


@pytest.mark.asyncio
async def test_boundary_blocks_add_endpoint_from_public_ip_loopback_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    request = _build_request(
        "/__gw__/add",
        client_host="8.8.8.8",
        body={"token": "tok123", "gateway_key": "agent", "whitelist_key": ["okx_key"]},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["code"] == "admin_endpoint_network_restricted"


@pytest.mark.asyncio
async def test_boundary_allows_admin_endpoints_from_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    request = _build_request(
        "/__gw__/lookup",
        client_host="10.0.0.8",
        body={"upstream_base": "https://upstream.example.com/v1", "gateway_key": "agent"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200
