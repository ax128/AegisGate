from __future__ import annotations

import json

import pytest
from fastapi.responses import JSONResponse, Response
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
    gateway_token: str | None = None,
    filter_mode: str | None = None,
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
    if gateway_token is not None:
        scope["aegis_gateway_token"] = gateway_token
    if filter_mode is not None:
        scope["aegis_filter_mode"] = filter_mode

    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": payload, "more_body": False}

    return Request(scope, receive)


def _build_multipart_request(
    path: str,
    *,
    content_length: int,
    method: str = "POST",
    client_host: str = "127.0.0.1",
    token_authenticated: bool = False,
) -> Request:
    raw_headers = [
        (b"content-type", b"multipart/form-data; boundary=abc"),
        (b"content-length", str(int(content_length)).encode("latin-1")),
    ]
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

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


async def _allow_next(_request: Request) -> JSONResponse:
    return JSONResponse(status_code=200, content={"ok": True})


def _response_json(response: Response) -> dict:
    return json.loads(bytes(response.body).decode("utf-8"))


@pytest.mark.asyncio
async def test_boundary_blocks_non_token_v1_requests() -> None:
    request = _build_request(
        "/v1/responses", token_authenticated=False, body={"input": "hello"}
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "token_route_required"


@pytest.mark.asyncio
async def test_boundary_allows_ready_passthrough() -> None:
    request = _build_request("/ready", method="GET", token_authenticated=False)

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


def test_ready_returns_503_when_app_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.app.state, "ready", False, raising=False)

    response = gateway.ready()

    assert response.status_code == 503
    assert json.loads(bytes(response.body).decode("utf-8")) == {"status": "starting"}


@pytest.mark.asyncio
async def test_boundary_allows_ready_passthrough_when_hmac_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    request = _build_request("/ready", method="GET", token_authenticated=False)

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_allows_token_authenticated_v1_requests() -> None:
    request = _build_request(
        "/v1/responses", token_authenticated=True, body={"input": "hello"}
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200
    assert request.state.security_boundary["request_body_size"] > 0


@pytest.mark.asyncio
async def test_boundary_allows_large_multipart_for_openai_image_edits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "max_request_body_bytes", 12_000_000)
    monkeypatch.setattr(gateway.settings, "max_multipart_body_bytes", 60_000_000)
    request = _build_multipart_request(
        "/v1/images/edits",
        content_length=20_000_000,
        token_authenticated=True,
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200
    assert request.state.security_boundary["request_body_size"] == 20_000_000
    assert int(request.state.security_boundary["max_request_body_bytes"]) >= 60_000_000


@pytest.mark.asyncio
async def test_boundary_allows_large_multipart_for_openai_image_edits_with_trailing_slash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "max_request_body_bytes", 12_000_000)
    monkeypatch.setattr(gateway.settings, "max_multipart_body_bytes", 60_000_000)
    request = _build_multipart_request(
        "/v1/images/edits/",
        content_length=20_000_000,
        token_authenticated=True,
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200
    assert request.state.security_boundary["request_body_size"] == 20_000_000
    assert int(request.state.security_boundary["max_request_body_bytes"]) >= 60_000_000


@pytest.mark.asyncio
async def test_boundary_rejects_large_multipart_for_non_overridden_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "max_request_body_bytes", 12_000_000)
    monkeypatch.setattr(gateway.settings, "max_multipart_body_bytes", 60_000_000)
    request = _build_multipart_request(
        "/v1/responses",
        content_length=20_000_000,
        token_authenticated=True,
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 413
    body = _response_json(response)
    assert body["error"]["code"] == "request_body_too_large"


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
    body = _response_json(response)
    assert body["error"]["code"] == "token_route_required"


@pytest.mark.asyncio
async def test_boundary_allows_non_token_v1_when_default_upstream_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1"
    )
    request = _build_request(
        "/v1/responses", token_authenticated=False, body={"input": "hello"}
    )
    captured: dict[str, object] = {}

    async def _capture_next(req: Request) -> JSONResponse:
        captured["aegis_token_authenticated"] = req.scope.get(
            "aegis_token_authenticated"
        )
        captured["aegis_upstream_base"] = req.scope.get("aegis_upstream_base")
        captured["tenant_id"] = req.state.security_boundary.get("tenant_id")
        return JSONResponse(status_code=200, content={"ok": True})

    response = await gateway.security_boundary_middleware(request, _capture_next)

    assert response.status_code == 200
    assert captured["aegis_token_authenticated"] is True
    assert captured["aegis_upstream_base"] == "http://cli-proxy-api:8317/v1"
    assert isinstance(captured["tenant_id"], str)
    assert captured["tenant_id"].startswith("internal:")
    assert captured["tenant_id"] != "default"


@pytest.mark.asyncio
async def test_boundary_blocks_public_non_token_v1_with_default_upstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1"
    )
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    request = _build_request(
        "/v1/responses",
        token_authenticated=False,
        client_host="8.8.8.8",
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "token_route_required"


@pytest.mark.asyncio
async def test_boundary_blocks_non_token_v2_when_default_upstream_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1"
    )
    request = _build_request(
        "/v2/proxy",
        token_authenticated=False,
        headers={"x-target-url": "https://example.com/api"},
        body={"hello": "world"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
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
        body={
            "upstream_base": "https://upstream.example.com/v1",
            "gateway_key": "agent",
        },
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "loopback_only_reject"


@pytest.mark.asyncio
async def test_boundary_blocks_admin_endpoints_from_public_ip_loopback_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    request = _build_request(
        "/__gw__/register",
        client_host="8.8.8.8",
        body={
            "upstream_base": "https://upstream.example.com/v1",
            "gateway_key": "agent",
        },
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "admin_endpoint_network_restricted"


@pytest.mark.asyncio
async def test_boundary_ignores_xff_from_untrusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/__gw__/register",
        client_host="172.18.0.4",
        headers={"x-forwarded-for": "8.8.8.8"},
        body={
            "upstream_base": "https://upstream.example.com/v1",
            "gateway_key": "agent",
        },
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_blocks_xff_public_when_trusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "172.18.0.4")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/__gw__/register",
        client_host="172.18.0.4",
        headers={"x-forwarded-for": "8.8.8.8"},
        body={
            "upstream_base": "https://upstream.example.com/v1",
            "gateway_key": "agent",
        },
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "admin_endpoint_network_restricted"


@pytest.mark.asyncio
async def test_boundary_blocks_public_numeric_token_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "allow_public_numeric_tokens", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        gateway_token="8317",
        client_host="8.8.8.8",
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "numeric_token_public_restricted"


@pytest.mark.asyncio
async def test_boundary_allows_internal_numeric_token_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "allow_public_numeric_tokens", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        gateway_token="8317",
        client_host="10.0.0.8",
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_allows_public_numeric_token_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "allow_public_numeric_tokens", True)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        gateway_token="8317",
        client_host="8.8.8.8",
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_blocks_public_passthrough_mode_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "allow_public_passthrough_mode", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        gateway_token="tok123",
        filter_mode="passthrough",
        client_host="8.8.8.8",
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "passthrough_mode_public_restricted"


@pytest.mark.asyncio
async def test_boundary_allows_internal_passthrough_mode_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "allow_public_passthrough_mode", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        gateway_token="tok123",
        filter_mode="passthrough",
        client_host="10.0.0.8",
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_allows_public_passthrough_mode_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "allow_public_passthrough_mode", True)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        gateway_token="tok123",
        filter_mode="passthrough",
        client_host="8.8.8.8",
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_treats_xff_from_untrusted_proxy_as_public_for_numeric_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "allow_public_numeric_tokens", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        gateway_token="8317",
        client_host="10.0.0.8",
        headers={"x-forwarded-for": "8.8.8.8"},
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "numeric_token_public_restricted"


@pytest.mark.asyncio
async def test_boundary_allows_internal_xff_when_proxy_trusted_for_numeric_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "172.18.0.4")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "allow_public_numeric_tokens", False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        gateway_token="8317",
        client_host="172.18.0.4",
        headers={"x-forwarded-for": "10.0.0.8"},
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_blocks_add_endpoint_from_public_ip() -> None:
    request = _build_request(
        "/__gw__/add",
        client_host="8.8.8.8",
        body={"token": "tok123", "gateway_key": "agent", "whitelist_key": ["okx_key"]},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "loopback_only_reject"


@pytest.mark.asyncio
async def test_boundary_blocks_add_endpoint_from_public_ip_loopback_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    request = _build_request(
        "/__gw__/add",
        client_host="8.8.8.8",
        body={"token": "tok123", "gateway_key": "agent", "whitelist_key": ["okx_key"]},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    body = _response_json(response)
    assert body["error"]["code"] == "admin_endpoint_network_restricted"


@pytest.mark.asyncio
async def test_boundary_allows_admin_endpoints_from_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    request = _build_request(
        "/__gw__/lookup",
        client_host="10.0.0.8",
        body={
            "upstream_base": "https://upstream.example.com/v1",
            "gateway_key": "agent",
        },
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200
