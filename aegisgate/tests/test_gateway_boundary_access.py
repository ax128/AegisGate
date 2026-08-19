from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response
from starlette.requests import Request

from aegisgate.core import gateway
from aegisgate.core import gateway_auth
from aegisgate.core import gateway_network
from aegisgate.core import gateway_ui_routes
from aegisgate.core import gw_tokens
from aegisgate.core.security_boundary import (
    NonceReplayCache,
    build_signature_payload,
    compute_hmac_sha256,
)


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
async def test_boundary_treats_xff_from_untrusted_proxy_as_public_for_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", "")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "xff_strict_internal", True)
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


@pytest.fixture
def _clear_gw_tokens() -> None:
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    yield
    with gw_tokens._lock:
        gw_tokens._tokens.clear()


@pytest.mark.asyncio
async def test_ui_rules_add_rejects_invalid_regex(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules_path = tmp_path / "security_rules.yaml"
    monkeypatch.setattr(gateway_ui_routes.settings, "security_rules_path", str(rules_path))

    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/__ui__/api/rules/command_patterns",
            json={"id": "bad", "regex": "("},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_regex"
    assert not rules_path.exists()


@pytest.mark.asyncio
async def test_ui_rules_update_rejects_invalid_regex_without_changing_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules_path = tmp_path / "security_rules.yaml"
    rules_path.write_text(
        yaml.safe_dump(
            {
                "anomaly_detector": {
                    "command_patterns": [
                        {"id": "existing", "regex": r"\brm\s+-rf\b"}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    before = rules_path.read_text(encoding="utf-8")
    monkeypatch.setattr(gateway_ui_routes.settings, "security_rules_path", str(rules_path))

    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.patch(
            "/__ui__/api/rules/command_patterns/existing",
            json={"regex": "("},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_regex"
    assert rules_path.read_text(encoding="utf-8") == before


def test_gw_tokens_save_raises_when_token_file_cannot_be_persisted(
    monkeypatch: pytest.MonkeyPatch, _clear_gw_tokens: None
) -> None:
    with gw_tokens._lock:
        gw_tokens._tokens["tok"] = {
            "upstream_base": "https://upstream.example.com/v1",
            "whitelist_key": [],
        }

    def fail_named_temporary_file(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(gw_tokens.tempfile, "NamedTemporaryFile", fail_named_temporary_file)

    with pytest.raises(OSError, match="disk full"):
        gw_tokens._save()


def test_gw_tokens_register_rolls_back_memory_when_persistence_fails(
    monkeypatch: pytest.MonkeyPatch, _clear_gw_tokens: None
) -> None:
    token = "A" * gw_tokens._TOKEN_LEN
    monkeypatch.setattr(gw_tokens, "_generate_alnum_token", lambda length: token)

    def fail_save() -> None:
        raise OSError("disk full")

    monkeypatch.setattr(gw_tokens, "_save", fail_save)

    with pytest.raises(OSError, match="disk full"):
        gw_tokens.register("https://upstream.example.com/v1")

    assert gw_tokens.get(token) is None


def test_gw_tokens_builtin_injection_keeps_memory_when_persistence_fails(
    monkeypatch: pytest.MonkeyPatch, _clear_gw_tokens: None
) -> None:
    monkeypatch.setattr(gw_tokens.settings, "enable_builtin_compat_tokens", True)

    def fail_save() -> None:
        raise OSError("disk full")

    monkeypatch.setattr(gw_tokens, "_save", fail_save)

    gw_tokens.inject_builtin_compat_tokens()

    mapping = gw_tokens.get("claude-to-gpt")
    assert mapping is not None
    assert mapping["compat"] == "openai_chat"


def test_gw_tokens_docker_upstreams_keep_memory_when_persistence_fails(
    monkeypatch: pytest.MonkeyPatch, _clear_gw_tokens: None
) -> None:
    monkeypatch.setattr(gw_tokens.settings, "docker_upstreams", "8317:cli-proxy-api")

    def fail_save() -> None:
        raise OSError("disk full")

    monkeypatch.setattr(gw_tokens, "_save", fail_save)

    injected = gw_tokens.inject_docker_upstreams()

    assert injected == 1
    mapping = gw_tokens.get("8317")
    assert mapping is not None
    assert mapping["upstream_base"] == "http://cli-proxy-api:8317/v1"


@pytest.mark.asyncio
async def test_boundary_allows_large_body_for_token_routed_generic_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Token-routed (generic-proxy / CLIProxyAPI) requests may carry large
    # multimodal bodies (e.g. inline image/video) that exceed the 12MB text limit.
    monkeypatch.setattr(gateway.settings, "max_request_body_bytes", 12_000_000)
    monkeypatch.setattr(gateway.settings, "v2_max_request_body_bytes", 64_000_000)
    request = _build_request(
        "/v1/chat/completions",
        token_authenticated=True,
        gateway_token="tok-123",
        headers={"content-length": "20000000"},
        body={"messages": []},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200
    assert int(request.state.security_boundary["max_request_body_bytes"]) >= 64_000_000


@pytest.mark.asyncio
async def test_boundary_keeps_text_limit_for_direct_non_token_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A direct (non-token) call keeps the 12MB text limit; the generic-proxy
    # override must not loosen ordinary openai-compatible routes.
    monkeypatch.setattr(gateway.settings, "max_request_body_bytes", 12_000_000)
    monkeypatch.setattr(gateway.settings, "v2_max_request_body_bytes", 64_000_000)
    request = _build_request(
        "/v1/chat/completions",
        token_authenticated=True,
        headers={"content-length": "20000000"},
        body={"messages": []},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 413
    assert _response_json(response)["error"]["code"] == "request_body_too_large"


def _hmac_headers(
    *,
    body: dict,
    path: str,
    secret: str,
    nonce: str,
    timestamp: str | None = None,
    method: str = "POST",
    content_type: str = "application/json",
) -> dict[str, str]:
    payload_body = json.dumps(body).encode("utf-8")
    ts = timestamp if timestamp is not None else str(int(time.time()))
    signed = build_signature_payload(
        timestamp=ts,
        nonce=nonce,
        body=payload_body,
        method=method,
        path=path,
        query="",
        content_type=content_type,
    )
    return {
        "x-aegis-signature": compute_hmac_sha256(secret, signed),
        "x-aegis-timestamp": ts,
        "x-aegis-nonce": nonce,
        "user-agent": "b7-hmac-test",
    }


@pytest.mark.asyncio
async def test_hmac_missing_headers_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    monkeypatch.setattr(gateway.settings, "request_hmac_secret", "unit-hmac-secret")
    monkeypatch.setattr(gateway, "_nonce_cache", NonceReplayCache())
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 401
    assert _response_json(response)["error"]["code"] == "hmac_header_missing"


@pytest.mark.asyncio
async def test_hmac_invalid_signature_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "unit-hmac-secret"
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    monkeypatch.setattr(gateway.settings, "request_hmac_secret", secret)
    monkeypatch.setattr(gateway, "_nonce_cache", NonceReplayCache())
    body = {"input": "hello"}
    headers = _hmac_headers(body=body, path="/v1/responses", secret=secret, nonce="n-bad-sig")
    headers["x-aegis-signature"] = "0" * 64
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        headers=headers,
        body=body,
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 401
    assert _response_json(response)["error"]["code"] == "hmac_signature_invalid"


@pytest.mark.asyncio
async def test_hmac_replayed_nonce_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "unit-hmac-secret"
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    monkeypatch.setattr(gateway.settings, "request_hmac_secret", secret)
    monkeypatch.setattr(gateway, "_nonce_cache", NonceReplayCache())
    body = {"input": "hello"}
    headers = _hmac_headers(body=body, path="/v1/responses", secret=secret, nonce="n-replay")
    first = _build_request(
        "/v1/responses",
        token_authenticated=True,
        headers=headers,
        body=body,
    )
    second = _build_request(
        "/v1/responses",
        token_authenticated=True,
        headers=headers,
        body=body,
    )

    first_response = await gateway.security_boundary_middleware(first, _allow_next)
    second_response = await gateway.security_boundary_middleware(second, _allow_next)

    assert first_response.status_code == 200
    assert second_response.status_code == 409
    assert _response_json(second_response)["error"]["code"] == "replay_nonce_detected"


@pytest.mark.asyncio
async def test_hmac_valid_signature_allows_token_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "unit-hmac-secret"
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    monkeypatch.setattr(gateway.settings, "request_hmac_secret", secret)
    monkeypatch.setattr(gateway, "_nonce_cache", NonceReplayCache())
    body = {"input": "hello"}
    headers = _hmac_headers(body=body, path="/v1/responses", secret=secret, nonce="n-ok")
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        headers=headers,
        body=body,
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200
    assert request.state.security_boundary["auth_verified"] is True


@pytest.mark.asyncio
async def test_hmac_timestamp_outside_replay_window_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Signature is valid for the stale timestamp, so only the window check can reject."""
    secret = "unit-hmac-secret"
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    monkeypatch.setattr(gateway.settings, "request_hmac_secret", secret)
    monkeypatch.setattr(gateway, "_nonce_cache", NonceReplayCache())
    body = {"input": "hello"}
    window = gateway.settings.request_replay_window_seconds
    now = int(time.time())

    for label, ts in (("stale", now - window - 60), ("future", now + window + 60)):
        headers = _hmac_headers(
            body=body,
            path="/v1/responses",
            secret=secret,
            nonce=f"n-{label}",
            timestamp=str(ts),
        )
        request = _build_request(
            "/v1/responses",
            token_authenticated=True,
            headers=headers,
            body=body,
        )

        response = await gateway.security_boundary_middleware(request, _allow_next)

        assert response.status_code == 401, label
        assert (
            _response_json(response)["error"]["code"] == "hmac_timestamp_out_of_window"
        ), label


@pytest.mark.asyncio
async def test_hmac_non_numeric_timestamp_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "unit-hmac-secret"
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    monkeypatch.setattr(gateway.settings, "request_hmac_secret", secret)
    monkeypatch.setattr(gateway, "_nonce_cache", NonceReplayCache())
    body = {"input": "hello"}
    headers = _hmac_headers(
        body=body,
        path="/v1/responses",
        secret=secret,
        nonce="n-bad-ts",
        timestamp="not-a-timestamp",
    )
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        headers=headers,
        body=body,
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 401
    assert _response_json(response)["error"]["code"] == "hmac_timestamp_invalid"


@pytest.mark.asyncio
async def test_hmac_enabled_without_secret_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enabling HMAC with a blank secret must refuse traffic, not wave it through."""
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    monkeypatch.setattr(gateway.settings, "request_hmac_secret", "   ")
    request = _build_request(
        "/v1/responses",
        token_authenticated=True,
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 500
    assert _response_json(response)["error"]["code"] == "hmac_misconfigured"


def _ui_session(monkeypatch: pytest.MonkeyPatch, *, user_agent: str = "b7-ui") -> str:
    """Install a known gateway key and mint a session bound to `user_agent`."""
    import aegisgate.core.gateway_keys as gateway_keys

    monkeypatch.setattr(gateway.settings, "gateway_key", "b7-ui-secret")
    monkeypatch.setattr(gateway_auth.settings, "gateway_key", "b7-ui-secret")
    monkeypatch.setattr(gateway_keys, "_gateway_key_cached", "b7-ui-secret")
    bootstrap = _build_request(
        "/__ui__/api/tokens",
        method="POST",
        headers={"user-agent": user_agent},
        body={},
    )
    return gateway_auth._create_ui_session_token(bootstrap)


def _ui_write_request(
    session: str,
    *,
    csrf: str | None = None,
    user_agent: str = "b7-ui",
) -> Request:
    headers = {
        "user-agent": user_agent,
        "cookie": f"{gateway_auth._UI_SESSION_COOKIE}={session}",
    }
    if csrf is not None:
        headers["x-aegis-ui-csrf"] = csrf
    return _build_request(
        "/__ui__/api/tokens",
        method="POST",
        headers=headers,
        body={"upstream_base": "https://example.com"},
    )


@pytest.mark.asyncio
async def test_ui_write_without_session_is_unauthorized() -> None:
    request = _build_request("/__ui__/api/tokens", method="POST", body={"upstream_base": "https://example.com"})

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 401
    assert _response_json(response)["error"] == "ui_auth_required"


@pytest.mark.asyncio
async def test_ui_write_without_csrf_is_forbidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _ui_session(monkeypatch)

    response = await gateway.security_boundary_middleware(
        _ui_write_request(session), _allow_next
    )

    assert response.status_code == 403
    assert _response_json(response)["error"] == "ui_csrf_invalid"


@pytest.mark.asyncio
async def test_ui_write_with_malformed_csrf_is_forbidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong token takes a different branch than a missing one."""
    session = _ui_session(monkeypatch)

    response = await gateway.security_boundary_middleware(
        _ui_write_request(session, csrf="0" * 64), _allow_next
    )

    assert response.status_code == 403
    assert _response_json(response)["error"] == "ui_csrf_invalid"


@pytest.mark.asyncio
async def test_ui_csrf_token_from_another_session_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _ui_session(monkeypatch)
    foreign = gateway_auth._create_ui_session_token(
        _build_request(
            "/__ui__/api/tokens",
            method="POST",
            headers={"user-agent": "b7-ui"},
            body={},
        )
    )
    assert foreign != session

    response = await gateway.security_boundary_middleware(
        _ui_write_request(session, csrf=gateway_auth._ui_csrf_token(foreign)),
        _allow_next,
    )

    assert response.status_code == 403
    assert _response_json(response)["error"] == "ui_csrf_invalid"


@pytest.mark.asyncio
async def test_ui_write_with_csrf_reaches_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _ui_session(monkeypatch)

    response = await gateway.security_boundary_middleware(
        _ui_write_request(session, csrf=gateway_auth._ui_csrf_token(session)),
        _allow_next,
    )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_ui_expired_session_is_unauthorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Carries a matching CSRF token, so only the session TTL can reject it."""
    _ui_session(monkeypatch)
    bootstrap = _build_request(
        "/__ui__/api/tokens",
        method="POST",
        headers={"user-agent": "b7-ui"},
        body={},
    )
    issued_at = (
        int(time.time()) - gateway_auth.settings.local_ui_session_ttl_seconds - 60
    )
    nonce = "b7-expired-nonce"
    expired = ".".join(
        (
            str(issued_at),
            nonce,
            gateway_auth._ui_session_signature(
                issued_at, gateway_auth._ui_client_fingerprint(bootstrap), nonce
            ),
        )
    )

    response = await gateway.security_boundary_middleware(
        _ui_write_request(expired, csrf=gateway_auth._ui_csrf_token(expired)),
        _allow_next,
    )

    assert response.status_code == 401
    assert _response_json(response)["error"] == "ui_auth_required"


@pytest.mark.asyncio
async def test_ui_session_is_bound_to_client_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stolen cookie replayed from a different user agent must not authenticate."""
    session = _ui_session(monkeypatch, user_agent="b7-ui")

    response = await gateway.security_boundary_middleware(
        _ui_write_request(
            session,
            csrf=gateway_auth._ui_csrf_token(session),
            user_agent="stolen-cookie-agent",
        ),
        _allow_next,
    )

    assert response.status_code == 401
    assert _response_json(response)["error"] == "ui_auth_required"


@pytest.mark.asyncio
async def test_ui_rejects_non_loopback_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "local_ui_allow_internal_network", False)
    request = _build_request(
        "/__ui__/api/tokens", method="GET", client_host="203.0.113.10"
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    assert _response_json(response)["error"]["code"] == "local_ui_network_restricted"


@pytest.mark.asyncio
async def test_ui_internal_network_access_requires_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _login_page_status(*, allow_internal: bool) -> int:
        monkeypatch.setattr(
            gateway.settings, "local_ui_allow_internal_network", allow_internal
        )
        request = _build_request(
            "/__ui__/login", method="GET", client_host="10.1.2.3"
        )
        response = await gateway.security_boundary_middleware(request, _allow_next)
        return response.status_code

    assert await _login_page_status(allow_internal=False) == 403
    assert await _login_page_status(allow_internal=True) == 200


@pytest.mark.asyncio
async def test_ui_login_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = gateway._AdminRateLimiter(max_per_minute=1)
    monkeypatch.setattr(gateway, "_UI_LOGIN_RATE_LIMITER", limiter)
    first = _build_request(
        "/__ui__/api/login",
        method="POST",
        client_host="127.0.0.42",
        body={"password": "x"},
    )
    second = _build_request(
        "/__ui__/api/login",
        method="POST",
        client_host="127.0.0.42",
        body={"password": "x"},
    )

    first_response = await gateway.security_boundary_middleware(first, _allow_next)
    second_response = await gateway.security_boundary_middleware(second, _allow_next)

    assert first_response.status_code == 200
    assert second_response.status_code == 429
    assert _response_json(second_response)["error"] == "ui_login_rate_limited"


@pytest.mark.asyncio
async def test_ui_login_rate_limit_boundary_is_per_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """max_per_minute=2 pins the >= comparison that a single-request budget cannot."""
    monkeypatch.setattr(
        gateway, "_UI_LOGIN_RATE_LIMITER", gateway._AdminRateLimiter(max_per_minute=2)
    )

    async def _login_from(client_host: str) -> int:
        request = _build_request(
            "/__ui__/api/login",
            method="POST",
            client_host=client_host,
            body={"password": "x"},
        )
        response = await gateway.security_boundary_middleware(request, _allow_next)
        return response.status_code

    assert [await _login_from("127.0.0.43") for _ in range(3)] == [200, 200, 429]
    assert await _login_from("127.0.0.44") == 200


def _reset_trusted_proxy(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr(gateway.settings, "trusted_proxy_ips", value)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)


@pytest.mark.asyncio
async def test_boundary_rejects_default_v1_when_xff_from_untrusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1"
    )
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "xff_strict_internal", True)
    _reset_trusted_proxy(monkeypatch, "")
    request = _build_request(
        "/v1/responses",
        token_authenticated=False,
        client_host="172.18.0.4",
        headers={"x-forwarded-for": "8.8.8.8"},
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    assert _response_json(response)["error"]["code"] == "token_route_required"


@pytest.mark.asyncio
async def test_boundary_allows_default_v1_xff_when_proxy_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1"
    )
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "xff_strict_internal", True)
    _reset_trusted_proxy(monkeypatch, "172.18.0.4")
    request = _build_request(
        "/v1/responses",
        token_authenticated=False,
        client_host="172.18.0.4",
        headers={"x-forwarded-for": "10.0.0.8"},
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_allows_proxy_token_v1_despite_untrusted_xff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1"
    )
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "xff_strict_internal", True)
    _reset_trusted_proxy(monkeypatch, "")
    monkeypatch.setattr(gateway, "get_proxy_token_value", lambda: "proxy-secret")
    request = _build_request(
        "/v1/responses",
        token_authenticated=False,
        client_host="172.18.0.4",
        headers={
            "x-forwarded-for": "8.8.8.8",
            "x-aegis-proxy-token": "proxy-secret",
        },
        body={"input": "hello"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_rejects_ui_login_when_xff_from_untrusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "local_ui_allow_internal_network", True)
    monkeypatch.setattr(gateway.settings, "xff_strict_internal", True)
    _reset_trusted_proxy(monkeypatch, "")
    request = _build_request(
        "/__ui__/login",
        method="GET",
        client_host="172.18.0.4",
        headers={"x-forwarded-for": "8.8.8.8"},
    )

    response = await gateway.security_boundary_middleware(request, _allow_next)

    assert response.status_code == 403
    assert _response_json(response)["error"]["code"] == "local_ui_network_restricted"


@pytest.mark.asyncio
async def test_xff_strict_internal_false_restores_old_admin_and_v1_and_ui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway.settings, "upstream_base_url", "http://cli-proxy-api:8317/v1"
    )
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway.settings, "local_ui_allow_internal_network", True)
    monkeypatch.setattr(gateway.settings, "xff_strict_internal", False)
    _reset_trusted_proxy(monkeypatch, "")
    headers = {"x-forwarded-for": "8.8.8.8"}

    admin = _build_request(
        "/__gw__/register",
        client_host="172.18.0.4",
        headers=headers,
        body={
            "upstream_base": "https://upstream.example.com/v1",
            "gateway_key": "agent",
        },
    )
    v1 = _build_request(
        "/v1/responses",
        token_authenticated=False,
        client_host="172.18.0.4",
        headers=headers,
        body={"input": "hello"},
    )
    ui = _build_request(
        "/__ui__/login",
        method="GET",
        client_host="172.18.0.4",
        headers=headers,
    )

    assert (
        await gateway.security_boundary_middleware(admin, _allow_next)
    ).status_code == 200
    assert (await gateway.security_boundary_middleware(v1, _allow_next)).status_code == 200
    assert (await gateway.security_boundary_middleware(ui, _allow_next)).status_code == 200
