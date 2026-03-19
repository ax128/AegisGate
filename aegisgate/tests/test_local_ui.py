import json
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse
from starlette.requests import Request

from aegisgate.core import gateway
from aegisgate.core import gateway_ui_config


def _build_request(
    path: str,
    *,
    client_host: str = "127.0.0.1",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> Request:
    raw_headers = []
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
    }

    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def _find_route_handler(path: str, method: str):
    for route in gateway.app.router.routes:
        if not isinstance(route, APIRoute):
            continue
        if getattr(route, "path", None) != path:
            continue
        methods = getattr(route, "methods", None) or set()
        if method.upper() in methods:
            return route.endpoint
    raise AssertionError(f"route not found: {method} {path}")


async def _allow_next(_request: Request):
    return JSONResponse(status_code=200, content={"ok": True})


@asynccontextmanager
async def _async_client(*, headers: dict[str, str] | None = None):
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://127.0.0.1",
        headers=headers,
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_boundary_allows_local_ui_login_from_loopback_without_hmac_headers(monkeypatch):
    monkeypatch.setattr(gateway.settings, "enable_request_hmac_auth", True)
    request = _build_request("/__ui__/login", client_host="127.0.0.1")
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_blocks_local_ui_from_public_ip():
    request = _build_request("/__ui__", client_host="8.8.8.8")
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 403
    body = json.loads(bytes(response.body).decode("utf-8"))
    assert body["error"]["code"] == "local_ui_network_restricted"


@pytest.mark.asyncio
async def test_boundary_blocks_local_ui_from_private_ip_by_default():
    request = _build_request("/__ui__", client_host="10.0.0.8")
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 403
    body = json.loads(bytes(response.body).decode("utf-8"))
    assert body["error"]["code"] == "local_ui_network_restricted"


@pytest.mark.asyncio
async def test_boundary_allows_local_ui_from_private_ip_when_enabled(monkeypatch):
    monkeypatch.setattr(gateway.settings, "local_ui_allow_internal_network", True)
    request = _build_request("/__ui__/login", client_host="10.0.0.8")
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_boundary_redirects_unauthenticated_local_ui_requests():
    request = _build_request("/__ui__", client_host="127.0.0.1")
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 303
    assert response.headers["location"] == "/__ui__/login"


@pytest.mark.asyncio
async def test_boundary_allows_authenticated_local_ui_requests(monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_key", "agent")
    auth_request = _build_request("/__ui__/api/bootstrap", client_host="127.0.0.1", headers={"user-agent": "pytest"})
    cookie = gateway._create_ui_session_token(auth_request)
    request = _build_request(
        "/__ui__/api/bootstrap",
        client_host="127.0.0.1",
        headers={"cookie": f"{gateway._UI_SESSION_COOKIE}={cookie}", "user-agent": "pytest"},
    )
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_local_ui_login_rejects_default_password(monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_key", "agent")
    handler = _find_route_handler("/__ui__/api/login", "POST")
    request = _build_request(
        "/__ui__/api/login",
        method="POST",
        headers={"content-type": "application/json"},
        body=b'{"password":"admin123"}',
    )
    response = await handler(request)
    assert response.status_code == 403
    assert b"ui_login_failed" in response.body


def test_local_ui_bootstrap_returns_expected_fields():
    request = _build_request(
        "/__ui__/api/bootstrap",
        headers={"cookie": f"{gateway._UI_SESSION_COOKIE}=token", "user-agent": "pytest"},
    )
    payload = gateway.local_ui_bootstrap(request)
    assert payload["status"] == "running"
    assert payload["app_name"] == gateway.settings.app_name
    assert "server" in payload
    assert "security" in payload
    assert "v2" in payload
    assert "docs" in payload
    assert "ui" in payload


def test_local_ui_index_serves_html_file():
    response = gateway.local_ui_index()
    assert response.status_code == 200
    assert response.media_type == "text/html; charset=utf-8"


@pytest.mark.asyncio
async def test_login_and_docs_require_auth(monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_key", "agent")
    monkeypatch.setattr(gateway, "_is_loopback_ip", lambda host: host in {"127.0.0.1", "testclient"})
    async with _async_client() as client:
        bootstrap = await client.get("/__ui__/api/bootstrap", follow_redirects=False)
        assert bootstrap.status_code == 401

        failed = await client.post("/__ui__/api/login", json={"password": "wrong"})
        assert failed.status_code == 403

        default_password = await client.post("/__ui__/api/login", json={"password": "admin123"})
        assert default_password.status_code == 403

        logged_in = await client.post("/__ui__/api/login", json={"password": "agent"})
        assert logged_in.status_code == 200
        assert gateway._UI_SESSION_COOKIE in client.cookies

        docs_list = await client.get("/__ui__/api/docs")
        assert docs_list.status_code == 200
        items = docs_list.json()["items"]
        assert items

        doc_id = items[0]["id"]
        doc_content = await client.get(f"/__ui__/api/docs/{doc_id}")
        assert doc_content.status_code == 200
        assert "content" in doc_content.json()

        logout_without_csrf = await client.post("/__ui__/api/logout")
        assert logout_without_csrf.status_code == 403

        csrf_token = (await client.get("/__ui__/api/bootstrap")).json()["ui"]["csrf_token"]
        logout = await client.post("/__ui__/api/logout", headers={"x-aegis-ui-csrf": csrf_token})
        assert logout.status_code == 200


@pytest.mark.asyncio
async def test_ui_session_is_bound_to_user_agent(monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_key", "agent")
    monkeypatch.setattr(gateway, "_is_loopback_ip", lambda host: host in {"127.0.0.1", "testclient"})
    async with _async_client(headers={"user-agent": "agent-a"}) as client_a:
        login = await client_a.post("/__ui__/api/login", json={"password": "agent"})
        assert login.status_code == 200
        cookie = client_a.cookies.get(gateway._UI_SESSION_COOKIE)
        assert cookie is not None
    async with _async_client(headers={"user-agent": "agent-b"}) as client_b:
        client_b.cookies.set(gateway._UI_SESSION_COOKIE, cookie)
        response = await client_b.get("/__ui__/api/bootstrap")
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_ui_login_rate_limit(monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_key", "agent")
    monkeypatch.setattr(gateway, "_is_loopback_ip", lambda host: host in {"127.0.0.1", "testclient"})
    monkeypatch.setattr(gateway._UI_LOGIN_RATE_LIMITER, "_max", 1)
    gateway._UI_LOGIN_RATE_LIMITER._buckets.clear()
    async with _async_client() as client:
        first = await client.post("/__ui__/api/login", json={"password": "wrong"})
        assert first.status_code == 403
        second = await client.post("/__ui__/api/login", json={"password": "wrong"})
        assert second.status_code == 429


def test_ui_config_payload_contains_defaults():
    payload = gateway._ui_config_payload()
    items = payload["items"]
    assert isinstance(items, list)
    assert items
    first = items[0]
    assert "value" in first
    assert "default" in first
    assert "section" in first


@pytest.mark.asyncio
async def test_ui_config_update_persists_env(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(gateway.settings, "gateway_key", "agent")
    monkeypatch.setattr(gateway, "_is_loopback_ip", lambda host: host in {"127.0.0.1", "testclient"})
    env_path = tmp_path / ".env"
    env_path.write_text("AEGIS_LOG_LEVEL=info\nAEGIS_SECURITY_LEVEL=medium\n", encoding="utf-8")
    monkeypatch.setattr(gateway_ui_config, "_ENV_PATH", env_path)

    reloaded = {"called": False}

    def fake_reload_settings() -> None:
        reloaded["called"] = True

    monkeypatch.setattr("aegisgate.core.hot_reload.reload_settings", fake_reload_settings)

    async with _async_client() as client:
        login = await client.post("/__ui__/api/login", json={"password": "agent"})
        assert login.status_code == 200
        csrf_token = (await client.get("/__ui__/api/bootstrap")).json()["ui"]["csrf_token"]
        response = await client.post(
            "/__ui__/api/config",
            headers={"x-aegis-ui-csrf": csrf_token},
            json={
                "values": {
                    "log_level": "debug",
                    "strict_command_block_enabled": True,
                    "v2_enable_response_command_filter": False,
                }
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True

    saved = env_path.read_text(encoding="utf-8")
    assert "AEGIS_LOG_LEVEL=debug" in saved
    assert "AEGIS_STRICT_COMMAND_BLOCK_ENABLED=true" in saved
    assert "AEGIS_V2_ENABLE_RESPONSE_COMMAND_FILTER=false" in saved
    assert reloaded["called"] is True
