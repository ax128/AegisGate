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
    monkeypatch.setattr(gateway, "gw_tokens_register", lambda upstream, key, whitelist_key=None: ("token123", False))
    request = _build_request(
        "/__gw__/register",
        {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent", "whitelist_key": ["bn_key"]},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_register(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert body["baseUrl"] == "http://127.0.0.1:18080/v1/__gw__/t/token123"
    assert body["whitelist_key"] == ["bn_key"]


@pytest.mark.asyncio
async def test_gw_register_base_url_uses_forwarded_headers(monkeypatch):
    monkeypatch.setattr(gateway, "gw_tokens_register", lambda upstream, key, whitelist_key=None: ("token123", False))
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
    assert body["whitelist_key"] == []


def test_sanitize_public_host_replaces_zero_host():
    assert gateway._sanitize_public_host("0.0.0.0:18080") == "127.0.0.1:18080"


@pytest.mark.asyncio
async def test_gw_register_accepts_set_like_whitelist_payload(monkeypatch):
    captured: dict[str, object] = {}

    def fake_register(upstream, key, whitelist_key=None):
        captured["whitelist_key"] = whitelist_key
        return "token123", False

    monkeypatch.setattr(gateway, "gw_tokens_register", fake_register)
    request = _build_request(
        "/__gw__/register",
        {
            "upstream_base": "https://gmn.chuangzuoli.com/v1",
            "gateway_key": "agent",
            "whitelist_key": {"bn_key": True, "okx_key": 1, "skip": 0},
        },
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_register(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert captured["whitelist_key"] == ["bn_key", "okx_key"]
    assert body["whitelist_key"] == ["bn_key", "okx_key"]


@pytest.mark.asyncio
async def test_gw_register_rejects_non_string_upstream_base():
    request = _build_request(
        "/__gw__/register",
        {"upstream_base": ["https://api.example.com/v1"], "gateway_key": "agent"},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_register(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 400
    assert body["error"] == "missing_params"


@pytest.mark.asyncio
async def test_gw_register_rejects_example_upstream():
    request = _build_request(
        "/__gw__/register",
        {
            "upstream_base": "https://your-upstream.example.com/v1",
            "gateway_key": "agent",
        },
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_register(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 400
    assert body["error"] == "example_upstream_forbidden"


@pytest.mark.asyncio
async def test_gw_add_appends_whitelist_keys(monkeypatch):
    state = {
        "upstream_base": "https://gmn.chuangzuoli.com/v1",
        "gateway_key": "agent",
        "whitelist_key": ["bn_key"],
    }
    monkeypatch.setattr(gateway, "gw_tokens_get", lambda token: dict(state) if token == "tok123" else None)
    monkeypatch.setattr(gateway, "gw_tokens_find_token", lambda _upstream, _key: "tok123")
    captured: dict[str, object] = {}

    def fake_update(_token, *, upstream_base=None, gateway_key=None, whitelist_key=None):
        captured["upstream_base"] = upstream_base
        captured["gateway_key"] = gateway_key
        captured["whitelist_key"] = list(whitelist_key or [])
        state["upstream_base"] = str(upstream_base or state["upstream_base"])
        state["gateway_key"] = str(gateway_key or state["gateway_key"])
        state["whitelist_key"] = list(whitelist_key or [])
        return True

    monkeypatch.setattr(gateway, "gw_tokens_update", fake_update)
    request = _build_request(
        "/__gw__/add",
        {"token": "tok123", "gateway_key": "agent", "whitelist_key": ["okx_key", "bn_key"]},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_add(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 200
    assert body["added"] == ["okx_key"]
    assert body["whitelist_key"] == ["bn_key", "okx_key"]
    assert captured["upstream_base"] == "https://gmn.chuangzuoli.com/v1"
    assert captured["gateway_key"] == "agent"


@pytest.mark.asyncio
async def test_gw_add_replaces_upstream_base_when_provided(monkeypatch):
    state = {
        "upstream_base": "https://old.example.com/v1",
        "gateway_key": "agent",
        "whitelist_key": ["bn_key"],
    }
    monkeypatch.setattr(gateway, "gw_tokens_get", lambda token: dict(state) if token == "tok123" else None)
    monkeypatch.setattr(
        gateway,
        "gw_tokens_find_token",
        lambda upstream, key: "tok123" if (upstream, key) == ("https://new.example.com/v1", "agent") else None,
    )

    def fake_update(_token, *, upstream_base=None, gateway_key=None, whitelist_key=None):
        state["upstream_base"] = str(upstream_base or state["upstream_base"])
        state["gateway_key"] = str(gateway_key or state["gateway_key"])
        state["whitelist_key"] = list(whitelist_key or [])
        return True

    monkeypatch.setattr(gateway, "gw_tokens_update", fake_update)
    request = _build_request(
        "/__gw__/add",
        {
            "token": "tok123",
            "gateway_key": "agent",
            "upstream_base": "https://new.example.com/v1/",
            "whitelist_key": ["okx_key"],
        },
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_add(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 200
    assert body["upstream_base"] == "https://new.example.com/v1"
    assert body["whitelist_key"] == ["bn_key", "okx_key"]


@pytest.mark.asyncio
async def test_gw_add_rejects_upstream_pair_conflict(monkeypatch):
    monkeypatch.setattr(
        gateway,
        "gw_tokens_get",
        lambda token: {"upstream_base": "https://old.example.com/v1", "gateway_key": "agent", "whitelist_key": []}
        if token == "tok123"
        else None,
    )
    monkeypatch.setattr(gateway, "gw_tokens_find_token", lambda upstream, key: "othertok" if (upstream, key) == ("https://new.example.com/v1", "agent") else None)
    request = _build_request(
        "/__gw__/add",
        {
            "token": "tok123",
            "gateway_key": "agent",
            "upstream_base": "https://new.example.com/v1",
            "whitelist_key": ["okx_key"],
        },
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_add(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 409
    assert body["error"] == "upstream_pair_conflict"


@pytest.mark.asyncio
async def test_gw_remove_deletes_whitelist_keys(monkeypatch):
    state = {
        "upstream_base": "https://gmn.chuangzuoli.com/v1",
        "gateway_key": "agent",
        "whitelist_key": ["bn_key", "okx_key"],
    }
    monkeypatch.setattr(gateway, "gw_tokens_get", lambda token: dict(state) if token == "tok123" else None)

    def fake_update(_token, *, upstream_base=None, gateway_key=None, whitelist_key=None):
        state["upstream_base"] = str(upstream_base or state["upstream_base"])
        state["gateway_key"] = str(gateway_key or state["gateway_key"])
        state["whitelist_key"] = list(whitelist_key or [])
        return True

    monkeypatch.setattr(gateway, "gw_tokens_update", fake_update)
    request = _build_request(
        "/__gw__/remove",
        {"token": "tok123", "gateway_key": "agent", "whitelist_key": ["okx_key", "missing"]},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_remove(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 200
    assert body["removed"] == ["okx_key"]
    assert body["whitelist_key"] == ["bn_key"]


@pytest.mark.asyncio
async def test_gw_add_requires_token_gateway_key_and_whitelist_list():
    request = _build_request(
        "/__gw__/add",
        {"token": "tok123", "gateway_key": "agent", "whitelist_key": "okx_key"},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_add(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 400
    assert body["error"] == "missing_params"


@pytest.mark.asyncio
async def test_gw_add_rejects_gateway_key_mismatch(monkeypatch):
    monkeypatch.setattr(
        gateway,
        "gw_tokens_get",
        lambda token: {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent", "whitelist_key": []}
        if token == "tok123"
        else None,
    )
    request = _build_request(
        "/__gw__/add",
        {"token": "tok123", "gateway_key": "other", "whitelist_key": ["okx_key"]},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_add(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 403
    assert body["error"] == "gateway_key_mismatch"


@pytest.mark.asyncio
async def test_gw_register_without_whitelist_keeps_existing(monkeypatch):
    call_shape: dict[str, object] = {}
    state = {
        "upstream_base": "https://gmn.chuangzuoli.com/v1",
        "gateway_key": "agent",
        "whitelist_key": ["bn_key"],
    }

    def fake_register(*args):
        call_shape["arg_count"] = len(args)
        return "tok123", True

    monkeypatch.setattr(gateway, "gw_tokens_register", fake_register)
    monkeypatch.setattr(gateway, "gw_tokens_get", lambda token: dict(state) if token == "tok123" else None)
    request = _build_request(
        "/__gw__/register",
        {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent"},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_register(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 200
    assert call_shape["arg_count"] == 2
    assert body["already_registered"] is True
    assert body["whitelist_key"] == ["bn_key"]


@pytest.mark.asyncio
async def test_gw_add_returns_404_when_update_fails(monkeypatch):
    monkeypatch.setattr(
        gateway,
        "gw_tokens_get",
        lambda token: {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent", "whitelist_key": []}
        if token == "tok123"
        else None,
    )
    monkeypatch.setattr(gateway, "gw_tokens_find_token", lambda _upstream, _key: "tok123")
    monkeypatch.setattr(gateway, "gw_tokens_update", lambda *_args, **_kwargs: False)
    request = _build_request(
        "/__gw__/add",
        {"token": "tok123", "gateway_key": "agent", "whitelist_key": ["okx_key"]},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_add(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 404
    assert body["error"] == "token_not_found"


@pytest.mark.asyncio
async def test_gw_remove_returns_404_when_update_fails(monkeypatch):
    monkeypatch.setattr(
        gateway,
        "gw_tokens_get",
        lambda token: {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent", "whitelist_key": ["bn_key"]}
        if token == "tok123"
        else None,
    )
    monkeypatch.setattr(gateway, "gw_tokens_update", lambda *_args, **_kwargs: False)
    request = _build_request(
        "/__gw__/remove",
        {"token": "tok123", "gateway_key": "agent", "whitelist_key": ["bn_key"]},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_remove(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 404
    assert body["error"] == "token_not_found"


@pytest.mark.asyncio
async def test_gw_unregister_requires_token_and_gateway_key():
    request = _build_request(
        "/__gw__/unregister",
        {"token": "tok123"},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_unregister(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 400
    assert body["error"] == "missing_params"


@pytest.mark.asyncio
async def test_gw_unregister_rejects_gateway_key_mismatch(monkeypatch):
    monkeypatch.setattr(
        gateway,
        "gw_tokens_get",
        lambda token: {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent", "whitelist_key": []}
        if token == "tok123"
        else None,
    )
    request = _build_request(
        "/__gw__/unregister",
        {"token": "tok123", "gateway_key": "wrong"},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_unregister(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 403
    assert body["error"] == "gateway_key_mismatch"


@pytest.mark.asyncio
async def test_gw_unregister_success(monkeypatch):
    monkeypatch.setattr(
        gateway,
        "gw_tokens_get",
        lambda token: {"upstream_base": "https://gmn.chuangzuoli.com/v1", "gateway_key": "agent", "whitelist_key": []}
        if token == "tok123"
        else None,
    )
    monkeypatch.setattr(gateway, "gw_tokens_unregister", lambda token: token == "tok123")
    request = _build_request(
        "/__gw__/unregister",
        {"token": "tok123", "gateway_key": "agent"},
        headers={"host": "127.0.0.1:18080"},
    )
    resp = await gateway.gw_unregister(request)
    body = json.loads(resp.body.decode("utf-8"))
    assert resp.status_code == 200
    assert body["ok"] is True
