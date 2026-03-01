import json

import pytest

from aegisgate.core import gateway
from aegisgate.core.gateway import GWTokenRewriteMiddleware


async def _run_asgi_request(app, *, path: str, headers: list[tuple[bytes, bytes]] | None = None) -> tuple[int, dict]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": headers or [],
    }

    state = {"sent": False}

    async def receive():
        if state["sent"]:
            return {"type": "http.disconnect"}
        state["sent"] = True
        return {"type": "http.request", "body": b"", "more_body": False}

    messages: list[dict] = []

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)

    status = 500
    payload: dict = {}
    for message in messages:
        if message.get("type") == "http.response.start":
            status = int(message.get("status", 500))
        if message.get("type") == "http.response.body":
            body = message.get("body", b"")
            if body:
                payload = json.loads(body.decode("utf-8"))
    return status, payload


@pytest.mark.asyncio
async def test_gw_token_rewrite_routes_to_responses_and_injects_headers(monkeypatch):
    mapping = {
        "upstream_base": "https://upstream.example.com/v1",
        "gateway_key": "agent",
        "whitelist_key": ["bn_key", "okx_key"],
    }
    monkeypatch.setattr(gateway, "gw_tokens_get", lambda token: mapping if token == "tok12345" else None)

    captured: dict[str, object] = {}

    async def downstream(scope, receive, send):
        captured["path"] = scope.get("path")
        captured["headers"] = list(scope.get("headers") or [])
        captured["aegis_token_authenticated"] = scope.get("aegis_token_authenticated")
        captured["aegis_upstream_base"] = scope.get("aegis_upstream_base")
        captured["aegis_gateway_key"] = scope.get("aegis_gateway_key")
        captured["aegis_redaction_whitelist_keys"] = scope.get("aegis_redaction_whitelist_keys")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{\"ok\": true}", "more_body": False})

    app = GWTokenRewriteMiddleware(downstream)
    status, _ = await _run_asgi_request(
        app,
        path="/v1/__gw__/t/tok12345/responses",
        headers=[
            (b"x-upstream-base", b"https://evil.example.com/v1"),
            (b"gateway-key", b"wrong"),
            (b"gateway_key", b"wrong2"),
            (b"authorization", b"Bearer demo"),
        ],
    )

    headers = {
        k.decode("latin-1").lower(): v.decode("utf-8")
        for k, v in (captured["headers"] or [])
    }
    assert status == 200
    assert captured["path"] == "/v1/responses"
    assert captured["aegis_token_authenticated"] is True
    assert captured["aegis_upstream_base"] == "https://upstream.example.com/v1"
    assert captured["aegis_gateway_key"] == "agent"
    assert captured["aegis_redaction_whitelist_keys"] == ["bn_key", "okx_key"]
    assert "x-upstream-base" not in headers
    assert "gateway-key" not in headers
    assert "gateway_key" not in headers
    assert headers["authorization"] == "Bearer demo"


@pytest.mark.asyncio
async def test_gw_token_rewrite_returns_404_when_token_not_found(monkeypatch):
    monkeypatch.setattr(gateway, "gw_tokens_get", lambda token: None)

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{\"ok\": true}", "more_body": False})

    app = GWTokenRewriteMiddleware(downstream)
    status, payload = await _run_asgi_request(app, path="/v1/__gw__/t/notfound/responses")

    assert status == 404
    assert payload["error"] == "token_not_found"


@pytest.mark.asyncio
async def test_gw_token_rewrite_supports_v2_routes(monkeypatch):
    mapping = {
        "upstream_base": "https://upstream.example.com/v1",
        "gateway_key": "agent",
        "whitelist_key": ["bn_key"],
    }
    monkeypatch.setattr(gateway, "gw_tokens_get", lambda token: mapping if token == "tok12345" else None)

    captured: dict[str, object] = {}

    async def downstream(scope, receive, send):
        captured["path"] = scope.get("path")
        captured["aegis_token_authenticated"] = scope.get("aegis_token_authenticated")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{\"ok\": true}", "more_body": False})

    app = GWTokenRewriteMiddleware(downstream)
    status, _ = await _run_asgi_request(app, path="/v2/__gw__/t/tok12345/proxy")

    assert status == 200
    assert captured["path"] == "/v2/proxy"
    assert captured["aegis_token_authenticated"] is True
