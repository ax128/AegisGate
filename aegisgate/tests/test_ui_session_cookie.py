"""Console session cookies stay on /__ui__ and are not forwarded upstream."""

from __future__ import annotations

import re
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from aegisgate.core.gateway_auth import _UI_SESSION_COOKIE
from aegisgate.core.gateway_ui_routes import register_ui_routes

# Obvious stand-in. Not a session secret.
_FAKE_SESSION = "fake-console-session-0000"
_FAKE_PASSWORD = "fake-ui-password-0000"
_UI_COOKIE_PATH = "/__ui__"
_KEPT_COOKIE = "upstream_pref=keep-me"


def _cookie_path(set_cookie: str) -> str:
    match = re.search(r"(?i)(?:^|;)\s*Path=([^;]*)", set_cookie)
    if match is None:
        raise AssertionError("Set-Cookie is missing Path")
    return match.group(1).strip().strip('"')


def _ui_app(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    import aegisgate.core.gateway_keys as gateway_keys
    from aegisgate.config.settings import settings

    monkeypatch.setattr(settings, "gateway_key", _FAKE_PASSWORD)
    monkeypatch.setattr(gateway_keys, "_gateway_key_cached", _FAKE_PASSWORD)
    app = FastAPI()
    register_ui_routes(app)
    return TestClient(app)


def test_login_set_cookie_is_scoped_to_ui_path(monkeypatch: pytest.MonkeyPatch) -> None:
    with _ui_app(monkeypatch) as client:
        response = client.post("/__ui__/api/login", json={"password": _FAKE_PASSWORD})
    assert response.status_code == 200
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 1
    assert cookies[0].split("=", 1)[0] == _UI_SESSION_COOKIE
    assert _cookie_path(cookies[0]) == _UI_COOKIE_PATH


def test_logout_clears_ui_path_and_legacy_root_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _ui_app(monkeypatch) as client:
        response = client.post("/__ui__/api/logout")
    assert response.status_code == 200
    cookies = response.headers.get_list("set-cookie")
    assert [item.split("=", 1)[0] for item in cookies] == [
        _UI_SESSION_COOKIE,
        _UI_SESSION_COOKIE,
    ]
    assert [_cookie_path(item) for item in cookies] == [_UI_COOKIE_PATH, "/"]
    assert all("Max-Age=0" in item for item in cookies)


def test_gateway_key_rotation_reissues_session_cookie_on_ui_path(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aegisgate.core.gateway_keys as gateway_keys
    from aegisgate.config.settings import settings

    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "gateway_key", settings.gateway_key)
    monkeypatch.setattr(
        gateway_keys, "_gateway_key_cached", gateway_keys._gateway_key_cached
    )
    app = FastAPI()
    register_ui_routes(app)
    with TestClient(app) as client:
        response = client.post("/__ui__/api/keys/gateway/rotate")
    assert response.status_code == 200, response.text
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 1
    assert cookies[0].split("=", 1)[0] == _UI_SESSION_COOKIE
    assert _cookie_path(cookies[0]) == _UI_COOKIE_PATH


def _post_chat_and_capture_upstream_headers(
    monkeypatch: pytest.MonkeyPatch, cookie_header: str
) -> dict[str, str]:
    from aegisgate.adapters.openai_compat import router as openai_router
    from aegisgate.config import settings as settings_module
    from aegisgate.core.gateway import app

    monkeypatch.setattr(
        settings_module.settings,
        "upstream_base_url",
        "http://127.0.0.1:9/v1",
        raising=False,
    )
    monkeypatch.setattr(
        settings_module.settings, "enable_gateway_forward", False, raising=False
    )
    captured: dict[str, Any] = {}

    async def fake_forward_json(*, url, payload, headers, connect_urls, host_header):
        captured["url"] = url
        captured["headers"] = dict(headers)
        return 200, {
            "id": "chat-1",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }

    async def passthrough_pipeline(_pipeline, item, _ctx):
        return item

    async def no_semantic(*_args, **_kwargs):
        return None

    monkeypatch.setattr(openai_router, "_forward_json_with_pinning", fake_forward_json)
    monkeypatch.setattr(openai_router, "_run_request_pipeline", passthrough_pipeline)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", passthrough_pipeline)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", no_semantic)
    monkeypatch.setattr(openai_router, "_write_audit_event", lambda *a, **k: None)
    monkeypatch.setattr(openai_router, "debug_log_original", lambda *a, **k: None)

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        response = client.post(
            "/v1/chat/completions",
            headers={"Cookie": cookie_header},
            json={"model": "m", "messages": [{"role": "user", "content": "hi"}]},
        )
    assert response.status_code == 200, response.text
    assert str(captured["url"]).endswith("/v1/chat/completions")
    return {key.lower(): value for key, value in captured["headers"].items()}


def test_chat_completions_does_not_forward_console_session_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _post_chat_and_capture_upstream_headers(
        monkeypatch,
        f"{_UI_SESSION_COOKIE}={_FAKE_SESSION}; {_KEPT_COOKIE}",
    )
    assert sent.get("cookie") == _KEPT_COOKIE
    assert _FAKE_SESSION not in "\n".join(sent.values())


def _v2_request(cookie: str) -> Request:
    body = b"{}"
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v2/chat",
            "headers": [
                (b"x-target-url", b"https://upstream.example.com/v1/chat"),
                (b"content-type", b"application/json"),
                (b"cookie", cookie.encode("ascii")),
            ],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        },
        receive,
    )


@pytest.mark.asyncio
async def test_v2_proxy_does_not_forward_console_session_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.v2_proxy import router as v2_router

    monkeypatch.setattr(v2_router.settings, "v2_target_allowlist", "upstream.example.com")
    monkeypatch.setattr(v2_router.settings, "v2_block_internal_targets", False)
    monkeypatch.setattr(v2_router.settings, "v2_enable_request_redaction", False)
    monkeypatch.setattr(v2_router.settings, "v2_enable_response_command_filter", False)
    monkeypatch.setattr(v2_router.settings, "enable_exact_value_redaction", False)

    captured: dict[str, Any] = {}

    class _Upstream:
        status_code = 200
        headers = {"content-type": "application/json"}
        content = b'{"ok":true}'

    class _FakeClient:
        async def request(self, **kwargs: Any) -> _Upstream:
            captured["headers"] = dict(kwargs.get("headers") or {})
            return _Upstream()

    async def fake_get_v2_async_client() -> _FakeClient:
        return _FakeClient()

    monkeypatch.setattr(v2_router, "_get_v2_async_client", fake_get_v2_async_client)
    response = await v2_router.proxy_v2(
        _v2_request(f"{_UI_SESSION_COOKIE}={_FAKE_SESSION}; {_KEPT_COOKIE}")
    )
    assert response.status_code == 200
    sent = {key.lower(): value for key, value in captured["headers"].items()}
    assert sent.get("cookie") == _KEPT_COOKIE
    assert _FAKE_SESSION not in "\n".join(sent.values())
