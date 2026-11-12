"""Logout must make the presented UI session cookie unusable on the server.

The cookie is a stateless HMAC. Clearing it in the browser is not enough:
a copy replayed with the same client fingerprint has to be rejected, while a
different session that was never logged out keeps working.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.config.settings import settings
from aegisgate.core import gateway, gateway_keys, gateway_ui_routes

# Obvious fake. Not a gateway key, not a session secret.
_FAKE_GATEWAY_KEY = "fake-ui-logout-key-0000"
_USER_AGENT = "v8-logout-replay"
_SESSION_COOKIE = "aegis_ui_session"


def _install_fake_gateway_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "gateway_key", _FAKE_GATEWAY_KEY)
    monkeypatch.setattr(gateway_keys, "_gateway_key_cached", _FAKE_GATEWAY_KEY)
    monkeypatch.setattr(
        gateway,
        "_UI_LOGIN_RATE_LIMITER",
        gateway._AdminRateLimiter(max_per_minute=10),
    )


def _ui_app() -> FastAPI:
    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    app.middleware("http")(gateway.security_boundary_middleware)
    return app


def _session_value(response) -> str:
    for raw in response.headers.get_list("set-cookie"):
        if raw.startswith(f"{_SESSION_COOKIE}="):
            value = raw.split(";", 1)[0].split("=", 1)[1]
            if value:
                return value
    listed = response.headers.get_list("set-cookie")
    raise AssertionError(f"login did not set {_SESSION_COOKIE}: {listed}")


def _replay_headers(token: str, csrf: str | None = None) -> dict[str, str]:
    headers = {
        "user-agent": _USER_AGENT,
        "cookie": f"{_SESSION_COOKIE}={token}",
    }
    if csrf is not None:
        headers["x-aegis-ui-csrf"] = csrf
    return headers


def test_logout_rejects_replayed_session_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cookie captured before logout must not authenticate afterwards."""
    _install_fake_gateway_key(monkeypatch)
    with TestClient(_ui_app(), client=("127.0.0.88", 50000)) as client:
        first = client.post(
            "/__ui__/api/login",
            json={"password": _FAKE_GATEWAY_KEY},
            headers={"user-agent": _USER_AGENT},
        )
        assert first.status_code == 200, first.text
        stolen = _session_value(first)

        client.cookies.clear()
        opened = client.get(
            "/__ui__/api/bootstrap",
            headers=_replay_headers(stolen),
        )
        assert opened.status_code == 200, opened.text
        csrf = opened.json()["ui"]["csrf_token"]
        assert csrf

        second = client.post(
            "/__ui__/api/login",
            json={"password": _FAKE_GATEWAY_KEY},
            headers={"user-agent": _USER_AGENT},
        )
        assert second.status_code == 200, second.text
        other = _session_value(second)

        client.cookies.clear()
        logged_out = client.post(
            "/__ui__/api/logout",
            headers=_replay_headers(stolen, csrf),
        )
        assert logged_out.status_code == 200, logged_out.text
        cleared = " ".join(logged_out.headers.get_list("set-cookie")).lower()
        assert _SESSION_COOKIE in cleared
        assert "max-age=0" in cleared

        client.cookies.clear()
        replay = client.get(
            "/__ui__/api/bootstrap",
            headers=_replay_headers(stolen),
        )
        assert replay.status_code == 401, (
            "logged-out session cookie was still accepted: "
            f"{replay.status_code} {replay.text}"
        )
        assert replay.json()["error"] == "ui_auth_required"

        client.cookies.clear()
        survivor = client.get(
            "/__ui__/api/bootstrap",
            headers=_replay_headers(other),
        )
        assert survivor.status_code == 200, survivor.text
