"""P4 acceptance: Location / Set-Cookie / Access-Control-Allow-Origin writeback."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

import httpx
import pytest
from fastapi.testclient import TestClient

from aegisgate.config import settings as settings_module
from aegisgate.core import forward_routes, gw_forwards


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: Mapping[str, str] | None = None,
        chunks: tuple[bytes, ...] = (b"ok",),
    ) -> None:
        self.status_code = status_code
        self.headers = headers if headers is not None else {"content-type": "text/plain"}
        self._chunks = chunks

    async def aiter_raw(self):
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        return None


class _FakeClient:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.captured: dict[str, Any] = {}

    def build_request(self, method, url, headers=None, content=None, extensions=None):
        self.captured.update(url=url, headers=dict(headers or {}))
        return object()

    async def send(self, request, stream: bool = False):
        return self.response


def _entry(**overrides) -> dict:
    entry = {
        "enabled": True,
        "upstream_base": "https://api.xxx.com",
        "expose": "internal",
        "filters": {"mode": "policy"},
    }
    entry.update(overrides)
    return entry


@pytest.fixture()
def forward_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "gw_forwards.json"
    monkeypatch.setattr(settings_module.settings, "gw_forwards_path", str(path), raising=False)
    monkeypatch.setattr(settings_module.settings, "enable_gateway_forward", True, raising=False)
    monkeypatch.setattr(
        settings_module.settings, "forward_allow_public_baseline_off", False, raising=False
    )
    monkeypatch.setattr(
        settings_module.settings, "enable_request_hmac_auth", False, raising=False
    )
    path.write_text(
        json.dumps({"version": 1, "forwards": {"api.ag.com": _entry()}}), encoding="utf-8"
    )
    gw_forwards.load(replace=True)
    yield
    monkeypatch.setattr(
        settings_module.settings, "enable_gateway_forward", False, raising=False
    )
    gw_forwards.load(replace=True)


@contextmanager
def _client():
    from aegisgate.core.gateway import app

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        yield client


def _install(monkeypatch: pytest.MonkeyPatch, response: _FakeResponse) -> None:
    fake = _FakeClient(response)

    async def _get() -> _FakeClient:
        return fake

    monkeypatch.setattr(forward_routes, "_upstream_client", _get)


class TestRewriteHelpers:
    def test_absolute_location_mapped_to_gateway(self) -> None:
        assert (
            forward_routes.rewrite_location(
                "https://api.xxx.com/oauth/cb?code=1",
                upstream_host="api.xxx.com",
                gateway_origin="https://api.ag.com",
            )
            == "https://api.ag.com/oauth/cb?code=1"
        )

    def test_location_other_host_untouched(self) -> None:
        value = "https://elsewhere.test/x"
        assert (
            forward_routes.rewrite_location(
                value, upstream_host="api.xxx.com", gateway_origin="https://api.ag.com"
            )
            == value
        )

    def test_relative_location_untouched(self) -> None:
        assert (
            forward_routes.rewrite_location(
                "/dashboard", upstream_host="api.xxx.com", gateway_origin="https://api.ag.com"
            )
            == "/dashboard"
        )

    def test_set_cookie_domain_rewritten(self) -> None:
        rewritten = forward_routes.rewrite_set_cookie(
            "sid=1; Domain=api.xxx.com; Path=/; HttpOnly",
            upstream_host="api.xxx.com",
            gateway_host="api.ag.com",
        )
        assert "Domain=api.ag.com" in rewritten
        assert "api.xxx.com" not in rewritten
        assert "HttpOnly" in rewritten

    def test_set_cookie_parent_domain_rewritten(self) -> None:
        rewritten = forward_routes.rewrite_set_cookie(
            "sid=1; Domain=.xxx.com; Path=/",
            upstream_host="api.xxx.com",
            gateway_host="api.ag.com",
        )
        assert "Domain=api.ag.com" in rewritten

    def test_set_cookie_unmappable_domain_dropped(self) -> None:
        rewritten = forward_routes.rewrite_set_cookie(
            "sid=1; Domain=other.test; Path=/",
            upstream_host="api.xxx.com",
            gateway_host="api.ag.com",
        )
        assert "Domain" not in rewritten
        assert "Path=/" in rewritten

    def test_set_cookie_without_domain_untouched(self) -> None:
        value = "sid=1; Path=/; Secure"
        assert (
            forward_routes.rewrite_set_cookie(
                value, upstream_host="api.xxx.com", gateway_host="api.ag.com"
            )
            == value
        )

    def test_acao_upstream_origin_rewritten(self) -> None:
        assert (
            forward_routes.rewrite_access_control_allow_origin(
                "https://api.xxx.com",
                upstream_origin="https://api.xxx.com",
                gateway_origin="https://api.ag.com",
            )
            == "https://api.ag.com"
        )

    def test_acao_wildcard_untouched(self) -> None:
        assert (
            forward_routes.rewrite_access_control_allow_origin(
                "*",
                upstream_origin="https://api.xxx.com",
                gateway_origin="https://api.ag.com",
            )
            == "*"
        )


class TestIntegration:
    def test_location_and_acao_rewritten(self, forward_env, monkeypatch) -> None:
        _install(
            monkeypatch,
            _FakeResponse(
                status_code=302,
                headers={
                    "location": "https://api.xxx.com/dashboard",
                    "access-control-allow-origin": "https://api.xxx.com",
                },
            ),
        )
        with _client() as client:
            response = client.get(
                "/admin", headers={"Host": "api.ag.com"}, follow_redirects=False
            )
        assert response.status_code == 302
        assert response.headers["location"] == "http://api.ag.com/dashboard"
        assert response.headers["access-control-allow-origin"] == "http://api.ag.com"

    def test_each_set_cookie_is_rewritten_separately(self, forward_env, monkeypatch) -> None:
        headers = httpx.Headers(
            [
                ("content-type", "text/plain"),
                ("set-cookie", "a=1; Domain=api.xxx.com; Path=/"),
                ("set-cookie", "b=2; Domain=other.test; Path=/"),
            ]
        )
        _install(monkeypatch, _FakeResponse(headers=headers))
        with _client() as client:
            response = client.get("/x", headers={"Host": "api.ag.com"})
        cookies = response.headers.get_list("set-cookie")
        assert len(cookies) == 2
        assert cookies[0] == "a=1; Domain=api.ag.com; Path=/"
        assert "Domain" not in cookies[1]
        assert cookies[1].startswith("b=2;")
