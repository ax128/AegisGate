"""Guards for the console's first-run path and its feedback surfaces.

The console could accept an upstream the forwarder would later refuse, and the
one value a new user actually needs — the client ``base_url`` — was shown once
in a dialog and then nowhere. These tests pin the parts of that fix that are
cheap to break again:

* the upstream validator stays a *view* of the forwarder's rules, not a second
  copy that can drift;
* the reachability probe stays narrow (validated target, metadata hosts
  refused, no response body echoed back);
* the markup and scripts keep the affordances the fix introduced.

There is no browser in CI, so the front-end half is structural — the same
approach ``test_ui_stylesheet.py`` takes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.core import gateway_ui_config, gateway_ui_routes, hot_reload
from aegisgate.core.gateway_keys import upstream_base_error

_WWW = Path(__file__).resolve().parents[2] / "www"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(gateway_ui_config, "_ENV_PATH", tmp_path / ".env")
    monkeypatch.setattr(hot_reload, "reload_settings", lambda: None)
    monkeypatch.setattr(gateway_ui_routes, "write_audit", lambda payload: None)
    monkeypatch.setattr(
        gateway_ui_routes.settings,
        "gw_tokens_path",
        str(tmp_path / "gw_tokens.json"),
        raising=False,
    )
    import aegisgate.core.gw_tokens as gw_tokens

    monkeypatch.setattr(gw_tokens, "_tokens", {}, raising=False)

    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Upstream validation
# ---------------------------------------------------------------------------


class TestUpstreamValidator:
    """The console must never store a base the forwarder will reject.

    ``_normalize_upstream_base`` is the rule; ``upstream_base_error`` only
    translates its failures. Pinning the agreement here is what keeps them from
    becoming two independent lists.
    """

    ACCEPTED = (
        "https://api.openai.com/v1",
        "http://127.0.0.1:11434/v1",
        "http://host.docker.internal:8317/v1",
        "https://api.example.com",
    )
    REJECTED = (
        "api.openai.com/v1",
        "ftp://api.example.com/v1",
        "https://",
        "https://api.example.com/v1?key=x",
        "https://api.example.com/v1#frag",
        "",
    )

    @pytest.mark.parametrize("value", ACCEPTED)
    def test_accepted_values_are_forwardable(self, value: str) -> None:
        from aegisgate.adapters.openai_compat.upstream import _normalize_upstream_base

        assert upstream_base_error(value) is None
        # Whatever the console lets through, the forwarder must also accept.
        _normalize_upstream_base(value)

    @pytest.mark.parametrize("value", REJECTED)
    def test_rejected_values_report_a_chinese_reason(self, value: str) -> None:
        message = upstream_base_error(value)
        assert message, f"{value!r} should have been rejected"
        assert re.search(r"[一-鿿]", message), message

    def test_credentials_in_the_url_are_refused(self) -> None:
        """Stricter than the forwarder on purpose: userinfo leaks into logs."""
        assert upstream_base_error("https://user:pass@api.example.com/v1")

    def test_trailing_slash_is_not_an_error(self) -> None:
        assert upstream_base_error("https://api.example.com/v1/") is None


class TestTokenRoutesValidateUpstream:
    def test_register_rejects_a_scheme_less_upstream(self, client: TestClient) -> None:
        response = client.post(
            "/__ui__/api/tokens", json={"upstream_base": "api.openai.com/v1"}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_upstream_base"

    def test_register_accepts_a_valid_upstream(self, client: TestClient) -> None:
        response = client.post(
            "/__ui__/api/tokens", json={"upstream_base": "https://api.openai.com/v1"}
        )
        assert response.status_code == 201
        body = response.json()
        assert body["base_url"].endswith(f"/v1/__gw__/t/{body['token']}")

    def test_update_rejects_a_query_bearing_upstream(self, client: TestClient) -> None:
        created = client.post(
            "/__ui__/api/tokens", json={"upstream_base": "https://api.example.com/v1"}
        ).json()
        response = client.patch(
            f"/__ui__/api/tokens/{created['token']}",
            json={"upstream_base": "https://api.example.com/v1?key=leak"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_upstream_base"


# ---------------------------------------------------------------------------
# Reachability probe
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.text = "upstream body that must never reach the browser"


class _FakeClient:
    """Stands in for httpx.AsyncClient and records how it was constructed."""

    calls: list[dict[str, Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        type(self).calls.append(kwargs)
        self._kwargs = kwargs

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def request(self, method: str, url: str) -> _FakeResponse:
        type(self).calls[-1].setdefault("requests", []).append((method, url))
        return _FakeResponse(401)


@pytest.fixture()
def fake_httpx(monkeypatch: pytest.MonkeyPatch):
    import httpx

    _FakeClient.calls = []
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    return _FakeClient


class TestUpstreamProbe:
    def test_probe_reports_status_without_the_body(
        self, client: TestClient, fake_httpx: type[_FakeClient]
    ) -> None:
        response = client.post(
            "/__ui__/api/tokens/probe",
            json={"upstream_base": "https://api.example.com/v1"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["reachable"] is True
        assert body["status_code"] == 401
        assert "upstream body" not in response.text
        assert set(body) == {"ok", "reachable", "status_code", "elapsed_ms"}

    def test_probe_sends_one_request_without_following_redirects(
        self, client: TestClient, fake_httpx: type[_FakeClient]
    ) -> None:
        client.post(
            "/__ui__/api/tokens/probe",
            json={"upstream_base": "https://api.example.com/v1"},
        )
        call = fake_httpx.calls[-1]
        assert call["follow_redirects"] is False
        assert call["timeout"] == pytest.approx(3.0)
        assert call["requests"] == [("HEAD", "https://api.example.com/v1")]

    def test_probe_validates_the_target_like_registration_does(
        self, client: TestClient, fake_httpx: type[_FakeClient]
    ) -> None:
        response = client.post(
            "/__ui__/api/tokens/probe", json={"upstream_base": "api.example.com/v1"}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_upstream_base"
        assert fake_httpx.calls == []

    @pytest.mark.parametrize(
        "target",
        [
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal/v1",
        ],
    )
    def test_probe_refuses_cloud_metadata_endpoints(
        self, client: TestClient, fake_httpx: type[_FakeClient], target: str
    ) -> None:
        response = client.post("/__ui__/api/tokens/probe", json={"upstream_base": target})
        assert response.status_code == 400
        assert response.json()["error"] == "probe_target_forbidden"
        assert fake_httpx.calls == []

    def test_probe_allows_a_loopback_upstream(
        self, client: TestClient, fake_httpx: type[_FakeClient]
    ) -> None:
        """A local Ollama/vLLM upstream is the common case this page configures."""
        response = client.post(
            "/__ui__/api/tokens/probe",
            json={"upstream_base": "http://127.0.0.1:11434/v1"},
        )
        assert response.status_code == 200
        assert response.json()["reachable"] is True

    def test_probe_turns_a_transport_failure_into_a_readable_result(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import httpx

        class _Failing(_FakeClient):
            async def request(self, method: str, url: str) -> _FakeResponse:
                raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(httpx, "AsyncClient", _Failing)
        response = client.post(
            "/__ui__/api/tokens/probe",
            json={"upstream_base": "http://127.0.0.1:9/v1"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["reachable"] is False
        assert body["reason"] == "connect_error"
        assert "connection refused" in body["detail"]


# ---------------------------------------------------------------------------
# Console markup and scripts
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def html() -> str:
    return (_WWW / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def app_js() -> str:
    return (_WWW / "assets" / "app.js").read_text(encoding="utf-8")


class TestFirstRunPath:
    def test_overview_carries_the_getting_started_card(self, html: str) -> None:
        assert 'id="onboard-steps"' in html

    def test_token_table_exposes_the_client_base_url(self, html: str) -> None:
        assert "客户端 Base URL" in html

    def test_base_url_is_built_from_the_same_route_as_the_server(
        self, app_js: str
    ) -> None:
        """The console derives base_url client-side; the shape must not drift.

        gateway_auth._gateway_token_base_url owns the real one.
        """
        from aegisgate.core import gateway_auth

        server_src = Path(gateway_auth.__file__).read_text(encoding="utf-8")
        assert "/v1/__gw__/t/" in server_src
        assert "/v1/__gw__/t/${token}" in app_js

    def test_skip_link_precedes_the_sidebar(self, html: str) -> None:
        assert html.index('class="skip-link"') < html.index('class="sidebar"')


class TestFeedbackSurfaces:
    def test_restart_button_keeps_a_label_element(self, html: str, app_js: str) -> None:
        """Writing to button.textContent wiped the icon and never restored it."""
        assert 'id="restart-label"' in html
        assert 'btn.textContent = "重启中…"' not in app_js

    def test_unsaved_config_edits_prompt_before_unload(self, app_js: str) -> None:
        assert 'addEventListener("beforeunload"' in app_js
        assert "dirtyFields.size" in app_js

    def test_saving_a_section_does_not_reload_the_whole_console(
        self, app_js: str
    ) -> None:
        """loadBootstrap re-rendered every panel and reset the docs viewer."""
        save = app_js[app_js.index("async function saveSection") :]
        save = save[: save.index("\nfunction setActiveNav")]
        assert "loadBootstrap()" not in save
        assert "refreshOverview()" in save

    def test_tables_have_skeleton_and_actionable_empty_states(
        self, app_js: str
    ) -> None:
        assert "function showSkeleton" in app_js
        assert "data-empty-action" in app_js

    def test_config_search_spans_every_section(self, html: str, app_js: str) -> None:
        assert 'id="config-global-search"' in html
        assert "function filterAllSections" in app_js

    def test_docs_open_on_the_console_quickstart(self, app_js: str) -> None:
        assert 'PREFERRED_FIRST_DOC = "WEBUI-QUICKSTART.md"' in app_js

    def test_markdown_renders_tables_with_scoped_headers(self, app_js: str) -> None:
        assert "markdown-table" in app_js
        assert re.search(r"<th>(?!\$\{)", app_js) is None


class TestLoginPage:
    @pytest.fixture(scope="class")
    def login_html(self) -> str:
        return (_WWW / "login.html").read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def login_js(self) -> str:
        return (_WWW / "assets" / "login.js").read_text(encoding="utf-8")

    def test_key_lookup_commands_are_copyable(self, login_html: str) -> None:
        assert "docker compose exec aegisgate cat config/aegis_gateway.key" in login_html
        assert 'data-copy="cat config/aegis_gateway.key"' in login_html

    def test_rate_limited_login_gets_a_chinese_message(self, login_js: str) -> None:
        assert "429" in login_js
        assert "登录尝试过于频繁" in login_js

    def test_a_dropped_secure_cookie_is_explained(self, login_js: str) -> None:
        """Over HTTP the Secure cookie is discarded and the redirect bounced back
        to the login page with nothing on screen."""
        assert "AEGIS_LOCAL_UI_SECURE_COOKIE" in login_js
        assert "/__ui__/api/bootstrap" in login_js
