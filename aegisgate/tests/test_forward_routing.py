"""P1 acceptance: Host resolution, matching, reserved paths, expose gate and branch split."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.responses import JSONResponse

from aegisgate.config import settings as settings_module
from aegisgate.core import forward_middleware, gateway_network, gw_forwards
from aegisgate.core.forward_middleware import HostForwardMiddleware, _is_reserved_path, route_host


class _Recorder:
    """Inner ASGI app: records the scope it was handed and answers 200."""

    def __init__(self) -> None:
        self.scopes: list[dict[str, Any]] = []

    async def __call__(self, scope, receive, send) -> None:
        self.scopes.append(scope)
        response = JSONResponse({"ok": True})
        await response(scope, receive, send)


def _scope(
    path: str,
    *,
    method: str = "GET",
    host: str | None = "api.ag.com",
    headers: dict[str, str] | None = None,
    client: tuple[str, int] = ("127.0.0.1", 51000),
    scope_type: str = "http",
    token_authenticated: bool = False,
) -> dict[str, Any]:
    raw_headers: list[tuple[bytes, bytes]] = []
    if host is not None:
        raw_headers.append((b"host", host.encode("latin-1")))
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode("latin-1"), value.encode("latin-1")))
    scope: dict[str, Any] = {
        "type": scope_type,
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "root_path": "",
        "query_string": b"",
        "headers": raw_headers,
        "client": client,
        "server": ("127.0.0.1", 18080),
    }
    if token_authenticated:
        scope["aegis_token_authenticated"] = True
    return scope


def _invoke(app, scope: dict[str, Any]) -> tuple[int, dict]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(
        m.get("body", b"") for m in messages if m["type"] == "http.response.body"
    )
    return start["status"], json.loads(body or b"{}")


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
def rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "gw_forwards.json"
    monkeypatch.setattr(settings_module.settings, "gw_forwards_path", str(path), raising=False)
    monkeypatch.setattr(settings_module.settings, "enable_gateway_forward", True, raising=False)
    monkeypatch.setattr(
        settings_module.settings, "forward_allow_public_baseline_off", False, raising=False
    )
    monkeypatch.setattr(
        settings_module.settings, "enable_request_hmac_auth", False, raising=False
    )
    monkeypatch.setattr(settings_module.settings, "trusted_proxy_ips", "", raising=False)
    monkeypatch.setattr(settings_module.settings, "xff_strict_internal", True, raising=False)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)

    def _load(forwards: dict) -> None:
        path.write_text(
            json.dumps({"version": 1, "forwards": forwards}), encoding="utf-8"
        )
        gw_forwards.load(replace=True)

    yield _load, path
    monkeypatch.setattr(
        settings_module.settings, "enable_gateway_forward", False, raising=False
    )
    monkeypatch.setattr(settings_module.settings, "trusted_proxy_ips", "", raising=False)
    gw_forwards.load(replace=True)


class TestRouteHost:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("API.Ag.com", "api.ag.com"),
            ("api.ag.com:443", "api.ag.com"),
            ("api.ag.com.", "api.ag.com"),
            ("[::1]:8080", "::1"),
            ("", ""),
        ],
    )
    def test_normalization(self, raw: str, expected: str) -> None:
        assert route_host(raw) == expected


class TestHostResolution:
    def test_untrusted_client_cannot_spoof_forwarded_host(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        recorder = _Recorder()
        status, _ = _invoke(
            HostForwardMiddleware(recorder),
            _scope("/v1/models", headers={"x-forwarded-host": "api.ag.com"}, host="evil.test"),
        )
        assert status == 200
        # The spoofed header bought nothing: Host did not match a rule.
        assert "aegis_forward_rule" not in recorder.scopes[0]

    def test_trusted_proxy_forwarded_host_is_honoured(
        self, rules, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        monkeypatch.setattr(settings_module.settings, "trusted_proxy_ips", "10.0.0.1", raising=False)
        monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
        monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
        recorder = _Recorder()
        _invoke(
            HostForwardMiddleware(recorder),
            _scope(
                "/v1/models",
                headers={"x-forwarded-host": "api.ag.com"},
                host="internal.gateway",
                client=("10.0.0.1", 40000),
            ),
        )
        assert recorder.scopes[0]["path"] == "/__fwd__/v1/models"

    def test_duplicate_host_header_is_rejected(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        scope = _scope("/v1/models")
        scope["headers"].append((b"host", b"api.ag.com"))
        recorder = _Recorder()
        status, body = _invoke(HostForwardMiddleware(recorder), scope)
        assert status == 400
        assert body["error_code"] == "duplicate_host_header"
        assert recorder.scopes == []


class TestMatching:
    def test_unknown_host_passes_through_untouched(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        recorder = _Recorder()
        original = _scope("/foo", host="other.test")
        _invoke(HostForwardMiddleware(recorder), original)
        assert recorder.scopes[0]["path"] == "/foo"
        assert "aegis_forward_rule" not in recorder.scopes[0]

    def test_disabled_rule_denies(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry(enabled=False)})
        recorder = _Recorder()
        status, body = _invoke(HostForwardMiddleware(recorder), _scope("/v1/models"))
        assert status == 403
        assert body["error_code"] == "forward_rule_disabled"
        assert recorder.scopes == []

    def test_invalid_rule_denies(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry(filters={"mode": "custom", "custom": {"nope": True}})})
        recorder = _Recorder()
        status, body = _invoke(HostForwardMiddleware(recorder), _scope("/v1/models"))
        assert status == 403
        assert body["error_code"] == "forward_rule_invalid"

    def test_forward_switch_off_passes_through(self, rules, monkeypatch) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        monkeypatch.setattr(
            settings_module.settings, "enable_gateway_forward", False, raising=False
        )
        recorder = _Recorder()
        _invoke(HostForwardMiddleware(recorder), _scope("/v1/models"))
        assert "aegis_forward_rule" not in recorder.scopes[0]

    def test_token_path_wins(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        recorder = _Recorder()
        _invoke(
            HostForwardMiddleware(recorder),
            _scope("/v1/models", token_authenticated=True),
        )
        assert recorder.scopes[0]["path"] == "/v1/models"
        assert "aegis_forward_rule" not in recorder.scopes[0]


class TestReservedPaths:
    @pytest.mark.parametrize(
        "path",
        ["/", "/metrics", "/health", "/ready", "/robots.txt", "/favicon.ico", "/__ui__", "/__ui__/assets/app.js", "/__gw__/register"],
    )
    def test_reserved_paths_never_forward(self, rules, monkeypatch, path: str) -> None:
        load, _ = rules
        # internal rule + public client: reserved paths must still be answered by
        # the gateway (pass-through), not turned into a 403.
        load({"api.ag.com": _entry(expose="internal")})
        recorder = _Recorder()
        status, _ = _invoke(
            HostForwardMiddleware(recorder),
            _scope(path, method="POST", client=("8.8.8.8", 40000)),
        )
        assert status == 200
        assert recorder.scopes[0]["path"] == path
        assert "aegis_forward_rule" not in recorder.scopes[0]

    def test_lookalike_prefix_is_not_reserved(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        recorder = _Recorder()
        _invoke(HostForwardMiddleware(recorder), _scope("/__ui__x", method="POST"))
        assert recorder.scopes[0]["path"] == "/__fwd__/__ui__x"


class TestExposeGate:
    def test_internal_rule_denies_public_client(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry(expose="internal")})
        recorder = _Recorder()
        status, body = _invoke(
            HostForwardMiddleware(recorder),
            _scope("/v1/models", client=("8.8.8.8", 40000)),
        )
        assert status == 403
        assert body["error_code"] == "forward_expose_internal"
        assert recorder.scopes == []

    def test_internal_rule_allows_internal_client(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry(expose="internal")})
        recorder = _Recorder()
        status, _ = _invoke(
            HostForwardMiddleware(recorder),
            _scope("/v1/models", client=("127.0.0.1", 40000)),
        )
        assert status == 200
        assert recorder.scopes[0]["path"] == "/__fwd__/v1/models"

    def test_public_rule_allows_public_client(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry(expose="public")})
        recorder = _Recorder()
        status, _ = _invoke(
            HostForwardMiddleware(recorder),
            _scope("/v1/models", client=("8.8.8.8", 40000)),
        )
        assert status == 200
        assert recorder.scopes[0]["path"] == "/__fwd__/v1/models"


class TestBranchMatrix:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("POST", "/v1/chat/completions"),
            ("POST", "/v1/responses"),
            ("POST", "/v1/messages"),
        ],
    )
    def test_llm_routes_keep_path_and_inject_contract(
        self, rules, method: str, path: str
    ) -> None:
        load, _ = rules
        load({"api.ag.com": _entry(upstream_base="http://127.0.0.1:8317")})
        recorder = _Recorder()
        _invoke(HostForwardMiddleware(recorder), _scope(path, method=method))
        scope = recorder.scopes[0]
        assert scope["path"] == path
        assert scope["aegis_token_authenticated"] is True
        assert scope["aegis_gateway_token"] == "forward:api.ag.com"
        assert scope["aegis_tenant_id"].startswith("forward:")
        assert scope["aegis_upstream_base"] == "http://127.0.0.1:8317"
        assert scope["aegis_filter_mode"] is None
        assert scope["aegis_forward_rule"].host == "api.ag.com"

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("POST", "/v1/embeddings"),
            ("POST", "/v1/files"),
            ("POST", "/v1/images/edits"),
            ("GET", "/v1/models"),
            ("GET", "/v1/messages"),
            ("POST", "/v2/x"),
            ("GET", "/relay/generate"),
            ("GET", "/admin"),
            ("DELETE", "/anything"),
        ],
    )
    def test_passthrough_routes_rewrite_prefix(
        self, rules, method: str, path: str
    ) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        recorder = _Recorder()
        _invoke(HostForwardMiddleware(recorder), _scope(path, method=method))
        scope = recorder.scopes[0]
        assert scope["path"] == f"/__fwd__{path}"
        assert scope["aegis_forward_path"] == path
        assert "aegis_token_authenticated" not in scope
        assert scope["aegis_forward_rule"].host == "api.ag.com"

    def test_trailing_slash_still_llm(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        recorder = _Recorder()
        _invoke(
            HostForwardMiddleware(recorder),
            _scope("/v1/chat/completions/", method="POST"),
        )
        assert recorder.scopes[0]["path"] == "/v1/chat/completions/"
        assert recorder.scopes[0]["aegis_token_authenticated"] is True

    def test_websocket_scope_untouched(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        recorded: list[dict[str, Any]] = []

        async def inner(scope, receive, send) -> None:
            recorded.append(scope)

        asyncio.run(
            HostForwardMiddleware(inner)(_scope("/ws", scope_type="websocket"), None, None)
        )
        assert recorded[0]["path"] == "/ws"
        assert "aegis_forward_rule" not in recorded[0]

    def test_client_trust_headers_stripped(self, rules) -> None:
        load, _ = rules
        load({"api.ag.com": _entry()})
        recorder = _Recorder()
        _invoke(
            HostForwardMiddleware(recorder),
            _scope(
                "/v1/chat/completions",
                method="POST",
                headers={
                    "x-upstream-base": "http://attacker.test",
                    "x-aegis-forward-host": "other.ag.com",
                    "x-aegis-redaction-whitelist": "ssn",
                },
            ),
        )
        names = {name.lower() for name, _ in recorder.scopes[0]["headers"]}
        assert b"x-upstream-base" not in names
        assert b"x-aegis-forward-host" not in names
        assert b"x-aegis-redaction-whitelist" not in names

    def test_scope_upstream_path_skips_ssrf(self, rules) -> None:
        from aegisgate.adapters.openai_compat.upstream import _effective_gateway_headers
        from starlette.requests import Request

        load, _ = rules
        load({"api.ag.com": _entry(upstream_base="http://127.0.0.1:8317")})
        recorder = _Recorder()
        _invoke(
            HostForwardMiddleware(recorder),
            _scope("/v1/chat/completions", method="POST"),
        )
        injected = recorder.scopes[0]
        headers = _effective_gateway_headers(Request(injected))
        assert headers["x-upstream-base"] == "http://127.0.0.1:8317"
        assert headers["x-aegis-upstream-source"] == "scope"


class TestCopyConsistencyGuards:
    def test_x_forwarded_host_has_one_read_point(self) -> None:
        package_root = Path(__file__).resolve().parents[1]
        offenders = []
        for path in package_root.rglob("*.py"):
            if "tests" in path.parts:
                continue
            if "x-forwarded-host" in path.read_text(encoding="utf-8").lower():
                offenders.append(path.relative_to(package_root).as_posix())
        assert offenders == ["core/gateway_network.py"]

    def test_public_base_url_uses_the_same_trust_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aegisgate.core.gateway_auth import _public_base_url
        from starlette.requests import Request

        monkeypatch.setattr(settings_module.settings, "trusted_proxy_ips", "10.0.0.1", raising=False)
        monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
        monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)
        request = Request(
            _scope(
                "/",
                host="internal.gateway",
                headers={"x-forwarded-host": "gw.example.com", "x-forwarded-proto": "https"},
                client=("10.0.0.1", 40000),
            )
        )
        assert gateway_network.trusted_forwarded_host(request) == "gw.example.com"
        assert _public_base_url(request) == "https://gw.example.com"

    def test_reserved_paths_cover_passthrough_admin_and_mounts(self) -> None:
        from aegisgate.core import gateway

        source_files = [
            path
            for path in (Path(__file__).resolve().parents[1]).rglob("*.py")
            if "tests" not in path.parts
            and "_RESERVED_PATHS: frozenset" in path.read_text(encoding="utf-8")
        ]
        assert [p.name for p in source_files] == ["forward_middleware.py"]

        assert gateway._PASSTHROUGH_PATHS <= forward_middleware._RESERVED_PATHS
        for endpoint in gateway._ADMIN_ENDPOINTS:
            assert _is_reserved_path(endpoint)
        for route in gateway.app.routes:
            if route.__class__.__name__ == "Mount":
                assert _is_reserved_path(getattr(route, "path", ""))
