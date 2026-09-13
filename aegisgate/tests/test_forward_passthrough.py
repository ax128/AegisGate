"""P3 acceptance: the /__fwd__/ passthrough route and its forwarding behaviour."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

import httpx
import pytest
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient
from starlette.requests import Request

from aegisgate.config import settings as settings_module
from aegisgate.core import forward_routes, gw_forwards


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: Mapping[str, str] | None = None,
        chunks: tuple[bytes, ...] = (b"hello",),
    ) -> None:
        self.status_code = status_code
        self.headers = dict(headers or {"content-type": "application/json"})
        self._chunks = chunks
        self.closed = False

    async def aiter_raw(self):
        for chunk in self._chunks:
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class _FakeClient:
    def __init__(self, *, response: _FakeResponse | None = None, error: Exception | None = None):
        self.response = response or _FakeResponse()
        self.error = error
        self.captured: dict[str, Any] = {}

    def build_request(self, method, url, headers=None, content=None, extensions=None):
        self.captured.update(
            method=method,
            url=url,
            headers=dict(headers or {}),
            content=content,
            extensions=extensions,
        )
        return object()

    async def send(self, request, stream: bool = False):
        self.captured["stream"] = stream
        content = self.captured.get("content")
        if content is not None and not isinstance(content, (bytes, bytearray)):
            # A streamed upload: drain it the way httpx would.
            self.captured["streamed"] = True
            self.captured["content"] = b"".join([chunk async for chunk in content])
        if self.error is not None:
            raise self.error
        return self.response


async def _empty_receive() -> dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


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
    monkeypatch.setattr(settings_module.settings, "upstream_base_url", "http://127.0.0.1:9/v1", raising=False)

    def write(forwards: dict) -> None:
        path.write_text(json.dumps({"version": 1, "forwards": forwards}), encoding="utf-8")
        gw_forwards.load(replace=True)

    write({})
    yield write
    monkeypatch.setattr(
        settings_module.settings, "enable_gateway_forward", False, raising=False
    )
    gw_forwards.load(replace=True)


@contextmanager
def _client():
    from aegisgate.core.gateway import app

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        yield client


def _install_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeClient) -> _FakeClient:
    async def _get() -> _FakeClient:
        return fake

    monkeypatch.setattr(forward_routes, "_upstream_client", _get)
    return fake


class TestZeroChangeSnapshot:
    """§6.3: with no rule matching, every response is byte-identical to before."""

    SNAPSHOT = (
        ("GET", "/foo", 404, '{"detail":"Not Found"}'),
        ("GET", "/v1/models", 405, '{"detail":"Method Not Allowed"}'),
        ("OPTIONS", "/health", 405, '{"detail":"Method Not Allowed"}'),
        ("GET", "/__fwd__/x", 404, '{"detail":"Not Found"}'),
    )

    @pytest.mark.parametrize(("method", "path", "status", "body"), SNAPSHOT)
    def test_snapshot_matches_baseline(
        self, forward_env, method: str, path: str, status: int, body: str
    ) -> None:
        with _client() as client:
            response = client.request(method, path)
        assert response.status_code == status
        assert response.text == body


class TestForwarding:
    def test_get_is_forwarded_to_upstream(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            response = client.get(
                "/v1/models", headers={"Host": "api.ag.com"}
            )
        assert response.status_code == 200
        assert response.text == "hello"
        assert fake.captured["url"] == "https://api.xxx.com/v1/models"
        assert fake.captured["headers"]["Host"] == "api.xxx.com"
        assert fake.captured["extensions"] == {"sni_hostname": "api.xxx.com"}
        assert fake.captured["stream"] is True

    def test_query_string_is_preserved(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            client.get("/v1/models?limit=5&x=1", headers={"Host": "api.ag.com"})
        assert fake.captured["url"] == "https://api.xxx.com/v1/models?limit=5&x=1"

    def test_v1_other_post_is_forwarded_not_generic_proxy(
        self, forward_env, monkeypatch
    ) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            response = client.post(
                "/v1/embeddings",
                headers={"Host": "api.ag.com"},
                json={"input": "x"},
            )
        assert response.status_code == 200
        assert fake.captured["url"] == "https://api.xxx.com/v1/embeddings"

    def test_v2_path_is_forwarded_not_v2_proxy(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            client.get("/v2/models", headers={"Host": "api.ag.com"})
        assert fake.captured["url"] == "https://api.xxx.com/v2/models"

    def test_double_prefix_is_forwarded_verbatim(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            client.get("/__fwd__/x", headers={"Host": "api.ag.com"})
        assert fake.captured["url"] == "https://api.xxx.com/__fwd__/x"

    def test_client_trust_and_hop_by_hop_headers_are_stripped(
        self, forward_env, monkeypatch
    ) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            client.get(
                "/v1/models",
                headers={
                    "Host": "api.ag.com",
                    "x-aegis-filter-mode": "passthrough",
                    "x-upstream-base": "http://attacker.test",
                    "Connection": "keep-alive, x-drop-me",
                    "x-drop-me": "1",
                },
            )
        sent = {k.lower(): v for k, v in fake.captured["headers"].items()}
        assert "x-aegis-filter-mode" not in sent
        assert "x-upstream-base" not in sent
        assert "x-drop-me" not in sent
        assert "connection" not in sent

    def test_upstream_unreachable_is_502(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry()})
        _install_client(
            monkeypatch, _FakeClient(error=httpx.ConnectError("connection refused"))
        )
        with _client() as client:
            response = client.get("/v1/models", headers={"Host": "api.ag.com"})
        assert response.status_code == 502
        assert response.json()["error"]["code"] == "upstream_unreachable"
        # The exception text (addresses, errno) stays in the log.
        assert "refused" not in response.text

    def test_encoded_path_reaches_upstream_encoded(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            client.get("/files/a%2Fb%3Fx%23y?q=1", headers={"Host": "api.ag.com"})
        assert fake.captured["url"] == "https://api.xxx.com/files/a%2Fb%3Fx%23y?q=1"

    def test_content_length_upload_is_streamed(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            client.put("/v1/files/x", headers={"Host": "api.ag.com"}, content=b"0123456789")
        assert fake.captured["streamed"] is True
        assert fake.captured["content"] == b"0123456789"
        assert fake.captured["headers"]["Content-Length"] == "10"

    def test_request_without_body_sends_none(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            client.get("/v1/models", headers={"Host": "api.ag.com"})
        assert fake.captured["content"] == b""

    def test_chunked_body_over_the_cap_is_413(self, forward_env, monkeypatch) -> None:
        for name, value in (
            ("max_request_body_bytes", 8),
            ("v2_max_request_body_bytes", 0),
            ("forward_max_request_body_bytes", 8),
        ):
            monkeypatch.setattr(settings_module.settings, name, value, raising=False)
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())

        def chunks():
            yield b"0123456789"
            yield b"0123456789"

        with _client() as client:
            # DELETE: the boundary does not read the body of this method itself.
            response = client.request(
                "DELETE", "/v1/things/1", headers={"Host": "api.ag.com"}, content=chunks()
            )
        assert response.status_code == 413
        assert "url" not in fake.captured

    def test_spoofed_forwarding_headers_are_replaced(self, forward_env, monkeypatch) -> None:
        monkeypatch.setattr(settings_module.settings, "enforce_loopback_only", False, raising=False)
        forward_env({"api.ag.com": _entry(expose="public")})
        fake = _install_client(monkeypatch, _FakeClient())
        from aegisgate.core.gateway import app

        with TestClient(app, client=("8.8.8.8", 50000)) as client:
            client.get(
                "/admin",
                headers={
                    "Host": "api.ag.com",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "Forwarded": "for=127.0.0.1",
                },
            )
        sent = {k.lower(): v for k, v in fake.captured["headers"].items()}
        assert sent["x-forwarded-for"] == "8.8.8.8"
        assert sent["x-forwarded-host"] == "api.ag.com"
        assert "x-real-ip" not in sent
        assert "forwarded" not in sent

    def test_gateway_console_cookie_is_not_forwarded(self, forward_env, monkeypatch) -> None:
        from aegisgate.core.gateway_auth import _UI_SESSION_COOKIE

        assert _UI_SESSION_COOKIE.startswith(forward_routes._GATEWAY_COOKIE_PREFIX)
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            client.get(
                "/admin",
                headers={"Host": "api.ag.com", "Cookie": f"{_UI_SESSION_COOKIE}=s3cr3t; theirs=1"},
            )
        assert fake.captured["headers"]["cookie"] == "theirs=1"


class TestRawRelay:
    def test_encoding_and_length_travel_with_the_raw_body(self) -> None:
        out = forward_routes._build_client_response_headers(
            {
                "content-type": "text/html",
                "content-encoding": "br",
                "content-length": "42",
                "transfer-encoding": "chunked",
            }
        )
        assert out["content-encoding"] == "br"
        assert out["content-length"] == "42"
        assert "transfer-encoding" not in out

    async def test_mid_stream_error_still_closes_the_upstream(self) -> None:
        upstream = _FakeResponse(chunks=(b"data: a\n\n", httpx.ReadError("reset")))
        received = [chunk async for chunk in forward_routes._relay_body(upstream)]
        assert received == [b"data: a\n\n"]
        assert upstream.closed is True

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("/a/../b", "/b"),
            ("/../../etc/x", "/etc/x"),
            ("/a/./b/.", "/a/b/"),
            ("/a/%2e%2e/b", "/a/%2e%2e/b"),
            ("/", "/"),
        ],
    )
    def test_dot_segments_are_clamped_at_the_root(self, raw: str, expected: str) -> None:
        assert forward_routes._remove_dot_segments(raw) == expected


class TestRejectReasons:
    """§12.5: each forward reject reason, with the metric label recorded."""

    @pytest.fixture()
    def recorded(self, monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, str | None]]:
        from aegisgate.core import gateway

        calls: list[tuple[int, str | None]] = []
        original = gateway._record_request_observability

        def spy(**kwargs):
            calls.append((kwargs["status_code"], kwargs["reject_reason"]))
            return original(**kwargs)

        monkeypatch.setattr(gateway, "_record_request_observability", spy)
        return calls

    @pytest.mark.parametrize(
        ("entry", "reason"),
        [
            (_entry(enabled=False), "forward_rule_disabled"),
            (_entry(filters={"mode": "custom", "custom": {"nope": True}}), "forward_rule_invalid"),
        ],
    )
    def test_rule_state_reasons(self, forward_env, recorded, entry, reason) -> None:
        forward_env({"api.ag.com": entry})
        with _client() as client:
            response = client.get("/v1/models", headers={"Host": "api.ag.com"})
        assert response.status_code == 403
        assert response.json()["error_code"] == reason
        assert (403, reason) in recorded

    def test_config_invalid(self, forward_env, recorded, tmp_path) -> None:
        forward_env({"api.ag.com": _entry()})
        from aegisgate.config import settings as settings_module

        Path(settings_module.settings.gw_forwards_path).write_text("{ broken", encoding="utf-8")
        gw_forwards.load(replace=True)
        with _client() as client:
            response = client.get("/v1/models", headers={"Host": "api.ag.com"})
        assert response.json()["error_code"] == "forward_config_invalid"
        assert (403, "forward_config_invalid") in recorded

    def test_expose_internal(self, forward_env, recorded, monkeypatch) -> None:
        monkeypatch.setattr(settings_module.settings, "enforce_loopback_only", False, raising=False)
        forward_env({"api.ag.com": _entry(expose="internal")})
        fake = _install_client(monkeypatch, _FakeClient())
        from aegisgate.core.gateway import app

        with TestClient(app, client=("8.8.8.8", 50000)) as client:
            response = client.get("/v1/models", headers={"Host": "api.ag.com"})
        assert response.json()["error_code"] == "forward_expose_internal"
        assert (403, "forward_expose_internal") in recorded
        assert "url" not in fake.captured

    def test_duplicate_host_header(self, forward_env, recorded) -> None:
        forward_env({"api.ag.com": _entry()})
        with _client() as client:
            response = client.get(
                "/v1/models", headers=[("Host", "api.ag.com"), ("Host", "api.ag.com")]
            )
        assert response.status_code == 400
        assert response.json()["error_code"] == "duplicate_host_header"
        assert (400, "duplicate_host_header") in recorded


class TestStreaming:
    async def test_returns_streaming_response_and_passes_chunks(
        self, forward_env, monkeypatch
    ) -> None:
        forward_env({"api.ag.com": _entry()})
        fake = _install_client(
            monkeypatch,
            _FakeClient(
                response=_FakeResponse(
                    status_code=200,
                    headers={"content-type": "text/event-stream"},
                    chunks=(b"data: a\n\n", b"data: b\n\n"),
                )
            ),
        )
        rule = gw_forwards.get("api.ag.com")
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/__fwd__/events",
            "raw_path": b"/__fwd__/events",
            "root_path": "",
            "query_string": b"",
            "headers": [(b"host", b"api.ag.com")],
            "client": ("127.0.0.1", 5000),
            "server": ("127.0.0.1", 18080),
            "aegis_forward_rule": rule,
            "aegis_forward_path": "/events",
        }
        response = await forward_routes._forward_request(
            Request(scope, _empty_receive), rule
        )
        assert isinstance(response, StreamingResponse)
        chunks: list[bytes] = []
        async for chunk in response.body_iterator:
            chunks.append(chunk if isinstance(chunk, bytes) else bytes(chunk))
        assert b"".join(chunks) == b"data: a\n\ndata: b\n\n"
        assert fake.captured["url"] == "https://api.xxx.com/events"


class TestHttpUpstream:
    def test_http_upstream_sets_host_without_sni(self, forward_env, monkeypatch) -> None:
        forward_env({"api.ag.com": _entry(upstream_base="http://127.0.0.1:8317")})
        fake = _install_client(monkeypatch, _FakeClient())
        with _client() as client:
            response = client.get("/v1/models", headers={"Host": "api.ag.com"})
        assert response.status_code == 200
        assert fake.captured["url"] == "http://127.0.0.1:8317/v1/models"
        assert fake.captured["headers"]["Host"] == "127.0.0.1:8317"
        assert fake.captured["extensions"] is None


def test_forward_prefix_has_its_own_route_label() -> None:
    from aegisgate.core.gateway import _observability_route_label

    assert _observability_route_label("/__fwd__/v1/models") == "forward"


class TestBoundaryBodyCap:
    """§12.5: forwarded requests use forward_max_request_body_bytes; others keep 12MB."""

    @staticmethod
    def _request(path: str, *, content_length: int, forward_rule=None, token_auth: bool = False):
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "query_string": b"",
            "headers": [
                (b"content-length", str(content_length).encode()),
                (b"content-type", b"application/json"),
            ],
            "client": ("127.0.0.1", 5000),
            "server": ("127.0.0.1", 18080),
        }
        if forward_rule is not None:
            scope["aegis_forward_rule"] = forward_rule
        if token_auth:
            scope["aegis_token_authenticated"] = True
        return scope

    async def test_forward_request_gets_the_forward_cap(
        self, forward_env, monkeypatch
    ) -> None:
        from aegisgate.config import settings as settings_module
        from aegisgate.core import gateway
        from starlette.responses import JSONResponse

        monkeypatch.setattr(
            settings_module.settings, "max_request_body_bytes", 12_000_000, raising=False
        )
        # Isolate the forward bump from the v2 bump.
        monkeypatch.setattr(
            settings_module.settings, "v2_max_request_body_bytes", 0, raising=False
        )
        monkeypatch.setattr(
            settings_module.settings, "forward_max_request_body_bytes", 64_000_000, raising=False
        )
        forward_env({"api.ag.com": _entry()})
        rule = gw_forwards.get("api.ag.com")

        async def _allow(_request) -> JSONResponse:
            return JSONResponse(status_code=200, content={"ok": True})

        async def _receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        forwarded = await gateway.security_boundary_middleware(
            Request(
                self._request("/__fwd__/v1/embeddings", content_length=20_000_000, forward_rule=rule),
                _receive,
            ),
            _allow,
        )
        assert forwarded.status_code == 200

        # A non-forwarded path keeps the 12MB default and is rejected.
        plain = await gateway.security_boundary_middleware(
            Request(self._request("/foo", content_length=20_000_000), _receive), _allow
        )
        assert plain.status_code == 413
