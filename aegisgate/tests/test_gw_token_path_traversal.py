"""Token routes must reject '.' and '..' path segments before rewriting.

Starlette's TestClient removes literal dot segments before the ASGI app runs,
so ``/x/../chat/completions`` arrives already rewritten to a normal chat path.
Those cases build an ASGI scope and call the middleware directly. ``%2e%2e``
is different: TestClient decodes it and leaves ``..`` in ``scope["path"]``,
which is the path the middleware actually matches.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.adapters.openai_compat.upstream import _build_upstream_url
from aegisgate.config.settings import settings
from aegisgate.core import gw_tokens
from aegisgate.core.context import RequestContext
from aegisgate.core.gateway import GWTokenRewriteMiddleware, app

_UPSTREAM = "http://127.0.0.1:9/v1"
_CHAT = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}


class _Recorder:
    """Inner app that records the rewritten scope and answers 200."""

    def __init__(self) -> None:
        self.scopes: list[dict[str, Any]] = []

    async def __call__(self, scope, receive, send) -> None:
        self.scopes.append(scope)
        response = JSONResponse({"ok": True, "path": scope.get("path")})
        await response(scope, receive, send)


def _scope(path: str, *, method: str = "GET") -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }


async def _invoke(application, scope: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await application(scope, receive, send)
    start = next(item for item in messages if item["type"] == "http.response.start")
    body = b"".join(
        item.get("body", b"")
        for item in messages
        if item["type"] == "http.response.body"
    )
    parsed = json.loads(body.decode("utf-8")) if body else {}
    return int(start["status"]), parsed


@pytest.fixture()
def token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Register one token the same way the console's register handler does."""
    monkeypatch.setattr(settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    monkeypatch.setattr(gw_tokens, "_tokens", {})
    registered, _existed = gw_tokens.register(_UPSTREAM)
    return registered


@pytest.fixture()
def client(token: str):
    with TestClient(app, client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def _install_chat_capture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {"paths": []}
    original = openai_router._build_upstream_url

    def spy(path: str, base: str) -> str:
        captured["paths"].append(path)
        return original(path, base)

    async def fake_forward(*, url, payload, headers, connect_urls, host_header):
        captured["url"] = url
        captured["filter_mode"] = headers.get("x-aegis-filter-mode")
        return 200, {
            "id": "chat-1",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }

    async def passthrough_pipeline(_pipeline, item, _ctx):
        return item

    async def no_semantic(*_args, **_kwargs):
        return None

    monkeypatch.setattr(openai_router, "_build_upstream_url", spy)
    monkeypatch.setattr(openai_router, "_forward_json_with_pinning", fake_forward)
    monkeypatch.setattr(openai_router, "_run_request_pipeline", passthrough_pipeline)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", passthrough_pipeline)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", no_semantic)
    monkeypatch.setattr(openai_router, "_write_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(openai_router, "debug_log_original", lambda *args, **kwargs: None)
    return captured


@pytest.mark.parametrize(
    "tail",
    [
        "/../../admin",
        "/x/../chat/completions",
        "/%2e%2e/admin",
        "/%2E%2E/admin",
        "/./chat/completions",
        "/%2e/chat/completions",
    ],
)
async def test_dot_segments_are_rejected_before_rewrite(token: str, tail: str) -> None:
    recorder = _Recorder()
    status, body = await _invoke(
        GWTokenRewriteMiddleware(recorder),
        _scope(f"/v1/__gw__/t/{token}{tail}"),
    )
    assert status == 400
    assert body["error"] == "invalid_path"
    assert recorder.scopes == []


def test_percent_encoded_parent_segment_is_rejected(
    client: TestClient, token: str
) -> None:
    response = client.get(f"/v1/__gw__/t/{token}/%2e%2e/admin")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_path"


def test_normal_chat_path_is_rewritten(
    client: TestClient, token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _install_chat_capture(monkeypatch)
    response = client.post(
        f"/v1/__gw__/t/{token}/chat/completions",
        json=_CHAT,
    )
    assert response.status_code == 200, response.text
    assert captured["paths"] == ["/v1/chat/completions"]
    assert captured["url"] == "http://127.0.0.1:9/v1/chat/completions"


async def test_rewrite_keeps_path_and_raw_path_free_of_dot_segments(token: str) -> None:
    recorder = _Recorder()
    status, _body = await _invoke(
        GWTokenRewriteMiddleware(recorder),
        _scope(f"/v1/__gw__/t/{token}/chat/completions", method="POST"),
    )
    assert status == 200
    rewritten = recorder.scopes[0]
    assert rewritten["path"] == "/v1/chat/completions"
    assert rewritten["raw_path"] == b"/v1/chat/completions"
    assert "." not in _path_segments(rewritten["path"])
    assert rewritten["aegis_upstream_base"] == _UPSTREAM


async def test_dotted_filename_is_still_rewritten(token: str) -> None:
    recorder = _Recorder()
    status, _body = await _invoke(
        GWTokenRewriteMiddleware(recorder),
        _scope(f"/v1/__gw__/t/{token}/files/report.pdf"),
    )
    assert status == 200
    rewritten = recorder.scopes[0]
    assert rewritten["path"] == "/v1/files/report.pdf"
    assert rewritten["raw_path"] == b"/v1/files/report.pdf"


async def test_well_known_segment_is_not_a_dot_segment(token: str) -> None:
    recorder = _Recorder()
    status, _body = await _invoke(
        GWTokenRewriteMiddleware(recorder),
        _scope(f"/v1/__gw__/t/{token}/.well-known/jwks.json"),
    )
    assert status == 200
    rewritten = recorder.scopes[0]
    assert rewritten["path"] == "/v1/.well-known/jwks.json"
    assert rewritten["raw_path"] == b"/v1/.well-known/jwks.json"


async def test_rest_version_prefix_replaces_the_gateway_version(token: str) -> None:
    recorder = _Recorder()
    status, _body = await _invoke(
        GWTokenRewriteMiddleware(recorder),
        _scope(f"/v1/__gw__/t/{token}/v2/messages"),
    )
    assert status == 200
    rewritten = recorder.scopes[0]
    assert rewritten["path"] == "/v2/messages"
    assert rewritten["raw_path"] == b"/v2/messages"


async def test_token_without_a_suffix_rewrites_to_the_version_root(token: str) -> None:
    recorder = _Recorder()
    status, _body = await _invoke(
        GWTokenRewriteMiddleware(recorder),
        _scope(f"/v2/__gw__/t/{token}"),
    )
    assert status == 200
    rewritten = recorder.scopes[0]
    assert rewritten["path"] == "/v2"
    assert rewritten["raw_path"] == b"/v2"


async def test_redact_suffix_rewrites_chat_path(token: str) -> None:
    recorder = _Recorder()
    status, _body = await _invoke(
        GWTokenRewriteMiddleware(recorder),
        _scope(f"/v1/__gw__/t/{token}__redact/chat/completions", method="POST"),
    )
    assert status == 200
    rewritten = recorder.scopes[0]
    assert rewritten["path"] == "/v1/chat/completions"
    assert rewritten["raw_path"] == b"/v1/chat/completions"
    assert rewritten["aegis_filter_mode"] == "redact"


def test_v2_prefix_is_rewritten(
    client: TestClient, token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aegisgate.adapters.v2_proxy import router as v2_router

    captured: dict[str, Any] = {}

    async def fake_extract(request):
        captured["path"] = request.scope["path"]
        captured["raw_path"] = request.scope["raw_path"]
        return None, "stopped-before-upstream"

    monkeypatch.setattr(v2_router, "_extract_target_url", fake_extract)
    response = client.get(f"/v2/__gw__/t/{token}/proxy")
    assert response.status_code == 400
    assert captured["path"] == "/v2/proxy"
    assert captured["raw_path"] == b"/v2/proxy"


def test_unknown_token_returns_404(client: TestClient) -> None:
    response = client.get("/v1/__gw__/t/missing-token/chat/completions")
    assert response.status_code == 404
    assert response.json()["error"] == "token_not_found"


async def test_unknown_filter_mode_returns_400(token: str) -> None:
    recorder = _Recorder()
    status, body = await _invoke(
        GWTokenRewriteMiddleware(recorder),
        _scope(f"/v1/__gw__/t/{token}__nope/chat/completions"),
    )
    assert status == 400
    assert body["error"] == "invalid_filter_mode"
    assert recorder.scopes == []


@pytest.mark.parametrize(
    "path",
    [
        "/v1/../admin",
        "/v1/x/../chat/completions",
        "/v1/./chat/completions",
        "/v1/%2e%2e/admin",
        "/v1/%2E%2E/admin",
        "/v1/%2e/chat/completions",
        "/../admin",
    ],
)
def test_build_upstream_url_rejects_dot_segments(path: str) -> None:
    with pytest.raises(ValueError, match="^invalid_path$"):
        _build_upstream_url(path, _UPSTREAM)


def test_build_upstream_url_keeps_ordinary_paths() -> None:
    assert (
        _build_upstream_url("/v1/chat/completions", _UPSTREAM)
        == "http://127.0.0.1:9/v1/chat/completions"
    )
    assert (
        _build_upstream_url("/v1/files/report.pdf", _UPSTREAM)
        == "http://127.0.0.1:9/v1/files/report.pdf"
    )
    assert (
        _build_upstream_url("/v1/.well-known/jwks.json", _UPSTREAM)
        == "http://127.0.0.1:9/v1/.well-known/jwks.json"
    )
    assert (
        _build_upstream_url("/v1/files/..hidden", _UPSTREAM)
        == "http://127.0.0.1:9/v1/files/..hidden"
    )
    assert (
        _build_upstream_url("/v1/chat/completions?ref=..", _UPSTREAM)
        == "http://127.0.0.1:9/v1/chat/completions?ref=.."
    )


async def test_stream_transport_turns_dot_segment_into_400() -> None:
    from aegisgate.adapters.openai_compat.stream_transport import prepare_stream_transport

    ctx = RequestContext(
        request_id="req-test",
        session_id="sess-test",
        route="/v1/chat/completions",
    )

    async def resolve(_headers):
        return (_UPSTREAM, (), "")

    response = await prepare_stream_transport(
        ctx=ctx,
        request_headers={},
        request_path="/v1/../admin",
        forced_upstream_base=None,
        resolve_upstream_base=resolve,
        build_upstream_url=_build_upstream_url,
        build_connect_urls_for_path=lambda _path, _bases: (),
        build_forward_headers=lambda headers: dict(headers),
        with_trace_forward_headers=lambda headers, _request_id: dict(headers),
        invalid_upstream_response=lambda detail: JSONResponse(
            status_code=400,
            content={"error": "invalid_upstream_base", "detail": detail},
        ),
        invalid_upstream_logger=lambda _request_id, _detail: None,
    )
    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert json.loads(response.body)["detail"] == "invalid_path"


def _path_segments(path: str) -> list[str]:
    return path.split("/")
