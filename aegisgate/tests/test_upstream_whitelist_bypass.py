"""Pin A2: whitelist bypass skips both pipelines, with a public-client gate."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.requests import Request

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.adapters.openai_compat.upstream import (
    _is_upstream_whitelisted,
    _should_bypass_filters_for_whitelist,
)
from aegisgate.config.settings import settings
from aegisgate.core import gateway
from aegisgate.core.models import InternalRequest

_PII = "user@example.com"
_UPSTREAM = "https://upstream.example.com/v1"


def _seed_policy(ctx, policy_name: str = "default") -> dict[str, object]:
    ctx.enabled_filters = {"redaction"}
    ctx.risk_threshold = 0.85
    return {"enabled_filters": set(ctx.enabled_filters), "threshold": ctx.risk_threshold}


def _chat_payload() -> dict[str, Any]:
    return {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": f"email me at {_PII}"}],
        "request_id": "wl-chat",
        "session_id": "wl-chat",
    }


def _responses_payload() -> dict[str, Any]:
    return {
        "model": "gpt-5.4",
        "input": f"email me at {_PII}",
        "request_id": "wl-responses",
        "session_id": "wl-responses",
    }


def _messages_payload() -> dict[str, Any]:
    return {
        "model": "claude-sonnet-4.5",
        "max_tokens": 32,
        "messages": [{"role": "user", "content": f"email me at {_PII}"}],
        "request_id": "wl-messages",
        "session_id": "wl-messages",
    }


def _generic_payload() -> dict[str, Any]:
    return {
        "model": "generic-model",
        "input": f"email me at {_PII}",
        "request_id": "wl-generic",
        "session_id": "wl-generic",
    }


def _install_common_mocks(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {"payloads": [], "pipeline_calls": 0}

    async def fake_resolve(_headers):
        return (_UPSTREAM, (), "")

    async def fake_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    async def fake_request_pipeline(pipeline, req: InternalRequest, ctx):
        captured["pipeline_calls"] += 1
        return req

    async def fake_response_pipeline(pipeline, resp, ctx):
        return resp

    async def fake_forward_json(*, url, payload, headers, connect_urls, host_header):
        captured["payloads"].append(payload)
        if "messages" in str(payload.get("messages", "")) or payload.get("max_tokens"):
            return 200, {
                "id": "msg-1",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "ok"}],
                "model": "claude-sonnet-4.5",
            }
        if "input" in payload and "messages" not in payload:
            return 200, {
                "id": "resp-1",
                "object": "response",
                "status": "completed",
                "output": [],
            }
        return 200, {
            "id": "chat-1",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }

    async def fake_iter_stream(
        *, url, payload, headers, connect_urls, host_header
    ) -> AsyncGenerator[bytes, None]:
        captured["payloads"].append(payload)
        yield b'data: {"ok":true}\n\n'
        yield b"data: [DONE]\n\n"

    async def fake_semantic(*args, **kwargs):
        return None

    monkeypatch.setattr(openai_router.policy_engine, "resolve", _seed_policy)
    monkeypatch.setattr(openai_router, "_resolve_upstream_base", fake_resolve)
    monkeypatch.setattr(openai_router, "_run_payload_transform", fake_transform)
    monkeypatch.setattr(openai_router, "_run_request_pipeline", fake_request_pipeline)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", fake_response_pipeline)
    monkeypatch.setattr(openai_router, "_write_audit_event", lambda *a, **k: None)
    monkeypatch.setattr(openai_router, "debug_log_original", lambda *a, **k: None)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", fake_semantic)
    monkeypatch.setattr(
        openai_router, "_forward_json_with_pinning", fake_forward_json
    )
    monkeypatch.setattr(
        openai_router, "_iter_forward_stream_with_pinning", fake_iter_stream
    )
    monkeypatch.setattr(
        openai_router,
        "_build_streaming_response",
        lambda generator: generator
        if hasattr(generator, "__anext__")
        else StreamingResponse(generator, media_type="text/event-stream"),
    )
    return captured


async def _drain(response: object) -> bytes:
    if isinstance(response, JSONResponse):
        return bytes(response.body)
    chunks: list[bytes] = []
    if isinstance(response, StreamingResponse):
        async for chunk in response.body_iterator:
            chunks.append(bytes(chunk) if not isinstance(chunk, bytes) else chunk)
        return b"".join(chunks)
    async for chunk in response:  # type: ignore[union-attr]
        chunks.append(chunk)
    return b"".join(chunks)


@pytest.fixture
def whitelist_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "upstream_whitelist_url_list", _UPSTREAM)
    monkeypatch.setattr(settings, "allow_public_upstream_whitelist", False)
    monkeypatch.setattr(openai_router.settings, "upstream_whitelist_url_list", _UPSTREAM)
    monkeypatch.setattr(openai_router.settings, "allow_public_upstream_whitelist", False)
    yield
    # settings is a process singleton; fixture setattr already restored by monkeypatch.


@pytest.mark.parametrize(
    ("client_is_internal", "allow_public", "expected"),
    [
        (None, False, True),
        (True, False, True),
        (False, False, False),
        (False, True, True),
    ],
)
def test_should_bypass_filters_for_whitelist_public_gate(
    monkeypatch: pytest.MonkeyPatch,
    client_is_internal: bool | None,
    allow_public: bool,
    expected: bool,
) -> None:
    monkeypatch.setattr(settings, "upstream_whitelist_url_list", _UPSTREAM)
    monkeypatch.setattr(settings, "allow_public_upstream_whitelist", allow_public)
    assert _is_upstream_whitelisted(_UPSTREAM)
    boundary: dict[str, object]
    if client_is_internal is None:
        boundary = {}
    else:
        boundary = {"client_is_internal": client_is_internal}
    assert (
        _should_bypass_filters_for_whitelist(_UPSTREAM, boundary) is expected
    )


def test_should_not_bypass_when_upstream_not_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "upstream_whitelist_url_list", "")
    assert _should_bypass_filters_for_whitelist(_UPSTREAM, {}) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("execute", "payload", "path", "is_stream"),
    [
        (openai_router._execute_chat_once, _chat_payload, "/v1/chat/completions", False),
        (
            openai_router._execute_responses_once,
            _responses_payload,
            "/v1/responses",
            False,
        ),
        (openai_router._execute_messages_once, _messages_payload, "/v1/messages", False),
        (openai_router._execute_generic_once, _generic_payload, "/v1/embeddings", False),
        (
            openai_router._execute_chat_stream_once,
            _chat_payload,
            "/v1/chat/completions",
            True,
        ),
        (
            openai_router._execute_responses_stream_once,
            _responses_payload,
            "/v1/responses",
            True,
        ),
        (
            openai_router._execute_messages_stream_once,
            _messages_payload,
            "/v1/messages",
            True,
        ),
        (
            openai_router._execute_generic_stream_once,
            _generic_payload,
            "/v1/embeddings",
            True,
        ),
    ],
    ids=[
        "chat_once",
        "responses_once",
        "messages_once",
        "generic_once",
        "chat_stream",
        "responses_stream",
        "messages_stream",
        "generic_stream",
    ],
)
async def test_whitelist_bypass_forwards_plaintext_pii_on_eight_paths(
    monkeypatch: pytest.MonkeyPatch,
    whitelist_settings,
    execute,
    payload,
    path: str,
    is_stream: bool,
) -> None:
    captured = _install_common_mocks(monkeypatch)
    result = await execute(
        payload=payload(),
        request_headers={"X-Upstream-Base": _UPSTREAM},
        request_path=path,
        boundary={},
    )
    if is_stream:
        await _drain(result)
    assert captured["pipeline_calls"] == 0
    assert captured["payloads"], f"{execute.__name__} did not forward"
    blob = json.dumps(captured["payloads"][0], ensure_ascii=False)
    assert _PII in blob


@pytest.mark.asyncio
async def test_public_client_does_not_bypass_whitelist_when_flag_false(
    monkeypatch: pytest.MonkeyPatch,
    whitelist_settings,
) -> None:
    captured = _install_common_mocks(monkeypatch)
    result = await openai_router._execute_chat_once(
        payload=_chat_payload(),
        request_headers={"X-Upstream-Base": _UPSTREAM},
        request_path="/v1/chat/completions",
        boundary={"client_is_internal": False},
    )
    del result
    assert captured["pipeline_calls"] == 1


@pytest.mark.asyncio
async def test_boundary_sets_client_is_internal_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)

    async def _allow(_request: Request) -> JSONResponse:
        return JSONResponse(status_code=200, content={"ok": True})

    internal = _gateway_request("/v1/responses", client_host="127.0.0.1")
    await gateway.security_boundary_middleware(internal, _allow)
    assert internal.state.security_boundary["client_is_internal"] is True

    public = _gateway_request("/v1/responses", client_host="8.8.8.8")
    await gateway.security_boundary_middleware(public, _allow)
    assert public.state.security_boundary["client_is_internal"] is False


def test_startup_warns_that_whitelist_skips_redaction() -> None:
    source = (gateway.__file__ or "")
    text = open(source, encoding="utf-8").read()
    assert "unredacted original request body" in text
    assert "AEGIS_ALLOW_PUBLIC_UPSTREAM_WHITELIST" in text


def _gateway_request(path: str, *, client_host: str) -> Request:
    payload = json.dumps({"input": "hello"}).encode("utf-8")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode("latin-1")),
        ],
        "client": (client_host, 50000),
        "server": ("127.0.0.1", 18080),
        "aegis_token_authenticated": True,
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": payload, "more_body": False}

    return Request(scope, receive)
