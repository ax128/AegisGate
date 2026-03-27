from __future__ import annotations

from typing import Any

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse


def _seed_policy(ctx, policy_name: str = "default") -> dict[str, object]:
    ctx.enabled_filters = {"redaction"}
    ctx.risk_threshold = 0.85
    return {"enabled_filters": set(ctx.enabled_filters), "threshold": ctx.risk_threshold}


def _install_route_mocks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    audit_calls: list[str] = []

    async def _inline_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    async def _identity_response_pipeline(pipeline, resp: InternalResponse, ctx):
        return resp

    async def _noop_semantic_review(*args, **kwargs):
        return None

    monkeypatch.setattr(openai_router.policy_engine, "resolve", _seed_policy)
    monkeypatch.setattr(openai_router, "_resolve_upstream_base", lambda headers: "http://upstream.test")
    monkeypatch.setattr(openai_router, "_build_upstream_url", lambda path, base: f"{base}{path}")
    monkeypatch.setattr(openai_router, "_build_forward_headers", lambda headers: {"x-forwarded-for": "test"})
    monkeypatch.setattr(openai_router, "_run_payload_transform", _inline_payload_transform)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", _identity_response_pipeline)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", _noop_semantic_review)
    monkeypatch.setattr(openai_router, "debug_log_original", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        openai_router,
        "_write_audit_event",
        lambda ctx, boundary=None: audit_calls.append(ctx.request_id),
    )
    return audit_calls


def _build_request(
    *,
    path: str,
    headers: list[tuple[bytes, bytes]] | None = None,
    scope_updates: dict[str, Any] | None = None,
) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers or [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    }
    if scope_updates:
        scope.update(scope_updates)
    return Request(scope)


@pytest.mark.asyncio
async def test_chat_request_redaction_preserves_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "gpt-5.4",
        "messages": [
            {
                "role": "user",
                "name": "alice",
                "content": [
                    {
                        "type": "text",
                        "text": "token=sk-live-secret",
                        "cache_control": {"type": "ephemeral"},
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": "https://example.com/cat.png"},
                    },
                ],
                "provider_meta": {"channel": "alpha"},
            }
        ],
        "request_id": "chat-redaction-shape",
        "session_id": "chat-redaction-shape",
    }
    forwarded_payloads: list[dict[str, Any]] = []
    audit_calls = _install_route_mocks(monkeypatch)

    async def fake_request_pipeline(pipeline, req: InternalRequest, ctx):
        assert req.messages[0].content == "token=sk-live-secret [IMAGE_CONTENT]"
        return req.model_copy(
            update={
                "messages": [
                    InternalMessage(
                        role="user",
                        content="[REDACTED:AWS_SECRET_ACCESS_KEY] [IMAGE_CONTENT]",
                        source="user",
                    )
                ]
            }
        )

    async def fake_forward_json(url: str, forwarded_payload: dict[str, Any], headers: dict[str, str]):
        forwarded_payloads.append(forwarded_payload)
        return 200, {
            "id": "chat-1",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }

    monkeypatch.setattr(openai_router, "_run_request_pipeline", fake_request_pipeline)
    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await openai_router._execute_chat_once(
        payload=payload,
        request_headers={},
        request_path="/v1/chat/completions",
        boundary={},
    )

    assert isinstance(result, dict)
    assert audit_calls == ["chat-redaction-shape"]
    assert len(forwarded_payloads) == 1
    forwarded_message = forwarded_payloads[0]["messages"][0]
    assert forwarded_message["role"] == "user"
    assert forwarded_message["name"] == "alice"
    assert forwarded_message["provider_meta"] == {"channel": "alpha"}
    assert forwarded_message["content"][0] == {
        "type": "text",
        "text": "token=[REDACTED:TOKEN]",
        "cache_control": {"type": "ephemeral"},
    }
    assert forwarded_message["content"][1] == {
        "type": "image_url",
        "image_url": {"url": "https://example.com/cat.png"},
    }


@pytest.mark.asyncio
async def test_chat_request_redaction_does_not_return_403(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "gpt-5.4",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Authorization: Bearer sk-live-secret"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/diagram.png"}},
                ],
            }
        ],
        "request_id": "chat-redaction-allow",
        "session_id": "chat-redaction-allow",
    }
    forwarded_payloads: list[dict[str, Any]] = []
    _install_route_mocks(monkeypatch)

    async def fake_request_pipeline(pipeline, req: InternalRequest, ctx):
        return req.model_copy(
            update={
                "messages": [
                    InternalMessage(
                        role="user",
                        content="[REDACTED:AUTH_BEARER] [IMAGE_CONTENT]",
                        source="user",
                    )
                ]
            }
        )

    async def fake_forward_json(url: str, forwarded_payload: dict[str, Any], headers: dict[str, str]):
        forwarded_payloads.append(forwarded_payload)
        return 200, {
            "id": "chat-allow",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }

    monkeypatch.setattr(openai_router, "_run_request_pipeline", fake_request_pipeline)
    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await openai_router._execute_chat_once(
        payload=payload,
        request_headers={},
        request_path="/v1/chat/completions",
        boundary={},
    )

    assert forwarded_payloads
    assert not isinstance(result, JSONResponse)


@pytest.mark.asyncio
async def test_responses_request_redaction_structured_input(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "gpt-5.4",
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "Authorization: Bearer sk-live-secret"},
                    {"type": "input_image", "image_url": "https://example.com/cat.png"},
                ],
                "provider_field": {"keep": True},
            }
        ],
        "request_id": "responses-redaction-shape",
        "session_id": "responses-redaction-shape",
    }
    forwarded_payloads: list[dict[str, Any]] = []
    audit_calls = _install_route_mocks(monkeypatch)

    async def fake_request_pipeline(pipeline, req: InternalRequest, ctx):
        assert req.messages[0].content == "Authorization: Bearer sk-live-secret [IMAGE_CONTENT]"
        return req.model_copy(
            update={
                "messages": [
                    InternalMessage(
                        role="user",
                        content="[REDACTED:AUTH_BEARER] [IMAGE_CONTENT]",
                        source="user",
                    )
                ]
            }
        )

    async def fake_forward_json(url: str, forwarded_payload: dict[str, Any], headers: dict[str, str]):
        forwarded_payloads.append(forwarded_payload)
        return 200, {
            "id": "resp-1",
            "object": "response",
            "model": "gpt-5.4",
            "output": [{"type": "output_text", "text": "ok"}],
        }

    monkeypatch.setattr(openai_router, "_run_request_pipeline", fake_request_pipeline)
    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await openai_router._execute_responses_once(
        payload=payload,
        request_headers={},
        request_path="/v1/responses",
        boundary={},
    )

    assert isinstance(result, dict)
    assert audit_calls == ["responses-redaction-shape"]
    assert forwarded_payloads[0]["input"] == [
        {
            "role": "user",
            "content": [
                {"type": "input_text", "text": "Authorization: Bearer [REDACTED:TOKEN]"},
                {"type": "input_image", "image_url": "https://example.com/cat.png"},
            ],
            "provider_field": {"keep": True},
        }
    ]


@pytest.mark.asyncio
async def test_messages_request_redaction_preserves_anthropic_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "claude-sonnet-4.5",
        "system": [
            {"type": "text", "text": "Authorization: Bearer sk-live-system-secret", "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": "Keep this guidance."},
        ],
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "token=sk-live-user-secret"},
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/cat.png"}},
                ],
                "metadata": {"segment": "alpha"},
            }
        ],
        "max_tokens": 256,
        "tool_choice": {"type": "auto"},
        "provider_meta": {"channel": "anthropic"},
        "request_id": "messages-redaction-shape",
        "session_id": "messages-redaction-shape",
    }
    forwarded_payloads: list[dict[str, Any]] = []
    audit_calls = _install_route_mocks(monkeypatch)

    async def fake_request_pipeline(pipeline, req: InternalRequest, ctx):
        assert req.route == "/v1/messages"
        assert [message.role for message in req.messages] == ["system", "user"]
        assert req.messages[0].content == "Authorization: Bearer sk-live-system-secret Keep this guidance."
        assert req.messages[1].content == "token=sk-live-user-secret [IMAGE_CONTENT]"
        return req.model_copy(
            update={
                "messages": [
                    InternalMessage(
                        role="system",
                        content="[REDACTED:AUTH_BEARER] Keep this guidance.",
                        source="system",
                    ),
                    InternalMessage(
                        role="user",
                        content="[REDACTED:AWS_SECRET_ACCESS_KEY] [IMAGE_CONTENT]",
                        source="user",
                    ),
                ]
            }
        )

    async def fake_forward_json(url: str, forwarded_payload: dict[str, Any], headers: dict[str, str]):
        forwarded_payloads.append(forwarded_payload)
        return 200, {
            "id": "msg-1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-sonnet-4.5",
        }

    monkeypatch.setattr(openai_router, "_run_request_pipeline", fake_request_pipeline)
    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)
    monkeypatch.setattr(openai_router, "_effective_gateway_headers", lambda request: {})

    result = await openai_router.messages(
        payload,
        _build_request(path="/v1/messages", scope_updates={"aegis_upstream_route_path": "/v1/messages"}),
    )

    assert isinstance(result, (dict, JSONResponse))
    assert audit_calls == ["messages-redaction-shape"]
    assert len(forwarded_payloads) == 1
    assert forwarded_payloads[0]["system"] == [
        {
            "type": "text",
            "text": "Authorization: Bearer [REDACTED:TOKEN]",
            "cache_control": {"type": "ephemeral"},
        },
        {"type": "text", "text": "Keep this guidance."},
    ]
    assert forwarded_payloads[0]["messages"] == [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "token=[REDACTED:TOKEN]"},
                {"type": "image", "source": {"type": "url", "url": "https://example.com/cat.png"}},
            ],
            "metadata": {"segment": "alpha"},
        }
    ]
    assert forwarded_payloads[0]["max_tokens"] == 256
    assert forwarded_payloads[0]["tool_choice"] == {"type": "auto"}
    assert forwarded_payloads[0]["provider_meta"] == {"channel": "anthropic"}


@pytest.mark.asyncio
async def test_messages_stream_request_redaction_preserves_anthropic_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "claude-sonnet-4.5",
        "system": [{"type": "text", "text": "Authorization: Bearer sk-live-system-secret"}],
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "token=sk-live-user-secret"},
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/cat.png"}},
                ],
            }
        ],
        "max_tokens": 256,
        "stream": True,
        "request_id": "messages-redaction-stream",
        "session_id": "messages-redaction-stream",
    }
    forwarded_payloads: list[dict[str, Any]] = []
    audit_calls = _install_route_mocks(monkeypatch)

    async def fake_request_pipeline(pipeline, req: InternalRequest, ctx):
        return req.model_copy(
            update={
                "messages": [
                    InternalMessage(
                        role="system",
                        content="[REDACTED:AUTH_BEARER]",
                        source="system",
                    ),
                    InternalMessage(
                        role="user",
                        content="[REDACTED:AWS_SECRET_ACCESS_KEY] [IMAGE_CONTENT]",
                        source="user",
                    ),
                ]
            }
        )

    async def fake_forward_stream_lines(
        url: str,
        forwarded_payload: dict[str, Any],
        headers: dict[str, str],
    ):
        forwarded_payloads.append(forwarded_payload)
        yield b"data: {\"type\":\"message_start\"}\n\n"
        yield b"data: [DONE]\n\n"

    monkeypatch.setattr(openai_router, "_run_request_pipeline", fake_request_pipeline)
    monkeypatch.setattr(openai_router, "_forward_stream_lines", fake_forward_stream_lines)
    monkeypatch.setattr(openai_router, "_effective_gateway_headers", lambda request: {})

    response = await openai_router.messages(
        payload,
        _build_request(path="/v1/messages", scope_updates={"aegis_upstream_route_path": "/v1/messages"}),
    )

    assert isinstance(response, StreamingResponse)
    body = b""
    async for chunk in response.body_iterator:
        body += bytes(chunk)
    assert b"message_start" in body
    assert len(forwarded_payloads) == 1
    assert forwarded_payloads[0]["system"] == [
        {"type": "text", "text": "Authorization: Bearer [REDACTED:TOKEN]"}
    ]
    assert forwarded_payloads[0]["messages"] == [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "token=[REDACTED:TOKEN]"},
                {"type": "image", "source": {"type": "url", "url": "https://example.com/cat.png"}},
            ],
        }
    ]
    assert audit_calls == ["messages-redaction-stream"]


@pytest.mark.asyncio
async def test_messages_request_redaction_avoids_generic_403(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "claude-sonnet-4.5",
        "system": [{"type": "text", "text": "Authorization: Bearer sk-live-system-secret"}],
        "messages": [{"role": "user", "content": [{"type": "text", "text": "token=sk-live-user-secret"}]}],
        "max_tokens": 256,
        "request_id": "messages-redaction-allow",
        "session_id": "messages-redaction-allow",
    }
    forwarded_payloads: list[dict[str, Any]] = []
    _install_route_mocks(monkeypatch)

    async def fake_request_pipeline(pipeline, req: InternalRequest, ctx):
        ctx.request_disposition = "sanitize"
        return req.model_copy(
            update={
                "messages": [
                    InternalMessage(role="system", content="[REDACTED:AUTH_BEARER]", source="system"),
                    InternalMessage(role="user", content="[REDACTED:AWS_SECRET_ACCESS_KEY]", source="user"),
                ]
            }
        )

    async def fake_forward_json(url: str, forwarded_payload: dict[str, Any], headers: dict[str, str]):
        forwarded_payloads.append(forwarded_payload)
        return 200, {
            "id": "msg-allow",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-sonnet-4.5",
        }

    monkeypatch.setattr(openai_router, "_run_request_pipeline", fake_request_pipeline)
    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)
    monkeypatch.setattr(openai_router, "_effective_gateway_headers", lambda request: {})

    result = await openai_router.messages(
        payload,
        _build_request(path="/v1/messages", scope_updates={"aegis_upstream_route_path": "/v1/messages"}),
    )

    assert forwarded_payloads
    assert not isinstance(result, JSONResponse) or result.status_code != 403
