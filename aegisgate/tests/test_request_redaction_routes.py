from __future__ import annotations

from typing import Any

import pytest
from fastapi.responses import JSONResponse

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse


def _seed_policy(ctx, policy_name: str = "default") -> dict[str, object]:
    ctx.enabled_filters = {"redaction"}
    ctx.risk_threshold = 0.85
    return {"enabled_filters": set(ctx.enabled_filters), "threshold": ctx.risk_threshold}


def _install_route_mocks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    audit_calls: list[str] = []

    async def _identity_response_pipeline(pipeline, resp: InternalResponse, ctx):
        return resp

    async def _noop_semantic_review(*args, **kwargs):
        return None

    monkeypatch.setattr(openai_router.policy_engine, "resolve", _seed_policy)
    monkeypatch.setattr(openai_router, "_resolve_upstream_base", lambda headers: "http://upstream.test")
    monkeypatch.setattr(openai_router, "_build_upstream_url", lambda path, base: f"{base}{path}")
    monkeypatch.setattr(openai_router, "_build_forward_headers", lambda headers: {"x-forwarded-for": "test"})
    monkeypatch.setattr(openai_router, "_run_response_pipeline", _identity_response_pipeline)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", _noop_semantic_review)
    monkeypatch.setattr(openai_router, "debug_log_original", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        openai_router,
        "_write_audit_event",
        lambda ctx, boundary=None: audit_calls.append(ctx.request_id),
    )
    return audit_calls


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
    assert forwarded_message["content"] == [
        {
            "type": "text",
            "text": "[REDACTED:AWS_SECRET_ACCESS_KEY]",
            "cache_control": {"type": "ephemeral"},
        },
        {
            "type": "image_url",
            "image_url": {"url": "https://example.com/cat.png"},
        },
    ]


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
                {"type": "input_text", "text": "[REDACTED:AUTH_BEARER]"},
                {"type": "input_image", "image_url": "https://example.com/cat.png"},
            ],
            "provider_field": {"keep": True},
        }
    ]
