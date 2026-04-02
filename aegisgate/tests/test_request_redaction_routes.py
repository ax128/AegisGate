from __future__ import annotations

from typing import Any

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.kv import KVStore


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

    async def _noop_store_io(*args, **kwargs):
        return None

    monkeypatch.setattr(openai_router.policy_engine, "resolve", _seed_policy)
    monkeypatch.setattr(openai_router, "_resolve_upstream_base", lambda headers: "http://upstream.test")
    monkeypatch.setattr(openai_router, "_build_upstream_url", lambda path, base: f"{base}{path}")
    monkeypatch.setattr(openai_router, "_build_forward_headers", lambda headers: {"x-forwarded-for": "test"})
    monkeypatch.setattr(openai_router, "_run_payload_transform", _inline_payload_transform)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", _identity_response_pipeline)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", _noop_semantic_review)
    monkeypatch.setattr(openai_router, "run_store_io", _noop_store_io)
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
    scope: dict[str, Any] = {
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


def _to_bytes(value: bytes | str | memoryview[int]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return value.tobytes()


class _MemoryKVStore(KVStore):
    def __init__(self) -> None:
        self._mappings: dict[tuple[str, str], dict[str, str]] = {}

    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        self._mappings[(session_id, request_id)] = dict(mapping)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return dict(self._mappings.get((session_id, request_id), {}))

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return self._mappings.pop((session_id, request_id), {})

    def save_pending_confirmation(self, **kwargs) -> None:  # pragma: no cover
        raise AssertionError("unexpected confirmation persistence in request redaction test")

    def get_latest_pending_confirmation(self, *args, **kwargs):  # pragma: no cover
        return None

    def get_single_pending_confirmation(self, *args, **kwargs):  # pragma: no cover
        return None

    def compare_and_update_pending_confirmation_status(self, **kwargs) -> bool:  # pragma: no cover
        return False

    def get_pending_confirmation(self, confirm_id: str):  # pragma: no cover
        return None

    def update_pending_confirmation_status(self, **kwargs) -> None:  # pragma: no cover
        raise AssertionError("unexpected confirmation status update in request redaction test")

    def delete_pending_confirmation(self, **kwargs) -> bool:  # pragma: no cover
        return False

    def prune_pending_confirmations(self, now_ts: int) -> int:  # pragma: no cover
        return 0

    def clear_all_pending_confirmations(self) -> int:  # pragma: no cover
        return 0


def _install_real_redaction_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    redaction_filter = RedactionFilter(_MemoryKVStore())

    async def _run_real_redaction_only(pipeline, req: InternalRequest, ctx):
        return redaction_filter.process_request(req, ctx)

    monkeypatch.setattr(openai_router, "_run_request_pipeline", _run_real_redaction_only)


def _explicit_secret_prompt() -> str:
    return "Authorization: Bearer " + "sk-live-" + "secretvalue123456"


async def _run_supported_v1_route(
    monkeypatch: pytest.MonkeyPatch,
    *,
    route_name: str,
    prompt_text: str,
) -> tuple[dict | JSONResponse | StreamingResponse, str]:
    forwarded_payloads: list[dict[str, Any]] = []
    _install_route_mocks(monkeypatch)
    _install_real_redaction_pipeline(monkeypatch)

    async def fake_forward_json(url: str, forwarded_payload: dict[str, Any], headers: dict[str, str]):
        forwarded_payloads.append(forwarded_payload)
        if route_name == "chat":
            return 200, {
                "id": "chat-benign",
                "object": "chat.completion",
                "model": "gpt-5.4",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }
        if route_name == "responses":
            return 200, {
                "id": "resp-benign",
                "object": "response",
                "model": "gpt-5.4",
                "output": [{"type": "output_text", "text": "ok"}],
            }
        return 200, {
            "id": "msg-benign",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-sonnet-4.5",
        }

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    if route_name == "chat":
        result = await openai_router._execute_chat_once(
            payload={
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": prompt_text}],
                "request_id": "chat-benign-examples",
                "session_id": "chat-benign-examples",
            },
            request_headers={},
            request_path="/v1/chat/completions",
            boundary={},
        )
        return result, forwarded_payloads[0]["messages"][0]["content"]

    if route_name == "responses":
        result = await openai_router._execute_responses_once(
            payload={
                "model": "gpt-5.4",
                "input": prompt_text,
                "request_id": "responses-benign-examples",
                "session_id": "responses-benign-examples",
            },
            request_headers={},
            request_path="/v1/responses",
            boundary={},
        )
        return result, forwarded_payloads[0]["input"]

    monkeypatch.setattr(openai_router, "_effective_gateway_headers", lambda request: {})
    result = await openai_router.messages(
        {
            "model": "claude-sonnet-4.5",
            "messages": [{"role": "user", "content": prompt_text}],
            "max_tokens": 128,
            "request_id": "messages-benign-examples",
            "session_id": "messages-benign-examples",
        },
        _build_request(path="/v1/messages", scope_updates={"aegis_upstream_route_path": "/v1/messages"}),
    )
    return result, forwarded_payloads[0]["messages"][0]["content"]


async def _run_supported_v1_compat_route(
    monkeypatch: pytest.MonkeyPatch,
    *,
    route_name: str,
    prompt_text: str,
) -> tuple[dict | JSONResponse | StreamingResponse, str]:
    forwarded_payloads: list[dict[str, Any]] = []
    _install_route_mocks(monkeypatch)
    _install_real_redaction_pipeline(monkeypatch)

    async def fake_forward_json(url: str, forwarded_payload: dict[str, Any], headers: dict[str, str]):
        forwarded_payloads.append(forwarded_payload)
        if route_name == "chat_from_responses":
            return 200, {
                "id": "resp-compat-chat",
                "object": "response",
                "model": "gpt-5.4",
                "output_text": "ok",
                "output": [{"type": "message", "content": [{"type": "output_text", "text": "ok"}]}],
            }
        if route_name == "responses_from_chat":
            return 200, {
                "id": "chat-compat-responses",
                "object": "chat.completion",
                "model": "gpt-5.4",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }
        return 200, {
            "id": "resp-compat-messages",
            "object": "response",
            "model": "gpt-5.4",
            "output_text": "ok",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "ok"}]}],
        }

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    if route_name == "chat_from_responses":
        result = await openai_router.chat_completions(
            {
                "model": "gpt-5.4",
                "input": prompt_text,
                "request_id": "chat-compat-redaction",
                "session_id": "chat-compat-redaction",
            },
            _build_request(path="/v1/chat/completions"),
        )
        return result, forwarded_payloads[0]["input"]

    if route_name == "responses_from_chat":
        result = await openai_router.responses(
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": prompt_text}],
                "request_id": "responses-compat-redaction",
                "session_id": "responses-compat-redaction",
            },
            _build_request(path="/v1/responses"),
        )
        return result, forwarded_payloads[0]["messages"][0]["content"]

    monkeypatch.setattr(openai_router, "_effective_gateway_headers", lambda request: {})
    result = await openai_router.messages(
        {
            "model": "claude-sonnet-4.5",
            "messages": [{"role": "user", "content": prompt_text}],
            "max_tokens": 128,
            "request_id": "messages-compat-redaction",
            "session_id": "messages-compat-redaction",
        },
        _build_request(
            path="/v1/messages",
            scope_updates={"aegis_compat": "openai_chat"},
        ),
    )
    return result, forwarded_payloads[0]["input"][0]["content"]


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
        body += _to_bytes(chunk)
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


@pytest.mark.asyncio
async def test_benign_examples_avoid_false_positives(monkeypatch: pytest.MonkeyPatch) -> None:
    benign_prompt = (
        "Review this infra note without redacting it: host api.service.internal resolves to 10.24.8.9, "
        "and the sample docs line is address: 123 Example Lane."
    )

    for route_name in ("chat", "responses", "messages"):
        _, forwarded_text = await _run_supported_v1_route(
            monkeypatch,
            route_name=route_name,
            prompt_text=benign_prompt,
        )
        assert forwarded_text == benign_prompt


@pytest.mark.asyncio
async def test_benign_examples_do_not_trigger_403(monkeypatch: pytest.MonkeyPatch) -> None:
    benign_prompt = (
        "Security review snippet: the dev host admin.corp.internal points to 10.0.0.12 and "
        "the mock address field is address: 42 Example Road."
    )

    for route_name in ("chat", "responses", "messages"):
        result, forwarded_text = await _run_supported_v1_route(
            monkeypatch,
            route_name=route_name,
            prompt_text=benign_prompt,
        )
        assert forwarded_text == benign_prompt
        assert not isinstance(result, JSONResponse) or result.status_code != 403


@pytest.mark.asyncio
async def test_explicit_secret_still_redacts_on_supported_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_prompt = _explicit_secret_prompt()

    for route_name in ("chat", "responses", "messages"):
        _, forwarded_text = await _run_supported_v1_route(
            monkeypatch,
            route_name=route_name,
            prompt_text=secret_prompt,
        )
        assert forwarded_text != secret_prompt
        assert "sk-live-" not in forwarded_text


@pytest.mark.asyncio
async def test_benign_examples_avoid_false_positives_on_compat_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    benign_prompt = (
        "Review this infra note without redacting it: host api.service.internal resolves to 10.24.8.9, "
        "and the sample docs line is address: 123 Example Lane."
    )

    for route_name in ("chat_from_responses", "responses_from_chat", "messages_compat"):
        _, forwarded_text = await _run_supported_v1_compat_route(
            monkeypatch,
            route_name=route_name,
            prompt_text=benign_prompt,
        )
        assert forwarded_text == benign_prompt


@pytest.mark.asyncio
async def test_explicit_secret_still_redacts_on_compat_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_prompt = _explicit_secret_prompt()

    for route_name in ("chat_from_responses", "responses_from_chat", "messages_compat"):
        result, forwarded_text = await _run_supported_v1_compat_route(
            monkeypatch,
            route_name=route_name,
            prompt_text=secret_prompt,
        )
        assert forwarded_text != secret_prompt
        assert "sk-live-" not in forwarded_text
        assert not isinstance(result, JSONResponse) or result.status_code != 403
