from __future__ import annotations

from collections.abc import AsyncGenerator
import json

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.core import pipeline as pipeline_module


def _seed_policy(ctx, policy_name: str = "default") -> dict[str, object]:
    ctx.enabled_filters = {"redaction", "anomaly_detector"}
    ctx.risk_threshold = 0.85
    return {"enabled_filters": set(ctx.enabled_filters), "threshold": ctx.risk_threshold}


def _raise_unexpected(*args, **kwargs):
    raise AssertionError("passthrough 模式不应触发过滤/摘录逻辑")


async def _raise_unexpected_async(*args, **kwargs):
    raise AssertionError("passthrough 模式不应触发过滤/摘录逻辑")


async def _collect_stream_body(response: StreamingResponse) -> bytes:
    chunks: list[bytes] = []
    async for chunk in response.body_iterator:
        if isinstance(chunk, memoryview):
            data = chunk.tobytes()
        elif isinstance(chunk, bytes):
            data = chunk
        else:
            data = str(chunk).encode("utf-8")
        chunks.append(data)
    return b"".join(chunks)


def _install_inline_payload_transform(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(
        openai_router,
        "_run_payload_transform",
        fake_run_payload_transform,
    )


def _install_common_passthrough_mocks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    audit_calls: list[str] = []
    monkeypatch.setattr(openai_router.policy_engine, "resolve", _seed_policy)
    monkeypatch.setattr(openai_router, "_resolve_upstream_base", lambda headers: "http://upstream.test")
    monkeypatch.setattr(openai_router, "_build_upstream_url", lambda path, base: f"{base}{path}")
    monkeypatch.setattr(openai_router, "_build_forward_headers", lambda headers: {"x-forwarded-for": "test"})
    _install_inline_payload_transform(monkeypatch)
    monkeypatch.setattr(openai_router, "_run_request_pipeline", _raise_unexpected_async)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", _raise_unexpected_async)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", _raise_unexpected_async)
    monkeypatch.setattr(openai_router, "debug_log_original", _raise_unexpected)
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
    scope_updates: dict[str, object] | None = None,
) -> Request:
    scope: dict[str, object] = {
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


def test_responses_stream_debug_log_filter() -> None:
    assert openai_router._should_log_responses_stream_event("response.created") is False
    assert openai_router._should_log_responses_stream_event("response.completed") is False
    assert openai_router._should_log_responses_stream_event("response.output_text.delta") is False
    assert openai_router._should_log_responses_stream_event("response.failed") is True


def test_filter_done_debug_log_only_when_filter_hits() -> None:
    assert pipeline_module._should_log_filter_done(phase="request", is_stream=False, report={"hit": False}) is False
    assert pipeline_module._should_log_filter_done(phase="request", is_stream=False, report={"hit": True}) is True
    assert pipeline_module._should_log_filter_done(phase="response", is_stream=True, report={"hit": True}) is False


@pytest.mark.asyncio
async def test_chat_endpoint_redirects_responses_json_back_to_chat_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "input": "hello",
        "request_id": "redirect-json",
        "session_id": "redirect-json",
    }

    async def fake_responses(payload_arg: dict, request_arg: Request):
        return {"id": "resp-1", "model": "gpt-5.4", "output_text": "收到。"}

    monkeypatch.setattr(openai_router, "responses", fake_responses)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.chat_completions(payload, request)
    assert isinstance(result, dict)
    assert result["object"] == "chat.completion"
    assert result["choices"][0]["message"]["content"] == "收到。"


@pytest.mark.asyncio
async def test_chat_endpoint_redirects_responses_function_calls_back_to_chat_tool_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "input": "call tool",
        "request_id": "redirect-json-tool-call",
        "session_id": "redirect-json-tool-call",
    }

    async def fake_responses(payload_arg: dict, request_arg: Request):
        return {
            "id": "resp-tool-1",
            "model": "gpt-5.4",
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "lookup_profile",
                    "arguments": '{"user_id": 7}',
                }
            ],
        }

    monkeypatch.setattr(openai_router, "responses", fake_responses)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.chat_completions(payload, request)
    assert isinstance(result, dict)
    assert result["choices"][0]["finish_reason"] == "tool_calls"
    assert result["choices"][0]["message"]["tool_calls"] == [
        {
            "id": "call_1",
            "type": "function",
            "function": {
                "name": "lookup_profile",
                "arguments": '{"user_id": 7}',
            },
        }
    ]


@pytest.mark.asyncio
async def test_chat_endpoint_redirects_responses_stream_back_to_chat_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "input": "hello",
        "stream": True,
        "request_id": "redirect-stream",
        "session_id": "redirect-stream",
    }

    async def responses_generator() -> AsyncGenerator[bytes, None]:
        yield (
            b'data: {"type":"response.created","response":{"id":"resp-1","model":"gpt-5.4","status":"in_progress"}}\n\n'
        )
        yield (
            b'data: {"type":"response.output_text.delta","delta":"\xe6\x94\xb6\xe5\x88\xb0\xe3\x80\x82"}\n\n'
        )
        yield b'data: [DONE]\n\n'

    async def fake_responses(payload_arg: dict, request_arg: Request):
        return StreamingResponse(responses_generator(), media_type="text/event-stream")

    monkeypatch.setattr(openai_router, "responses", fake_responses)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.chat_completions(payload, request)
    assert isinstance(result, StreamingResponse)
    body = await _collect_stream_body(result)
    assert b"chat.completion.chunk" in body
    assert b"response.output_text.delta" not in body
    assert b"[DONE]" in body


@pytest.mark.asyncio
async def test_chat_endpoint_redirects_responses_stream_tool_calls_back_to_chat_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "input": "call tool",
        "stream": True,
        "request_id": "redirect-stream-tool-call",
        "session_id": "redirect-stream-tool-call",
    }

    async def responses_generator() -> AsyncGenerator[bytes, None]:
        yield (
            b'data: {"type":"response.output_item.done","response_id":"resp-1","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"lookup_profile","arguments":"{\\"user_id\\": 7}"}}\n\n'
        )
        yield (
            b'data: {"type":"response.completed","response":{"id":"resp-1","model":"gpt-5.4","status":"completed","output":[{"type":"function_call","call_id":"call_1","name":"lookup_profile","arguments":"{\\"user_id\\": 7}"}]}}\n\n'
        )
        yield b"data: [DONE]\n\n"

    async def fake_responses(payload_arg: dict, request_arg: Request):
        return StreamingResponse(responses_generator(), media_type="text/event-stream")

    monkeypatch.setattr(openai_router, "responses", fake_responses)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.chat_completions(payload, request)
    assert isinstance(result, StreamingResponse)
    body = await _collect_stream_body(result)
    assert b"chat.completion.chunk" in body
    assert b'"tool_calls"' in body
    assert b"lookup_profile" in body
    assert b'"finish_reason": "tool_calls"' in body or b'"finish_reason":"tool_calls"' in body
    assert b"response.output_item.done" not in body
    assert b"[DONE]" in body


@pytest.mark.asyncio
async def test_chat_endpoint_redirects_responses_stream_without_done_still_closes_chat_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "input": "hello",
        "stream": True,
        "request_id": "redirect-stream-no-done",
        "session_id": "redirect-stream-no-done",
    }

    async def responses_generator() -> AsyncGenerator[bytes, None]:
        yield (
            b'data: {"type":"response.output_text.delta","delta":"\xe6\x94\xb6\xe5\x88\xb0\xe3\x80\x82"}\n\n'
        )

    async def fake_responses(payload_arg: dict, request_arg: Request):
        return StreamingResponse(responses_generator(), media_type="text/event-stream")

    monkeypatch.setattr(openai_router, "responses", fake_responses)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.chat_completions(payload, request)
    assert isinstance(result, StreamingResponse)
    body = await _collect_stream_body(result)
    assert b"chat.completion.chunk" in body
    assert b'"content":"\xe6\x94\xb6\xe5\x88\xb0\xe3\x80\x82"' in body or b'"content": "\xe6\x94\xb6\xe5\x88\xb0\xe3\x80\x82"' in body
    assert body.endswith(b"data: [DONE]\n\n")


@pytest.mark.asyncio
async def test_responses_endpoint_redirects_chat_json_back_to_responses_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "request_id": "redirect-chat-json",
        "session_id": "redirect-chat-json",
    }

    async def fake_chat(payload_arg: dict, request_arg: Request):
        return {
            "id": "chat-1",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [{"message": {"role": "assistant", "content": "收到。"}}],
        }

    monkeypatch.setattr(openai_router, "chat_completions", fake_chat)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/responses",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.responses(payload, request)
    assert isinstance(result, dict)
    assert result["object"] == "response"
    assert result["output_text"] == "收到。"


@pytest.mark.asyncio
async def test_responses_endpoint_redirects_chat_tool_calls_back_to_responses_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "request_id": "redirect-chat-tool-json",
        "session_id": "redirect-chat-tool-json",
    }

    async def fake_chat(payload_arg: dict, request_arg: Request):
        return {
            "id": "chat-1",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "lookup_profile",
                                    "arguments": '{"user_id": 7}',
                                },
                            }
                        ],
                    },
                }
            ],
        }

    monkeypatch.setattr(openai_router, "chat_completions", fake_chat)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/responses",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.responses(payload, request)
    assert isinstance(result, dict)
    assert result["object"] == "response"
    assert result["output"] == [
        {
            "type": "function_call",
            "id": "call_1",
            "call_id": "call_1",
            "name": "lookup_profile",
            "arguments": '{"user_id": 7}',
        }
    ]


@pytest.mark.asyncio
async def test_responses_endpoint_redirects_chat_stream_back_to_responses_events(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": True,
        "request_id": "redirect-chat-stream",
        "session_id": "redirect-chat-stream",
    }

    async def chat_generator() -> AsyncGenerator[bytes, None]:
        yield (
            b'data: {"id":"chat-1","object":"chat.completion.chunk","model":"gpt-5.4","choices":[{"index":0,"delta":{"role":"assistant","content":"\xe6\x94\xb6\xe5\x88\xb0\xe3\x80\x82"},"finish_reason":null}]}\n\n'
        )
        yield b"data: [DONE]\n\n"

    async def fake_chat(payload_arg: dict, request_arg: Request):
        return StreamingResponse(chat_generator(), media_type="text/event-stream")

    monkeypatch.setattr(openai_router, "chat_completions", fake_chat)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/responses",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.responses(payload, request)
    assert isinstance(result, StreamingResponse)
    body = await _collect_stream_body(result)
    assert b'"type": "response.created"' in body or b'"type":"response.created"' in body
    assert b'"type": "response.output_text.delta"' in body or b'"type":"response.output_text.delta"' in body
    assert b"chat.completion.chunk" not in body
    assert b"[DONE]" in body


@pytest.mark.asyncio
async def test_responses_endpoint_redirects_chat_stream_tool_calls_back_to_responses_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": True,
        "request_id": "redirect-chat-stream-tool-call",
        "session_id": "redirect-chat-stream-tool-call",
    }

    async def chat_generator() -> AsyncGenerator[bytes, None]:
        yield (
            b'data: {"id":"chat-1","object":"chat.completion.chunk","model":"gpt-5.4","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup_profile","arguments":"{\\"user_id\\": 7}"}}]},"finish_reason":null}]}\n\n'
        )
        yield (
            b'data: {"id":"chat-1","object":"chat.completion.chunk","model":"gpt-5.4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n'
        )
        yield b"data: [DONE]\n\n"

    async def fake_chat(payload_arg: dict, request_arg: Request):
        return StreamingResponse(chat_generator(), media_type="text/event-stream")

    monkeypatch.setattr(openai_router, "chat_completions", fake_chat)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/responses",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.responses(payload, request)
    assert isinstance(result, StreamingResponse)
    body = await _collect_stream_body(result)
    assert b'"type":"response.output_item.added"' in body or b'"type": "response.output_item.added"' in body
    assert b'"type":"response.output_item.done"' in body or b'"type": "response.output_item.done"' in body
    assert b'"type":"response.completed"' in body or b'"type": "response.completed"' in body
    assert b'"type":"function_call"' in body or b'"type": "function_call"' in body
    assert b"chat.completion.chunk" not in body
    assert b"[DONE]" in body


@pytest.mark.asyncio
async def test_responses_endpoint_redirects_chat_stream_tool_calls_without_done_still_completes_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_inline_payload_transform(monkeypatch)
    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": True,
        "request_id": "redirect-chat-stream-tool-call-no-done",
        "session_id": "redirect-chat-stream-tool-call-no-done",
    }

    async def chat_generator() -> AsyncGenerator[bytes, None]:
        yield (
            b'data: {"id":"chat-1","object":"chat.completion.chunk","model":"gpt-5.4","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup_profile","arguments":"{\\"user_id\\": 7}"}}]},"finish_reason":null}]}\n\n'
        )
        yield (
            b'data: {"id":"chat-1","object":"chat.completion.chunk","model":"gpt-5.4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n'
        )

    async def fake_chat(payload_arg: dict, request_arg: Request):
        return StreamingResponse(chat_generator(), media_type="text/event-stream")

    monkeypatch.setattr(openai_router, "chat_completions", fake_chat)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/responses",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await openai_router.responses(payload, request)
    assert isinstance(result, StreamingResponse)
    body = await _collect_stream_body(result)
    assert b'"type":"response.created"' in body or b'"type": "response.created"' in body
    assert b'"type":"response.output_item.done"' in body or b'"type": "response.output_item.done"' in body
    assert b'"type":"response.completed"' in body or b'"type": "response.completed"' in body
    assert b'"type":"function_call"' in body or b'"type": "function_call"' in body
    assert body.endswith(b"data: [DONE]\n\n")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("execute_fn", "payload", "request_path", "expected_forward_payload", "expected_body"),
    [
        (
            openai_router._execute_chat_once,
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "hello"}],
                "request_id": "chat-pass",
                "session_id": "chat-pass",
                "policy": "default",
            },
            "/v1/chat/completions",
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "hello"}],
            },
            {"id": "chat-1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        ),
        (
            openai_router._execute_responses_once,
            {
                "model": "gpt-5.4",
                "input": "hello",
                "request_id": "resp-pass",
                "session_id": "resp-pass",
                "metadata": {"trace": "x"},
            },
            "/v1/responses",
            {
                "model": "gpt-5.4",
                "input": "hello",
            },
            {"id": "resp-1", "output_text": "ok"},
        ),
    ],
)
async def test_passthrough_json_endpoints_skip_all_filters(
    monkeypatch: pytest.MonkeyPatch,
    execute_fn,
    payload: dict[str, object],
    request_path: str,
    expected_forward_payload: dict[str, object],
    expected_body: dict[str, object],
) -> None:
    audit_calls = _install_common_passthrough_mocks(monkeypatch)

    async def fake_forward_json(url: str, forwarded_payload: dict[str, object], headers: dict[str, str]):
        assert forwarded_payload == expected_forward_payload
        assert url == f"http://upstream.test{request_path}"
        return 200, expected_body

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await execute_fn(
        payload=payload,
        request_headers={"x-aegis-filter-mode": "passthrough"},
        request_path=request_path,
        boundary={},
        tenant_id="default",
    )

    assert result == expected_body
    assert audit_calls == [str(payload["request_id"])]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("execute_fn", "payload", "request_path", "expected_forward_payload", "expected_chunks"),
    [
        (
            openai_router._execute_chat_stream_once,
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
                "request_id": "chat-stream-pass",
                "session_id": "chat-stream-pass",
                "policy": "default",
            },
            "/v1/chat/completions",
            {
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
            [b"data: chat-1\n\n", b"data: [DONE]\n\n"],
        ),
        (
            openai_router._execute_responses_stream_once,
            {
                "model": "gpt-5.4",
                "input": "hello",
                "stream": True,
                "request_id": "resp-stream-pass",
                "session_id": "resp-stream-pass",
                "metadata": {"trace": "x"},
            },
            "/v1/responses",
            {
                "model": "gpt-5.4",
                "input": "hello",
                "stream": True,
            },
            [b"data: resp-1\n\n", b"data: [DONE]\n\n"],
        ),
    ],
)
async def test_passthrough_stream_endpoints_skip_all_filters(
    monkeypatch: pytest.MonkeyPatch,
    execute_fn,
    payload: dict[str, object],
    request_path: str,
    expected_forward_payload: dict[str, object],
    expected_chunks: list[bytes],
) -> None:
    audit_calls = _install_common_passthrough_mocks(monkeypatch)

    async def fake_forward_stream_lines(
        url: str,
        forwarded_payload: dict[str, object],
        headers: dict[str, str],
    ) -> AsyncGenerator[bytes, None]:
        assert forwarded_payload == expected_forward_payload
        assert url == f"http://upstream.test{request_path}"
        for chunk in expected_chunks:
            yield chunk

    monkeypatch.setattr(openai_router, "_forward_stream_lines", fake_forward_stream_lines)

    response = await execute_fn(
        payload=payload,
        request_headers={"x-aegis-filter-mode": "passthrough"},
        request_path=request_path,
        boundary={},
        tenant_id="default",
    )

    assert isinstance(response, StreamingResponse)
    assert await _collect_stream_body(response) == b"".join(expected_chunks)
    assert audit_calls == [str(payload["request_id"])]


@pytest.mark.asyncio
async def test_chat_passthrough_preserves_structured_content(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "gpt-5.4",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Authorization: Bearer sk-live-secret"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}},
                ],
                "provider_meta": {"channel": "alpha"},
            }
        ],
        "request_id": "chat-pass-structured",
        "session_id": "chat-pass-structured",
        "policy": "default",
    }
    audit_calls = _install_common_passthrough_mocks(monkeypatch)

    async def fake_forward_json(url: str, forwarded_payload: dict[str, object], headers: dict[str, str]):
        assert forwarded_payload == {
            "model": "gpt-5.4",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Authorization: Bearer sk-live-secret"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}},
                    ],
                    "provider_meta": {"channel": "alpha"},
                }
            ],
        }
        assert url == "http://upstream.test/v1/chat/completions"
        return 200, {"id": "chat-1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]}

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await openai_router._execute_chat_once(
        payload=payload,
        request_headers={"x-aegis-filter-mode": "passthrough"},
        request_path="/v1/chat/completions",
        boundary={},
    )

    assert isinstance(result, dict)
    assert result["choices"][0]["message"]["content"] == "ok"
    assert audit_calls == ["chat-pass-structured"]


@pytest.mark.asyncio
async def test_messages_passthrough_preserves_payload(monkeypatch: pytest.MonkeyPatch) -> None:
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
                "metadata": {"segment": "alpha"},
            }
        ],
        "max_tokens": 256,
        "request_id": "messages-pass-structured",
        "session_id": "messages-pass-structured",
        "policy": "default",
    }
    audit_calls = _install_common_passthrough_mocks(monkeypatch)

    async def fake_forward_json(url: str, forwarded_payload: dict[str, object], headers: dict[str, str]):
        assert forwarded_payload == {
            "model": "claude-sonnet-4.5",
            "system": [{"type": "text", "text": "Authorization: Bearer sk-live-system-secret"}],
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
        }
        assert url == "http://upstream.test/v1/messages"
        return 200, {
            "id": "msg-1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-sonnet-4.5",
        }

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await openai_router._execute_messages_once(
        payload=payload,
        request_headers={"x-aegis-filter-mode": "passthrough"},
        request_path="/v1/messages",
        boundary={},
        tenant_id="default",
    )

    assert isinstance(result, JSONResponse)
    assert result.status_code == 200
    assert audit_calls == ["messages-pass-structured"]


@pytest.mark.asyncio
async def test_messages_compat_openai_chat_delegates_to_responses_path(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "claude-sonnet-4.5",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 128,
        "request_id": "messages-compat-json",
        "session_id": "messages-compat-json",
    }
    delegated_payloads: list[dict[str, object]] = []

    def fake_messages_payload_to_responses_payload(
        payload_arg: dict,
        *,
        model_map: dict[str, str] | None = None,
        default_model: str | None = None,
    ) -> dict:
        return {
            "model": "gpt-5.4",
            "input": "hello",
            "request_id": payload_arg["request_id"],
            "session_id": payload_arg["session_id"],
        }

    async def fake_execute_responses_once(
        *,
        payload: dict[str, object],
        request_headers: dict[str, str],
        request_path: str,
        boundary: dict | None,
        tenant_id: str = "default",
        skip_confirmation: bool = False,
        forced_upstream_base: str | None = None,
    ) -> dict:
        delegated_payloads.append(payload)
        assert request_path == "/v1/responses"
        return {
            "id": "resp-1",
            "object": "response",
            "model": "gpt-5.4",
            "output_text": "ok",
        }

    monkeypatch.setattr(
        openai_router,
        "messages_payload_to_responses_payload",
        fake_messages_payload_to_responses_payload,
    )
    monkeypatch.setattr(openai_router, "_execute_responses_once", fake_execute_responses_once)
    async def fail_generic_once(*args, **kwargs):
        raise AssertionError("compat path 不应走 generic direct rewrite")

    monkeypatch.setattr(openai_router, "_execute_generic_once", fail_generic_once)

    response = await openai_router._messages_compat_openai_chat(
        payload=payload,
        request=_build_request(
            path="/v1/messages",
            scope_updates={"aegis_compat": "openai_chat"},
        ),
        gateway_headers={},
        boundary={},
        tenant_id="default",
    )

    assert delegated_payloads == [
        {
            "model": "gpt-5.4",
            "input": "hello",
            "request_id": "messages-compat-json",
            "session_id": "messages-compat-json",
        }
    ]
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_messages_compat_openai_chat_returns_messages_tool_use_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "model": "claude-sonnet-4.5",
        "messages": [{"role": "user", "content": "run tool"}],
        "max_tokens": 128,
        "request_id": "messages-compat-tool-json",
        "session_id": "messages-compat-tool-json",
        "policy": "strict",
    }

    async def fake_execute_responses_once(
        *,
        payload: dict[str, object],
        request_headers: dict[str, str],
        request_path: str,
        boundary: dict | None,
        tenant_id: str = "default",
        skip_confirmation: bool = False,
        forced_upstream_base: str | None = None,
    ) -> dict:
        assert payload["request_id"] == "messages-compat-tool-json"
        assert payload["session_id"] == "messages-compat-tool-json"
        assert payload["policy"] == "strict"
        return {
            "id": "resp-tool-1",
            "object": "response",
            "model": "gpt-5.4",
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "lookup_profile",
                    "arguments": '{"user_id": 7}',
                }
            ],
        }

    monkeypatch.setattr(openai_router, "_execute_responses_once", fake_execute_responses_once)

    response = await openai_router._messages_compat_openai_chat(
        payload=payload,
        request=_build_request(
            path="/v1/messages",
            scope_updates={"aegis_compat": "openai_chat"},
        ),
        gateway_headers={},
        boundary={},
        tenant_id="default",
    )

    assert isinstance(response, JSONResponse)
    raw_body = response.body
    if isinstance(raw_body, memoryview):
        body = json.loads(raw_body.tobytes().decode("utf-8"))
    else:
        body = json.loads(raw_body.decode("utf-8"))
    assert body["content"] == [
        {
            "type": "tool_use",
            "id": "call_1",
            "name": "lookup_profile",
            "input": {"user_id": 7},
        }
    ]


@pytest.mark.asyncio
async def test_responses_stream_preserves_event_and_data_order(monkeypatch: pytest.MonkeyPatch) -> None:
    audit_calls: list[str] = []
    _install_inline_payload_transform(monkeypatch)

    async def _identity_request_pipeline(pipeline, req, ctx):
        return req

    async def _noop_async(*args, **kwargs):
        return None

    monkeypatch.setattr(openai_router.policy_engine, "resolve", _seed_policy)
    monkeypatch.setattr(openai_router, "_resolve_upstream_base", lambda headers: "http://upstream.test")
    monkeypatch.setattr(openai_router, "_build_upstream_url", lambda path, base: f"{base}{path}")
    monkeypatch.setattr(openai_router, "_build_forward_headers", lambda headers: {"x-forwarded-for": "test"})
    monkeypatch.setattr(openai_router, "_run_request_pipeline", _identity_request_pipeline)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", _noop_async)
    monkeypatch.setattr(openai_router, "_apply_semantic_review", _noop_async)
    monkeypatch.setattr(openai_router, "debug_log_original", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        openai_router,
        "_write_audit_event",
        lambda ctx, boundary=None: audit_calls.append(ctx.request_id),
    )

    async def fake_forward_stream_lines(
        url: str,
        forwarded_payload: dict[str, object],
        headers: dict[str, str],
    ) -> AsyncGenerator[bytes, None]:
        assert url == "http://upstream.test/v1/responses"
        assert forwarded_payload == {"model": "gpt-5.4", "input": "hello", "stream": True}
        chunks = [
            b"event: response.created\n",
            b'data: {"type":"response.created","response":{"id":"resp-1","model":"gpt-5.4","status":"in_progress"}}\n',
            b"\n",
            b"event: response.output_text.delta\n",
            b'data: {"type":"response.output_text.delta","delta":"\xe6\x94\xb6\xe5\x88\xb0"}\n',
            b"\n",
            b"event: response.output_text.done\n",
            b'data: {"type":"response.output_text.done","text":"\xe6\x94\xb6\xe5\x88\xb0"}\n',
            b"\n",
            b"event: response.completed\n",
            b'data: {"type":"response.completed","response":{"id":"resp-1","status":"completed"}}\n',
            b"\n",
        ]
        for chunk in chunks:
            yield chunk

    monkeypatch.setattr(openai_router, "_forward_stream_lines", fake_forward_stream_lines)

    response = await openai_router._execute_responses_stream_once(
        payload={
            "model": "gpt-5.4",
            "input": "hello",
            "stream": True,
            "request_id": "resp-stream-order",
            "session_id": "resp-stream-order",
        },
        request_headers={},
        request_path="/v1/responses",
        boundary={},
        tenant_id="default",
    )

    assert isinstance(response, StreamingResponse)
    body = await _collect_stream_body(response)
    assert (
        b"event: response.output_text.delta\n"
        b'data: {"type":"response.output_text.delta","delta":"\xe6\x94\xb6\xe5\x88\xb0"}\n\n'
        in body
    )
    assert (
        b"event: response.output_text.done\n"
        b'data: {"type":"response.output_text.done","text":"\xe6\x94\xb6\xe5\x88\xb0"}\n\n'
        in body
    )
    assert body.index(b"event: response.output_text.delta") < body.index(b"event: response.output_text.done")
    assert body.index(b"event: response.output_text.done") < body.index(b"event: response.completed")
    assert body.endswith(b"data: [DONE]\n\n")
    assert audit_calls == ["resp-stream-order"]
