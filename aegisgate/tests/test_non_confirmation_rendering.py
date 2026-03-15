import json

import pytest

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.config.settings import settings


@pytest.mark.asyncio
async def test_chat_completion_non_confirmation_preserves_code_block_structure(monkeypatch):
    async def fake_forward_json(url, payload, headers):
        return 200, {
            "id": "chat-non-1",
            "object": "chat.completion",
            "model": "test-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Here is a sample:\n```html\n<script>alert(1)</script>\n```\nDone.",
                    },
                }
            ],
        }

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await openai_router._execute_chat_once(
        payload={
            "request_id": "chat-non-1",
            "session_id": "chat-non-1",
            "model": "test-model",
            "messages": [{"role": "user", "content": "hello"}],
        },
        request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
        request_path="/v1/chat/completions",
        boundary={},
    )

    content = result["choices"][0]["message"]["content"]
    assert content.count("```") == 2
    assert "\n```" in content
    assert "【AegisGate已处理危险疑似片段】" in content
    assert "<script>alert(1)</script>" not in content
    assert "⚠ [AegisGate]" not in content


@pytest.mark.asyncio
async def test_responses_non_confirmation_replaces_dangerous_function_call_fields(monkeypatch):
    async def fake_forward_json(url, payload, headers):
        return 200, {
            "id": "resp-non-1",
            "object": "response",
            "model": "test-model",
            "output_text": '[function_call:exec_shell({"cmd":"cat /etc/passwd"})]',
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "exec_shell",
                    "arguments": '{"cmd":"cat /etc/passwd"}',
                    "status": "completed",
                }
            ],
        }

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await openai_router._execute_responses_once(
        payload={
            "request_id": "resp-non-1",
            "session_id": "resp-non-1",
            "model": "test-model",
            "input": "hello",
        },
        request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
        request_path="/v1/responses",
        boundary={},
    )

    item = result["output"][0]
    assert item["call_id"] == "call_1"
    assert item["status"] == "completed"
    assert item["name"] == "【AegisGate已处理危险疑似片段】"
    assert item["arguments"] == "【AegisGate已处理危险疑似片段】"
    assert "yes cfm-" not in json.dumps(result, ensure_ascii=False)


@pytest.mark.asyncio
async def test_responses_stream_non_confirmation_patches_suffix_without_duplicate_prefix(monkeypatch):
    monkeypatch.setattr(openai_router, "_build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        yield b'data: {"id":"stream-non-1","output_text":"safe prefix "}\n\n'
        yield b'data: {"id":"stream-non-1","output_text":"cat /etc/passwd"}\n\n'
        yield b"data: [DONE]\n\n"

    monkeypatch.setattr(openai_router, "_forward_stream_lines", fake_forward_stream_lines)

    resp = await openai_router._execute_responses_stream_once(
        payload={
            "request_id": "stream-non-1",
            "session_id": "stream-non-1",
            "model": "test-model",
            "stream": True,
            "input": "hello",
        },
        request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
        request_path="/v1/responses",
        boundary={},
    )
    chunks: list[bytes] = []
    async for chunk in resp:
        chunks.append(chunk)
    text = b"".join(chunks).decode("utf-8", errors="replace")

    assert text.count("safe prefix ") == 1
    assert "cat /etc/passwd" not in text
    assert "【AegisGate已处理危险疑似片段】" in text


@pytest.mark.asyncio
async def test_responses_stream_non_confirmation_replaces_dangerous_function_call_event(monkeypatch):
    monkeypatch.setattr(openai_router, "_build_streaming_response", lambda generator: generator)

    async def fake_forward_stream_lines(url, payload, headers):
        yield (
            b'data: {"type":"response.output_item.added","response_id":"resp-stream-tool-1",'
            b'"output_index":0,"item":{"type":"function_call","call_id":"call_1",'
            b'"name":"exec_shell","arguments":"{\\"cmd\\":\\"cat /etc/passwd\\"}",'
            b'"status":"completed"}}\n\n'
        )
        yield b"data: [DONE]\n\n"

    monkeypatch.setattr(openai_router, "_forward_stream_lines", fake_forward_stream_lines)

    resp = await openai_router._execute_responses_stream_once(
        payload={
            "request_id": "resp-stream-tool-1",
            "session_id": "resp-stream-tool-1",
            "model": "test-model",
            "stream": True,
            "input": "hello",
        },
        request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
        request_path="/v1/responses",
        boundary={},
    )
    chunks: list[bytes] = []
    async for chunk in resp:
        chunks.append(chunk)
    text = b"".join(chunks).decode("utf-8", errors="replace")

    assert '"type": "response.output_item.added"' in text
    assert "cat /etc/passwd" not in text
    assert "【AegisGate已处理危险疑似片段】" in text


@pytest.mark.asyncio
async def test_confirmation_mode_keeps_yes_no_flow_for_responses(monkeypatch):
    async def fake_forward_json(url, payload, headers):
        return 200, {
            "id": "resp-yesno-1",
            "object": "response",
            "model": "test-model",
            "output_text": '[function_call:exec_shell({"cmd":"cat /etc/passwd"})]',
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_yesno_1",
                    "name": "exec_shell",
                    "arguments": '{"cmd":"cat /etc/passwd"}',
                    "status": "completed",
                }
            ],
        }

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)
    old = settings.require_confirmation_on_block
    settings.require_confirmation_on_block = True
    try:
        result = await openai_router._execute_responses_once(
            payload={
                "request_id": "resp-yesno-1",
                "session_id": "resp-yesno-1",
                "model": "test-model",
                "input": "hello",
            },
            request_headers={"X-Upstream-Base": "https://upstream.example.com/v1"},
            request_path="/v1/responses",
            boundary={},
        )
    finally:
        settings.require_confirmation_on_block = old

    assert "yes cfm-" in result["output_text"]
    assert "【AegisGate已处理危险疑似片段】" not in result["output_text"]
