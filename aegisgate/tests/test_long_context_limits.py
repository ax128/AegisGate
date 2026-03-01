from aegisgate.adapters.openai_compat.mapper import to_internal_chat, to_internal_responses
from aegisgate.adapters.openai_compat.router import (
    _PENDING_PAYLOAD_OMITTED_KEY,
    _build_chat_upstream_payload,
    _build_responses_upstream_payload,
    _cap_response_text,
    _prepare_pending_payload,
    _validate_payload_limits,
)
from aegisgate.config.settings import settings
from aegisgate.core.confirmation import payload_hash
from aegisgate.core.context import RequestContext


def test_validate_payload_limits_rejects_oversize_body():
    original = settings.max_request_body_bytes
    settings.max_request_body_bytes = 64
    try:
        ok, status, reason, _ = _validate_payload_limits(
            {"messages": [{"role": "user", "content": "x" * 1024}]},
            route="/v1/chat/completions",
        )
        assert ok is False
        assert status == 413
        assert reason == "request_body_too_large"
    finally:
        settings.max_request_body_bytes = original


def test_validate_payload_limits_rejects_too_many_messages():
    original = settings.max_messages_count
    settings.max_messages_count = 1
    try:
        ok, status, reason, _ = _validate_payload_limits(
            {
                "messages": [
                    {"role": "user", "content": "hello"},
                    {"role": "user", "content": "world"},
                ]
            },
            route="/v1/chat/completions",
        )
        assert ok is False
        assert status == 400
        assert reason == "messages_too_many"
    finally:
        settings.max_messages_count = original


def test_prepare_pending_payload_omits_large_payload():
    original = settings.max_pending_payload_bytes
    settings.max_pending_payload_bytes = 80
    try:
        stored_payload, stored_hash, omitted, payload_size = _prepare_pending_payload(
            {"messages": [{"role": "user", "content": "x" * 1000}]}
        )
        assert omitted is True
        assert payload_size > 80
        assert stored_payload.get(_PENDING_PAYLOAD_OMITTED_KEY) is True
        assert stored_hash == payload_hash(stored_payload)
    finally:
        settings.max_pending_payload_bytes = original


def test_cap_response_text_truncates_and_marks_context():
    original = settings.max_response_length
    settings.max_response_length = 20
    try:
        ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions")
        output = _cap_response_text("A" * 80, ctx)
        assert output.endswith(" [TRUNCATED]")
        assert "response_truncated" in ctx.security_tags
        assert "response:length_cap" in ctx.enforcement_actions
    finally:
        settings.max_response_length = original


def test_mapper_flattens_multimodal_binary_to_placeholders():
    original = settings.max_content_length_per_message
    settings.max_content_length_per_message = 1000
    try:
        image_data = "data:image/png;base64," + ("A" * 4000)
        req = to_internal_chat(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "look at this"},
                            {"type": "image_url", "image_url": {"url": image_data}},
                            image_data,
                        ],
                    }
                ]
            }
        )
        content = req.messages[0].content
        assert "look at this" in content
        assert "[IMAGE_CONTENT]" in content
        assert image_data not in content
    finally:
        settings.max_content_length_per_message = original


def test_mapper_caps_responses_input_length():
    original = settings.max_content_length_per_message
    settings.max_content_length_per_message = 32
    try:
        req = to_internal_responses({"input": "z" * 200})
        assert req.messages[0].content.endswith(" [TRUNCATED]")
        assert len(req.messages[0].content) <= 32 + len(" [TRUNCATED]")
    finally:
        settings.max_content_length_per_message = original


def test_mapper_responses_uses_latest_user_content_from_conversation_input():
    req = to_internal_responses(
        {
            "input": [
                {
                    "role": "assistant",
                    "content": "Action Bind Token: act-0b8ba9524e",
                },
                {
                    "role": "user",
                    "content": "为什么不出力",
                },
            ]
        }
    )
    assert req.messages[0].content == "为什么不出力"
    assert "act-0b8ba9524e" not in req.messages[0].content


def test_mapper_responses_strips_system_exec_runtime_lines():
    req = to_internal_responses(
        {
            "input": (
                "System: [2026-02-26 22:46:45 GMT+1] Exec completed (x, code 0)\n"
                "System: [2026-02-26 22:46:53 GMT+1] Exec failed (y, signal SIGKILL)\n"
                "3"
            )
        }
    )
    assert "Exec completed" not in req.messages[0].content
    assert "Exec failed" not in req.messages[0].content
    assert req.messages[0].content == "3"


def test_chat_upstream_payload_preserves_multimodal_structure():
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe image"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64," + ("A" * 2048)}},
                ],
            }
        ]
    }
    req = to_internal_chat(payload)
    upstream_payload = _build_chat_upstream_payload(payload, req.messages)
    assert isinstance(upstream_payload["messages"][0]["content"], list)
    assert any(isinstance(part, dict) and part.get("type") == "image_url" for part in upstream_payload["messages"][0]["content"])


def test_responses_upstream_payload_preserves_structured_input():
    payload = {
        "input": [
            {"type": "input_text", "text": "analyze this video"},
            {"type": "input_video", "video_url": "https://example.com/video.mp4"},
        ]
    }
    req = to_internal_responses(payload)
    upstream_payload = _build_responses_upstream_payload(payload, req.messages)
    assert isinstance(upstream_payload["input"], list)


def test_responses_upstream_payload_drops_gateway_confirmation_template_from_history():
    payload = {
        "input": [
            {
                "role": "assistant",
                "content": (
                    "⚠️ 安全确认（高风险操作）\n"
                    "放行（复制这一行）：yes cfm-abc123def456 act-bada1fe8dd\n"
                    "取消（复制这一行）：no cfm-abc123def456 act-bada1fe8dd\n"
                    "确认编号：cfm-abc123def456"
                ),
            },
            {"role": "user", "content": "继续分析这个问题"},
        ]
    }
    req = to_internal_responses(payload)
    upstream_payload = _build_responses_upstream_payload(payload, req.messages)
    items = upstream_payload["input"]
    assert isinstance(items, list)
    assert len(items) == 1
    assert items[0]["role"] == "user"


def test_responses_upstream_payload_keeps_normal_assistant_history():
    payload = {
        "input": [
            {"role": "assistant", "content": "这是正常回答，不是网关确认模板。"},
            {"role": "user", "content": "继续"},
        ]
    }
    req = to_internal_responses(payload)
    upstream_payload = _build_responses_upstream_payload(payload, req.messages)
    items = upstream_payload["input"]
    assert isinstance(items, list)
    assert len(items) == 2


def test_responses_upstream_payload_drops_gateway_upstream_recovery_notice_from_history():
    payload = {
        "input": [
            {
                "role": "assistant",
                "content": "[AegisGate] 上游流提前断开（未收到 [DONE]）。已返回可恢复内容，建议重试获取完整结果。",
            },
            {"role": "user", "content": "重试一下"},
        ]
    }
    req = to_internal_responses(payload)
    upstream_payload = _build_responses_upstream_payload(payload, req.messages)
    items = upstream_payload["input"]
    assert isinstance(items, list)
    assert len(items) == 1
    assert items[0]["role"] == "user"
    assert "重试一下" in str(items[0]["content"])


def test_responses_upstream_payload_strips_system_exec_runtime_lines_in_user_input():
    payload = {
        "input": [
            {
                "role": "user",
                "content": (
                    "System: [2026-02-26 22:46:45 GMT+1] Exec completed (x, code 0)\n"
                    "[Telegram] 什么意思"
                ),
            }
        ]
    }
    req = to_internal_responses(payload)
    upstream_payload = _build_responses_upstream_payload(payload, req.messages)
    items = upstream_payload["input"]
    assert isinstance(items, list)
    assert len(items) == 1
    assert items[0]["role"] == "user"
    assert "Exec completed" not in str(items[0]["content"])
    assert "什么意思" in str(items[0]["content"])


def test_responses_upstream_payload_keeps_encrypted_content_raw():
    encrypted_blob = "9xQeWvG816bUx9EPjHmaT23yvVMZbrrpQ9e3Qk6nQJ2J"
    payload = {
        "input": [
            {
                "role": "user",
                "encrypted_content": encrypted_blob,
            }
        ]
    }
    req = to_internal_responses(payload)
    upstream_payload = _build_responses_upstream_payload(payload, req.messages)
    items = upstream_payload["input"]
    assert isinstance(items, list)
    assert len(items) == 1
    assert items[0]["encrypted_content"] == encrypted_blob


def test_responses_upstream_payload_tool_output_uses_relaxed_redaction():
    card_like = "4111 1111 1111 1111"
    payload = {
        "input": [
            {
                "type": "tool_output",
                "output": f"result: {card_like}",
            }
        ]
    }
    req = to_internal_responses(payload)
    upstream_payload = _build_responses_upstream_payload(payload, req.messages)
    items = upstream_payload["input"]
    assert isinstance(items, list)
    assert len(items) == 1
    assert card_like in str(items[0]["output"])


def test_responses_upstream_payload_developer_ip_not_redacted():
    payload = {
        "input": [
            {
                "role": "developer",
                "content": "debug endpoint 10.10.10.10 for local tracing",
            },
            {
                "role": "user",
                "content": "继续",
            },
        ]
    }
    req = to_internal_responses(payload)
    upstream_payload = _build_responses_upstream_payload(payload, req.messages)
    items = upstream_payload["input"]
    assert isinstance(items, list)
    assert len(items) == 2
    assert "10.10.10.10" in str(items[0]["content"])
