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
