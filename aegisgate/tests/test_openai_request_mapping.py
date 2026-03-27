from __future__ import annotations

from aegisgate.adapters.openai_compat.mapper import to_internal_chat, to_internal_messages


def test_to_internal_chat_flattens_structured_content_for_analysis() -> None:
    payload = {
        "model": "gpt-5.4",
        "request_id": "map-chat-1",
        "session_id": "map-chat-1",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Authorization: Bearer [REDACTED:TOKEN]"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}},
                    {"type": "tool_result", "content": [{"text": "nested text"}]},
                ],
            }
        ],
    }

    req = to_internal_chat(payload)

    assert req.route == "/v1/chat/completions"
    assert len(req.messages) == 1
    assert req.messages[0].content == "Authorization: Bearer [REDACTED:TOKEN] [IMAGE_CONTENT] nested text"


def test_to_internal_messages_flattens_anthropic_blocks_for_analysis() -> None:
    payload = {
        "model": "claude-sonnet-4.5",
        "request_id": "map-messages-1",
        "session_id": "map-messages-1",
        "system": [
            {"type": "text", "text": "System token=sk-live-system-secret"},
            {"type": "text", "text": "Keep this guidance."},
        ],
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Authorization: Bearer sk-live-user-secret"},
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/cat.png"}},
                ],
            }
        ],
        "max_tokens": 256,
        "metadata": {"upstream": "anthropic"},
    }

    req = to_internal_messages(payload)

    assert req.route == "/v1/messages"
    assert len(req.messages) == 2
    assert req.messages[0].role == "system"
    assert req.messages[0].content == "System token=sk-live-system-secret Keep this guidance."
    assert req.messages[1].role == "user"
    assert req.messages[1].content == "Authorization: Bearer sk-live-user-secret [IMAGE_CONTENT]"
    assert req.metadata["raw"]["metadata"] == {"upstream": "anthropic"}
