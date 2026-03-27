from __future__ import annotations

from aegisgate.adapters.openai_compat.mapper import to_internal_chat


def test_to_internal_chat_flattens_structured_content_for_analysis() -> None:
    payload = {
        "model": "gpt-5.4",
        "request_id": "map-chat-1",
        "session_id": "map-chat-1",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Authorization: Bearer sk-live-secret"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}},
                    {"type": "tool_result", "content": [{"text": "nested text"}]},
                ],
            }
        ],
    }

    req = to_internal_chat(payload)

    assert req.route == "/v1/chat/completions"
    assert len(req.messages) == 1
    assert req.messages[0].content == "Authorization: Bearer sk-live-secret [IMAGE_CONTENT] nested text"
