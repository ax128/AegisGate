from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisgate.adapters.openai_compat import mapper
from aegisgate.adapters.openai_compat.mapper import (
    messages_payload_to_responses_payload,
    responses_response_to_messages_response,
    to_internal_chat,
    to_internal_messages,
)


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


def test_messages_payload_to_responses_payload_preserves_context_and_structured_blocks() -> None:
    payload = {
        "model": "claude-sonnet-4.5",
        "request_id": "compat-msg-1",
        "session_id": "compat-msg-1",
        "policy": "strict",
        "metadata": {"tenant": "alpha"},
        "system": [
            {"type": "text", "text": "You are careful."},
            {"type": "text", "text": "Do not leak secrets."},
        ],
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_123",
                        "name": "lookup_profile",
                        "input": {"user_id": 7},
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Show the result."},
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/cat.png"}},
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_123",
                        "content": [{"type": "text", "text": "profile ok"}],
                    }
                ],
            },
        ],
        "tools": [
            {
                "name": "lookup_profile",
                "description": "Fetch a profile",
                "input_schema": {"type": "object", "properties": {"user_id": {"type": "integer"}}},
            }
        ],
        "tool_choice": {"type": "auto"},
        "max_tokens": 256,
        "temperature": 0.2,
    }

    result = messages_payload_to_responses_payload(payload, default_model="gpt-5.4")

    assert result["model"] == "gpt-5.4"
    assert result["request_id"] == "compat-msg-1"
    assert result["session_id"] == "compat-msg-1"
    assert result["policy"] == "strict"
    assert result["metadata"] == {"tenant": "alpha"}
    assert result["instructions"] == "You are careful. Do not leak secrets."
    assert result["store"] is False
    assert result["tool_choice"] == "auto"
    assert result["max_output_tokens"] == 256
    assert result["temperature"] == 0.2
    assert result["tools"] == [
        {
            "type": "function",
            "name": "lookup_profile",
            "description": "Fetch a profile",
            "parameters": {"type": "object", "properties": {"user_id": {"type": "integer"}}},
        }
    ]
    assert result["input"] == [
        {
            "role": "assistant",
            "content": [
                {
                    "type": "function_call",
                    "call_id": "toolu_123",
                    "name": "lookup_profile",
                    "arguments": '{"user_id": 7}',
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "input_text", "text": "Show the result."},
                {"type": "input_image", "image_url": "https://example.com/cat.png"},
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "function_call_output",
                    "call_id": "toolu_123",
                    "output": "profile ok",
                }
            ],
        },
    ]


def test_messages_payload_to_responses_payload_preserves_base64_image() -> None:
    # Standard Anthropic image block uses a base64 source (no `url`); it must be
    # forwarded as a reconstructed data URL, not flattened to a text placeholder.
    b64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4"
        "2mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    )
    payload = {
        "model": "claude-sonnet-4.5",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What is this?"},
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": b64,
                        },
                    },
                ],
            }
        ],
    }

    result = messages_payload_to_responses_payload(payload, default_model="gpt-5.4")

    assert result["input"] == [
        {
            "role": "user",
            "content": [
                {"type": "input_text", "text": "What is this?"},
                {
                    "type": "input_image",
                    "image_url": f"data:image/png;base64,{b64}",
                },
            ],
        }
    ]


def test_messages_payload_to_responses_payload_preserves_base64_document() -> None:
    # Anthropic document (PDF) block uses a base64 source; it must be forwarded as
    # a Responses input_file (data URL in file_data) so a Claude-backed upstream
    # receives the document instead of a dropped placeholder.
    b64 = "JVBERi0xLjQKJ"  # truncated base64 PDF marker
    payload = {
        "model": "claude-sonnet-4.5",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Summarize this"},
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": b64,
                        },
                    },
                ],
            }
        ],
    }

    result = messages_payload_to_responses_payload(payload, default_model="gpt-5.4")

    assert result["input"] == [
        {
            "role": "user",
            "content": [
                {"type": "input_text", "text": "Summarize this"},
                {
                    "type": "input_file",
                    "file_data": f"data:application/pdf;base64,{b64}",
                },
            ],
        }
    ]


def test_responses_response_to_messages_response_preserves_function_calls() -> None:
    resp = {
        "id": "resp-tool-1",
        "object": "response",
        "model": "gpt-5.4",
        "output": [
            {
                "type": "function_call",
                "id": "fc_1",
                "call_id": "call_1",
                "name": "lookup_profile",
                "arguments": '{"user_id": 7}',
            },
            {
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "处理完成"}],
            },
        ],
        "usage": {"input_tokens": 12, "output_tokens": 34},
        "aegisgate": {"action": "review"},
    }

    result = responses_response_to_messages_response(resp, original_model="claude-sonnet-4.5")

    assert result["model"] == "claude-sonnet-4.5"
    assert result["usage"] == {"input_tokens": 12, "output_tokens": 34}
    assert result["aegisgate"] == {"action": "review"}
    assert result["content"] == [
        {
            "type": "tool_use",
            "id": "call_1",
            "name": "lookup_profile",
            "input": {"user_id": 7},
        },
        {"type": "text", "text": "处理完成"},
    ]
    # A tool call must surface stop_reason=tool_use so Anthropic clients run the
    # tool and continue the turn; reporting end_turn breaks the tool loop.
    assert result["stop_reason"] == "tool_use"


def test_responses_response_to_messages_response_text_only_is_end_turn() -> None:
    resp = {
        "id": "resp-text-1",
        "model": "gpt-5.4",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "hello"}],
            }
        ],
        "usage": {"input_tokens": 3, "output_tokens": 5},
    }

    result = responses_response_to_messages_response(resp, original_model="claude-sonnet-4.5")

    assert result["stop_reason"] == "end_turn"


def test_responses_response_to_messages_response_maps_max_tokens() -> None:
    resp = {
        "id": "resp-incomplete-1",
        "model": "gpt-5.4",
        "status": "incomplete",
        "incomplete_details": {"reason": "max_output_tokens"},
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "partial"}],
            }
        ],
        "usage": {"input_tokens": 9, "output_tokens": 128},
    }

    result = responses_response_to_messages_response(resp, original_model="claude-sonnet-4.5")

    assert result["stop_reason"] == "max_tokens"


def test_configured_allowed_models_extend_builtin_whitelist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Models added via config extend the built-in allowlist (union). The built-in
    # set stays a floor, so unknown models are still rejected.
    monkeypatch.setattr(mapper, "_configured_allowed_models", frozenset({"gpt-5.5"}))

    ok = mapper.messages_payload_to_responses_payload(
        {"model": "claude-x", "messages": []}, default_model="gpt-5.5"
    )
    assert ok["model"] == "gpt-5.5"

    with pytest.raises(ValueError):
        mapper.messages_payload_to_responses_payload(
            {"model": "claude-x", "messages": []}, default_model="totally-unknown"
        )


def test_load_global_model_map_loads_allowed_models(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(mapper, "_configured_allowed_models", frozenset())
    cfg = tmp_path / "model_map.json"
    cfg.write_text(json.dumps({"map": {}, "allowed_models": ["gpt-5.5", "gpt-5.6"]}))
    monkeypatch.setattr(mapper.settings, "compat_model_map_path", str(cfg))

    mapper.load_global_model_map()

    assert "gpt-5.5" in mapper._configured_allowed_models
    assert "gpt-5.6" in mapper._configured_allowed_models


def test_messages_payload_sets_store_false_maps_stop_and_drops_top_k() -> None:
    result = messages_payload_to_responses_payload(
        {
            "model": "claude-sonnet-4.5",
            "messages": [{"role": "user", "content": "hi"}],
            "stop_sequences": ["END", "STOP"],
            "top_k": 8,
        },
        default_model="gpt-5.4",
    )
    assert result["store"] is False
    assert result["stop"] == ["END", "STOP"]
    # The Responses API has no top_k; forwarding it would 400 upstream.
    assert "top_k" not in result


def test_messages_payload_skips_thinking_blocks() -> None:
    result = messages_payload_to_responses_payload(
        {
            "model": "claude-sonnet-4.5",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": "internal chain of thought"},
                        {"type": "redacted_thinking", "data": "redacted"},
                        {"type": "text", "text": "visible answer"},
                    ],
                }
            ],
        },
        default_model="gpt-5.4",
    )
    assert result["input"][0]["content"] == [
        {"type": "input_text", "text": "visible answer"}
    ]
    scanned = to_internal_messages(
        {
            "model": "claude-sonnet-4.5",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": "internal chain of thought"},
                        {"type": "text", "text": "visible answer"},
                    ],
                }
            ],
        }
    )
    assert scanned.messages[0].content == "visible answer"
    assert "[NON_TEXT_PART]" not in scanned.messages[0].content


@pytest.mark.parametrize(
    ("anthropic_choice", "expected_responses", "expected_tag"),
    [
        ({"type": "auto"}, "auto", None),
        ({"type": "any"}, "auto", "tool_choice_any_mapped_to_auto"),
        ({"type": "tool", "name": "lookup_profile"}, {"type": "function", "name": "lookup_profile"}, None),
        ({"type": "mystery"}, "auto", "tool_choice_unknown_mapped_to_auto"),
    ],
)
def test_anthropic_tool_choice_maps_to_responses(
    anthropic_choice: object,
    expected_responses: object,
    expected_tag: str | None,
) -> None:
    mapped, tag = mapper.map_anthropic_tool_choice_to_responses(anthropic_choice)
    assert mapped == expected_responses
    assert tag == expected_tag
    payload = messages_payload_to_responses_payload(
        {
            "model": "claude-sonnet-4.5",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": anthropic_choice,
        },
        default_model="gpt-5.4",
    )
    assert payload["tool_choice"] == expected_responses
    tags = (payload.get("metadata") or {}).get("aegisgate_compat_tags")
    if expected_tag is None:
        assert not tags
    else:
        assert expected_tag in tags


@pytest.mark.parametrize(
    ("responses_choice", "expected_anthropic", "expected_tag"),
    [
        ("auto", {"type": "auto"}, None),
        ("required", {"type": "any"}, "tool_choice_required_mapped_to_any"),
        ({"type": "function", "name": "lookup_profile"}, {"type": "tool", "name": "lookup_profile"}, None),
        ("mystery", {"type": "auto"}, "tool_choice_unknown_mapped_to_auto"),
    ],
)
def test_responses_tool_choice_maps_to_anthropic(
    responses_choice: object,
    expected_anthropic: object,
    expected_tag: str | None,
) -> None:
    mapped, tag = mapper.map_responses_tool_choice_to_anthropic(responses_choice)
    assert mapped == expected_anthropic
    assert tag == expected_tag


def test_convert_responses_tool_choice_nests_function_for_chat() -> None:
    from aegisgate.adapters.openai_compat.compat_bridge import (
        convert_responses_payload_to_chat,
    )

    result = convert_responses_payload_to_chat(
        {
            "model": "gpt-5.4",
            "input": "hi",
            "tool_choice": {"type": "function", "name": "lookup_profile"},
            "parallel_tool_calls": False,
        }
    )
    assert result["tool_choice"] == {
        "type": "function",
        "function": {"name": "lookup_profile"},
    }
    assert result["parallel_tool_calls"] is False


def test_sanitize_for_responses_renames_max_completion_tokens() -> None:
    from aegisgate.adapters.openai_compat.payload_compat import sanitize_for_responses

    result = sanitize_for_responses(
        {
            "model": "gpt-5.4",
            "input": "hi",
            "max_completion_tokens": 128,
            "messages": [{"role": "user", "content": "hi"}],
        }
    )
    assert result["max_output_tokens"] == 128
    assert "max_completion_tokens" not in result
    assert "messages" not in result


def test_sanitize_for_chat_keeps_parallel_tool_calls_and_reasoning() -> None:
    from aegisgate.adapters.openai_compat.payload_compat import sanitize_for_chat

    kept = sanitize_for_chat(
        {
            "model": "gpt-5.4",
            "messages": [{"role": "user", "content": "hi"}],
            "parallel_tool_calls": True,
            "reasoning": {"effort": "low"},
            "store": True,
        }
    )
    assert kept["parallel_tool_calls"] is True
    assert kept["reasoning"] == {"effort": "low"}
    assert "store" not in kept

    dropped = sanitize_for_chat(
        {
            "model": "gpt-5.4",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning": {"effort": None, "summary": None},
        }
    )
    assert "reasoning" not in dropped

