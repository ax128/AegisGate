"""Tests for aegisgate.adapters.openai_compat.sanitize — helper functions."""

from __future__ import annotations

from aegisgate.adapters.openai_compat.sanitize import (
    _looks_like_gateway_confirmation_text,
    _looks_like_gateway_internal_history_text,
    _looks_like_gateway_upstream_recovery_notice_text,
    _sanitize_chat_messages_for_upstream_with_hits,
    _sanitize_payload_for_log,
    _should_skip_responses_field_redaction,
    _strip_system_exec_runtime_lines,
)


class TestLooksLikeGatewayConfirmationText:

    def test_chinese_confirmation(self) -> None:
        text = "⚠️ 安全确认（高风险操作）\n确认编号：cfm-123"
        assert _looks_like_gateway_confirmation_text(text) is True

    def test_english_confirmation(self) -> None:
        text = "Safety Confirmation (High-Risk Action)\nConfirmation ID: cfm-abc"
        assert _looks_like_gateway_confirmation_text(text) is True

    def test_action_text_confirmation(self) -> None:
        text = "放行（复制这一行）：yes cfm-123\n取消（复制这一行）：no cfm-456"
        assert _looks_like_gateway_confirmation_text(text) is True

    def test_normal_text_not_confirmation(self) -> None:
        assert _looks_like_gateway_confirmation_text("hello world") is False

    def test_empty_text(self) -> None:
        assert _looks_like_gateway_confirmation_text("") is False

    def test_none_text(self) -> None:
        assert _looks_like_gateway_confirmation_text(None) is False


class TestLooksLikeGatewayUpstreamRecoveryNotice:

    def test_exact_notice(self) -> None:
        text = "[AegisGate] 上游流提前断开（未收到 [DONE]）。已返回可恢复内容，建议重试获取完整结果。"
        assert _looks_like_gateway_upstream_recovery_notice_text(text) is True

    def test_lowercase_match(self) -> None:
        text = "[aegisgate] 上游流提前断开（未收到 [done]）"
        assert _looks_like_gateway_upstream_recovery_notice_text(text) is True

    def test_english_match(self) -> None:
        text = "upstream stream closed early (missing [done])"
        assert _looks_like_gateway_upstream_recovery_notice_text(text) is True

    def test_normal_text(self) -> None:
        assert _looks_like_gateway_upstream_recovery_notice_text("normal") is False


class TestLooksLikeGatewayInternalHistoryText:

    def test_confirmation_is_internal(self) -> None:
        text = "⚠️ 安全确认（高风险操作）\n确认编号：cfm-123"
        assert _looks_like_gateway_internal_history_text(text) is True

    def test_recovery_is_internal(self) -> None:
        text = "[AegisGate] 上游流提前断开（未收到 [DONE]）。已返回可恢复内容，建议重试获取完整结果。"
        assert _looks_like_gateway_internal_history_text(text) is True

    def test_normal_text_not_internal(self) -> None:
        assert _looks_like_gateway_internal_history_text("hello") is False


class TestStripSystemExecRuntimeLines:

    def test_removes_exec_lines(self) -> None:
        text = "line1\n  System: [tool] Exec completed\nline3"
        result = _strip_system_exec_runtime_lines(text)
        assert "Exec completed" not in result
        assert "line1" in result
        assert "line3" in result

    def test_preserves_normal_lines(self) -> None:
        text = "line1\nline2\nline3"
        assert _strip_system_exec_runtime_lines(text) == text

    def test_empty_input(self) -> None:
        assert _strip_system_exec_runtime_lines("") == ""

    def test_none_input(self) -> None:
        assert _strip_system_exec_runtime_lines(None) == ""


class TestSanitizePayloadForLog:

    def test_removes_parameters(self) -> None:
        value = {"name": "test", "parameters": {"x": 1}}
        result = _sanitize_payload_for_log(value)
        assert "parameters" not in result
        assert result["name"] == "test"

    def test_empties_tools(self) -> None:
        value = {"tools": [{"name": "tool1"}]}
        result = _sanitize_payload_for_log(value)
        assert result["tools"] == []

    def test_nested_dict(self) -> None:
        value = {"outer": {"parameters": {"x": 1}, "keep": "y"}}
        result = _sanitize_payload_for_log(value)
        assert "parameters" not in result["outer"]
        assert result["outer"]["keep"] == "y"

    def test_list_input(self) -> None:
        value = [{"parameters": {"x": 1}}, "raw"]
        result = _sanitize_payload_for_log(value)
        assert "parameters" not in result[0]
        assert result[1] == "raw"

    def test_scalar_passthrough(self) -> None:
        assert _sanitize_payload_for_log(42) == 42
        assert _sanitize_payload_for_log("hello") == "hello"


class TestShouldSkipResponsesFieldRedaction:

    def test_non_content_keys_skipped(self) -> None:
        assert _should_skip_responses_field_redaction("id") is True
        assert _should_skip_responses_field_redaction("type") is True
        assert _should_skip_responses_field_redaction("role") is True

    def test_crypto_fields_skipped(self) -> None:
        assert _should_skip_responses_field_redaction("ciphertext") is True
        assert _should_skip_responses_field_redaction("nonce") is True
        assert _should_skip_responses_field_redaction("signature") is True

    def test_suffix_patterns_skipped(self) -> None:
        assert _should_skip_responses_field_redaction("payload_encrypted") is True
        assert _should_skip_responses_field_redaction("data_nonce") is True

    def test_content_not_skipped(self) -> None:
        assert _should_skip_responses_field_redaction("content") is False
        assert _should_skip_responses_field_redaction("text") is False

    def test_empty_not_skipped(self) -> None:
        assert _should_skip_responses_field_redaction("") is False
        assert _should_skip_responses_field_redaction(None) is False


class TestSanitizeChatStructuredContent:

    def test_chat_structured_content_redacts_only_text_parts(self) -> None:
        messages = [
            {
                "role": "user",
                "name": "alice",
                "content": [
                    {"type": "text", "text": "Authorization: Bearer sk-live-secret"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}},
                    {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
                ],
                "provider_meta": {"keep": True},
            }
        ]

        sanitized, hits = _sanitize_chat_messages_for_upstream_with_hits(messages)

        assert sanitized == [
            {
                "role": "user",
                "name": "alice",
                "content": [
                    {"type": "text", "text": "Authorization: Bearer [REDACTED:TOKEN]"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}},
                    {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
                ],
                "provider_meta": {"keep": True},
            }
        ]
        assert hits == [
            {
                "path": "messages[0].content[0].text",
                "field": "text",
                "role": "user",
                "pattern": "TOKEN",
                "count": 1,
            }
        ]

    def test_chat_structured_content_preserves_unknown_nested_fields(self) -> None:
        messages = [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": "safe",
                        "annotations": [{"vendor": "x"}],
                    }
                ],
                "metadata": {"provider": "demo"},
            }
        ]

        sanitized, hits = _sanitize_chat_messages_for_upstream_with_hits(messages)

        assert sanitized == messages
        assert hits == []
