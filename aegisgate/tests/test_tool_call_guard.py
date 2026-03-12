from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.tool_call_guard import ToolCallGuard


def test_tool_call_guard_allows_benign_tool_when_no_whitelist_is_configured():
    plugin = ToolCallGuard()
    ctx = RequestContext(
        request_id="req-tool",
        session_id="s1",
        route="/v1/chat/completions",
        enabled_filters={"tool_call_guard"},
    )
    resp = InternalResponse(
        request_id="req-tool",
        session_id="s1",
        model="gpt",
        output_text="will call tool",
        metadata={
            "tool_calls": [
                {"name": "weather_lookup", "arguments": {"location": "Tokyo"}},
            ]
        },
    )

    out = plugin.process_response(resp, ctx)
    assert out.output_text == "will call tool"
    assert ctx.requires_human_review is False
    assert "tool_call_violation" not in ctx.security_tags
    assert ctx.risk_score == 0.0


def test_tool_call_guard_blocks_dangerous_arguments_from_chat_raw_payload():
    plugin = ToolCallGuard()
    ctx = RequestContext(
        request_id="req-tool-raw",
        session_id="s1",
        route="/v1/chat/completions",
        enabled_filters={"tool_call_guard"},
    )
    resp = InternalResponse(
        request_id="req-tool-raw",
        session_id="s1",
        model="gpt",
        output_text="tool summary",
        raw={
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "type": "function",
                                "function": {"name": "exec_shell", "arguments": '{"cmd":"cat /etc/passwd && whoami"}'},
                            }
                        ]
                    }
                }
            ]
        },
    )

    out = plugin.process_response(resp, ctx)
    assert out.output_text.startswith("[AegisGate] tool call blocked")
    assert ctx.requires_human_review is True
    assert ctx.risk_score >= 0.96


def test_tool_call_guard_reads_responses_function_call_items():
    plugin = ToolCallGuard()
    ctx = RequestContext(
        request_id="req-tool-resp",
        session_id="s1",
        route="/v1/responses",
        enabled_filters={"tool_call_guard"},
    )
    resp = InternalResponse(
        request_id="req-tool-resp",
        session_id="s1",
        model="gpt",
        output_text="response tool call",
        raw={
            "output": [
                {
                    "type": "function_call",
                    "name": "exec_shell",
                    "arguments": '{"cmd":"cat /etc/passwd"}',
                }
            ]
        },
    )

    plugin.process_response(resp, ctx)
    assert ctx.requires_human_review is True
    assert "tool_call_violation" in ctx.security_tags
