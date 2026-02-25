from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.tool_call_guard import ToolCallGuard


def test_tool_call_guard_blocks_disallowed_tool():
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
                {"name": "exec_shell", "arguments": {"cmd": "cat /etc/passwd"}},
            ]
        },
    )

    out = plugin.process_response(resp, ctx)
    assert out.output_text.startswith("[AegisGate] tool call blocked")
    assert ctx.requires_human_review is True
    assert "tool_call_violation" in ctx.security_tags
