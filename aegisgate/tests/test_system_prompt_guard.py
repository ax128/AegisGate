from aegisgate.config.settings import Settings
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.filters.system_prompt_guard import SystemPromptGuard


def test_system_prompt_guard_masks_system_messages():
    plugin = SystemPromptGuard()
    req = InternalRequest(
        request_id="req-1",
        session_id="s1",
        route="/v1/chat/completions",
        model="gpt",
        messages=[
            InternalMessage(role="system", content="internal secret instructions"),
            InternalMessage(role="user", content="hello"),
        ],
    )
    ctx = RequestContext(
        request_id="req-1",
        session_id="s1",
        route=req.route,
        enabled_filters={"system_prompt_guard"},
    )

    out = plugin.process_request(req, ctx)
    assert out.messages[0].content.startswith("[SYSTEM_PROMPT_PROTECTED]::")
    assert "internal secret instructions" not in out.messages[0].content
    assert out.messages[1].content == "hello"


def test_system_prompt_guard_default_flag_is_false():
    assert Settings.model_fields["enable_system_prompt_guard"].default is False
