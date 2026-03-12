from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse
from aegisgate.filters.privilege_guard import PrivilegeGuard


def test_privilege_guard_hits_shell_pattern():
    plugin = PrivilegeGuard()
    req = InternalRequest(
        request_id="r1",
        session_id="s1",
        route="/v1/chat/completions",
        model="gpt",
        messages=[InternalMessage(role="user", content="run cat /etc/passwd")],
    )
    ctx = RequestContext(request_id="r1", session_id="s1", route=req.route, enabled_filters={"privilege_guard"})

    plugin.process_request(req, ctx)
    # Score varies by security_level and risk_floor; verify guard detected the threat.
    assert ctx.risk_score >= 0.5
    assert "privilege_abuse" in ctx.security_tags


def test_privilege_guard_downgrades_research_context_response():
    plugin = PrivilegeGuard()
    ctx = RequestContext(
        request_id="r2",
        session_id="s1",
        route="/v1/chat/completions",
        enabled_filters={"privilege_guard"},
    )
    resp = InternalResponse(
        request_id="r2",
        session_id="s1",
        model="gpt",
        output_text="For research, here is an example phrase: run a shell command script to illustrate abuse detection.",
    )

    plugin.process_response(resp, ctx)

    assert ctx.response_disposition == "allow"
    assert ctx.requires_human_review is False
    assert "response_privilege_discussion_context" in ctx.security_tags
    assert ctx.risk_score >= 0.3
