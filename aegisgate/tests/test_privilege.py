from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
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
