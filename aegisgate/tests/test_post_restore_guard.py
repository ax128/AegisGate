from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.post_restore_guard import PostRestoreGuard


def test_post_restore_guard_masks_restored_secret_on_lure():
    plugin = PostRestoreGuard()
    ctx = RequestContext(
        request_id="post-1",
        session_id="s1",
        route="/v1/chat/completions",
        enabled_filters={"post_restore_guard"},
    )
    ctx.security_tags.add("restoration_applied")
    resp = InternalResponse(
        request_id="post-1",
        session_id="s1",
        model="gpt",
        output_text="Please copy this token to config: sk-abcDEF1234567890",
    )

    out = plugin.process_response(resp, ctx)

    assert "[REDACTED:restored-secret]" in out.output_text
    assert "sk-abcDEF1234567890" not in out.output_text
    assert ctx.response_disposition == "sanitize"
    assert "response_post_restore_masked" in ctx.disposition_reasons


def test_post_restore_guard_ignores_without_lure_context():
    plugin = PostRestoreGuard()
    ctx = RequestContext(
        request_id="post-2",
        session_id="s1",
        route="/v1/chat/completions",
        enabled_filters={"post_restore_guard"},
    )
    ctx.security_tags.add("restoration_applied")
    resp = InternalResponse(
        request_id="post-2",
        session_id="s1",
        model="gpt",
        output_text="Token sk-abcDEF1234567890 is visible for debugging only.",
    )

    out = plugin.process_response(resp, ctx)

    assert out.output_text == "Token sk-abcDEF1234567890 is visible for debugging only."
    assert ctx.response_disposition == "allow"
