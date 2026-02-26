from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.core.context import RequestContext


def test_write_audit_event_includes_poison_traceback(monkeypatch):
    captured: dict = {}

    def fake_write_audit(event: dict):
        captured.update(event)

    monkeypatch.setattr(openai_router, "write_audit", fake_write_audit)
    ctx = RequestContext(request_id="audit-1", session_id="s1", route="/v1/chat/completions")
    ctx.poison_traceback.append(
        {
            "phase": "retrieval",
            "source": "retrieval",
            "item_id": "chunk-1",
            "signals": ["retrieval_instruction_en"],
        }
    )

    openai_router._write_audit_event(ctx, boundary={"auth_verified": True})

    assert "poison_traceback" in captured
    assert isinstance(captured["poison_traceback"], list)
    assert captured["poison_traceback"][0]["item_id"] == "chunk-1"
