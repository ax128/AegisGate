from pathlib import Path

from aegisgate.core.context import RequestContext
from aegisgate.policies.policy_engine import PolicyEngine


def test_policy_engine_always_enables_redaction(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "default.yaml").write_text(
        "enabled_filters:\n  - anomaly_detector\nrisk_threshold: 0.70\n",
        encoding="utf-8",
    )

    engine = PolicyEngine(rules_dir=str(rules_dir))
    ctx = RequestContext(request_id="p1", session_id="s1", route="/v1/chat/completions")
    result = engine.resolve(ctx, policy_name="default")

    assert "redaction" in result["enabled_filters"]
    assert "redaction" in ctx.enabled_filters


def test_builtin_default_policy_enables_low_false_positive_guards(tmp_path: Path):
    engine = PolicyEngine(rules_dir=str(tmp_path / "missing-rules"))
    ctx = RequestContext(request_id="p2", session_id="s1", route="/v1/chat/completions")

    result = engine.resolve(ctx, policy_name="default")

    assert "untrusted_content_guard" in result["enabled_filters"]
    assert "tool_call_guard" in result["enabled_filters"]
