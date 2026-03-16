from aegisgate.core.confirmation import confirmation_template, parse_confirmation_decision


def test_confirmation_decision_yes_keywords_no_longer_recognized():
    """YES_WORDS is now empty — all yes-like inputs resolve to 'unknown'."""
    assert parse_confirmation_decision("yes").value == "unknown"
    assert parse_confirmation_decision("y").value == "unknown"
    assert parse_confirmation_decision("ok").value == "unknown"
    assert parse_confirmation_decision("确认").value == "unknown"
    assert parse_confirmation_decision("confirm").value == "unknown"


def test_confirmation_decision_confirm_equals_is_unknown():
    assert parse_confirmation_decision("confirm=").value == "unknown"


def test_confirmation_decision_no_keywords():
    assert parse_confirmation_decision("no").value == "no"
    assert parse_confirmation_decision("cancel").value == "no"
    assert parse_confirmation_decision("取消").value == "no"


def test_confirmation_decision_yes_and_no_resolves_to_no():
    """With YES_WORDS empty, only 'no' is recognized."""
    assert parse_confirmation_decision("yes no").value == "no"


def test_confirmation_decision_unknown_for_other_text():
    assert parse_confirmation_decision("please explain").value == "unknown"


def test_confirmation_template_is_informational_only():
    """Template no longer contains yes/no approval options."""
    confirm_id = "cfm-abc123def456"
    text = confirmation_template(confirm_id, reason="test", summary="summary")
    assert confirm_id in text
    assert "yes" not in text.lower() or "yes" not in text
    assert "不支持放行" in text
    assert "approval is not available" in text.lower()


def test_confirmation_template_with_action_token_uses_bound_pair():
    """action_token is accepted but template remains informational only."""
    confirm_id = "cfm-abc123def456"
    action_token = "act-bada1fe8dd"
    text = confirmation_template(confirm_id, reason="test", summary="summary", action_token=action_token)
    assert confirm_id in text
    assert "不支持放行" in text
    # No yes/no copy-ready lines
    assert f"yes {confirm_id}" not in text
