from aegisgate.core.confirmation import confirmation_template, parse_confirmation_decision


def test_confirmation_decision_yes_keywords():
    assert parse_confirmation_decision("yes").value == "yes"
    assert parse_confirmation_decision("y").value == "yes"
    assert parse_confirmation_decision("ok").value == "yes"
    assert parse_confirmation_decision("确认").value == "yes"
    assert parse_confirmation_decision("confirm").value == "yes"


def test_confirmation_decision_confirm_equals_is_unknown():
    assert parse_confirmation_decision("confirm=").value == "unknown"


def test_confirmation_decision_no_keywords():
    assert parse_confirmation_decision("no").value == "no"
    assert parse_confirmation_decision("cancel").value == "no"
    assert parse_confirmation_decision("取消").value == "no"


def test_confirmation_decision_ambiguous_when_yes_and_no():
    assert parse_confirmation_decision("yes no").value == "ambiguous"


def test_confirmation_decision_unknown_for_other_text():
    assert parse_confirmation_decision("please explain").value == "unknown"


def test_confirmation_template_contains_copy_ready_commands():
    confirm_id = "cfm-abc123def456"
    text = confirmation_template(confirm_id, reason="test", summary="summary")
    assert f"yes {confirm_id}" in text
    assert f"no {confirm_id}" in text


def test_confirmation_template_with_action_token_uses_bound_pair():
    confirm_id = "cfm-abc123def456"
    action_token = "act-bada1fe8dd"
    text = confirmation_template(confirm_id, reason="test", summary="summary", action_token=action_token)
    assert f"yes {confirm_id}--{action_token}" in text
    assert f"no {confirm_id}--{action_token}" in text
