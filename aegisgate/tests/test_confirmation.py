from aegisgate.core.confirmation import parse_confirmation_decision


def test_confirmation_decision_yes_keywords():
    assert parse_confirmation_decision("yes").value == "yes"
    assert parse_confirmation_decision("ok").value == "yes"
    assert parse_confirmation_decision("确认").value == "yes"


def test_confirmation_decision_no_keywords():
    assert parse_confirmation_decision("no").value == "no"
    assert parse_confirmation_decision("cancel").value == "no"
    assert parse_confirmation_decision("取消").value == "no"


def test_confirmation_decision_ambiguous_when_yes_and_no():
    assert parse_confirmation_decision("yes no").value == "ambiguous"


def test_confirmation_decision_unknown_for_other_text():
    assert parse_confirmation_decision("please explain").value == "unknown"
