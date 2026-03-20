from aegisgate.core import confirmation_flow


def test_get_reason_and_summary_defaults_for_request_phase():
    reason, summary = confirmation_flow.get_reason_and_summary(
        confirmation_flow.PHASE_REQUEST,
        disposition_reasons=[],
        security_tags={"response_high_risk", "request_privilege_abuse"},
    )

    assert reason == "请求被安全策略拦截"
    assert summary == "触发信号：request_blocked"


def test_get_reason_and_summary_uses_custom_reason_and_response_tags():
    reason, summary = confirmation_flow.get_reason_and_summary(
        confirmation_flow.PHASE_RESPONSE,
        disposition_reasons=["custom_reason"],
        security_tags={
            "request_ignored",
            "response_zulu",
            "response_alpha",
            "response_bravo",
            "response_extra",
        },
    )

    assert reason == "custom_reason"
    assert summary == "触发信号：custom_reason（response_alpha、response_bravo、response_extra）"


def test_build_confirmation_message_prepends_note():
    message = confirmation_flow.build_confirmation_message(
        confirm_id="cfm-123",
        reason="高风险响应",
        summary="触发信号：response_high_risk",
        note="请联系管理员",
        action_token="act-123",
    )

    assert message.startswith("请联系管理员\n\n")
    assert "cfm-123" in message
    assert "高风险响应" in message


def test_build_confirmation_metadata_marks_pending_as_required():
    metadata = confirmation_flow.build_confirmation_metadata(
        confirm_id="cfm-456",
        status="pending",
        reason="高风险命令响应",
        summary="检测到高风险命令输出信号",
        phase=confirmation_flow.PHASE_RESPONSE,
        payload_omitted=True,
        action_token="act-456",
    )

    assert metadata == {
        "required": True,
        "confirm_id": "cfm-456",
        "status": "pending",
        "reason": "高风险命令响应",
        "summary": "检测到高风险命令输出信号",
        "phase": "response",
        "payload_omitted": True,
        "action_token": "act-456",
    }
