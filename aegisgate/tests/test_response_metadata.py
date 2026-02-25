from aegisgate.core.models import InternalResponse
from aegisgate.adapters.openai_compat.mapper import to_chat_response


def test_chat_response_contains_aegisgate_metadata_if_present():
    resp = InternalResponse(
        request_id="r1",
        session_id="s1",
        model="gpt",
        output_text="ok",
        metadata={"aegisgate": {"risk_score": 0.2, "requires_human_review": False}},
    )

    output = to_chat_response(resp)
    assert "aegisgate" in output
    assert output["aegisgate"]["risk_score"] == 0.2
