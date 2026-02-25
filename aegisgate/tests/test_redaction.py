from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.filters.redaction import RedactionFilter, _mask_for_log
from aegisgate.storage.sqlite_store import SqliteKVStore


def test_redaction_replaces_email(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    plugin = RedactionFilter(store)

    req = InternalRequest(
        request_id="r1",
        session_id="s1",
        route="/v1/chat/completions",
        model="gpt",
        messages=[InternalMessage(role="user", content="my email is a@b.com")],
    )
    ctx = RequestContext(request_id="r1", session_id="s1", route=req.route, enabled_filters={"redaction"})

    out = plugin.process_request(req, ctx)
    assert "{{AG_R1_EMAIL_1}}" in out.messages[0].content
    assert ctx.redaction_mapping["{{AG_R1_EMAIL_1}}"] == "a@b.com"


def test_redaction_replaces_chinese_mobile(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    plugin = RedactionFilter(store)

    req = InternalRequest(
        request_id="r2",
        session_id="s1",
        route="/v1/chat/completions",
        model="gpt",
        messages=[InternalMessage(role="user", content="我的手机号是13800138000")],
    )
    ctx = RequestContext(request_id="r2", session_id="s1", route=req.route, enabled_filters={"redaction"})

    out = plugin.process_request(req, ctx)
    assert "{{AG_R2_CN_MOBILE_1}}" in out.messages[0].content


def test_redaction_log_masks_sensitive_value(tmp_path, monkeypatch):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    plugin = RedactionFilter(store)
    captured: list[str] = []

    def fake_info(message, *args):
        captured.append(message % args)

    monkeypatch.setattr("aegisgate.filters.redaction.logger.info", fake_info)

    raw_secret = "sk-test-abcdefghijklmnopqrstuvwxyz12345"
    req = InternalRequest(
        request_id="r3",
        session_id="s1",
        route="/v1/chat/completions",
        model="gpt",
        messages=[InternalMessage(role="user", content=f"token={raw_secret}")],
    )
    ctx = RequestContext(request_id="r3", session_id="s1", route=req.route, enabled_filters={"redaction"})

    plugin.process_request(req, ctx)

    assert captured
    last_log = captured[-1]
    assert raw_secret not in last_log
    assert _mask_for_log(raw_secret) in last_log
    assert "redaction_applied" in last_log
    assert "marker" in last_log
