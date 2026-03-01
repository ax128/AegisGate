from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.sqlite_store import SqliteKVStore
from aegisgate.util.masking import mask_for_log as _mask_for_log


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

    # 脱敏事件升级为 WARNING 级别
    def fake_warning(message, *args):
        captured.append(message % args)

    monkeypatch.setattr("aegisgate.filters.redaction.logger.warning", fake_warning)

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
    # 日志需包含 session_id、route 和 msg_role 以便追溯调用方
    assert "s1" in last_log          # session_id
    assert "user" in last_log        # msg_role
    assert "TOKEN" in last_log       # kind


def test_redaction_field_aware_bearer_token(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    plugin = RedactionFilter(store)

    req = InternalRequest(
        request_id="r4",
        session_id="s1",
        route="/v1/chat/completions",
        model="gpt",
        messages=[InternalMessage(role="user", content="Authorization: Bearer abcdefghijklmnopQRST1234")],
    )
    ctx = RequestContext(request_id="r4", session_id="s1", route=req.route, enabled_filters={"redaction"})

    out = plugin.process_request(req, ctx)
    assert "{{AG_R4_AUTH_BEARER_1}}" in out.messages[0].content
    assert ctx.redaction_mapping["{{AG_R4_AUTH_BEARER_1}}"].startswith("Authorization: Bearer ")


def test_redaction_reuses_placeholder_for_same_value(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    plugin = RedactionFilter(store)

    secret = "token=sk-abcdeABCDE1234567890xyz"
    req = InternalRequest(
        request_id="r5",
        session_id="s1",
        route="/v1/chat/completions",
        model="gpt",
        messages=[InternalMessage(role="user", content=f"{secret} and again {secret}")],
    )
    ctx = RequestContext(request_id="r5", session_id="s1", route=req.route, enabled_filters={"redaction"})

    out = plugin.process_request(req, ctx)
    marker = "{{AG_R5_TOKEN_1}}"
    assert out.messages[0].content.count(marker) == 2
    assert len(ctx.redaction_mapping) == 1


def test_redaction_normalizes_invisible_chars_before_matching(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    plugin = RedactionFilter(store)

    req = InternalRequest(
        request_id="r6",
        session_id="s1",
        route="/v1/chat/completions",
        model="gpt",
        messages=[InternalMessage(role="user", content="my email is a\u200bb@c.com")],
    )
    ctx = RequestContext(request_id="r6", session_id="s1", route=req.route, enabled_filters={"redaction"})

    out = plugin.process_request(req, ctx)
    assert "{{AG_R6_EMAIL_1}}" in out.messages[0].content


def test_redaction_relaxes_pii_for_responses_route(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    plugin = RedactionFilter(store)

    req = InternalRequest(
        request_id="r7",
        session_id="s1",
        route="/v1/responses",
        model="gpt",
        messages=[InternalMessage(role="user", content="email a@b.com token=sk-abcdeABCDE1234567890xyz")],
    )
    ctx = RequestContext(request_id="r7", session_id="s1", route=req.route, enabled_filters={"redaction"})

    out = plugin.process_request(req, ctx)
    text = out.messages[0].content
    assert "a@b.com" in text
    assert "{{AG_R7_TOKEN_1}}" in text
    assert "sk-abcdeABCDE1234567890xyz" not in text
