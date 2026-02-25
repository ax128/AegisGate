import time

from aegisgate.core.confirmation import payload_hash
from aegisgate.storage.sqlite_store import SqliteKVStore


def test_pending_confirmation_lifecycle(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    now = int(time.time())
    payload = {"model": "gpt", "messages": [{"role": "user", "content": "hello"}]}
    request_hash = payload_hash(payload)

    store.save_pending_confirmation(
        confirm_id="cfm-abc123def456",
        session_id="s1",
        route="/v1/chat/completions",
        request_id="r1",
        model="gpt",
        upstream_base="https://example.com/v1",
        pending_request_payload=payload,
        pending_request_hash=request_hash,
        reason="高风险响应",
        summary="触发信号：response_anomaly_high_risk_command",
        created_at=now,
        expires_at=now + 300,
        retained_until=now + 3600,
    )

    pending = store.get_latest_pending_confirmation(session_id="s1", now_ts=now)
    assert pending is not None
    assert pending["confirm_id"] == "cfm-abc123def456"
    assert pending["pending_request_hash"] == request_hash
    assert pending["status"] == "pending"

    store.update_pending_confirmation_status(confirm_id="cfm-abc123def456", status="executed", now_ts=now + 1)
    pending2 = store.get_latest_pending_confirmation(session_id="s1", now_ts=now + 1)
    assert pending2 is None


def test_pending_confirmation_expires(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    now = int(time.time())
    payload = {"model": "gpt", "input": "hello"}
    request_hash = payload_hash(payload)

    store.save_pending_confirmation(
        confirm_id="cfm-expire000001",
        session_id="s2",
        route="/v1/responses",
        request_id="r2",
        model="gpt",
        upstream_base="https://example.com/v1",
        pending_request_payload=payload,
        pending_request_hash=request_hash,
        reason="高风险响应",
        summary="触发信号：response_unicode_bidi",
        created_at=now,
        expires_at=now + 1,
        retained_until=now + 3600,
    )

    assert store.get_latest_pending_confirmation(session_id="s2", now_ts=now) is not None
    assert store.get_latest_pending_confirmation(session_id="s2", now_ts=now + 5) is None

    by_id = store.get_pending_confirmation("cfm-expire000001")
    assert by_id is not None
    assert by_id["status"] == "expired"
