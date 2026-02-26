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


def test_pending_confirmation_tenant_isolation(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    now = int(time.time())
    payload = {"model": "gpt", "messages": [{"role": "user", "content": "hello"}]}
    request_hash = payload_hash(payload)

    store.save_pending_confirmation(
        confirm_id="cfm-tenant00001",
        session_id="shared-session",
        tenant_id="tenant-a",
        route="/v1/chat/completions",
        request_id="r-a",
        model="gpt",
        upstream_base="https://example.com/v1",
        pending_request_payload=payload,
        pending_request_hash=request_hash,
        reason="高风险响应",
        summary="tenant-a",
        created_at=now,
        expires_at=now + 300,
        retained_until=now + 3600,
    )
    store.save_pending_confirmation(
        confirm_id="cfm-tenant00002",
        session_id="shared-session",
        tenant_id="tenant-b",
        route="/v1/chat/completions",
        request_id="r-b",
        model="gpt",
        upstream_base="https://example.com/v1",
        pending_request_payload=payload,
        pending_request_hash=request_hash,
        reason="高风险响应",
        summary="tenant-b",
        created_at=now + 1,
        expires_at=now + 300,
        retained_until=now + 3600,
    )

    pending_a = store.get_single_pending_confirmation(
        session_id="shared-session",
        route="/v1/chat/completions",
        now_ts=now + 2,
        tenant_id="tenant-a",
        recover_executing_before=None,
    )
    pending_b = store.get_single_pending_confirmation(
        session_id="shared-session",
        route="/v1/chat/completions",
        now_ts=now + 2,
        tenant_id="tenant-b",
        recover_executing_before=None,
    )
    assert pending_a is not None and pending_a["confirm_id"] == "cfm-tenant00001"
    assert pending_b is not None and pending_b["confirm_id"] == "cfm-tenant00002"


def test_pending_confirmation_recovers_stale_executing(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    now = int(time.time())
    payload = {"model": "gpt", "messages": [{"role": "user", "content": "hello"}]}
    request_hash = payload_hash(payload)

    store.save_pending_confirmation(
        confirm_id="cfm-execstale01",
        session_id="s-exec",
        tenant_id="default",
        route="/v1/chat/completions",
        request_id="r-exec",
        model="gpt",
        upstream_base="https://example.com/v1",
        pending_request_payload=payload,
        pending_request_hash=request_hash,
        reason="高风险响应",
        summary="executing stale",
        created_at=now - 100,
        expires_at=now + 300,
        retained_until=now + 3600,
    )
    store.update_pending_confirmation_status(confirm_id="cfm-execstale01", status="executing", now_ts=now - 90)

    recovered = store.get_single_pending_confirmation(
        session_id="s-exec",
        route="/v1/chat/completions",
        now_ts=now,
        tenant_id="default",
        recover_executing_before=now - 30,
    )
    assert recovered is not None
    assert recovered["status"] == "pending"
