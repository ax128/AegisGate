import time

from aegisgate.config.settings import settings
from aegisgate.core.confirmation import payload_hash
from aegisgate.storage.sqlite_store import SqliteKVStore, json_loads


def _save_pending(store: SqliteKVStore, *, confirm_id: str, session_id: str, route: str, now: int) -> None:
    payload = {"model": "gpt", "messages": [{"role": "user", "content": "hello"}]}
    store.save_pending_confirmation(
        confirm_id=confirm_id,
        session_id=session_id,
        route=route,
        request_id=f"req-{confirm_id}",
        model="gpt",
        upstream_base="https://example.com/v1",
        pending_request_payload=payload,
        pending_request_hash=payload_hash(payload),
        reason="高风险响应",
        summary=f"summary-{confirm_id}",
        created_at=now,
        expires_at=now + 300,
        retained_until=now + 3600,
    )


def test_get_single_pending_confirmation_returns_none_for_multiple_matches(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    now = int(time.time())

    _save_pending(store, confirm_id="cfm-a", session_id="shared", route="/v1/chat/completions", now=now)
    _save_pending(store, confirm_id="cfm-b", session_id="shared", route="/v1/chat/completions", now=now + 1)

    pending = store.get_single_pending_confirmation(
        session_id="shared",
        route="/v1/chat/completions",
        now_ts=now + 2,
    )

    assert pending is None


def test_get_single_pending_confirmation_returns_none_when_stale_executing_recovery_fails(tmp_path, monkeypatch):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    now = int(time.time())

    _save_pending(store, confirm_id="cfm-exec-fail", session_id="s1", route="/v1/chat/completions", now=now - 100)
    store.update_pending_confirmation_status(confirm_id="cfm-exec-fail", status="executing", now_ts=now - 90)
    monkeypatch.setattr(store, "compare_and_update_pending_confirmation_status", lambda **kwargs: False)

    pending = store.get_single_pending_confirmation(
        session_id="s1",
        route="/v1/chat/completions",
        now_ts=now,
        recover_executing_before=now - 30,
    )

    assert pending is None


def test_delete_and_clear_pending_confirmations_return_row_counts(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    now = int(time.time())

    _save_pending(store, confirm_id="cfm-delete", session_id="s1", route="/v1/chat/completions", now=now)
    _save_pending(store, confirm_id="cfm-clear", session_id="s2", route="/v1/responses", now=now + 1)

    assert store.delete_pending_confirmation(confirm_id="cfm-delete") is True
    assert store.delete_pending_confirmation(confirm_id="missing") is False
    assert store.get_pending_confirmation("cfm-delete") is None
    assert store.clear_all_pending_confirmations() == 1
    assert store.get_pending_confirmation("cfm-clear") is None


def test_prune_pending_confirmations_recovers_stale_executing_records(tmp_path, monkeypatch):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    now = int(time.time())
    old_timeout = settings.confirmation_executing_timeout_seconds

    _save_pending(store, confirm_id="cfm-retained", session_id="s1", route="/v1/chat/completions", now=now - 200)
    _save_pending(store, confirm_id="cfm-executing", session_id="s2", route="/v1/chat/completions", now=now - 100)
    store.update_pending_confirmation_status(confirm_id="cfm-executing", status="executing", now_ts=now - 90)

    active = store.get_pending_confirmation("cfm-retained")
    assert active is not None

    with store._managed_connection() as conn:
        conn.execute(
            "UPDATE pending_confirmation SET retained_until = ? WHERE confirm_id = ?",
            (now - 1, "cfm-retained"),
        )
        conn.commit()

    monkeypatch.setattr(settings, "confirmation_executing_timeout_seconds", 30)
    try:
        removed = store.prune_pending_confirmations(now)
    finally:
        monkeypatch.setattr(settings, "confirmation_executing_timeout_seconds", old_timeout)

    recovered = store.get_pending_confirmation("cfm-executing")
    assert removed == 1
    assert recovered is not None
    assert recovered["status"] == "pending"
    assert recovered["updated_at"] == now


def test_json_loads_returns_empty_dict_for_non_dict_payload():
    assert json_loads('["not","a","dict"]') == {}
