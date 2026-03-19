from __future__ import annotations

from typing import Any

from aegisgate.adapters.openai_compat import pipeline_runtime


class InMemoryStore:
    def __init__(self, name: str) -> None:
        self.name = name
        self.mappings: dict[tuple[str, str], dict[str, str]] = {}
        self.pending: dict[str, dict[str, Any]] = {}
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        self.mappings[(session_id, request_id)] = dict(mapping)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return dict(self.mappings.get((session_id, request_id), {}))

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return dict(self.mappings.pop((session_id, request_id), {}))

    def save_pending_confirmation(
        self,
        *,
        confirm_id: str,
        session_id: str,
        route: str,
        request_id: str,
        model: str,
        upstream_base: str,
        pending_request_payload: dict[str, Any],
        pending_request_hash: str,
        reason: str,
        summary: str,
        created_at: int,
        expires_at: int,
        retained_until: int,
        tenant_id: str = "default",
    ) -> None:
        self.pending[confirm_id] = {
            "confirm_id": confirm_id,
            "session_id": session_id,
            "route": route,
            "request_id": request_id,
            "model": model,
            "upstream_base": upstream_base,
            "pending_request_payload": dict(pending_request_payload),
            "pending_request_hash": pending_request_hash,
            "reason": reason,
            "summary": summary,
            "status": "pending",
            "created_at": created_at,
            "expires_at": expires_at,
            "retained_until": retained_until,
            "updated_at": created_at,
            "tenant_id": tenant_id,
        }

    def get_latest_pending_confirmation(
        self,
        session_id: str,
        now_ts: int,
        *,
        tenant_id: str = "default",
    ) -> dict[str, Any] | None:
        matches = [
            record
            for record in self.pending.values()
            if record["session_id"] == session_id
            and record["tenant_id"] == tenant_id
            and record["status"] == "pending"
            and int(record["expires_at"]) > int(now_ts)
        ]
        if not matches:
            return None
        return dict(max(matches, key=lambda item: int(item["created_at"])))

    def get_single_pending_confirmation(
        self,
        *,
        session_id: str,
        route: str,
        now_ts: int,
        tenant_id: str = "default",
        recover_executing_before: int | None = None,
    ) -> dict[str, Any] | None:
        del recover_executing_before
        matches = [
            dict(record)
            for record in self.pending.values()
            if record["session_id"] == session_id
            and record["route"] == route
            and record["tenant_id"] == tenant_id
            and record["status"] == "pending"
            and int(record["expires_at"]) > int(now_ts)
        ]
        if len(matches) != 1:
            return None
        return matches[0]

    def compare_and_update_pending_confirmation_status(
        self,
        *,
        confirm_id: str,
        expected_status: str,
        new_status: str,
        now_ts: int,
    ) -> bool:
        record = self.pending.get(confirm_id)
        if record is None or record["status"] != expected_status:
            return False
        record["status"] = new_status
        record["updated_at"] = now_ts
        return True

    def get_pending_confirmation(self, confirm_id: str) -> dict[str, Any] | None:
        record = self.pending.get(confirm_id)
        return dict(record) if record is not None else None

    def update_pending_confirmation_status(self, *, confirm_id: str, status: str, now_ts: int) -> None:
        record = self.pending.get(confirm_id)
        if record is None:
            return
        record["status"] = status
        record["updated_at"] = now_ts

    def delete_pending_confirmation(self, *, confirm_id: str) -> bool:
        return self.pending.pop(confirm_id, None) is not None

    def prune_pending_confirmations(self, now_ts: int) -> int:
        removable = [confirm_id for confirm_id, record in self.pending.items() if int(record["retained_until"]) <= int(now_ts)]
        for confirm_id in removable:
            self.pending.pop(confirm_id, None)
        return len(removable)

    def clear_all_pending_confirmations(self) -> int:
        removed = len(self.pending)
        self.pending.clear()
        return removed


def test_get_pipeline_reuses_cached_instance_for_current_thread():
    pipeline_runtime.reset_pipeline_cache()

    first = pipeline_runtime._get_pipeline()
    second = pipeline_runtime._get_pipeline()

    assert first is second


def test_reset_pipeline_cache_invalidates_cached_pipeline():
    pipeline_runtime.reset_pipeline_cache()
    first = pipeline_runtime._get_pipeline()

    pipeline_runtime.reset_pipeline_cache()
    second = pipeline_runtime._get_pipeline()

    assert first is not second


def test_reload_runtime_dependencies_swaps_store_and_invalidates_pipeline(monkeypatch):
    original_backend = pipeline_runtime.store.backend

    class ReplacementStore:
        def marker(self) -> str:
            return "replacement"

    try:
        pipeline_runtime.reset_pipeline_cache()
        first = pipeline_runtime._get_pipeline()
        replacement = ReplacementStore()
        monkeypatch.setattr(pipeline_runtime, "create_store", lambda: replacement)

        pipeline_runtime.reload_runtime_dependencies()
        second = pipeline_runtime._get_pipeline()

        assert first is not second
        assert pipeline_runtime.store.backend is replacement
        assert pipeline_runtime.store.marker() == "replacement"
    finally:
        pipeline_runtime.store.swap(original_backend)
        pipeline_runtime.reset_pipeline_cache()


def test_close_runtime_dependencies_closes_retired_and_current_backends():
    original_backend = pipeline_runtime.store.backend
    closed: list[str] = []

    class ClosableStore:
        def __init__(self, name: str) -> None:
            self.name = name

        def close(self) -> None:
            closed.append(self.name)

        def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
            return None

        def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
            return {}

        def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
            return {}

        def save_pending_confirmation(self, **kwargs) -> None:
            return None

        def get_latest_pending_confirmation(self, session_id: str, now_ts: int, *, tenant_id: str = "default"):
            return None

        def get_single_pending_confirmation(
            self,
            *,
            session_id: str,
            route: str,
            now_ts: int,
            tenant_id: str = "default",
            recover_executing_before: int | None = None,
        ):
            return None

        def compare_and_update_pending_confirmation_status(
            self,
            *,
            confirm_id: str,
            expected_status: str,
            new_status: str,
            now_ts: int,
        ) -> bool:
            return False

        def get_pending_confirmation(self, confirm_id: str):
            return None

        def update_pending_confirmation_status(self, *, confirm_id: str, status: str, now_ts: int) -> None:
            return None

        def delete_pending_confirmation(self, *, confirm_id: str) -> bool:
            return False

        def prune_pending_confirmations(self, now_ts: int) -> int:
            return 0

        def clear_all_pending_confirmations(self) -> int:
            return 0

    first = ClosableStore("first")
    second = ClosableStore("second")
    try:
        pipeline_runtime.store.swap(first)
        pipeline_runtime.store.swap(second)

        pipeline_runtime.close_runtime_dependencies()

        assert closed == ["first", "second"]
    finally:
        pipeline_runtime.store.swap(original_backend)
        pipeline_runtime.reset_pipeline_cache()


def test_runtime_store_proxy_reads_retired_backend_after_hot_reload():
    first = InMemoryStore("first")
    second = InMemoryStore("second")
    proxy = pipeline_runtime.RuntimeStoreProxy(first)

    first.set_mapping("s1", "req-1", {"{{AG_REQ_1}}": "secret"})
    proxy.swap(second)

    assert proxy.get_mapping("s1", "req-1") == {"{{AG_REQ_1}}": "secret"}
    assert proxy.consume_mapping("s1", "req-1") == {"{{AG_REQ_1}}": "secret"}
    assert first.get_mapping("s1", "req-1") == {}


def test_runtime_store_proxy_handles_pending_records_across_retired_backends():
    first = InMemoryStore("first")
    second = InMemoryStore("second")
    proxy = pipeline_runtime.RuntimeStoreProxy(first)

    first.save_pending_confirmation(
        confirm_id="cfm-old",
        session_id="s1",
        route="/v1/chat/completions",
        request_id="req-old",
        model="gpt",
        upstream_base="http://example/v1",
        pending_request_payload={"messages": []},
        pending_request_hash="hash-old",
        reason="review",
        summary="summary",
        created_at=100,
        expires_at=200,
        retained_until=300,
    )
    proxy.swap(second)
    second.save_pending_confirmation(
        confirm_id="cfm-new",
        session_id="s1",
        route="/v1/chat/completions",
        request_id="req-new",
        model="gpt",
        upstream_base="http://example/v1",
        pending_request_payload={"messages": []},
        pending_request_hash="hash-new",
        reason="review",
        summary="summary",
        created_at=150,
        expires_at=250,
        retained_until=350,
    )

    latest = proxy.get_latest_pending_confirmation("s1", 120)
    assert latest is not None
    assert latest["confirm_id"] == "cfm-new"

    assert proxy.get_pending_confirmation("cfm-old")["confirm_id"] == "cfm-old"
    assert proxy.compare_and_update_pending_confirmation_status(
        confirm_id="cfm-old",
        expected_status="pending",
        new_status="executing",
        now_ts=121,
    )
    assert first.get_pending_confirmation("cfm-old")["status"] == "executing"

    proxy.update_pending_confirmation_status(confirm_id="cfm-old", status="expired", now_ts=122)
    assert first.get_pending_confirmation("cfm-old")["status"] == "expired"

    assert proxy.delete_pending_confirmation(confirm_id="cfm-old") is True
    assert first.get_pending_confirmation("cfm-old") is None

    assert proxy.prune_pending_confirmations(400) == 1
    assert second.get_pending_confirmation("cfm-new") is None


def test_runtime_store_proxy_returns_none_when_session_pending_records_span_backends():
    first = InMemoryStore("first")
    second = InMemoryStore("second")
    proxy = pipeline_runtime.RuntimeStoreProxy(first)

    first.save_pending_confirmation(
        confirm_id="cfm-old",
        session_id="s1",
        route="/v1/chat/completions",
        request_id="req-old",
        model="gpt",
        upstream_base="http://example/v1",
        pending_request_payload={"messages": []},
        pending_request_hash="hash-old",
        reason="review",
        summary="summary",
        created_at=100,
        expires_at=200,
        retained_until=300,
    )
    proxy.swap(second)
    second.save_pending_confirmation(
        confirm_id="cfm-new",
        session_id="s1",
        route="/v1/chat/completions",
        request_id="req-new",
        model="gpt",
        upstream_base="http://example/v1",
        pending_request_payload={"messages": []},
        pending_request_hash="hash-new",
        reason="review",
        summary="summary",
        created_at=150,
        expires_at=250,
        retained_until=350,
    )

    assert proxy.get_single_pending_confirmation(
        session_id="s1",
        route="/v1/chat/completions",
        now_ts=120,
    ) is None
    assert proxy.clear_all_pending_confirmations() == 2


def test_runtime_store_proxy_deduplicates_same_pending_record_across_reloaded_backends():
    first = InMemoryStore("first")
    second = InMemoryStore("second")
    proxy = pipeline_runtime.RuntimeStoreProxy(first)

    pending_record = dict(
        confirm_id="cfm-shared",
        session_id="s1",
        route="/v1/chat/completions",
        request_id="req-shared",
        model="gpt",
        upstream_base="http://example/v1",
        pending_request_payload={"messages": []},
        pending_request_hash="hash-shared",
        reason="review",
        summary="summary",
        created_at=100,
        expires_at=200,
        retained_until=300,
    )
    first.save_pending_confirmation(**pending_record)
    proxy.swap(second)
    second.save_pending_confirmation(**pending_record)

    pending = proxy.get_single_pending_confirmation(
        session_id="s1",
        route="/v1/chat/completions",
        now_ts=120,
    )

    assert pending is not None
    assert pending["confirm_id"] == "cfm-shared"
