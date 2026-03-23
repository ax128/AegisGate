"""Shared store and pipeline runtime for OpenAI-compatible routes."""

from __future__ import annotations

import threading
from typing import Any, cast

from aegisgate.core.pipeline import Pipeline
from aegisgate.filters.anomaly_detector import AnomalyDetector
from aegisgate.filters.exact_value_redaction import ExactValueRedactionFilter
from aegisgate.filters.injection_detector import PromptInjectionDetector
from aegisgate.filters.post_restore_guard import PostRestoreGuard
from aegisgate.filters.privilege_guard import PrivilegeGuard
from aegisgate.filters.rag_poison_guard import RagPoisonGuard
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.filters.request_sanitizer import RequestSanitizer
from aegisgate.filters.restoration import RestorationFilter
from aegisgate.filters.sanitizer import OutputSanitizer
from aegisgate.filters.system_prompt_guard import SystemPromptGuard
from aegisgate.filters.tool_call_guard import ToolCallGuard
from aegisgate.filters.untrusted_content_guard import UntrustedContentGuard
from aegisgate.init_config import ensure_runtime_storage_paths
from aegisgate.storage import create_store
from aegisgate.storage.kv import KVStore
from aegisgate.util.logger import logger


ensure_runtime_storage_paths()
_pipeline_local = threading.local()


def _close_store_backend(backend: object) -> None:
    close_method = getattr(backend, "close", None)
    if callable(close_method):
        try:
            close_method()
        except Exception as exc:  # pragma: no cover - operational safeguard
            logger.warning(
                "runtime store close failed backend=%s error=%s",
                type(backend).__name__,
                exc,
            )


class RuntimeStoreProxy(KVStore):
    """Stable store handle whose backend can be swapped on hot-reload."""

    def __init__(self, backend: object) -> None:
        self._backend = backend
        self._lock = threading.RLock()
        self._retired_backends: list[object] = []

    @property
    def backend(self) -> object:
        with self._lock:
            return self._backend

    def _backend_candidates(self) -> list[KVStore]:
        with self._lock:
            backends = [self._backend, *reversed(self._retired_backends)]
        seen: set[int] = set()
        candidates: list[KVStore] = []
        for backend in backends:
            backend_id = id(backend)
            if backend_id in seen:
                continue
            seen.add(backend_id)
            candidates.append(cast(KVStore, backend))
        return candidates

    def _typed_backend(self) -> KVStore:
        return cast(KVStore, self.backend)

    def swap(self, backend: object) -> None:
        with self._lock:
            old_backend = self._backend
            self._backend = backend
            if old_backend is not backend:
                # Keep old backends alive until shutdown so in-flight requests
                # can finish on the object they already captured.
                self._retired_backends.append(old_backend)

    def set_mapping(
        self, session_id: str, request_id: str, mapping: dict[str, str]
    ) -> None:
        self._typed_backend().set_mapping(session_id, request_id, mapping)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        for backend in self._backend_candidates():
            mapping = backend.get_mapping(session_id, request_id)
            if mapping:
                return mapping
        return {}

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        for backend in self._backend_candidates():
            mapping = backend.consume_mapping(session_id, request_id)
            if mapping:
                return mapping
        return {}

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
        self._typed_backend().save_pending_confirmation(
            confirm_id=confirm_id,
            session_id=session_id,
            route=route,
            request_id=request_id,
            model=model,
            upstream_base=upstream_base,
            pending_request_payload=pending_request_payload,
            pending_request_hash=pending_request_hash,
            reason=reason,
            summary=summary,
            created_at=created_at,
            expires_at=expires_at,
            retained_until=retained_until,
            tenant_id=tenant_id,
        )

    def get_latest_pending_confirmation(
        self,
        session_id: str,
        now_ts: int,
        *,
        tenant_id: str = "default",
    ) -> dict[str, Any] | None:
        latest: dict[str, Any] | None = None
        for backend in self._backend_candidates():
            record = backend.get_latest_pending_confirmation(
                session_id, now_ts, tenant_id=tenant_id
            )
            if record is None:
                continue
            if latest is None or int(record.get("created_at", 0)) > int(
                latest.get("created_at", 0)
            ):
                latest = record
        return latest

    def get_single_pending_confirmation(
        self,
        *,
        session_id: str,
        route: str,
        now_ts: int,
        tenant_id: str = "default",
        recover_executing_before: int | None = None,
    ) -> dict[str, Any] | None:
        match: dict[str, Any] | None = None
        seen_confirm_ids: set[str] = set()
        for backend in self._backend_candidates():
            record = backend.get_single_pending_confirmation(
                session_id=session_id,
                route=route,
                now_ts=now_ts,
                tenant_id=tenant_id,
                recover_executing_before=recover_executing_before,
            )
            if record is None:
                continue
            confirm_id = str(record.get("confirm_id", ""))
            if confirm_id and confirm_id in seen_confirm_ids:
                # After hot-reload, current and retired backends can point to the
                # same persistent record. Treat that as one logical match.
                continue
            if match is not None:
                return None
            match = record
            if confirm_id:
                seen_confirm_ids.add(confirm_id)
        return match

    def compare_and_update_pending_confirmation_status(
        self,
        *,
        confirm_id: str,
        expected_status: str,
        new_status: str,
        now_ts: int,
    ) -> bool:
        for backend in self._backend_candidates():
            changed = backend.compare_and_update_pending_confirmation_status(
                confirm_id=confirm_id,
                expected_status=expected_status,
                new_status=new_status,
                now_ts=now_ts,
            )
            if changed:
                return True
        return False

    def get_pending_confirmation(self, confirm_id: str) -> dict[str, Any] | None:
        for backend in self._backend_candidates():
            record = backend.get_pending_confirmation(confirm_id)
            if record is not None:
                return record
        return None

    def update_pending_confirmation_status(
        self, *, confirm_id: str, status: str, now_ts: int
    ) -> None:
        for backend in self._backend_candidates():
            if backend.get_pending_confirmation(confirm_id) is None:
                continue
            backend.update_pending_confirmation_status(
                confirm_id=confirm_id, status=status, now_ts=now_ts
            )
            return

    def delete_pending_confirmation(self, *, confirm_id: str) -> bool:
        for backend in self._backend_candidates():
            deleted = backend.delete_pending_confirmation(confirm_id=confirm_id)
            if deleted:
                return True
        return False

    def prune_pending_confirmations(self, now_ts: int) -> int:
        removed = 0
        for backend in self._backend_candidates():
            removed += int(backend.prune_pending_confirmations(now_ts))
        return removed

    def clear_all_pending_confirmations(self) -> int:
        removed = 0
        for backend in self._backend_candidates():
            removed += int(backend.clear_all_pending_confirmations())
        return removed

    def close(self) -> None:
        with self._lock:
            current_backend = self._backend
            retired_backends = list(self._retired_backends)
            self._retired_backends.clear()
        for backend in retired_backends:
            _close_store_backend(backend)
        _close_store_backend(current_backend)

    def __getattr__(self, name: str) -> object:
        with self._lock:
            backend = self._backend
        return getattr(backend, name)


store = RuntimeStoreProxy(create_store())


def _build_pipeline() -> Pipeline:
    request_filters = [
        ExactValueRedactionFilter(),
        RedactionFilter(store),
        SystemPromptGuard(),
        UntrustedContentGuard(),
        RequestSanitizer(),
        RagPoisonGuard(),
    ]
    response_filters = [
        ExactValueRedactionFilter(),
        AnomalyDetector(),
        PromptInjectionDetector(),
        RagPoisonGuard(),
        PrivilegeGuard(),
        ToolCallGuard(),
        RestorationFilter(store),
        PostRestoreGuard(),
        OutputSanitizer(),
    ]
    return Pipeline(request_filters=request_filters, response_filters=response_filters)


def _get_pipeline() -> Pipeline:
    from aegisgate.core.hot_reload import get_pipeline_generation

    pipeline = getattr(_pipeline_local, "pipeline", None)
    generation = getattr(_pipeline_local, "pipeline_gen", -1)
    current_generation = get_pipeline_generation()
    if pipeline is None or generation != current_generation:
        pipeline = _build_pipeline()
        _pipeline_local.pipeline = pipeline
        _pipeline_local.pipeline_gen = current_generation
    return pipeline


def reset_pipeline_cache() -> None:
    """Invalidate cached pipelines so the next request rebuilds them."""
    from aegisgate.core.hot_reload import _bump_pipeline_generation

    _pipeline_local.pipeline = None
    _pipeline_local.pipeline_gen = -1
    _bump_pipeline_generation()


def reload_runtime_dependencies() -> None:
    """Rebuild runtime dependencies that are selected from mutable settings."""
    ensure_runtime_storage_paths()
    new_store = create_store()
    store.swap(new_store)
    reset_pipeline_cache()


def close_runtime_dependencies() -> None:
    """Release runtime store resources during shutdown."""
    store.close()
    reset_pipeline_cache()


def prune_pending_confirmations(now_ts: int) -> int:
    return int(store.prune_pending_confirmations(now_ts))


def clear_pending_confirmations_on_startup() -> int:
    """启动时清空所有待确认记录，使重启后仅新请求的确认有效。"""
    return int(store.clear_all_pending_confirmations())
