"""Shared store and pipeline runtime for OpenAI-compatible routes."""

from __future__ import annotations

import threading
from typing import cast

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

_MAX_RETIRED_BACKENDS = 8
_STORAGE_SETTINGS_FIELDS = (
    "storage_backend",
    "sqlite_db_path",
    "redis_url",
    "redis_key_prefix",
    "postgres_dsn",
    "postgres_schema",
)


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
        overflow: list[object] = []
        retired_count = 0
        with self._lock:
            old_backend = self._backend
            self._backend = backend
            if old_backend is not backend:
                # Keep old backends alive so in-flight requests can finish on
                # the object they already captured. Cap the list so repeated
                # storage swaps cannot leak handles for the process lifetime.
                self._retired_backends.append(old_backend)
                while len(self._retired_backends) > _MAX_RETIRED_BACKENDS:
                    overflow.append(self._retired_backends.pop(0))
            retired_count = len(self._retired_backends)
        for retired in overflow:
            _close_store_backend(retired)
        logger.info(
            "runtime store swapped backend=%s retired_backends=%d closed_overflow=%d",
            type(backend).__name__,
            retired_count,
            len(overflow),
        )

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


def _storage_settings_changed(previous: object, current: object) -> bool:
    return any(
        getattr(previous, name) != getattr(current, name)
        for name in _STORAGE_SETTINGS_FIELDS
    )


def reload_runtime_dependencies(previous_settings: object | None = None) -> None:
    """Rebuild runtime dependencies that are selected from mutable settings.

    Store swap runs only when a storage-related setting changed. Log-level and
    threshold reloads must not churn backends.
    """
    from aegisgate.config.settings import settings

    ensure_runtime_storage_paths()
    if previous_settings is None or _storage_settings_changed(
        previous_settings, settings
    ):
        store.swap(create_store())
    reset_pipeline_cache()


def close_runtime_dependencies() -> None:
    """Release runtime store resources during shutdown."""
    store.close()
    reset_pipeline_cache()


def prune_expired_mappings(max_age_seconds: int) -> int:
    method = getattr(store, "prune_expired_mappings", None)
    if not callable(method):
        return 0
    try:
        return int(method(max_age_seconds=max_age_seconds))
    except TypeError:
        # Backward compatibility for implementations that only accept a positional argument.
        return int(method(int(max_age_seconds)))

