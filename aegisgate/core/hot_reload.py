"""File-based hot-reload watcher.

Polls watched files for mtime changes and triggers reload callbacks.
Runs as a background asyncio task started from the app lifespan.
"""

from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path
from typing import Any, Callable

from aegisgate.util.logger import logger

_DEFAULT_POLL_SECONDS = 5


class _WatchedFile:
    __slots__ = ("path", "label", "last_mtime_ns")

    def __init__(self, path: Path, label: str) -> None:
        self.path = path
        self.label = label
        self.last_mtime_ns: int = self._current_mtime()

    def _current_mtime(self) -> int:
        try:
            return self.path.stat().st_mtime_ns
        except OSError:
            return -1

    def changed(self) -> bool:
        now = self._current_mtime()
        if now != self.last_mtime_ns:
            self.last_mtime_ns = now
            return True
        return False


class HotReloader:
    """Lightweight polling-based file watcher with reload callbacks."""

    def __init__(self, poll_seconds: float = _DEFAULT_POLL_SECONDS) -> None:
        self._poll_seconds = max(1.0, float(poll_seconds))
        self._watches: list[tuple[_WatchedFile, Callable[[], None]]] = []
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    def watch(self, path: str | Path, label: str, callback: Callable[[], None]) -> None:
        """Register a file to watch. *callback* is invoked (sync) when mtime changes."""
        resolved = Path(path).resolve()
        self._watches.append((_WatchedFile(resolved, label), callback))

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop_event.clear()
        self._task = asyncio.get_event_loop().create_task(self._poll_loop())
        labels = [w.label for w, _ in self._watches]
        logger.info("hot_reload watcher started poll_seconds=%.1f watches=%s", self._poll_seconds, labels)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None
        logger.info("hot_reload watcher stopped")

    async def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self._poll_seconds)
            except asyncio.CancelledError:
                break
            for watched, callback in self._watches:
                try:
                    if watched.changed():
                        logger.info("hot_reload detected change file=%s label=%s", watched.path, watched.label)
                        callback()
                except Exception:
                    logger.exception("hot_reload callback error label=%s", watched.label)


# ---------------------------------------------------------------------------
# Reload actions
# ---------------------------------------------------------------------------

# Fields that must NOT be changed at runtime via hot-reload.
_IMMUTABLE_FIELDS: frozenset[str] = frozenset({
    "gateway_key",
    "enforce_loopback_only",
    "security_level",
    "enable_request_hmac_auth",
    "request_hmac_secret",
    "v2_block_internal_targets",
    "trusted_proxy_ips",
})


def reload_settings() -> None:
    """Reload .env into the global settings singleton.

    Security-critical fields in ``_IMMUTABLE_FIELDS`` are pinned at startup
    and cannot be changed via hot-reload.
    """
    from aegisgate.config.feature_flags import refresh_feature_flags
    from aegisgate.config.settings import Settings, settings

    try:
        fresh = Settings()
        for field_name in fresh.model_fields:
            if field_name in _IMMUTABLE_FIELDS:
                continue
            setattr(settings, field_name, getattr(fresh, field_name))
        refresh_feature_flags()
        # Re-check writable paths: reload may have reset audit_log_path /
        # sqlite_db_path back to the configured default, losing the runtime
        # fallback that was applied at startup when /app/logs is not writable.
        from aegisgate.init_config import ensure_runtime_storage_paths
        ensure_runtime_storage_paths()
        # Apply new log level immediately so callers see the change at once.
        from aegisgate.util.logger import apply_log_level
        apply_log_level(settings.log_level)
        logger.info("hot_reload settings reloaded from environment / .env")
    except Exception:
        logger.exception("hot_reload settings reload failed")


def reload_security_rules() -> None:
    """Invalidate all caches that depend on security_filters.yaml."""
    # 1. security_rules.py has mtime-based cache — next call auto-reloads.
    #    Force a load now so the YAML is parsed once, not per-thread.
    try:
        from aegisgate.config.security_rules import load_security_rules
        load_security_rules()
    except Exception:
        logger.exception("hot_reload security_rules load failed")
        return

    # 2. Clear router LRU caches (compiled regex from security rules).
    _clear_openai_lru_caches()
    _clear_v2_lru_caches()

    # 3. Reset filter pipeline so new filter instances pick up fresh rules.
    _reset_filter_pipeline()

    logger.info("hot_reload security rules + pipeline reloaded")


def reload_gw_tokens() -> None:
    """Reload gw_tokens.json into memory."""
    try:
        from aegisgate.core.gw_tokens import load
        load()
        logger.info("hot_reload gw_tokens reloaded")
    except Exception:
        logger.exception("hot_reload gw_tokens reload failed")


def reload_policy_cache() -> None:
    """Clear policy engine mtime cache so next resolve re-reads YAML."""
    try:
        from aegisgate.adapters.openai_compat.router import policy_engine
        if hasattr(policy_engine, "_cache") and hasattr(policy_engine, "_cache_lock"):
            with policy_engine._cache_lock:
                policy_engine._cache.clear()
            logger.info("hot_reload policy cache cleared")
    except Exception:
        logger.exception("hot_reload policy cache clear failed")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clear_openai_lru_caches() -> None:
    try:
        from aegisgate.adapters.openai_compat.router import (
            _responses_function_output_redaction_patterns,
            _responses_relaxed_redaction_patterns,
            _confirmation_hit_regex_patterns,
            _critical_danger_patterns,
        )
        _responses_function_output_redaction_patterns.cache_clear()
        _responses_relaxed_redaction_patterns.cache_clear()
        _confirmation_hit_regex_patterns.cache_clear()
        _critical_danger_patterns.cache_clear()
    except Exception:
        logger.exception("hot_reload openai lru cache clear failed")


def _clear_v2_lru_caches() -> None:
    try:
        from aegisgate.adapters.v2_proxy.router import (
            _v2_redaction_patterns,
            _v2_relaxed_redaction_patterns,
            _v2_dangerous_command_patterns,
        )
        _v2_redaction_patterns.cache_clear()
        _v2_relaxed_redaction_patterns.cache_clear()
        _v2_dangerous_command_patterns.cache_clear()
    except Exception:
        logger.exception("hot_reload v2 lru cache clear failed")


def _reset_filter_pipeline() -> None:
    """Reset thread-local pipeline so next request rebuilds with fresh rules."""
    try:
        from aegisgate.adapters.openai_compat.router import _pipeline_local
        # Clear for the current thread; other threads will see stale pipelines
        # until their next request, at which point _get_pipeline() must rebuild.
        # We set a generation counter so _get_pipeline can detect staleness.
        _pipeline_local.pipeline = None
        _bump_pipeline_generation()
    except Exception:
        logger.exception("hot_reload pipeline reset failed")


# Generation counter: incremented on each hot-reload so all threads know
# their cached pipeline is stale.
_pipeline_generation: int = 0
_pipeline_gen_lock = threading.Lock()


def _bump_pipeline_generation() -> None:
    global _pipeline_generation
    with _pipeline_gen_lock:
        _pipeline_generation += 1


def get_pipeline_generation() -> int:
    return _pipeline_generation


# ---------------------------------------------------------------------------
# Factory: build the watcher with standard AegisGate config files
# ---------------------------------------------------------------------------

def build_watcher() -> HotReloader:
    """Create a HotReloader pre-configured for all AegisGate config files."""
    from aegisgate.config.settings import settings

    watcher = HotReloader(poll_seconds=_DEFAULT_POLL_SECONDS)

    # .env files
    for env_candidate in [Path.cwd() / ".env", Path.cwd() / "config" / ".env"]:
        if env_candidate.exists():
            watcher.watch(env_candidate, f"env:{env_candidate.name}", reload_settings)

    # security_filters.yaml
    rules_path = Path(settings.security_rules_path)
    if not rules_path.is_absolute():
        rules_path = Path.cwd() / rules_path
    watcher.watch(rules_path, "security_filters.yaml", reload_security_rules)

    # gw_tokens.json
    tokens_path = Path(settings.gw_tokens_path)
    if not tokens_path.is_absolute():
        tokens_path = Path.cwd() / tokens_path
    watcher.watch(tokens_path, "gw_tokens.json", reload_gw_tokens)

    # policy YAML files
    policies_dir = rules_path.parent
    for policy_file in policies_dir.glob("*.yaml"):
        if policy_file.name == "security_filters.yaml":
            continue
        watcher.watch(policy_file, f"policy:{policy_file.name}", reload_policy_cache)

    return watcher
