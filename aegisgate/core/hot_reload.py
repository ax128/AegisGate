"""File-based hot-reload watcher.

Polls watched files for mtime changes and triggers reload callbacks.
Runs as a background asyncio task started from the app lifespan.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from types import SimpleNamespace
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
        self._degraded: bool = False
        self._last_error_label: str = ""

    @property
    def is_degraded(self) -> bool:
        """True if the last hot-reload cycle had a callback failure."""
        return self._degraded

    @property
    def degraded_label(self) -> str:
        """Label of the watch whose callback last failed, or empty string."""
        return self._last_error_label

    def watch(self, path: str | Path, label: str, callback: Callable[[], None]) -> None:
        """Register a file to watch. *callback* is invoked (sync) when mtime changes."""
        resolved = Path(path).resolve()
        self._watches.append((_WatchedFile(resolved, label), callback))

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._poll_loop(), name="aegisgate-hot-reload")
        labels = [w.label for w, _ in self._watches]
        logger.info(
            "hot_reload watcher started poll_seconds=%.1f watches=%s",
            self._poll_seconds,
            labels,
        )

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
                        logger.info(
                            "hot_reload detected change file=%s label=%s",
                            watched.path,
                            watched.label,
                        )
                        callback()
                        # Clear degraded if the previously failed label succeeds
                        if self._degraded and self._last_error_label == watched.label:
                            self._degraded = False
                            self._last_error_label = ""
                            logger.info("hot_reload recovered from degraded state label=%s", watched.label)
                except Exception:
                    logger.exception(
                        "hot_reload callback error label=%s", watched.label
                    )
                    self._degraded = True
                    self._last_error_label = watched.label


def _watch_label(prefix: str, path: Path) -> str:
    try:
        suffix = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        suffix = path.as_posix()
    return f"{prefix}:{suffix}"


# ---------------------------------------------------------------------------
# Reload actions
# ---------------------------------------------------------------------------

# Fields that must NOT be changed at runtime via hot-reload.
_IMMUTABLE_FIELDS: frozenset[str] = frozenset(
    {
        "gateway_key",
        "enforce_loopback_only",
        "security_level",
        "allow_public_numeric_tokens",
        "allow_public_passthrough_mode",
        "allow_public_upstream_whitelist",
        "enable_request_hmac_auth",
        "request_hmac_secret",
        "v2_block_internal_targets",
        "trusted_proxy_ips",
        "xff_strict_internal",
        "local_ui_allow_internal_network",
    }
)


def _parse_runtime_env_values() -> dict[str, str]:
    runtime_env_path = (Path.cwd() / "config" / ".env").resolve()
    values: dict[str, str] = {}
    if not runtime_env_path.exists():
        return values
    for raw_line in runtime_env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = raw_line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def _settings_from_runtime_env_file():
    from aegisgate.config.settings import Settings, settings

    runtime_values = _parse_runtime_env_values()
    merged: dict[str, object] = {
        field_name: getattr(settings, field_name)
        for field_name in Settings.model_fields
    }
    for field_name in Settings.model_fields:
        env_name = f"AEGIS_{field_name.upper()}"
        if env_name in runtime_values:
            merged[field_name] = runtime_values[env_name]
    return Settings.model_validate(merged)


def _mutable_settings_payload(source: object) -> dict[str, object]:
    from aegisgate.config.settings import Settings

    return {
        field_name: getattr(source, field_name)
        for field_name in Settings.model_fields
        if field_name not in _IMMUTABLE_FIELDS
    }


def _apply_settings_payload(target: object, payload: dict[str, object]) -> None:
    target.__dict__.update(payload)


def reload_settings() -> None:
    """Reload config/.env into the global settings singleton.

    Security-critical fields in ``_IMMUTABLE_FIELDS`` are pinned at startup
    and cannot be changed via hot-reload.

    Mutable fields are applied in one ``__dict__.update`` after a complete
    ``Settings`` is built. Failure after that point rolls the snapshot back
    so callers never keep a half-applied config.
    """
    from aegisgate.config.feature_flags import refresh_feature_flags
    from aegisgate.config.settings import settings
    from aegisgate.observability.logging import configure_logging

    previous_payload: dict[str, object] | None = None
    try:
        fresh = _settings_from_runtime_env_file()
        previous_payload = _mutable_settings_payload(settings)
        incoming = _mutable_settings_payload(fresh)
        _apply_settings_payload(settings, incoming)
        try:
            refresh_feature_flags()
            # Re-check writable paths: reload may have reset audit_log_path /
            # sqlite_db_path back to the configured default, losing the runtime
            # fallback that was applied at startup when /app/logs is not writable.
            from aegisgate.init_config import ensure_runtime_storage_paths

            ensure_runtime_storage_paths()
            from aegisgate.util.logger import apply_log_level

            apply_log_level(settings.log_level)
            configure_logging(settings.log_level)
            from aegisgate.adapters.openai_compat.pipeline_runtime import (
                reload_runtime_dependencies,
            )

            reload_runtime_dependencies(SimpleNamespace(**previous_payload))
            from aegisgate.adapters.openai_compat.upstream import (
                schedule_close_upstream_async_client,
            )

            schedule_close_upstream_async_client()
            from aegisgate.adapters.openai_compat.router import (
                reload_semantic_client_settings,
            )

            reload_semantic_client_settings()
            logger.info("hot_reload settings reloaded from config/.env")
        except Exception:
            _apply_settings_payload(settings, previous_payload)
            raise
    except Exception:
        logger.exception("hot_reload settings reload failed")


# Layers that must all succeed for a rules reload to count as applied. A console
# write that lands on disk but leaves one of these holding stale compiled
# patterns is a half-applied security policy, so the writer treats any of them
# failing as a failed write.
REQUIRED_SECURITY_RULE_RELOAD_LAYERS: tuple[str, ...] = (
    "yaml",
    "openai_lru",
    "v2_lru",
    "pipeline",
)


def reload_security_rules() -> dict[str, Any]:
    """Invalidate all caches that depend on security_filters.yaml.

    Every layer used to swallow its own exception, so a caller could not tell an
    applied reload from one where the V2 LRU still held the previous patterns.
    The per-layer outcome is returned instead: the console's write transaction
    needs it to decide whether the bytes it just wrote are actually running.
    """
    layers: dict[str, str] = {}
    errors: list[dict[str, str]] = []

    def _run(layer: str, action: Callable[[], None]) -> bool:
        try:
            action()
        except Exception as exc:
            logger.exception("hot_reload %s failed", layer)
            layers[layer] = "failed"
            errors.append({"layer": layer, "error": f"{type(exc).__name__}: {exc}"})
            return False
        layers[layer] = "ok"
        return True

    def _load_yaml() -> None:
        from aegisgate.config.security_rules import load_security_rules

        load_security_rules()

    # 1. security_rules.py has mtime-based cache — next call auto-reloads.
    #    Force a load now so the YAML is parsed once, not per-thread.
    if _run("yaml", _load_yaml):
        # 2. Clear router LRU caches (compiled regex from security rules).
        _run("openai_lru", _clear_openai_lru_caches)
        _run("v2_lru", _clear_v2_lru_caches)
        # 3. Reset filter pipeline so new filter instances pick up fresh rules.
        _run("pipeline", _reset_filter_pipeline)
    else:
        # A YAML that does not parse must not be followed by cache clears: the
        # layers would rebuild from the same broken file.
        for layer in REQUIRED_SECURITY_RULE_RELOAD_LAYERS[1:]:
            layers[layer] = "skipped"

    ok = all(layers.get(layer) == "ok" for layer in REQUIRED_SECURITY_RULE_RELOAD_LAYERS)
    result = {
        "ok": ok,
        "layers": layers,
        "errors": errors,
        "pipeline_generation": get_pipeline_generation(),
    }
    if ok:
        logger.info("hot_reload security rules + pipeline reloaded")
    else:
        logger.error("hot_reload security rules reload incomplete layers=%s", layers)
    return result


def reload_gw_tokens() -> None:
    """Reload gw_tokens.json into memory."""
    try:
        from aegisgate.core.gw_tokens import load

        load(replace=True)
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


# The three helpers below deliberately let their exception escape:
# ``reload_security_rules`` records which layer failed. Swallowing it here is
# what made a partially applied reload indistinguishable from a clean one.


def _clear_openai_lru_caches() -> None:
    from aegisgate.adapters.openai_compat.router import (
        _responses_function_output_redaction_patterns,
        _responses_relaxed_redaction_patterns,
        _confirmation_hit_regex_patterns,
        _critical_danger_patterns,
        _tool_call_guard_patterns,
    )

    _responses_function_output_redaction_patterns.cache_clear()
    _responses_relaxed_redaction_patterns.cache_clear()
    _confirmation_hit_regex_patterns.cache_clear()
    _critical_danger_patterns.cache_clear()
    _tool_call_guard_patterns.cache_clear()


def _clear_v2_lru_caches() -> None:
    from aegisgate.adapters.v2_proxy.router import (
        _v2_redaction_patterns,
        _v2_relaxed_redaction_patterns,
        _v2_dangerous_command_patterns,
    )

    _v2_redaction_patterns.cache_clear()
    _v2_relaxed_redaction_patterns.cache_clear()
    _v2_dangerous_command_patterns.cache_clear()


def _reset_filter_pipeline() -> None:
    """Reset cached pipelines so next request rebuilds with fresh rules."""
    from aegisgate.adapters.openai_compat.pipeline_runtime import (
        reset_pipeline_cache,
    )

    reset_pipeline_cache()


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

    env_candidate = Path.cwd() / "config" / ".env"
    watcher.watch(env_candidate, _watch_label("env", env_candidate), reload_settings)

    # security_filters.yaml — resolved through the one shared resolver, so the
    # watcher watches the file the runtime actually loads and the console writes.
    from aegisgate.config.security_rules import resolve_rules_file

    rules_path = resolve_rules_file(settings.security_rules_path)
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
