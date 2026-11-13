"""Tests for aegisgate.core.hot_reload — unit tests for WatchedFile and HotReloader."""

from __future__ import annotations

import asyncio
import inspect
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegisgate.core import hot_reload
from aegisgate.core.hot_reload import (
    HotReloader,
    _WatchedFile,
    _bump_pipeline_generation,
    _watch_label,
    get_pipeline_generation,
)
from aegisgate.util.logger import logger


class TestWatchedFile:
    def test_no_change_on_same_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("content")
        wf = _WatchedFile(f, "test")
        assert wf.changed() is False

    def test_detects_change(self, tmp_path: Path) -> None:
        import os, time

        f = tmp_path / "test.txt"
        f.write_text("original")
        wf = _WatchedFile(f, "test")
        # Force mtime change by writing and updating timestamp
        f.write_text("modified")
        # Ensure mtime_ns differs (filesystem granularity)
        new_ns = wf.last_mtime_ns + 1_000_000_000
        os.utime(f, ns=(new_ns, new_ns))
        assert wf.changed() is True

    def test_missing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "does_not_exist.txt"
        wf = _WatchedFile(f, "missing")
        assert wf.last_mtime_ns == -1
        assert wf.changed() is False


class TestWatchLabel:
    def test_produces_label(self) -> None:
        label = _watch_label("prefix", Path("/some/path/file.yaml"))
        assert label.startswith("prefix:")

    def test_relative_path(self, tmp_path: Path) -> None:
        label = _watch_label("env", tmp_path / ".env")
        assert "env:" in label


class TestHotReloader:
    def test_watch_adds_entry(self, tmp_path: Path) -> None:
        hr = HotReloader(poll_seconds=1.0)
        f = tmp_path / "config.yaml"
        f.write_text("data")
        hr.watch(f, "config", lambda: None)
        assert len(hr._watches) == 1

    def test_min_poll_seconds(self) -> None:
        hr = HotReloader(poll_seconds=0.1)
        assert hr._poll_seconds >= 1.0

    def test_start_stop(self) -> None:
        hr = HotReloader(poll_seconds=1.0)

        async def run():
            await hr.start()
            assert hr._task is not None
            await hr.stop()
            assert hr._task is None

        asyncio.run(run())

    def test_start_idempotent(self) -> None:
        async def run():
            hr = HotReloader(poll_seconds=1.0)
            await hr.start()
            task = hr._task
            await hr.start()  # Should not create new task
            assert hr._task is task
            await hr.stop()

        asyncio.run(run())

    def test_stop_when_not_started(self) -> None:
        async def run():
            hr = HotReloader(poll_seconds=1.0)
            await hr.stop()  # Should not raise

        asyncio.run(run())


class TestPipelineGeneration:
    def test_bump_increments(self) -> None:
        before = get_pipeline_generation()
        _bump_pipeline_generation()
        after = get_pipeline_generation()
        assert after == before + 1


class TestReloadSettings:
    def test_syncs_aegis_and_root_logger_levels(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / ".env").write_text("AEGIS_LOG_LEVEL=debug\n", encoding="utf-8")

        import aegisgate.config.feature_flags as feature_flags
        import aegisgate.adapters.openai_compat.pipeline_runtime as pipeline_runtime
        import aegisgate.adapters.openai_compat.router as router
        import aegisgate.init_config as init_config
        from aegisgate.config.settings import settings as runtime_settings

        monkeypatch.setattr(feature_flags, "refresh_feature_flags", lambda: None)
        monkeypatch.setattr(init_config, "ensure_runtime_storage_paths", lambda: None)
        monkeypatch.setattr(
            pipeline_runtime, "reload_runtime_dependencies", lambda *args, **kwargs: None
        )
        monkeypatch.setattr(router, "reload_semantic_client_settings", lambda: None)

        root_logger = logging.getLogger()
        original_root_level = root_logger.level
        original_aegis_level = logger.level
        try:
            root_logger.setLevel(logging.WARNING)
            logger.setLevel(logging.INFO)

            hot_reload.reload_settings()

            assert root_logger.level == logging.DEBUG
            assert logger.level == logging.DEBUG
        finally:
            root_logger.setLevel(original_root_level)
            logger.setLevel(original_aegis_level)

    def test_prefers_runtime_env_file_over_process_env_for_hot_reload(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / ".env").write_text("AEGIS_LOG_LEVEL=info\n", encoding="utf-8")
        monkeypatch.setenv("AEGIS_LOG_LEVEL", "debug")

        import aegisgate.config.feature_flags as feature_flags
        import aegisgate.adapters.openai_compat.pipeline_runtime as pipeline_runtime
        import aegisgate.adapters.openai_compat.router as router
        import aegisgate.init_config as init_config
        from aegisgate.config.settings import settings as runtime_settings

        monkeypatch.setattr(feature_flags, "refresh_feature_flags", lambda: None)
        monkeypatch.setattr(init_config, "ensure_runtime_storage_paths", lambda: None)
        monkeypatch.setattr(
            pipeline_runtime, "reload_runtime_dependencies", lambda *args, **kwargs: None
        )
        monkeypatch.setattr(router, "reload_semantic_client_settings", lambda: None)

        root_logger = logging.getLogger()
        original_root_level = root_logger.level
        original_aegis_level = logger.level
        original_runtime_level = runtime_settings.log_level
        try:
            root_logger.setLevel(logging.DEBUG)
            logger.setLevel(logging.DEBUG)
            runtime_settings.log_level = "debug"

            hot_reload.reload_settings()

            assert runtime_settings.log_level == "info"
            assert root_logger.level == logging.INFO
            assert logger.level == logging.INFO
        finally:
            root_logger.setLevel(original_root_level)
            logger.setLevel(original_aegis_level)
            runtime_settings.log_level = original_runtime_level


def test_reload_settings_failure_rolls_back_mutable_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".env").write_text("AEGIS_LOG_LEVEL=debug\n", encoding="utf-8")

    import aegisgate.config.feature_flags as feature_flags
    import aegisgate.adapters.openai_compat.pipeline_runtime as pipeline_runtime
    import aegisgate.adapters.openai_compat.router as router
    import aegisgate.init_config as init_config
    from aegisgate.config.settings import settings as runtime_settings

    monkeypatch.setattr(feature_flags, "refresh_feature_flags", lambda: None)
    monkeypatch.setattr(init_config, "ensure_runtime_storage_paths", lambda: None)
    monkeypatch.setattr(
        pipeline_runtime,
        "reload_runtime_dependencies",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(router, "reload_semantic_client_settings", lambda: None)

    original_level = runtime_settings.log_level
    hot_reload.reload_settings()
    assert runtime_settings.log_level == original_level


def test_reload_settings_readers_never_see_mixed_generations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".env").write_text(
        "AEGIS_LOG_LEVEL=debug\nAEGIS_FILTER_PIPELINE_TIMEOUT_S=12.5\n",
        encoding="utf-8",
    )

    import threading

    import aegisgate.config.feature_flags as feature_flags
    import aegisgate.adapters.openai_compat.pipeline_runtime as pipeline_runtime
    import aegisgate.adapters.openai_compat.router as router
    import aegisgate.init_config as init_config
    from aegisgate.config.settings import settings as runtime_settings

    monkeypatch.setattr(feature_flags, "refresh_feature_flags", lambda: None)
    monkeypatch.setattr(init_config, "ensure_runtime_storage_paths", lambda: None)
    monkeypatch.setattr(
        pipeline_runtime, "reload_runtime_dependencies", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(router, "reload_semantic_client_settings", lambda: None)

    old_pair = (runtime_settings.log_level, runtime_settings.filter_pipeline_timeout_s)
    new_pair = ("debug", 12.5)
    seen: list[tuple[object, object]] = []
    stop = threading.Event()

    def _reader() -> None:
        while not stop.is_set():
            seen.append(
                (
                    runtime_settings.log_level,
                    runtime_settings.filter_pipeline_timeout_s,
                )
            )

    reader = threading.Thread(target=_reader)
    original_level = runtime_settings.log_level
    original_timeout = runtime_settings.filter_pipeline_timeout_s
    try:
        reader.start()
        hot_reload.reload_settings()
        stop.set()
        reader.join(timeout=2)
        allowed = {old_pair, new_pair}
        mixed = [pair for pair in seen if pair not in allowed]
        assert not mixed
        assert runtime_settings.log_level == "debug"
        assert runtime_settings.filter_pipeline_timeout_s == 12.5
    finally:
        stop.set()
        runtime_settings.log_level = original_level
        runtime_settings.filter_pipeline_timeout_s = original_timeout


def test_log_level_reload_does_not_swap_store() -> None:
    from types import SimpleNamespace

    import aegisgate.adapters.openai_compat.pipeline_runtime as pipeline_runtime
    from aegisgate.config.settings import settings as runtime_settings

    swaps: list[object] = []
    original_swap = pipeline_runtime.store.swap
    pipeline_runtime.store.swap = lambda backend: swaps.append(backend)
    try:
        previous = SimpleNamespace(
            **{
                name: getattr(runtime_settings, name)
                for name in pipeline_runtime._STORAGE_SETTINGS_FIELDS
            }
        )
        pipeline_runtime.reload_runtime_dependencies(previous)
        assert swaps == []
    finally:
        pipeline_runtime.store.swap = original_swap


def test_storage_backend_change_swaps_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    import aegisgate.adapters.openai_compat.pipeline_runtime as pipeline_runtime
    from aegisgate.config.settings import settings as runtime_settings

    swaps: list[object] = []
    sentinel = object()
    monkeypatch.setattr(pipeline_runtime, "create_store", lambda: sentinel)
    monkeypatch.setattr(pipeline_runtime, "reset_pipeline_cache", lambda: None)
    monkeypatch.setattr(pipeline_runtime, "ensure_runtime_storage_paths", lambda: None)
    original_swap = pipeline_runtime.store.swap
    pipeline_runtime.store.swap = lambda backend: swaps.append(backend)
    try:
        previous = SimpleNamespace(
            **{
                name: getattr(runtime_settings, name)
                for name in pipeline_runtime._STORAGE_SETTINGS_FIELDS
            }
        )
        previous.storage_backend = "redis"
        pipeline_runtime.reload_runtime_dependencies(previous)
        assert swaps == [sentinel]
    finally:
        pipeline_runtime.store.swap = original_swap


class TestReloadSecurityRulesKeepsLastGood:
    """A rules file that stops parsing must not also take the running one down.

    Two failures used to follow one bad edit. The first is handled on purpose:
    ``reload_security_rules`` reports the ``yaml`` layer as failed and skips the
    three cache clears below it, so patterns already compiled keep filtering. The
    second was not handled at all — the parsed-rules cache is keyed on mtime, so
    the broken save invalidated it by itself, and everything that had to build
    from scratch afterwards (a pipeline thread the executor had not spawned yet,
    the console's own redaction panel) re-parsed the bad file and raised. The
    symptom follows traffic rather than the edit, which is what made it hard to
    read as a config problem.
    """

    _GOOD = """\
version: 3
redaction:
  field_value_min_len: 12
  pii_patterns:
    - id: SEED
      regex: 'seed-pattern'
"""
    _BROKEN = "redaction:\n  pii_patterns:\n   - id: X\n  bad: : :\n"

    @pytest.fixture()
    def rules_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        from aegisgate.config import security_rules
        from aegisgate.config.settings import settings

        path = tmp_path / "security_filters.yaml"
        path.write_text(self._GOOD, encoding="utf-8")
        monkeypatch.setattr(settings, "security_rules_path", str(path), raising=False)
        security_rules.invalidate_security_rules_cache()
        yield path
        security_rules.invalidate_security_rules_cache()

    @staticmethod
    def _rewrite(path: Path, text: str) -> None:
        """Write *text* and push mtime forward, so the cache genuinely misses.

        Without this the two saves can share a filesystem timestamp tick and the
        loader would answer from cache — the test would pass without ever
        exercising the path it is about.
        """
        import os

        before = path.stat().st_mtime_ns
        path.write_text(text, encoding="utf-8")
        after = before + 1_000_000_000
        os.utime(path, ns=(after, after))

    @staticmethod
    def _seed_id() -> str:
        from aegisgate.config.security_rules import load_security_rules

        return load_security_rules()["redaction"]["pii_patterns"][0]["id"]

    def test_broken_file_keeps_serving_the_last_good_document(
        self, rules_file: Path
    ) -> None:
        assert self._seed_id() == "SEED"

        self._rewrite(rules_file, self._BROKEN)
        result = hot_reload.reload_security_rules()

        assert result["ok"] is False
        assert result["layers"]["yaml"] == "failed"
        # Skipped, not run: rebuilding these from the same broken file is how a
        # parse error would reach the compiled patterns that are still working.
        assert result["layers"]["pipeline"] == "skipped"
        # The parse error is reported, not swallowed — that is the only signal a
        # caller gets that the file on disk and the rules in memory disagree.
        assert result["errors"] and result["errors"][0]["layer"] == "yaml"
        assert "Error" in result["errors"][0]["error"]

        # The part that used to raise. A fresh build now sees the rules the
        # process is actually enforcing instead of the bad bytes on disk.
        assert self._seed_id() == "SEED"

    def test_fixing_the_file_is_picked_up_again(self, rules_file: Path) -> None:
        assert self._seed_id() == "SEED"
        self._rewrite(rules_file, self._BROKEN)
        assert hot_reload.reload_security_rules()["ok"] is False

        # Pinning the last good document must not outlive the bad bytes: the
        # next change to the file has to be read, or a repaired file would never
        # take effect without a restart.
        self._rewrite(rules_file, self._GOOD.replace("SEED", "REPAIRED"))
        result = hot_reload.reload_security_rules()

        assert result["ok"] is True
        assert self._seed_id() == "REPAIRED"

    def test_broken_from_the_start_still_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aegisgate.config import security_rules
        from aegisgate.config.settings import settings

        path = tmp_path / "security_filters.yaml"
        path.write_text(self._BROKEN, encoding="utf-8")
        monkeypatch.setattr(settings, "security_rules_path", str(path), raising=False)
        security_rules.invalidate_security_rules_cache()
        try:
            # Nothing good was ever loaded, so there is nothing to keep. Serving
            # the built-in defaults here would quietly present them as the
            # deployment's own policy.
            result = hot_reload.reload_security_rules()
            assert result["ok"] is False
            with pytest.raises(Exception):
                security_rules.load_security_rules()
        finally:
            security_rules.invalidate_security_rules_cache()


class TestEveryRulesDerivedCacheIsCleared:
    """A rules-derived ``lru_cache`` that nobody clears is a silent staleness.

    ``_clear_openai_lru_caches`` is a hand-written list, and the modules it
    covers keep gaining helpers. When one is missed the adapter goes on serving
    patterns compiled from the previous rules file and only that one layer is
    stale — no error, no log line, and the surfaces it feeds (media locators and
    historical ``function_call`` arguments, via the credential-only set) simply
    do not see a rule the operator just added.
    """

    def _cached_names(self, module) -> set[str]:
        """``lru_cache``d callables the module itself defines.

        The ``__module__`` check keeps imported ones out — ``urllib.parse
        .urlsplit`` is memoised too, and clearing it on a rules reload would
        say nothing about this file.
        """
        names: set[str] = set()
        for name in dir(module):
            candidate = getattr(module, name, None)
            if not callable(candidate) or not hasattr(candidate, "cache_clear"):
                continue
            if getattr(candidate, "__module__", None) != module.__name__:
                continue
            names.add(name)
        return names

    @pytest.mark.parametrize("module_name", ["sanitize", "router"])
    def test_openai_adapter_caches_are_all_registered(
        self, monkeypatch: pytest.MonkeyPatch, module_name: str
    ) -> None:
        """Both modules ``_clear_openai_lru_caches`` reaches into, not just one.

        It clears three caches out of ``router`` and three out of ``sanitize``.
        Pinning only ``sanitize`` left the other half of its own list unguarded,
        which is the same silent staleness this class exists to prevent — a new
        rules-derived cache in ``router`` would have slipped through the test
        that was written to catch exactly that.
        """
        import importlib

        module = importlib.import_module(
            f"aegisgate.adapters.openai_compat.{module_name}"
        )

        cleared: set[str] = set()
        for name in self._cached_names(module):
            original = getattr(module, name)
            monkeypatch.setattr(
                original,
                "cache_clear",
                lambda _name=name: cleared.add(_name),
                raising=False,
            )

        hot_reload._clear_openai_lru_caches()

        missing = self._cached_names(module) - cleared
        assert not missing, (
            f"rules-derived caches in {module_name} never cleared on reload: "
            f"{sorted(missing)}. Add them to _clear_openai_lru_caches."
        )


def _stub_reload_collaborators(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep reload_settings on the path under test.

    It swallows its own exceptions, so a failure in feature flags, storage, or
    the semantic client would look like "the upstream client was not closed".
    """
    import aegisgate.adapters.openai_compat.pipeline_runtime as pipeline_runtime
    import aegisgate.adapters.openai_compat.router as router
    import aegisgate.config.feature_flags as feature_flags
    import aegisgate.init_config as init_config

    monkeypatch.setattr(feature_flags, "refresh_feature_flags", lambda: None)
    monkeypatch.setattr(init_config, "ensure_runtime_storage_paths", lambda: None)
    monkeypatch.setattr(
        pipeline_runtime, "reload_runtime_dependencies", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(router, "reload_semantic_client_settings", lambda: None)


def _watch_upstream_close(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.upstream.schedule_close_upstream_async_client",
        lambda *args, **kwargs: calls.append(1),
    )
    return calls


def _write_env(tmp_path: Path, body: str) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".env").write_text(body, encoding="utf-8")


def test_log_level_reload_does_not_schedule_upstream_client_close(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Saving a log-level edit rewrites .env. That must not drop the V1 pool."""
    monkeypatch.chdir(tmp_path)
    _write_env(tmp_path, "AEGIS_LOG_LEVEL=debug\n")
    _stub_reload_collaborators(monkeypatch)
    calls = _watch_upstream_close(monkeypatch)

    from aegisgate.config.settings import settings as runtime_settings

    snapshot = dict(hot_reload._mutable_settings_payload(runtime_settings))
    root_logger = logging.getLogger()
    original_root_level = root_logger.level
    original_aegis_level = logger.level
    runtime_settings.log_level = "warning"
    try:
        hot_reload.reload_settings()
        assert runtime_settings.log_level == "debug"
        assert calls == []
    finally:
        hot_reload._apply_settings_payload(runtime_settings, snapshot)
        root_logger.setLevel(original_root_level)
        logger.setLevel(original_aegis_level)


@pytest.mark.parametrize(
    ("env_name", "field_name", "previous", "expected"),
    [
        ("AEGIS_UPSTREAM_TIMEOUT_SECONDS", "upstream_timeout_seconds", 600.0, 30.0),
        ("AEGIS_UPSTREAM_MAX_CONNECTIONS", "upstream_max_connections", 300, 40),
        (
            "AEGIS_UPSTREAM_MAX_KEEPALIVE_CONNECTIONS",
            "upstream_max_keepalive_connections",
            100,
            12,
        ),
    ],
)
def test_upstream_pool_setting_reload_schedules_one_close(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    env_name: str,
    field_name: str,
    previous: float,
    expected: float,
) -> None:
    """The shared client only depends on timeout and the two pool limits."""
    monkeypatch.chdir(tmp_path)
    _write_env(tmp_path, f"{env_name}={expected}\n")
    _stub_reload_collaborators(monkeypatch)
    calls = _watch_upstream_close(monkeypatch)

    from aegisgate.config.settings import settings as runtime_settings

    snapshot = dict(hot_reload._mutable_settings_payload(runtime_settings))
    setattr(runtime_settings, field_name, previous)
    try:
        hot_reload.reload_settings()
        assert getattr(runtime_settings, field_name) == expected
        assert calls == [1]
    finally:
        hot_reload._apply_settings_payload(runtime_settings, snapshot)


def _schedule_upstream_close(grace_seconds: float | None = None) -> None:
    """Pass a grace when the production function accepts one.

    The pre-fix function closed immediately and took no grace argument. Calling
    that version with the keyword errored before the assertion that records the
    immediate ``aclose``. With the argument present, the test injects the grace.
    """
    import aegisgate.adapters.openai_compat.upstream as upstream

    schedule = upstream.schedule_close_upstream_async_client
    if (
        grace_seconds is not None
        and "grace_seconds" in inspect.signature(schedule).parameters
    ):
        schedule(grace_seconds=grace_seconds)
        return
    schedule()


class _Closeable:
    def __init__(self, closed: list[object]) -> None:
        self._closed = closed

    async def aclose(self) -> None:
        self._closed.append(self)


def _capture_call_later(monkeypatch: pytest.MonkeyPatch):
    """Record ``call_later`` without arming the timer.

    The grace under test can be zero. A real timer at delay 0 would close the
    client on the next loop turn and hide the bug the assertion is there for.
    """
    recorded: list[tuple[float, object, tuple]] = []

    class _Handle:
        def cancel(self) -> None:
            return None

    def wrapped(delay, callback, *args, **kwargs):
        recorded.append((float(delay), callback, args))
        return _Handle()

    monkeypatch.setattr(asyncio.get_running_loop(), "call_later", wrapped)
    return recorded


async def test_replaced_upstream_client_is_not_aclosed_during_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detaching the pool must not abort streams that are still reading."""
    import aegisgate.adapters.openai_compat.upstream as upstream

    closed: list[object] = []
    old = _Closeable(closed)
    monkeypatch.setattr(upstream, "_upstream_async_client", old)
    recorded = _capture_call_later(monkeypatch)
    grace_seconds = 0.0
    _schedule_upstream_close(grace_seconds)
    # One loop turn runs the old create_task(aclose) path. The deferred
    # callback is not armed, so a grace of 0 still has not fired.
    await asyncio.sleep(0)
    assert closed == [], "old upstream client was aclosed before the grace elapsed"
    assert upstream._upstream_async_client is None
    assert recorded, "close was not deferred with call_later"
    delay, callback, args = recorded[0]
    assert delay == grace_seconds
    assert "grace_seconds" in inspect.signature(
        upstream.schedule_close_upstream_async_client
    ).parameters
    callback(*args)
    await asyncio.sleep(0)
    assert closed == [old]


async def test_default_upstream_client_grace_is_timeout_plus_five(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In-flight reads use upstream_timeout_seconds; close no earlier than that plus 5s."""
    import aegisgate.adapters.openai_compat.upstream as upstream
    from aegisgate.config.settings import settings as runtime_settings

    closed: list[object] = []
    old = _Closeable(closed)
    monkeypatch.setattr(upstream, "_upstream_async_client", old)
    monkeypatch.setattr(runtime_settings, "upstream_timeout_seconds", 12.5)
    recorded = _capture_call_later(monkeypatch)
    upstream.schedule_close_upstream_async_client()
    await asyncio.sleep(0)
    assert closed == [], "old upstream client was aclosed before the grace elapsed"
    assert recorded, "close was not deferred with call_later"
    assert recorded[0][0] == 17.5
