"""Tests for aegisgate.core.hot_reload — unit tests for WatchedFile and HotReloader."""

from __future__ import annotations

import asyncio
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

