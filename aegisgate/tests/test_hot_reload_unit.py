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
            pipeline_runtime, "reload_runtime_dependencies", lambda: None
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
            pipeline_runtime, "reload_runtime_dependencies", lambda: None
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
