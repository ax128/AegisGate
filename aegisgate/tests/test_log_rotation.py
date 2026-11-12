"""Application logs rotate by size and stay owner-only.

A usual umask of 022 makes logging.FileHandler create 0644 files. These tests
force that umask so the result does not depend on the developer environment.
"""

from __future__ import annotations

import logging
import os
import stat
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pytest

from aegisgate.util.logger import DailyRotatingFileHandler


def _record(text: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="aegisgate.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=text,
        args=(),
        exc_info=None,
    )


@pytest.fixture
def _umask_022():
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def test_daily_log_rotates_by_size_and_is_owner_only(
    tmp_path: Path, _umask_022: None
) -> None:
    handler = DailyRotatingFileHandler(
        base_dir=tmp_path,
        max_bytes=300,
        backup_count=2,
    )
    try:
        handler.setFormatter(logging.Formatter("%(message)s"))
        payload = "x" * 180
        for _ in range(8):
            handler.emit(_record(payload))

        inner = handler._inner
        assert inner is not None
        assert isinstance(inner, RotatingFileHandler)
        log_file = Path(inner.baseFilename)
        assert log_file.is_file()

        backups = sorted(log_file.parent.glob(log_file.name + ".*"))
        assert backups, "size rotation produced no backup file"
        assert len(backups) <= 2
        assert log_file.stat().st_size < (len(payload) * 8) // 2

        for path in [log_file, *backups]:
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == 0o600, f"{path.name} mode is {oct(mode)}, expected 0o600"
    finally:
        handler.close()


def test_existing_log_file_is_tightened_to_owner_only(
    tmp_path: Path, _umask_022: None
) -> None:
    today = datetime.now(timezone.utc).strftime("%y/%m/%d")
    log_file = (tmp_path / today).with_suffix(".log")
    log_file.parent.mkdir(parents=True)
    log_file.write_text("previous\n", encoding="utf-8")
    log_file.chmod(0o644)

    handler = DailyRotatingFileHandler(
        base_dir=tmp_path,
        max_bytes=10_000,
        backup_count=1,
    )
    try:
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler.emit(_record("next"))
        mode = stat.S_IMODE(log_file.stat().st_mode)
        assert mode == 0o600, f"existing log mode is {oct(mode)}, expected 0o600"
        text = log_file.read_text(encoding="utf-8")
        assert "previous" in text
        assert "next" in text
    finally:
        handler.close()


def test_existing_rotated_backup_is_tightened_to_owner_only(
    tmp_path: Path, _umask_022: None
) -> None:
    today = datetime.now(timezone.utc).strftime("%y/%m/%d")
    log_file = (tmp_path / today).with_suffix(".log")
    log_file.parent.mkdir(parents=True)
    log_file.write_text("current\n", encoding="utf-8")
    log_file.chmod(0o644)
    backup = log_file.with_name(log_file.name + ".1")
    backup.write_text("older\n", encoding="utf-8")
    backup.chmod(0o644)

    handler = DailyRotatingFileHandler(
        base_dir=tmp_path,
        max_bytes=10_000,
        backup_count=2,
    )
    try:
        handler.emit(_record("next"))
        for path in (log_file, backup):
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == 0o600, f"{path.name} mode is {oct(mode)}, expected 0o600"
    finally:
        handler.close()


def test_older_day_logs_are_tightened_without_touching_other_files(
    tmp_path: Path, _umask_022: None
) -> None:
    older = tmp_path / "26" / "01" / "01.log"
    older.parent.mkdir(parents=True)
    older.write_text("old\n", encoding="utf-8")
    older.chmod(0o644)
    older_backup = older.with_name(older.name + ".1")
    older_backup.write_text("old-backup\n", encoding="utf-8")
    older_backup.chmod(0o644)
    unrelated = tmp_path / "notes.txt"
    unrelated.write_text("keep\n", encoding="utf-8")
    unrelated.chmod(0o644)

    handler = DailyRotatingFileHandler(
        base_dir=tmp_path,
        max_bytes=10_000,
        backup_count=1,
    )
    try:
        handler.emit(_record("today"))
        for path in (older, older_backup):
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == 0o600, f"{path.name} mode is {oct(mode)}, expected 0o600"
        assert stat.S_IMODE(unrelated.stat().st_mode) == 0o644
    finally:
        handler.close()
