"""Unified logger for the whole project."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from aegisgate.config.settings import settings

LOG_BASE_DIR = Path("logs") / "aegisgate"
MAX_BYTES = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 10


def _normalize_level(raw: str) -> int:
    candidate = str(raw or "INFO").strip().upper()
    return {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    }.get(candidate, logging.INFO)


class DailyRotatingFileHandler(logging.Handler):
    """Log to ``logs/aegisgate/YY/MM/DD.log``, rotating at *MAX_BYTES*."""

    def __init__(
        self,
        base_dir: Path | str = LOG_BASE_DIR,
        max_bytes: int = MAX_BYTES,
        backup_count: int = BACKUP_COUNT,
        encoding: str = "utf-8",
    ) -> None:
        super().__init__()
        self._base_dir = Path(base_dir)
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._encoding = encoding
        self._current_date: str = ""
        self._inner: RotatingFileHandler | None = None

    def _today(self) -> str:
        return datetime.now(timezone.utc).strftime("%y/%m/%d")

    def _ensure_handler(self) -> RotatingFileHandler:
        today = self._today()
        if self._inner is not None and today == self._current_date:
            return self._inner

        # Date changed or first call — switch file
        if self._inner is not None:
            self._inner.close()

        self._current_date = today
        log_path = self._base_dir / today
        log_file = log_path.with_suffix(".log")
        log_file.parent.mkdir(parents=True, exist_ok=True)

        self._inner = RotatingFileHandler(
            log_file,
            maxBytes=self._max_bytes,
            backupCount=self._backup_count,
            encoding=self._encoding,
        )
        if self.formatter:
            self._inner.setFormatter(self.formatter)
        self._inner.setLevel(self.level)
        return self._inner

    def setFormatter(self, fmt: logging.Formatter | None) -> None:  # noqa: N802
        super().setFormatter(fmt)
        if self._inner is not None and fmt is not None:
            self._inner.setFormatter(fmt)

    def setLevel(self, level: int | str) -> None:  # noqa: N802
        super().setLevel(level)
        if self._inner is not None:
            self._inner.setLevel(self.level)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            handler = self._ensure_handler()
            handler.emit(record)
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        if self._inner is not None:
            self._inner.close()
            self._inner = None
        super().close()


def _build_logger() -> logging.Logger:
    configured_logger = logging.getLogger("aegisgate")
    if configured_logger.handlers:
        return configured_logger

    resolved_level = _normalize_level(settings.log_level)
    configured_logger.setLevel(resolved_level)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(resolved_level)
    stream_handler.setFormatter(formatter)
    configured_logger.addHandler(stream_handler)

    try:
        daily_handler = DailyRotatingFileHandler(
            base_dir=LOG_BASE_DIR,
            max_bytes=MAX_BYTES,
            backup_count=BACKUP_COUNT,
        )
        daily_handler.setLevel(resolved_level)
        daily_handler.setFormatter(formatter)
        configured_logger.addHandler(daily_handler)
    except (OSError, PermissionError):
        # 无法写文件时仅使用 stderr（如 Docker 挂载的 logs 目录无写权限）
        pass

    configured_logger.propagate = False
    return configured_logger


logger = _build_logger()


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under aegisgate namespace."""

    return logger.getChild(name)
