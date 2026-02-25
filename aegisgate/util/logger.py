"""Unified logger for the whole project."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from aegisgate.config.settings import settings


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "aegisgate.log"
MAX_BYTES = 10 * 1024 * 1024
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
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        rotating_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        rotating_handler.setLevel(resolved_level)
        rotating_handler.setFormatter(formatter)
        configured_logger.addHandler(rotating_handler)
    except (OSError, PermissionError):
        # 无法写文件时仅使用 stderr（如 Docker 挂载的 logs 目录无写权限）
        pass

    configured_logger.propagate = False
    return configured_logger


logger = _build_logger()


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under aegisgate namespace."""

    return logger.getChild(name)
