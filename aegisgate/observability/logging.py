"""Structured logging bridge."""

from __future__ import annotations

from aegisgate.util.logger import logger


def log_event(event: str, **payload: object) -> None:
    logger.info("event=%s payload=%s", event, payload)
