"""Tracing helpers placeholder."""

from __future__ import annotations

from aegisgate.util.logger import logger


def trace(span_name: str, **fields: object) -> None:
    logger.info("trace span=%s fields=%s", span_name, fields)
