"""Metrics helpers placeholder."""

from __future__ import annotations

from aegisgate.util.logger import logger


def emit_counter(name: str, value: int = 1, labels: dict | None = None) -> None:
    logger.info("metric counter name=%s value=%s labels=%s", name, value, labels or {})
