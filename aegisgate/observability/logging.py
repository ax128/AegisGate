"""Structured logging bridge for AegisGate.

Provides optional JSON formatting and trace-context correlation when
OpenTelemetry is available.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from aegisgate.util.logger import logger


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1] is not None:
            payload["exception"] = self.formatException(record.exc_info)

        # Inject trace context when available
        trace_id, span_id = _current_trace_ids()
        if trace_id:
            payload["trace_id"] = trace_id
            payload["span_id"] = span_id

        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Configure the root logger.

    Parameters
    ----------
    level:
        Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    json_format:
        If ``True``, use JSON formatter for structured log output.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    if json_format:
        for handler in root.handlers:
            handler.setFormatter(JSONFormatter())
        logger.info("structured JSON logging enabled")


def _current_trace_ids() -> tuple[str, str]:
    """Extract current OTel trace/span IDs, or return empty strings."""
    try:
        from opentelemetry import trace as _otel_trace

        span = _otel_trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.trace_id:
            return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")
    except ImportError:
        pass
    return "", ""


# Legacy interface preserved for backward compatibility.
def log_event(event: str, **payload: object) -> None:
    """Emit a structured log event."""
    trace_id, span_id = _current_trace_ids()
    extra = dict(payload)
    if trace_id:
        extra["trace_id"] = trace_id
        extra["span_id"] = span_id
    logger.info("event=%s payload=%s", event, extra)
