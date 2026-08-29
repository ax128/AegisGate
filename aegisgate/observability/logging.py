"""Structured logging bridge for AegisGate.

Provides optional JSON formatting and trace-context correlation when
OpenTelemetry is available.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from aegisgate.util.logger import build_default_formatter, logger


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
    """Set the root level and the app logger's output format.

    Parameters
    ----------
    level:
        Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    json_format:
        If ``True``, use the JSON formatter for structured log output.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # The gateway logs through the "aegisgate" logger, which sets
    # propagate = False and owns its handlers (util/logger.py), and nothing in
    # this app ever adds a handler to root. Formatting root alone is exactly why
    # this flag produced no visible change: there was nothing on root to format.
    #
    # Both branches assign, rather than only the JSON one: hot-reload calls this
    # again on every .env change, so a one-way switch would leave a deployment
    # that turned the flag back off still emitting JSON until a restart.
    formatter = JSONFormatter() if json_format else build_default_formatter()
    for handler in logger.handlers:
        handler.setFormatter(formatter)
    if json_format:
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
