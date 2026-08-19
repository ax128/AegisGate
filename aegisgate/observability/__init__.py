"""Observability package — metrics, tracing, and structured logging."""

from aegisgate.observability.logging import configure_logging, log_event
from aegisgate.observability.metrics import (
    get_metrics_app,
    inc_request,
    observe_request_duration,
)
from aegisgate.observability.tracing import (
    get_tracer,
    init_tracing,
    trace,
    trace_span,
)

__all__ = [
    "configure_logging",
    "get_metrics_app",
    "get_tracer",
    "inc_request",
    "init_tracing",
    "log_event",
    "observe_request_duration",
    "trace",
    "trace_span",
]
