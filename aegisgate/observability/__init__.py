"""Observability package — metrics, tracing, and structured logging."""

from aegisgate.observability.logging import configure_logging
from aegisgate.observability.metrics import (
    get_metrics_app,
    inc_request,
    observe_request_duration,
)
from aegisgate.observability.tracing import (
    get_tracer,
    init_tracing,
    trace_span,
)

__all__ = [
    "configure_logging",
    "get_metrics_app",
    "get_tracer",
    "inc_request",
    "init_tracing",
    "observe_request_duration",
    "trace_span",
]
