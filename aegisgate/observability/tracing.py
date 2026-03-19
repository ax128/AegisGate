"""OpenTelemetry tracing integration for AegisGate.

All functions degrade to no-ops when ``opentelemetry`` is not installed.
"""

from __future__ import annotations

import contextlib
from collections.abc import Generator
from functools import wraps
from typing import Any, Callable, TypeVar

from aegisgate.util.logger import logger

F = TypeVar("F", bound=Callable[..., Any])

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False

_tracer_name = "aegisgate"
_TraceAttributeValue = str | bool | int | float | list[str] | list[bool] | list[int] | list[float]


def _coerce_trace_attribute(value: object) -> _TraceAttributeValue:
    if isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        items = list(value)
        if all(isinstance(item, str) for item in items):
            return items
        if all(isinstance(item, bool) for item in items):
            return items
        if all(isinstance(item, int) and not isinstance(item, bool) for item in items):
            return items
        if all(isinstance(item, float) for item in items):
            return items
    return str(value)


def _coerce_trace_attributes(attributes: dict[str, object]) -> dict[str, _TraceAttributeValue]:
    return {key: _coerce_trace_attribute(value) for key, value in attributes.items()}


def init_tracing(service_name: str = "aegisgate") -> None:
    """Initialize the OpenTelemetry TracerProvider.

    Call once during application startup. No-op if OTel is not installed.
    """
    if not _HAS_OTEL:
        logger.debug("opentelemetry not installed, tracing disabled")
        return

    provider = TracerProvider()
    # Default to console exporter; in production, users should configure
    # an OTLP exporter via OTEL_EXPORTER_OTLP_ENDPOINT env var.
    try:
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa: F811
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        logger.info("tracing initialized with OTLP exporter")
    except ImportError:
        import os
        if os.environ.get("AEGIS_OTEL_CONSOLE_EXPORTER", "").lower() in ("1", "true", "yes"):
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            logger.info("tracing initialized with console exporter (install opentelemetry-exporter-otlp for production)")
        else:
            logger.warning("OTLP exporter not installed, tracing spans will be discarded; set AEGIS_OTEL_CONSOLE_EXPORTER=true to use console exporter")

    _otel_trace.set_tracer_provider(provider)

    global _tracer_name
    _tracer_name = service_name


def get_tracer():
    """Return an OpenTelemetry tracer or a no-op substitute."""
    if _HAS_OTEL:
        return _otel_trace.get_tracer(_tracer_name)
    return _NoOpTracer()


@contextlib.contextmanager
def trace_span(name: str, **attributes: Any) -> Generator[Any, None, None]:
    """Context manager that creates a trace span.

    Usage::

        with trace_span("pipeline.request", filter_count=4) as span:
            ...
    """
    if _HAS_OTEL:
        tracer = _otel_trace.get_tracer(_tracer_name)
        with tracer.start_as_current_span(name, attributes=_coerce_trace_attributes(attributes)) as span:
            yield span
    else:
        yield None


def traced(span_name: str) -> Callable[[F], F]:
    """Decorator that wraps a function in a trace span."""

    def decorator(func: F) -> F:
        if not _HAS_OTEL:
            return func

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with trace_span(span_name):
                return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


# Legacy interface preserved for backward compatibility.
def trace(span_name: str, **fields: object) -> None:
    """Fire-and-forget trace event — prefer ``trace_span`` context manager."""
    if _HAS_OTEL:
        tracer = _otel_trace.get_tracer(_tracer_name)
        with tracer.start_as_current_span(span_name, attributes=_coerce_trace_attributes(fields)):
            pass
    else:
        logger.info("trace span=%s fields=%s", span_name, fields)


# ---------------------------------------------------------------------------
# No-op fallback
# ---------------------------------------------------------------------------

class _NoOpSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def add_event(self, name: str, attributes: dict | None = None) -> None:
        pass


class _NoOpTracer:
    @contextlib.contextmanager
    def start_as_current_span(self, name: str, **kwargs: Any) -> Generator[_NoOpSpan, None, None]:
        yield _NoOpSpan()
