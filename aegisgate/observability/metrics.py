"""Prometheus metrics for AegisGate.

All functions degrade to no-ops when ``prometheus-client`` is not installed,
so the gateway works without the ``observability`` extras.
"""

from __future__ import annotations

from aegisgate.util.logger import logger

try:
    from prometheus_client import Counter, Histogram, REGISTRY  # noqa: F401

    _HAS_PROMETHEUS = True
except ImportError:
    _HAS_PROMETHEUS = False

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
if _HAS_PROMETHEUS:
    REQUEST_TOTAL = Counter(
        "aegisgate_requests_total",
        "Total requests processed by the gateway",
        ["route", "status"],
    )
else:
    REQUEST_TOTAL = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------
if _HAS_PROMETHEUS:
    REQUEST_DURATION = Histogram(
        "aegisgate_request_duration_seconds",
        "End-to-end request latency",
        ["route"],
        buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    )
else:
    REQUEST_DURATION = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Convenience helpers (always safe to call)
# ---------------------------------------------------------------------------

def inc_request(route: str, status: int) -> None:
    """Increment the request counter."""
    if REQUEST_TOTAL is not None:
        REQUEST_TOTAL.labels(route=route, status=str(status)).inc()
    else:
        logger.debug("metric request route=%s status=%s", route, status)


def observe_request_duration(route: str, seconds: float) -> None:
    """Observe request latency."""
    if REQUEST_DURATION is not None:
        REQUEST_DURATION.labels(route=route).observe(seconds)


def get_metrics_app():
    """Return a Starlette-compatible ASGI app that serves ``/metrics``.

    Returns ``None`` when ``prometheus-client`` is unavailable.
    """
    if not _HAS_PROMETHEUS:
        return None
    from prometheus_client import make_asgi_app  # type: ignore[import-untyped]

    return make_asgi_app()
