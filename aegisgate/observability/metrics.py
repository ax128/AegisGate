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

# Security outcome counters.
#
# Deliberately not aegisgate_filter_hits_total / aegisgate_confirmations_total /
# aegisgate_upstream_errors_total: 2d4ce8e retired those names with different
# label sets, and reviving a name with incompatible labels puts two unrelated
# series under one identifier, which silently breaks any dashboard or recording
# rule that scraped the old build. New names, new contract.
#
# Every label set below is a bounded enum. Rule ids never become labels: the
# console can add rules to security_filters.yaml, so a rule-id label would let
# the series count grow with user configuration.
if _HAS_PROMETHEUS:
    FILTER_MATCHES = Counter(
        "aegisgate_filter_matches_total",
        # Incremented per pipeline run, not per request: the streaming path
        # re-runs the whole response pipeline every stream-scan interval, so one
        # long streamed answer contributes hundreds of increments on the
        # response side. Use aegisgate_disposition_total for per-request counts.
        "Filter matches, counted per pipeline run",
        ["filter", "phase"],
    )
    FILTER_ERRORS = Counter(
        "aegisgate_filter_errors_total",
        "Filter exceptions, counted per pipeline run",
        ["filter", "phase"],
    )
    DISPOSITION = Counter(
        "aegisgate_disposition_total",
        # Once per request *per phase*: one request advances both the
        # phase="request" and the phase="response" series, so a sum without a
        # phase selector doubles the request count. Spelled out here for the
        # same reason FILTER_MATCHES' counting rule is — this is the counter
        # someone reaches for to answer "how much did we block yesterday", and
        # that is the query they will write.
        "Final disposition, counted once per request per phase",
        ["phase", "disposition"],
    )
    STREAM_PROBES = Counter(
        "aegisgate_stream_probes_total",
        "Streaming response-pipeline probes",
        ["route"],
    )
    SEMANTIC_CALLS = Counter(
        "aegisgate_semantic_calls_total",
        "Semantic review outcomes",
        ["outcome"],
    )
else:
    FILTER_MATCHES = None  # type: ignore[assignment]
    FILTER_ERRORS = None  # type: ignore[assignment]
    DISPOSITION = None  # type: ignore[assignment]
    STREAM_PROBES = None  # type: ignore[assignment]
    SEMANTIC_CALLS = None  # type: ignore[assignment]

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


def inc_filter_match(filter_name: str, phase: str) -> None:
    """Count one filter hit.

    Per pipeline run, not per request — see FILTER_MATCHES' HELP text. Only
    hits increment, so a pipeline run where nothing matched does no atomic work
    at all, which matters because the streaming path calls this from inside the
    response probe.
    """
    if FILTER_MATCHES is not None:
        FILTER_MATCHES.labels(filter=filter_name, phase=phase).inc()


def inc_filter_error(filter_name: str, phase: str) -> None:
    """Count one filter exception.

    Its own counter rather than a disposition value: a filter blowing up and a
    request being blocked are different events, and the first is the one worth
    alerting on.
    """
    if FILTER_ERRORS is not None:
        FILTER_ERRORS.labels(filter=filter_name, phase=phase).inc()


def inc_disposition(phase: str, disposition: str) -> None:
    """Count the final disposition of one request. Exactly once per request."""
    if DISPOSITION is not None:
        DISPOSITION.labels(phase=phase, disposition=disposition).inc()


def inc_stream_probe(route: str) -> None:
    """Count one streaming response-pipeline probe."""
    if STREAM_PROBES is not None:
        STREAM_PROBES.labels(route=route).inc()


def inc_semantic_call(outcome: str) -> None:
    """Count one semantic review by outcome."""
    if SEMANTIC_CALLS is not None:
        SEMANTIC_CALLS.labels(outcome=outcome).inc()


def get_metrics_app():
    """Return a Starlette-compatible ASGI app that serves ``/metrics``.

    Returns ``None`` when ``prometheus-client`` is unavailable.
    """
    if not _HAS_PROMETHEUS:
        return None
    from prometheus_client import make_asgi_app  # type: ignore[import-untyped]

    return make_asgi_app()
