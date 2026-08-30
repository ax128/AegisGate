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
        # Two things a reader gets wrong, both on the metric because this is the
        # counter someone reaches for to answer "how much did we block
        # yesterday" and those are the queries they will write.
        #
        # One: once per request *per phase*. A request advances both the
        # phase="request" and the phase="response" series, so a sum without a
        # phase selector is twice the request count.
        #
        # Two: the response phase reports ctx.response_disposition, and that
        # field is "allow" until something sets it. A request blocked in the
        # request phase never reaches a response, so it lands in
        # phase="response",disposition="allow" — the response series counts
        # allows for responses that were never produced, inflated by exactly the
        # number of request-phase blocks. Read blocks from phase="request".
        # Making the response phase silent instead would be a different metric
        # with a harder question behind it (what counts as having reached a
        # response — an upstream 500 does), and that is a decision, not a
        # wording fix.
        "Disposition per phase, once per request; phase=response reports allow "
        "when the request was blocked before any response existed, so read "
        "blocks from phase=request",
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

    # Labelled by *validator name*, never by rule id: the same bounded-enum rule
    # as above, and here the bound is the number of pure functions implemented
    # in util/checksums.py — fixed at compile time.
    #
    # The cost is that the metric cannot say which rule failed. That is in the
    # audit line (report.validator_failed is a per-rule-id dict); the metric
    # answers "how big is this", which is the input the decision needs.
    PII_VALIDATOR_FAILURES = Counter(
        "aegisgate_pii_validator_failures_total",
        # The scope belongs on the metric, not only in config/README.md: the
        # person reading a flat zero here is exactly the person who will read it
        # as "we have no false positives". CARD, CN_ID and IBAN are not in the
        # relaxed id set, and /v1/chat/completions, /v1/responses and
        # /v1/messages run only that set — so these rules, and therefore their
        # check digits, never fire on the three protocol routes.
        "Values redacted by a PII rule whose check digit did not validate; V1 "
        "request pipeline only, and not on the relaxed protocol routes",
        ["validator"],
    )
else:
    FILTER_MATCHES = None  # type: ignore[assignment]
    FILTER_ERRORS = None  # type: ignore[assignment]
    DISPOSITION = None  # type: ignore[assignment]
    STREAM_PROBES = None  # type: ignore[assignment]
    SEMANTIC_CALLS = None  # type: ignore[assignment]
    PII_VALIDATOR_FAILURES = None  # type: ignore[assignment]

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
    """Count one phase's disposition. Once per request per phase.

    Callers pass ctx.response_disposition unchanged, which is "allow" on a
    request that was blocked before any response existed — see DISPOSITION's
    HELP text, and read blocks from phase="request".
    """
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


def inc_validator_failure(validator: str) -> None:
    """Count one distinct value that matched a PII rule but failed its checksum.

    Distinct values, not occurrences: the validator runs after the redaction
    filter's dedupe cache, so a value repeated in one request counts once.
    """
    if PII_VALIDATOR_FAILURES is not None:
        PII_VALIDATOR_FAILURES.labels(validator=validator).inc()


def get_metrics_app():
    """Return a Starlette-compatible ASGI app that serves ``/metrics``.

    Returns ``None`` when ``prometheus-client`` is unavailable.
    """
    if not _HAS_PROMETHEUS:
        return None
    from prometheus_client import make_asgi_app  # type: ignore[import-untyped]

    return make_asgi_app()
