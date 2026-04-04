"""Request/response pipeline executor."""

from __future__ import annotations

import threading
import time
from collections.abc import Sequence
from typing import Any

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger

# Filters slower than this threshold (seconds) will emit a WARNING for diagnosis.
_SLOW_FILTER_WARN_S = 1.0

_init_log_lock = threading.Lock()
_init_logged: bool = False

# H-07: Security-critical filters must never be silently forward-degraded when
# storage_failure_action=forward.  Only storage-backed filters (e.g. RedactionFilter
# with a storage dependency) should benefit from the forward fallback; pure security
# logic filters must always block on error.
_SECURITY_CRITICAL_FILTER_NAMES: frozenset[str] = frozenset({
    "injection_detector",
    "privilege_guard",
    "rag_poison_guard",
    "request_sanitizer",
})


def _should_log_filter_done(
    *, phase: str, is_stream: bool, report: dict[str, Any]
) -> bool:
    if phase != "request" and is_stream:
        return False
    return bool(report.get("hit"))


class Pipeline:
    def __init__(
        self,
        request_filters: Sequence[BaseFilter],
        response_filters: Sequence[BaseFilter],
    ) -> None:
        self.request_filters = list(request_filters)
        self.response_filters = list(response_filters)
        global _init_logged
        if not _init_logged:
            with _init_log_lock:
                if not _init_logged:
                    _init_logged = True
                    logger.info(
                        "pipeline initialized request_filters=%s response_filters=%s",
                        [p.name for p in self.request_filters],
                        [p.name for p in self.response_filters],
                    )

    def _run_phase(
        self,
        *,
        phase: str,
        current: Any,
        filters: list[BaseFilter],
        ctx: RequestContext,
        is_stream: bool = False,
    ) -> Any:
        for plugin in filters:
            if not plugin.enabled(ctx):
                continue
            t0 = time.monotonic()
            try:
                if phase == "request":
                    current = plugin.process_request(current, ctx)
                else:
                    current = plugin.process_response(current, ctx)
            except Exception as exc:
                elapsed = time.monotonic() - t0
                logger.exception(
                    "filter_error phase=%s filter=%s elapsed_s=%.3f request_id=%s",
                    phase,
                    plugin.name,
                    elapsed,
                    ctx.request_id,
                )
                ctx.add_report({"filter": plugin.name, "error": True, "hit": False})
                if phase == "request":
                    from aegisgate.config.settings import settings as _settings

                    is_security_critical = plugin.name in _SECURITY_CRITICAL_FILTER_NAMES
                    if _settings.storage_failure_action == "forward" and not is_security_critical:
                        logger.warning(
                            "filter_error_degraded phase=%s filter=%s request_id=%s — forwarding due to storage_failure_action=forward",
                            phase,
                            plugin.name,
                            ctx.request_id,
                        )
                        ctx.enforcement_actions.append(
                            f"request_pipeline:degraded:{plugin.name}"
                        )
                        continue
                    ctx.request_disposition = "block"
                    ctx.enforcement_actions.append(
                        f"request_pipeline:error:{plugin.name}"
                    )
                    ctx.disposition_reasons.append("request_filter_error")
                else:
                    ctx.response_disposition = "block"
                    ctx.enforcement_actions.append(
                        f"response_pipeline:error:{plugin.name}"
                    )
                    ctx.disposition_reasons.append("response_filter_error")
                break
            elapsed = time.monotonic() - t0
            report = plugin.report()
            ctx.add_report(report)
            if elapsed >= _SLOW_FILTER_WARN_S:
                extra = (
                    f" output_len={len(getattr(current, 'output_text', ''))}"
                    if phase == "response"
                    else ""
                )
                logger.warning(
                    "slow_filter phase=%s filter=%s elapsed_s=%.3f request_id=%s%s",
                    phase,
                    plugin.name,
                    elapsed,
                    ctx.request_id,
                    extra,
                )
            elif _should_log_filter_done(
                phase=phase, is_stream=is_stream, report=report
            ):
                logger.debug(
                    "filter_done phase=%s filter=%s elapsed_s=%.3f request_id=%s",
                    phase,
                    plugin.name,
                    elapsed,
                    ctx.request_id,
                )
        return current

    def run_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        return self._run_phase(
            phase="request",
            current=req,
            filters=self.request_filters,
            ctx=ctx,
        )

    def run_response(
        self, resp: InternalResponse, ctx: RequestContext
    ) -> InternalResponse:
        is_stream = (
            resp.raw.get("stream", False) if isinstance(resp.raw, dict) else False
        )
        return self._run_phase(
            phase="response",
            current=resp,
            filters=self.response_filters,
            ctx=ctx,
            is_stream=is_stream,
        )
