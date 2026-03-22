"""Request/response pipeline executor."""

from __future__ import annotations

import threading
import time
from typing import Any

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger

# Filters slower than this threshold (seconds) will emit a WARNING for diagnosis.
_SLOW_FILTER_WARN_S = 1.0

_init_log_lock = threading.Lock()
_init_logged: bool = False


def _should_log_filter_done(*, phase: str, is_stream: bool, report: dict[str, Any]) -> bool:
    if phase != "request" and is_stream:
        return False
    return bool(report.get("hit"))


class Pipeline:

    def __init__(self, request_filters: list[BaseFilter], response_filters: list[BaseFilter]) -> None:
        self.request_filters = request_filters
        self.response_filters = response_filters
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
            if phase == "request":
                current = plugin.process_request(current, ctx)
            else:
                current = plugin.process_response(current, ctx)
            elapsed = time.monotonic() - t0
            report = plugin.report()
            ctx.add_report(report)
            if elapsed >= _SLOW_FILTER_WARN_S:
                extra = f" output_len={len(current.output_text)}" if phase == "response" else ""
                logger.warning(
                    "slow_filter phase=%s filter=%s elapsed_s=%.3f request_id=%s%s",
                    phase,
                    plugin.name,
                    elapsed,
                    ctx.request_id,
                    extra,
                )
            elif _should_log_filter_done(phase=phase, is_stream=is_stream, report=report):
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

    def run_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        is_stream = resp.raw.get("stream", False) if isinstance(resp.raw, dict) else False
        return self._run_phase(
            phase="response",
            current=resp,
            filters=self.response_filters,
            ctx=ctx,
            is_stream=is_stream,
        )
