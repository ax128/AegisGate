"""Request/response pipeline executor."""

from __future__ import annotations

import time

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger

# Filters slower than this threshold (seconds) will emit a WARNING for diagnosis.
_SLOW_FILTER_WARN_S = 1.0


class Pipeline:
    def __init__(self, request_filters: list[BaseFilter], response_filters: list[BaseFilter]) -> None:
        self.request_filters = request_filters
        self.response_filters = response_filters
        logger.debug("request filter running: %s", [plugin.name for plugin in self.request_filters])
        logger.debug("response filter running: %s", [plugin.name for plugin in self.response_filters])

    def run_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        current = req
        for plugin in self.request_filters:
            if plugin.enabled(ctx):
                t0 = time.monotonic()
                current = plugin.process_request(current, ctx)
                elapsed = time.monotonic() - t0
                ctx.add_report(plugin.report())
                if elapsed >= _SLOW_FILTER_WARN_S:
                    logger.warning(
                        "slow_filter phase=request filter=%s elapsed_s=%.3f request_id=%s",
                        plugin.name, elapsed, ctx.request_id,
                    )
                else:
                    logger.debug(
                        "filter_done phase=request filter=%s elapsed_s=%.3f request_id=%s",
                        plugin.name, elapsed, ctx.request_id,
                    )
        return current

    def run_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        is_stream = resp.raw.get("stream", False) if isinstance(resp.raw, dict) else False
        current = resp
        for plugin in self.response_filters:
            if plugin.enabled(ctx):
                t0 = time.monotonic()
                current = plugin.process_response(current, ctx)
                elapsed = time.monotonic() - t0
                ctx.add_report(plugin.report())
                if elapsed >= _SLOW_FILTER_WARN_S:
                    logger.warning(
                        "slow_filter phase=response filter=%s elapsed_s=%.3f request_id=%s output_len=%s",
                        plugin.name, elapsed, ctx.request_id, len(current.output_text),
                    )
                elif not is_stream:
                    # Only emit per-filter DEBUG for non-stream; stream checks are
                    # already interval-gated so individual filter logs add noise.
                    logger.debug(
                        "filter_done phase=response filter=%s elapsed_s=%.3f request_id=%s",
                        plugin.name, elapsed, ctx.request_id,
                    )
        # Stream: no per-check log — the caller (router) logs stream start/finish.
        return current
