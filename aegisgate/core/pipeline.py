"""Request/response pipeline executor."""

from __future__ import annotations

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger


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
                current = plugin.process_request(current, ctx)
                ctx.add_report(plugin.report())
        return current

    def run_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        current = resp
        for plugin in self.response_filters:
            if plugin.enabled(ctx):
                current = plugin.process_response(current, ctx)
                ctx.add_report(plugin.report())
        return current
