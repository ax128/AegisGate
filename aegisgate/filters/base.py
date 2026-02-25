"""Base filter contract."""

from __future__ import annotations

from abc import ABC

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse


class BaseFilter(ABC):
    name = "base"

    def enabled(self, ctx: RequestContext) -> bool:
        return self.name in ctx.enabled_filters

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        return req

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        return resp

    def report(self) -> dict:
        return {"filter": self.name, "hit": False, "risk_score": 0.0}
