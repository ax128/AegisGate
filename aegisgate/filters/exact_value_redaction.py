"""Exact-value redaction filter (highest priority, V1 pipeline).

Replaces configured sensitive strings with ``[REDACTED:EXACT_VALUE]`` in both
request messages and response output text.  The filter bypasses the normal
``ctx.enabled_filters`` check and is controlled solely by the global setting
``enable_exact_value_redaction``.
"""

from __future__ import annotations

from aegisgate.config.redact_values import replace_exact_values
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter


class ExactValueRedactionFilter(BaseFilter):
    name = "exact_value_redaction"

    def enabled(self, ctx: RequestContext) -> bool:  # noqa: ARG002
        return settings.enable_exact_value_redaction

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        if not self.enabled(ctx):
            return req
        for msg in req.messages:
            if msg.content:
                replaced, n = replace_exact_values(msg.content)
                if n > 0:
                    msg.content = replaced
        return req

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        if not self.enabled(ctx):
            return resp
        if resp.output_text:
            replaced, n = replace_exact_values(resp.output_text)
            if n > 0:
                resp.output_text = replaced
        return resp

    def report(self) -> dict:
        return {"filter": self.name, "hit": False, "risk_score": 0.0}
