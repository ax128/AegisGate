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

    def __init__(self) -> None:
        self._report = self._empty_report()

    @classmethod
    def _empty_report(cls) -> dict:
        return {
            "filter": cls.name,
            "hit": False,
            "risk_score": 0.0,
            "replacements": 0,
        }

    def enabled(self, ctx: RequestContext) -> bool:  # noqa: ARG002
        return settings.enable_exact_value_redaction

    def _record(self, replacements: int) -> None:
        self._report = {
            "filter": self.name,
            "hit": replacements > 0,
            "risk_score": 0.0,
            "replacements": replacements,
        }

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = self._empty_report()
        if not self.enabled(ctx):
            return req
        total = 0
        for msg in req.messages:
            if msg.content:
                replaced, n = replace_exact_values(msg.content)
                if n > 0:
                    msg.content = replaced
                    total += n
        self._record(total)
        return req

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        self._report = self._empty_report()
        if not self.enabled(ctx):
            return resp
        if resp.output_text:
            replaced, n = replace_exact_values(resp.output_text)
            if n > 0:
                resp.output_text = replaced
            self._record(n)
        return resp

    def report(self) -> dict:
        # Used to be a constant ``hit: False``, so an audit event could not tell
        # a request that tripped the exact-value list from one that never had a
        # match in it.
        return dict(self._report)
