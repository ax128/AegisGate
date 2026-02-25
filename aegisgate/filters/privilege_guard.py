"""Privilege abuse detector."""

from __future__ import annotations

import re

from aegisgate.config.security_level import apply_floor, normalize_security_level
from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger


class PrivilegeGuard(BaseFilter):
    name = "privilege_guard"

    def __init__(self) -> None:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "blocked": []}
        rules = load_security_rules().get(self.name, {})
        level = normalize_security_level()
        self._request_risk_floor = apply_floor(float(rules.get("request_risk_floor", 0.9)), level=level)
        self._response_risk_floor = apply_floor(float(rules.get("response_risk_floor", 0.85)), level=level)

        blocked_patterns: list[tuple[str, re.Pattern[str]]] = []
        for item in rules.get("blocked_patterns", []):
            pattern_id = str(item.get("id", "privilege_rule"))
            regex = item.get("regex")
            if not regex:
                continue
            blocked_patterns.append((pattern_id, re.compile(regex, re.IGNORECASE)))
        self._blocked_patterns = blocked_patterns

    def _matches(self, text: str) -> list[str]:
        hits: list[str] = []
        for pattern_id, pattern in self._blocked_patterns:
            if pattern.search(text):
                hits.append(pattern_id)
        return hits

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        blocked: list[str] = []
        for msg in req.messages:
            blocked.extend(self._matches(msg.content))

        if blocked:
            ctx.risk_score = max(ctx.risk_score, self._request_risk_floor)
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "blocked": sorted(set(blocked)),
            }
            ctx.security_tags.add("privilege_abuse")
            logger.info("privilege guard hit request_id=%s", ctx.request_id)
        return req

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        blocked = self._matches(resp.output_text)
        if blocked:
            ctx.risk_score = max(ctx.risk_score, self._response_risk_floor)
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "blocked": sorted(set(blocked)),
            }
            ctx.security_tags.add("response_privilege_abuse")
            logger.info("privilege-like response detected request_id=%s", ctx.request_id)
        return resp

    def report(self) -> dict:
        return self._report
