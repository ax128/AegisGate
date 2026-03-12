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
        self._discussion_risk_score = max(0.0, float(rules.get("discussion_risk_score", 0.3)))

        blocked_patterns: list[tuple[str, re.Pattern[str]]] = []
        for item in rules.get("blocked_patterns", []):
            pattern_id = str(item.get("id", "privilege_rule"))
            regex = item.get("regex")
            if not regex:
                continue
            blocked_patterns.append((pattern_id, re.compile(regex, re.IGNORECASE)))
        self._blocked_patterns = blocked_patterns

        discussion_patterns: list[re.Pattern[str]] = []
        for regex in rules.get("discussion_context_patterns", []):
            if not regex:
                continue
            discussion_patterns.append(re.compile(str(regex), re.IGNORECASE))
        self._discussion_patterns = discussion_patterns

    def _matches(self, text: str) -> list[str]:
        hits: list[str] = []
        for pattern_id, pattern in self._blocked_patterns:
            if pattern.search(text):
                hits.append(pattern_id)
        return hits

    def _is_discussion_context(self, text: str) -> bool:
        return any(pattern.search(text) for pattern in self._discussion_patterns)

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        blocked: list[str] = []
        discussion_context = False
        for msg in req.messages:
            blocked.extend(self._matches(msg.content))
            discussion_context = discussion_context or self._is_discussion_context(msg.content)

        if blocked:
            if discussion_context:
                ctx.risk_score = max(ctx.risk_score, self._discussion_risk_score)
                ctx.security_tags.add("privilege_discussion_context")
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "blocked": sorted(set(blocked)),
                    "contextual_discussion": True,
                }
                logger.info(
                    "privilege guard downgraded discussion request_id=%s blocked=%s",
                    ctx.request_id,
                    sorted(set(blocked)),
                )
                return req

            ctx.risk_score = max(ctx.risk_score, self._request_risk_floor)
            ctx.request_disposition = "block"
            ctx.disposition_reasons.append("privilege_abuse")
            ctx.requires_human_review = True
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "blocked": sorted(set(blocked)),
                "contextual_discussion": False,
            }
            ctx.security_tags.add("privilege_abuse")
            logger.info("privilege guard hit request_id=%s blocked=%s", ctx.request_id, sorted(set(blocked)))
        return req

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        blocked = self._matches(resp.output_text)
        if blocked:
            if self._is_discussion_context(resp.output_text):
                ctx.risk_score = max(ctx.risk_score, self._discussion_risk_score)
                ctx.security_tags.add("response_privilege_discussion_context")
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "blocked": sorted(set(blocked)),
                    "contextual_discussion": True,
                }
                logger.debug(
                    "privilege-like response downgraded by discussion context request_id=%s blocked=%s",
                    ctx.request_id,
                    sorted(set(blocked)),
                )
                return resp

            ctx.risk_score = max(ctx.risk_score, self._response_risk_floor)
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("response_privilege_abuse")
            ctx.requires_human_review = True
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "blocked": sorted(set(blocked)),
                "contextual_discussion": False,
            }
            ctx.security_tags.add("response_privilege_abuse")
            logger.debug("privilege-like response detected request_id=%s blocked=%s", ctx.request_id, sorted(set(blocked)))
        return resp

    def report(self) -> dict:
        return self._report
