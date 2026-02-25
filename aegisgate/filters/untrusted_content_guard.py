"""Guard for indirect prompt injection from untrusted content.

Rules are loaded from external YAML for bilingual and tenant-friendly tuning.
"""

from __future__ import annotations

import re

from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger


class UntrustedContentGuard(BaseFilter):
    name = "untrusted_content_guard"

    def __init__(self) -> None:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "isolated_messages": 0,
            "suspicious_messages": 0,
        }

        rules = load_security_rules()
        guard_rules = rules.get(self.name, {})
        action_map = rules.get("action_map", {}).get(self.name, {})

        self._untrusted_sources = {str(item).lower() for item in guard_rules.get("untrusted_sources", [])}
        self._source_trust_matrix = {
            str(source).lower(): {
                "trusted": bool(config.get("trusted", False)),
                "risk_multiplier": float(config.get("risk_multiplier", 1.0)),
            }
            for source, config in (guard_rules.get("source_trust_matrix", {}) or {}).items()
        }

        self._boundary_start = str(guard_rules.get("boundary_start", "[UNTRUSTED_CONTENT_START]"))
        self._boundary_end = str(guard_rules.get("boundary_end", "[UNTRUSTED_CONTENT_END]"))
        self._risk_score = float(guard_rules.get("risk_score", 0.88))
        self._action_map = {str(key): str(value) for key, value in action_map.items()}

        patterns: list[re.Pattern[str]] = []
        for item in guard_rules.get("instructional_patterns", []):
            regex = item.get("regex")
            if not regex:
                continue
            patterns.append(re.compile(regex, re.IGNORECASE))
        self._instructional_patterns = patterns

    def _is_untrusted_source(self, source: str, metadata: dict) -> tuple[bool, float]:
        source_key = source.lower()

        if metadata.get("trusted") is False:
            return True, 1.2

        matrix_entry = self._source_trust_matrix.get(source_key)
        if matrix_entry is not None:
            return not matrix_entry.get("trusted", False), float(matrix_entry.get("risk_multiplier", 1.0))

        if source_key in self._untrusted_sources:
            return True, 1.0

        return False, 1.0

    def _apply_action(self, ctx: RequestContext, key: str) -> None:
        action = self._action_map.get(key)
        if not action:
            return

        ctx.enforcement_actions.append(f"{self.name}:{key}:{action}")
        if action == "block":
            ctx.risk_score = max(ctx.risk_score, 0.95)
            ctx.requires_human_review = True
        elif action == "review":
            ctx.risk_score = max(ctx.risk_score, 0.85)
            ctx.requires_human_review = True

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "isolated_messages": 0,
            "suspicious_messages": 0,
        }

        isolated = 0
        suspicious = 0

        for msg in req.messages:
            is_untrusted, risk_multiplier = self._is_untrusted_source(msg.source, msg.metadata)
            if not is_untrusted:
                continue

            isolated += 1
            ctx.untrusted_input_detected = True
            ctx.security_tags.add("untrusted_content")
            msg.metadata["isolated_by"] = self.name

            if any(pattern.search(msg.content) for pattern in self._instructional_patterns):
                suspicious += 1
                risk = min(1.0, self._risk_score * max(0.1, risk_multiplier))
                ctx.risk_score = max(ctx.risk_score, risk)
                ctx.security_tags.add("indirect_injection_suspected")
                self._apply_action(ctx, "suspicious_untrusted")

            msg.content = f"{self._boundary_start}\n{msg.content}\n{self._boundary_end}"

        if isolated > 0:
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "isolated_messages": isolated,
                "suspicious_messages": suspicious,
            }
            logger.info(
                "untrusted content isolated request_id=%s isolated=%d suspicious=%d",
                ctx.request_id,
                isolated,
                suspicious,
            )

        return req

    def report(self) -> dict:
        return self._report
