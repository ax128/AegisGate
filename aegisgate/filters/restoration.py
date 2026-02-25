"""Response-side placeholder restoration using externalized rules."""

from __future__ import annotations

import re
import time

from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.logger import logger


class RestorationFilter(BaseFilter):
    name = "restoration"

    def __init__(self, store: KVStore) -> None:
        self.store = store
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0}

        rules = load_security_rules()
        restoration_rules = rules.get(self.name, {})
        action_map = rules.get("action_map", {}).get(self.name, {})

        placeholder_regex = restoration_rules.get("placeholder_regex", r"\{\{AG_[A-Z0-9]+_[A-Z_]+_\d+\}\}")
        self._placeholder_re = re.compile(placeholder_regex)

        suspicious_patterns: list[re.Pattern[str]] = []
        for item in restoration_rules.get("suspicious_context_patterns", []):
            regex = item.get("regex")
            if not regex:
                continue
            suspicious_patterns.append(re.compile(regex, re.IGNORECASE))
        self._suspicious_patterns = suspicious_patterns

        restore_policy = restoration_rules.get("restore_policy", {})
        self._max_placeholders_per_response = int(restore_policy.get("max_placeholders_per_response", 20))
        self._restore_ttl_seconds = int(restore_policy.get("restore_ttl_seconds", 1800))
        self._allow_partial_restore = bool(restore_policy.get("allow_partial_restore", False))

        self._action_map = {str(key): str(value) for key, value in action_map.items()}

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

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0}

        # TTL guard: do not restore old mappings.
        if self._restore_ttl_seconds > 0:
            mapping_age = time.time() - ctx.redaction_created_at
            if mapping_age > self._restore_ttl_seconds:
                ctx.security_tags.add("restoration_stale_mapping")
                self._apply_action(ctx, "stale_mapping")
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "action": "blocked_due_to_stale_mapping",
                    "mapping_age_seconds": round(mapping_age, 2),
                }
                logger.info("restoration skipped stale mapping request_id=%s age=%.2f", ctx.request_id, mapping_age)
                ctx.redaction_mapping.clear()
                return resp

        mapping = dict(ctx.redaction_mapping)

        # One-time consume prevents stale mappings from being applied in future requests.
        consumed = self.store.consume_mapping(ctx.session_id, ctx.request_id)
        if not mapping:
            mapping = consumed

        if not mapping:
            return resp

        placeholders_in_output = self._placeholder_re.findall(resp.output_text)
        placeholder_count = len(placeholders_in_output)

        if placeholder_count > self._max_placeholders_per_response:
            ctx.security_tags.add("restoration_too_many_placeholders")
            self._apply_action(ctx, "too_many_placeholders")
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "action": "blocked_due_to_placeholder_volume",
                "placeholder_count": placeholder_count,
            }
            logger.info("restoration blocked placeholder volume request_id=%s count=%d", ctx.request_id, placeholder_count)
            ctx.redaction_mapping.clear()
            return resp

        missing_placeholders = {token for token in placeholders_in_output if token not in mapping}
        if missing_placeholders and not self._allow_partial_restore:
            ctx.security_tags.add("restoration_partial_missing")
            self._apply_action(ctx, "partial_restore")
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "action": "blocked_due_to_partial_restore",
                "missing_placeholders": len(missing_placeholders),
            }
            logger.info(
                "restoration blocked partial restore request_id=%s missing=%d",
                ctx.request_id,
                len(missing_placeholders),
            )
            ctx.redaction_mapping.clear()
            return resp

        placeholders_present = {token for token in placeholders_in_output if token in mapping}
        suspicious = any(pattern.search(resp.output_text) for pattern in self._suspicious_patterns)
        if placeholders_present and suspicious:
            ctx.security_tags.add("restoration_blocked")
            self._apply_action(ctx, "exfiltration")
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "action": "blocked_due_to_placeholder_exfil_risk",
                "blocked_placeholders": len(placeholders_present),
            }
            logger.info(
                "restoration blocked request_id=%s blocked_placeholders=%d",
                ctx.request_id,
                len(placeholders_present),
            )
            ctx.redaction_mapping.clear()
            return resp

        for placeholder, raw in mapping.items():
            resp.output_text = resp.output_text.replace(placeholder, raw)

        ctx.redaction_mapping.clear()
        ctx.security_tags.add("restoration_applied")

        self._report = {
            "filter": self.name,
            "hit": True,
            "risk_score": 0.0,
            "restored_items": len(mapping),
        }
        logger.info("restoration restored=%d request_id=%s", len(mapping), ctx.request_id)
        return resp

    def report(self) -> dict:
        return self._report
