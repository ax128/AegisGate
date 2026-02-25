"""Request-side minimal checks: leak protection + high-confidence intent blocking."""

from __future__ import annotations

import re

from aegisgate.config.security_level import apply_count, normalize_security_level
from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest
from aegisgate.filters.base import BaseFilter
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger


class RequestSanitizer(BaseFilter):
    name = "request_sanitizer"

    def __init__(self) -> None:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "action": "allow"}

        rules = load_security_rules()
        sanitizer_rules = rules.get(self.name, {})
        action_map = rules.get("action_map", {}).get(self.name, {})

        self._discussion_patterns = self._compile_patterns(sanitizer_rules.get("discussion_context_patterns", []))
        self._strong_intent_patterns = self._compile_tagged_patterns(
            sanitizer_rules.get("strong_intent_patterns", []),
            default_category="attack_intent",
        )
        self._leak_check_patterns = self._compile_patterns(sanitizer_rules.get("leak_check_patterns", []))
        self._shape_anomaly_patterns = self._compile_patterns(sanitizer_rules.get("shape_anomaly_patterns", []))

        # Compatibility with existing rule keys.
        self._command_patterns = self._compile_patterns(sanitizer_rules.get("command_patterns", []))
        self._encoded_payload_patterns = self._compile_patterns(sanitizer_rules.get("encoded_payload_patterns", []))

        redactions = sanitizer_rules.get("redactions", {})
        self._command_replacement = str(redactions.get("command", "[REDACTED:command]"))
        self._payload_replacement = str(redactions.get("payload", "[REDACTED:encoded-payload]"))
        self._shape_replacement = str(redactions.get("shape", "[REDACTED:shape-anomaly]"))
        self._block_message = str(sanitizer_rules.get("block_message", "[AegisGate] request blocked by security policy."))
        self._invisible_chars = set(sanitizer_rules.get("unicode_invisible_chars", ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"]))
        self._bidi_chars = set(sanitizer_rules.get("unicode_bidi_chars", ["\u202a", "\u202b", "\u202d", "\u202e", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069"]))
        level = normalize_security_level()
        self._invisible_char_threshold = apply_count(int(sanitizer_rules.get("invisible_char_threshold", 6)), level=level, minimum=1)
        self._truncate_at = apply_count(int(sanitizer_rules.get("truncate_at", 4000)), level=level, minimum=512)

        self._action_map = {str(key): str(value) for key, value in action_map.items()}

    @staticmethod
    def _compile_patterns(items: list[dict] | list[str]) -> list[re.Pattern[str]]:
        compiled: list[re.Pattern[str]] = []
        for item in items:
            if isinstance(item, dict):
                regex = item.get("regex")
            else:
                regex = item
            if not regex:
                continue
            compiled.append(re.compile(str(regex), re.IGNORECASE))
        return compiled

    @staticmethod
    def _compile_tagged_patterns(items: list[dict] | list[str], default_category: str) -> list[tuple[str, re.Pattern[str]]]:
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for item in items:
            category = default_category
            regex = None
            if isinstance(item, dict):
                regex = item.get("regex")
                category = str(item.get("category", default_category))
            else:
                regex = item
            if not regex:
                continue
            compiled.append((category, re.compile(str(regex), re.IGNORECASE)))
        return compiled

    def _matches_any(self, text: str, patterns: list[re.Pattern[str]]) -> bool:
        return any(pattern.search(text) for pattern in patterns)

    def _matched_categories(self, text: str) -> set[str]:
        categories: set[str] = set()
        for category, pattern in self._strong_intent_patterns:
            if pattern.search(text):
                categories.add(category)
        return categories

    def _shape_hits(self, text: str) -> set[str]:
        hits: set[str] = set()
        if self._matches_any(text, self._shape_anomaly_patterns):
            hits.add("shape_pattern")
        if self._matches_any(text, self._command_patterns):
            hits.add("command_payload")
        if self._matches_any(text, self._encoded_payload_patterns):
            hits.add("encoded_payload")

        invisible_count = sum(1 for char in text if char in self._invisible_chars)
        if invisible_count >= self._invisible_char_threshold:
            hits.add("unicode_invisible")
        if any(char in self._bidi_chars for char in text):
            hits.add("unicode_bidi")
        return hits

    def _apply_action(self, ctx: RequestContext, key: str, fallback: str) -> str:
        action = self._action_map.get(key, fallback)
        ctx.enforcement_actions.append(f"{self.name}:{key}:{action}")
        return action

    def _block_request(self, req: InternalRequest, ctx: RequestContext, reason: str) -> InternalRequest:
        ctx.request_disposition = "block"
        ctx.disposition_reasons.append(reason)
        ctx.requires_human_review = True
        ctx.risk_score = max(ctx.risk_score, 0.95)
        for msg in req.messages:
            msg.content = self._block_message
        return req

    def _sanitize_shape(self, req: InternalRequest) -> bool:
        any_sanitized = False
        for msg in req.messages:
            updated = msg.content
            for pattern in self._command_patterns:
                updated = pattern.sub(self._command_replacement, updated)
            for pattern in self._encoded_payload_patterns:
                updated = pattern.sub(self._payload_replacement, updated)
            for pattern in self._shape_anomaly_patterns:
                updated = pattern.sub(self._shape_replacement, updated)

            if any(char in self._bidi_chars or char in self._invisible_chars for char in updated):
                updated = "".join(char for char in updated if char not in self._bidi_chars and char not in self._invisible_chars)

            if self._truncate_at > 0 and len(updated) > self._truncate_at:
                updated = f"{updated[:self._truncate_at]} [TRUNCATED]"

            if updated != msg.content:
                msg.content = updated
                any_sanitized = True
        return any_sanitized

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "action": "allow"}

        discussion_context = False
        strong_intent_categories: set[str] = set()
        has_leak = False
        shape_hits: set[str] = set()

        for msg in req.messages:
            text = msg.content
            if self._matches_any(text, self._discussion_patterns):
                discussion_context = True

            strong_intent_categories.update(self._matched_categories(text))
            if self._matches_any(text, self._leak_check_patterns):
                has_leak = True
            shape_hits.update(self._shape_hits(text))

        if has_leak:
            action = self._apply_action(ctx, "leak_check", "block")
            if action == "block":
                self._block_request(req, ctx, reason="request_leak_check_failed")
                self._report = {"filter": self.name, "hit": True, "risk_score": ctx.risk_score, "action": "block"}
                logger.info("request blocked request_id=%s reason=leak_check", ctx.request_id)
                return req

        if strong_intent_categories:
            if "secret_exfiltration" in strong_intent_categories:
                action_key = "secret_exfiltration"
                reason = "request_secret_exfiltration"
            elif "privilege_escalation" in strong_intent_categories:
                action_key = "privilege_escalation"
                reason = "request_privilege_abuse"
            elif "rule_bypass" in strong_intent_categories:
                action_key = "rule_bypass"
                reason = "request_rule_bypass"
            else:
                action_key = "strong_intent"
                reason = "request_strong_intent_attack"

            action = self._apply_action(ctx, action_key, "block")
            if action == "block":
                self._block_request(req, ctx, reason=reason)
                self._report = {"filter": self.name, "hit": True, "risk_score": ctx.risk_score, "action": "block"}
                logger.info("request blocked request_id=%s reason=%s", ctx.request_id, reason)
                return req

        if shape_hits:
            action = self._apply_action(ctx, "shape_anomaly", "sanitize")
            if action == "block":
                self._block_request(req, ctx, reason="request_shape_anomaly")
                self._report = {"filter": self.name, "hit": True, "risk_score": ctx.risk_score, "action": "block"}
                logger.info("request blocked request_id=%s reason=shape_anomaly", ctx.request_id)
                return req

            if self._sanitize_shape(req):
                original_text = " ".join(m.content for m in req.messages).strip()
                debug_log_original("request_sanitizer_sanitized", original_text, reason="request_shape_sanitized")
                ctx.request_disposition = "sanitize"
                ctx.disposition_reasons.append("request_shape_sanitized")
                ctx.security_tags.add("request_sanitized")
                if discussion_context:
                    ctx.security_tags.add("request_discussion_context")
                ctx.enforcement_actions.append(f"{self.name}:sanitize:applied")
                self._report = {"filter": self.name, "hit": True, "risk_score": ctx.risk_score, "action": "sanitize"}
                logger.info("request sanitized request_id=%s signals=%s", ctx.request_id, sorted(shape_hits))

        return req

    def report(self) -> dict:
        return self._report
