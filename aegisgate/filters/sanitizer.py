"""Output sanitizer with externalized rules."""

from __future__ import annotations

import re

from aegisgate.config.security_level import apply_threshold, normalize_security_level
from aegisgate.config.security_rules import load_security_rules
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger


class OutputSanitizer(BaseFilter):
    name = "output_sanitizer"

    def __init__(self) -> None:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "action": "none"}

        rules = load_security_rules()
        sanitizer_rules = rules.get("sanitizer", {})
        action_map = rules.get("action_map", {}).get(self.name, {})
        thresholds = sanitizer_rules.get("thresholds", {})
        level = normalize_security_level()
        self._sanitize_threshold = apply_threshold(float(thresholds.get("sanitize", 0.35)), level=level)
        self._block_threshold = apply_threshold(float(thresholds.get("block", 0.7)), level=level)

        self._discussion_patterns = self._compile_patterns(sanitizer_rules.get("discussion_context_patterns", []))
        self._command_patterns = self._compile_patterns(sanitizer_rules.get("command_patterns", []))
        self._force_block_command_patterns = self._compile_id_patterns(
            sanitizer_rules.get("force_block_command_patterns", [])
        )
        self._encoded_payload_patterns = self._compile_patterns(sanitizer_rules.get("encoded_payload_patterns", []))
        self._system_leak_patterns = self._compile_patterns(sanitizer_rules.get("system_leak_patterns", []))
        self._unsafe_markup_patterns = self._compile_patterns(sanitizer_rules.get("unsafe_markup_patterns", []))
        self._unsafe_uri_patterns = self._compile_patterns(sanitizer_rules.get("unsafe_uri_patterns", []))
        redactions = sanitizer_rules.get("redactions", {})
        self._command_replacement = str(redactions.get("command", "[REDACTED:command]"))
        self._payload_replacement = str(redactions.get("payload", "[REDACTED:encoded-payload]"))
        self._uri_replacement = str(redactions.get("uri", "[unsafe-uri-removed]"))
        self._markup_replacement = str(redactions.get("markup", "[unsafe-tag-removed]"))
        self._block_message = str(sanitizer_rules.get("block_message", "[AegisGate] response blocked by security policy."))
        self._sanitize_prefix = str(sanitizer_rules.get("sanitize_prefix", "[AegisGate] content sanitized: "))
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

    @staticmethod
    def _compile_patterns(items: list[dict]) -> list[re.Pattern[str]]:
        compiled: list[re.Pattern[str]] = []
        for item in items:
            if isinstance(item, dict):
                regex = item.get("regex")
            else:
                regex = item
            if not regex:
                continue
            compiled.append(re.compile(regex, re.IGNORECASE))
        return compiled

    @staticmethod
    def _compile_id_patterns(items: list[dict]) -> list[tuple[str, re.Pattern[str]]]:
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            regex = item.get("regex")
            if not regex:
                continue
            pattern_id = str(item.get("id", "force_block_command"))
            compiled.append((pattern_id, re.compile(regex, re.IGNORECASE)))
        return compiled

    @staticmethod
    def _matches_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
        return any(pattern.search(text) for pattern in patterns)

    @staticmethod
    def _matched_pattern_ids(text: str, patterns: list[tuple[str, re.Pattern[str]]]) -> list[str]:
        hits: list[str] = []
        for pattern_id, pattern in patterns:
            if pattern.search(text):
                hits.append(pattern_id)
        return sorted(set(hits))

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "action": "none"}
        text = resp.output_text
        force_block_hits = (
            self._matched_pattern_ids(text, self._force_block_command_patterns)
            if settings.strict_command_block_enabled
            else []
        )
        if force_block_hits:
            debug_log_original("output_sanitizer_blocked", text, reason="response_forbidden_command")
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("response_forbidden_command")
            ctx.security_tags.add("response_forbidden_command")
            ctx.risk_score = max(ctx.risk_score, 1.0)
            resp.output_text = self._block_message
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "risk_threshold": ctx.risk_threshold,
                "signals": force_block_hits,
                "evidence": {"forbidden_command": force_block_hits},
                "action": "block",
            }
            logger.info(
                "response blocked request_id=%s reason=forbidden_command hits=%s",
                ctx.request_id,
                force_block_hits,
            )
            return resp

        if "response_injection_unicode_bidi" in ctx.security_tags:
            debug_log_original("output_sanitizer_blocked", text, reason="response_unicode_bidi")
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("response_unicode_bidi")
            ctx.requires_human_review = True
            ctx.risk_score = max(ctx.risk_score, 0.97)
            resp.output_text = self._block_message
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "risk_threshold": ctx.risk_threshold,
                "action": "block",
            }
            logger.info("response blocked request_id=%s reason=unicode_bidi", ctx.request_id)
            return resp

        discussion_context = self._matches_any(text, self._discussion_patterns)
        has_system_leak = self._matches_any(text, self._system_leak_patterns)
        has_unsafe_markup = self._matches_any(text, self._unsafe_markup_patterns)
        has_unsafe_uri = self._matches_any(text, self._unsafe_uri_patterns)
        has_command_payload = self._matches_any(text, self._command_patterns)
        has_encoded_payload = self._matches_any(text, self._encoded_payload_patterns)

        if has_system_leak:
            ctx.risk_score = max(ctx.risk_score, 0.9)
            ctx.security_tags.add("system_prompt_leak_signal")
            self._apply_action(ctx, "system_leak")
            if not discussion_context:
                debug_log_original("output_sanitizer_blocked", text, reason="response_system_prompt_leak")
                ctx.response_disposition = "block"
                ctx.disposition_reasons.append("response_system_prompt_leak")
                ctx.requires_human_review = True
                resp.output_text = self._block_message
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "risk_threshold": ctx.risk_threshold,
                    "action": "block",
                }
                logger.info("response blocked request_id=%s reason=system_prompt_leak", ctx.request_id)
                return resp

        # Block only on high-confidence risk and non-discussion context.
        if ctx.risk_score >= max(ctx.risk_threshold, self._block_threshold) and not discussion_context:
            debug_log_original("output_sanitizer_blocked", text, reason="response_high_risk")
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("response_high_risk")
            ctx.requires_human_review = True
            resp.output_text = self._block_message
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "risk_threshold": ctx.risk_threshold,
                "action": "block",
            }
            logger.info(
                "response blocked request_id=%s risk=%.2f threshold=%.2f discussion=%s",
                ctx.request_id,
                ctx.risk_score,
                ctx.risk_threshold,
                discussion_context,
            )
            return resp

        should_sanitize = (
            has_unsafe_markup
            or has_unsafe_uri
            or has_command_payload
            or has_encoded_payload
            or (ctx.risk_score >= self._sanitize_threshold)
        )
        if should_sanitize:
            cleaned = resp.output_text
            for pattern in self._command_patterns:
                cleaned = pattern.sub(self._command_replacement, cleaned)
            for pattern in self._encoded_payload_patterns:
                cleaned = pattern.sub(self._payload_replacement, cleaned)
            for pattern in self._unsafe_uri_patterns:
                cleaned = pattern.sub(self._uri_replacement, cleaned)
            for pattern in self._unsafe_markup_patterns:
                cleaned = pattern.sub(self._markup_replacement, cleaned)

            if cleaned != resp.output_text:
                debug_log_original("output_sanitizer_sanitized", resp.output_text, reason="response_sanitized")
                resp.output_text = f"{self._sanitize_prefix}{cleaned}"
                ctx.response_disposition = "sanitize"
                ctx.disposition_reasons.append("response_sanitized")
                ctx.security_tags.add("tool_calls_disabled_by_policy")
                ctx.enforcement_actions.append(f"{self.name}:tool_calls:disable")
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "risk_threshold": ctx.risk_threshold,
                    "action": "sanitize",
                }
                logger.info("response sanitized request_id=%s", ctx.request_id)

        return resp

    def report(self) -> dict:
        return self._report
