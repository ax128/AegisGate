"""Lightweight leak guard executed after restoration."""

from __future__ import annotations

import re

from aegisgate.config.settings import settings
from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.dangerous_response_log import mark_text_with_spans, write_dangerous_response_sample
from aegisgate.core.models import InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger


class PostRestoreGuard(BaseFilter):
    """Runs after restoration to mask restored secrets under exfiltration lure context."""

    name = "post_restore_guard"

    def __init__(self) -> None:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "action": "allow"}
        rules = load_security_rules()
        guard_rules = rules.get(self.name, {})
        action_map = rules.get("action_map", {}).get(self.name, {})

        self._lure_patterns = self._compile_patterns(guard_rules.get("lure_patterns", []))
        self._secret_patterns = self._compile_patterns(guard_rules.get("secret_patterns", []))
        self._replacement = str(guard_rules.get("replacement", "[REDACTED:restored-secret]"))
        self._block_message = str(guard_rules.get("block_message", "[AegisGate] response blocked by security policy."))
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
    def _matches_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
        return any(pattern.search(text) for pattern in patterns)

    def _apply_action(self, ctx: RequestContext, key: str, fallback: str) -> str:
        action = self._action_map.get(key, fallback)
        ctx.enforcement_actions.append(f"{self.name}:{key}:{action}")
        return action

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "action": "allow"}
        if "restoration_applied" not in ctx.security_tags:
            return resp

        text = resp.output_text
        has_lure = self._matches_any(text, self._lure_patterns)
        has_secret = self._matches_any(text, self._secret_patterns)
        if not (has_lure and has_secret):
            return resp

        action = self._apply_action(ctx, "restored_secret_lure", "sanitize")
        if action == "block":
            debug_log_original("post_restore_guard_blocked", text, reason="response_post_restore_blocked")
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("response_post_restore_blocked")
            ctx.requires_human_review = True
            ctx.risk_score = max(ctx.risk_score, 0.95)
            self._report = {"filter": self.name, "hit": True, "risk_score": ctx.risk_score, "action": "block"}
            logger.info("post restore guard blocked request_id=%s", ctx.request_id)
            return resp

        masked = text
        secret_spans: list[tuple[int, int]] = []
        for pattern in self._secret_patterns:
            for match in pattern.finditer(text):
                if match.start() != match.end():
                    secret_spans.append((match.start(), match.end()))
            masked = pattern.sub(self._replacement, masked)

        if masked != text:
            if settings.enable_dangerous_response_log and "dangerous_response_log:post_restore_guard" not in ctx.security_tags:
                marked_text = mark_text_with_spans(text, secret_spans)
                fragments: list[str] = []
                for start, end in secret_spans:
                    fragment = text[start:end]
                    if fragment and fragment not in fragments:
                        fragments.append(fragment)
                if fragments:
                    write_dangerous_response_sample(
                        {
                            "request_id": ctx.request_id,
                            "session_id": ctx.session_id,
                            "route": ctx.route,
                            "model": resp.model,
                            "source": self.name,
                            "response_disposition": "sanitize",
                            "reasons": list(dict.fromkeys(ctx.disposition_reasons + ["response_post_restore_masked"])),
                            "fragment_count": len(fragments),
                            "dangerous_fragments": fragments,
                            "content": marked_text,
                        }
                    )
                    ctx.security_tags.add("dangerous_response_log:post_restore_guard")
            debug_log_original("post_restore_guard_sanitized", text, reason="response_post_restore_masked")
            resp.output_text = masked
            ctx.response_disposition = "sanitize"
            ctx.disposition_reasons.append("response_post_restore_masked")
            ctx.security_tags.add("post_restore_secret_masked")
            ctx.risk_score = max(ctx.risk_score, 0.88)
            self._report = {"filter": self.name, "hit": True, "risk_score": ctx.risk_score, "action": "sanitize"}
            logger.info("post restore guard masked restored secrets request_id=%s", ctx.request_id)

        return resp

    def report(self) -> dict:
        return self._report
