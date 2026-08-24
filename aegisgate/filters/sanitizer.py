"""Output sanitizer with externalized rules."""

from __future__ import annotations

import re

from aegisgate.config.security_level import apply_threshold, normalize_security_level
from aegisgate.config.security_rules import load_security_rules
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext
from aegisgate.core.dangerous_response_log import mark_text_with_spans, write_dangerous_response_sample
from aegisgate.core.exfil_evidence import record_hit as record_exfil_hit
from aegisgate.core.models import InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger
from aegisgate.util.text_normalize import (
    any_pattern_hits,
    apply_rewrite_conservatively,
    build_haystacks,
    pattern_hits_in,
)


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
        # Same patterns, ids kept. The list above is consumed by the rewrite helpers,
        # which take bare patterns; evidence needs to name the rule that fired.
        self._command_patterns_by_id = self._compile_id_patterns(
            sanitizer_rules.get("command_patterns", [])
        )
        self._force_block_command_patterns = self._compile_id_patterns(
            sanitizer_rules.get("force_block_command_patterns", [])
        )
        self._encoded_payload_patterns = self._compile_patterns(sanitizer_rules.get("encoded_payload_patterns", []))
        self._system_leak_patterns = self._compile_patterns(sanitizer_rules.get("system_leak_patterns", []))
        self._unsafe_markup_patterns = self._compile_patterns(sanitizer_rules.get("unsafe_markup_patterns", []))
        # Same list with ids kept. An egress rule can live here rather than in
        # command_patterns (a markdown image with a key in its query is removed,
        # not scored), and without this the audit record would carry the chain
        # dimension while systematically missing the egress one.
        self._unsafe_markup_patterns_by_id = self._compile_id_patterns(
            sanitizer_rules.get("unsafe_markup_patterns", [])
        )
        self._unsafe_uri_patterns = self._compile_patterns(sanitizer_rules.get("unsafe_uri_patterns", []))
        # Spam noise patterns: reuse from injection_detector rules or sanitizer's own.
        inj_rules = rules.get("injection_detector", {})
        self._spam_noise_patterns = self._compile_patterns(inj_rules.get("spam_noise_patterns", []))
        redactions = sanitizer_rules.get("redactions", {})
        self._command_replacement = str(redactions.get("command", "[REDACTED:command]"))
        self._payload_replacement = str(redactions.get("payload", "[REDACTED:encoded-payload]"))
        self._uri_replacement = str(redactions.get("uri", "[unsafe-uri-removed]"))
        self._markup_replacement = str(redactions.get("markup", "[unsafe-tag-removed]"))
        self._spam_replacement = str(redactions.get("spam", "[AegisGate:spam-content-removed]"))
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
        return any_pattern_hits(patterns, build_haystacks(text))

    @staticmethod
    def _matched_pattern_ids(text: str, patterns: list[tuple[str, re.Pattern[str]]]) -> list[str]:
        hits: list[str] = []
        haystacks = build_haystacks(text)
        for pattern_id, pattern in patterns:
            if pattern_hits_in(pattern, haystacks):
                hits.append(pattern_id)
        return sorted(set(hits))

    @staticmethod
    def _collect_replacement_spans(text: str, patterns: list[re.Pattern[str]]) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        for pattern in patterns:
            for match in pattern.finditer(text):
                if match.start() != match.end():
                    spans.append((match.start(), match.end()))
        return spans

    def _record_exfil_spans(
        self,
        scan_text: str,
        ctx: RequestContext,
        *,
        text_len: int,
        patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    ) -> None:
        """Name the exfiltration rules that fired, with spans but no fragments.

        Only walked once the cheaper ``_matches_any`` already said something hit,
        so an ordinary no-hit response pays nothing for it.

        Two things this has to get right or the span is a lie. It searches the
        same haystacks ``_matches_any`` judged on — searching only the raw text
        would record nothing for a hit that exists solely in a normalised form,
        which is precisely the obfuscated traffic worth recording. And
        ``scan_text`` is ``output_text`` and ``tool_call_content`` joined by a
        space, while the sample log stores them separately, so an offset past
        the body is rebased onto the tool-call payload and named as such.
        """
        haystacks = build_haystacks(scan_text)
        for rule_id, pattern in patterns or self._command_patterns_by_id:
            match = None
            form = "raw"
            for index, haystack in enumerate(haystacks):
                match = pattern.search(haystack)
                if match is not None:
                    form = "raw" if index == 0 else "normalized"
                    break
            if match is None:
                continue
            if form != "raw":
                record_exfil_hit(
                    ctx,
                    rule_id=rule_id,
                    filter_name=self.name,
                    channel="response_text",
                    offset=None,
                    length=None,
                    form=form,
                )
                continue
            start = match.start()
            if start < text_len:
                channel, offset = "response_text", start
            else:
                # +1 for the space _scan_text joins the two channels with.
                channel, offset = "tool_call_arguments", start - (text_len + 1)
            record_exfil_hit(
                ctx,
                rule_id=rule_id,
                filter_name=self.name,
                channel=channel,
                offset=offset,
                length=len(match.group(0)),
                form=form,
            )

    def _log_dangerous_sample(
        self,
        *,
        text: str,
        ctx: RequestContext,
        resp: InternalResponse,
        spans: list[tuple[int, int]],
    ) -> None:
        if not settings.enable_dangerous_response_log or not spans:
            return
        if "dangerous_response_log:output_sanitizer" in ctx.security_tags:
            return

        marked_text = mark_text_with_spans(text, spans)
        fragments: list[str] = []
        for start, end in spans:
            fragment = text[start:end]
            if fragment and fragment not in fragments:
                fragments.append(fragment)
        if not fragments:
            return

        write_dangerous_response_sample(
            {
                "request_id": ctx.request_id,
                "session_id": ctx.session_id,
                "route": ctx.route,
                "model": resp.model,
                "source": self.name,
                "response_disposition": "sanitize",
                "reasons": list(dict.fromkeys(ctx.disposition_reasons + ["response_sanitized"])),
                "fragment_count": len(fragments),
                "dangerous_fragments": fragments,
                "content": marked_text,
            }
        )
        ctx.security_tags.add("dangerous_response_log:output_sanitizer")

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "action": "none"}

        # Combine output_text with tool call arguments for scanning.
        text = resp.output_text
        tc_content = resp.tool_call_content
        scan_text = f"{text} {tc_content}" if tc_content else text
        force_block_hits = (
            self._matched_pattern_ids(scan_text, self._force_block_command_patterns)
            if settings.strict_command_block_enabled
            else []
        )
        if force_block_hits:
            debug_log_original("output_sanitizer_blocked", text, reason="response_forbidden_command")
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("response_forbidden_command")
            ctx.security_tags.add("response_forbidden_command")
            ctx.risk_score = max(ctx.risk_score, 1.0)
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
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "risk_threshold": ctx.risk_threshold,
                "action": "block",
            }
            logger.info("response blocked request_id=%s reason=unicode_bidi", ctx.request_id)
            return resp

        discussion_context = self._matches_any(scan_text, self._discussion_patterns)
        has_system_leak = self._matches_any(scan_text, self._system_leak_patterns)
        has_unsafe_markup = self._matches_any(scan_text, self._unsafe_markup_patterns)
        has_unsafe_uri = self._matches_any(scan_text, self._unsafe_uri_patterns)
        has_command_payload = self._matches_any(scan_text, self._command_patterns)
        if has_command_payload:
            self._record_exfil_spans(scan_text, ctx, text_len=len(text))
        if has_unsafe_markup:
            self._record_exfil_spans(
                scan_text,
                ctx,
                text_len=len(text),
                patterns=self._unsafe_markup_patterns_by_id,
            )
        has_encoded_payload = self._matches_any(scan_text, self._encoded_payload_patterns)
        has_spam = self._matches_any(scan_text, self._spam_noise_patterns)

        if has_system_leak:
            ctx.risk_score = max(ctx.risk_score, 0.9)
            ctx.security_tags.add("system_prompt_leak_signal")
            self._apply_action(ctx, "system_leak")
            if not discussion_context:
                debug_log_original("output_sanitizer_blocked", text, reason="response_system_prompt_leak")
                ctx.response_disposition = "block"
                ctx.disposition_reasons.append("response_system_prompt_leak")
                ctx.requires_human_review = True
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

        # Encoded payloads alone (base64/hex in legitimate AI output) should
        # NOT trigger a full sanitization sweep.  They are only replaced when
        # another high-confidence signal is already present or risk_score is
        # elevated.
        risk_triggered = ctx.risk_score >= self._sanitize_threshold
        should_sanitize = (
            has_unsafe_markup
            or has_unsafe_uri
            or has_command_payload
            or has_spam
            or risk_triggered
        )
        # encoded_payload is replaced only when risk_score is already elevated
        # (indicating a confirmed threat), not merely because another pattern
        # type (markup, URI, etc.) happened to match.
        should_replace_encoded = has_encoded_payload and risk_triggered
        if should_sanitize or should_replace_encoded:
            replacement_spans: list[tuple[int, int]] = []
            cleaned = resp.output_text

            def _apply(
                current: str,
                patterns: list[re.Pattern[str]],
                replacement: str,
                enabled: bool,
            ) -> str:
                if not enabled:
                    return current
                replacement_spans.extend(
                    self._collect_replacement_spans(resp.output_text, patterns)
                )
                rewritten = apply_rewrite_conservatively(current, patterns, replacement)
                if rewritten != current and not any(
                    pattern.search(current) for pattern in patterns
                ):
                    replacement_spans.append((0, len(resp.output_text)))
                return rewritten

            cleaned = _apply(
                cleaned,
                self._command_patterns,
                self._command_replacement,
                has_command_payload or risk_triggered,
            )
            cleaned = _apply(
                cleaned,
                self._encoded_payload_patterns,
                self._payload_replacement,
                should_replace_encoded,
            )
            cleaned = _apply(
                cleaned,
                self._unsafe_uri_patterns,
                self._uri_replacement,
                has_unsafe_uri or risk_triggered,
            )
            cleaned = _apply(
                cleaned,
                self._unsafe_markup_patterns,
                self._markup_replacement,
                has_unsafe_markup or risk_triggered,
            )
            cleaned = _apply(
                cleaned,
                self._spam_noise_patterns,
                self._spam_replacement,
                has_spam or risk_triggered,
            )

            if cleaned != resp.output_text:
                self._log_dangerous_sample(
                    text=resp.output_text,
                    ctx=ctx,
                    resp=resp,
                    spans=replacement_spans,
                )
                debug_log_original("output_sanitizer_sanitized", resp.output_text, reason="response_sanitized")
                resp.output_text = cleaned
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
            elif should_sanitize:
                # Hit lived in tool_call_content (or another non-output_text
                # channel). Keep output_text, but still mark sanitize so
                # route renderers can scrub tool_use / tool_call envelopes.
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
                    "tool_call_content_only": True,
                }
                logger.info(
                    "response sanitized request_id=%s reason=tool_call_content_only",
                    ctx.request_id,
                )

        return resp

    def report(self) -> dict:
        return self._report
