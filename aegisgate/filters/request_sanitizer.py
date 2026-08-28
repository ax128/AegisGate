"""Request-side minimal checks: leak protection + high-confidence intent blocking."""

from __future__ import annotations

import re

from aegisgate.config.security_level import (
    apply_count,
    apply_threshold,
    normalize_security_level,
)
from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, is_derived_scan_message
from aegisgate.filters.base import BaseFilter
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger
from aegisgate.util.text_normalize import (
    any_pattern_hits,
    apply_rewrite_conservatively,
    build_haystacks,
    pattern_hits_in,
)


class RequestSanitizer(BaseFilter):
    name = "request_sanitizer"

    # Ceiling for the risk a strong-intent ``review`` hit raises the request to —
    # the value the leak_check branch uses, kept so ``review`` stays one thing in
    # the action_map vocabulary. The effective value is the smaller of this and
    # the response-side sanitize gate; see _strong_intent_review_risk below.
    _STRONG_INTENT_REVIEW_RISK_CEILING = 0.6
    # How far under that gate to land. At or above it, every hit becomes a
    # sanitize disposition, so this margin is the whole safety property.
    _STRONG_INTENT_GATE_MARGIN = 0.05

    def __init__(self) -> None:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "action": "allow",
        }

        rules = load_security_rules()
        sanitizer_rules = rules.get(self.name, {})
        action_map = rules.get("action_map", {}).get(self.name, {})

        # The risk a strong-intent ``review`` hit lands on — derived, not written
        # down, because the number that matters is not any of the gates this
        # branch was first checked against.
        #
        # ``review`` has to stay "record only, do not block". The response block
        # path needs max(risk_threshold, sanitizer block) and the stream
        # terminator needs max(risk_threshold, 0.9); both sit far above 0.6, which
        # is why 0.6 looked safe. The gate that actually binds is a third one:
        # OutputSanitizer sets ``risk_triggered`` at its *sanitize* threshold
        # (0.35 at medium), a true ``risk_triggered`` makes ``should_sanitize``
        # true, and a true ``should_sanitize`` sets ``response_disposition =
        # "sanitize"`` together with ``tool_calls_disabled_by_policy`` **even when
        # it rewrote nothing**. _stream_block_reason reads that disposition as a
        # terminator. So 0.6 turned "run a bash script that builds the image" —
        # which privilege_escalation_en matches — into a truncated answer with its
        # tool calls stripped, over a response containing nothing dangerous.
        #
        # leak_check keeps its 0.6 deliberately: it fires on an actual secret
        # shape in the request (sk-…, AKIA…, a JWT, a PEM header), so scrubbing
        # the answer that comes back is a defensible trade. These patterns are
        # natural-language verb tables — "print the token", "read the /etc/hosts
        # file", "bypass the CORS policy" — and the same number on that trigger
        # surface is not the same decision.
        sanitize_gate = apply_threshold(
            float(rules.get("sanitizer", {}).get("thresholds", {}).get("sanitize", 0.35)),
            level=normalize_security_level(),
        )
        self._strong_intent_review_risk = max(
            0.0,
            min(
                self._STRONG_INTENT_REVIEW_RISK_CEILING,
                sanitize_gate - self._STRONG_INTENT_GATE_MARGIN,
            ),
        )

        self._discussion_patterns = self._compile_patterns(
            sanitizer_rules.get("discussion_context_patterns", [])
        )
        self._strong_intent_patterns = self._compile_tagged_patterns(
            sanitizer_rules.get("strong_intent_patterns", []),
            default_category="attack_intent",
        )
        self._leak_check_patterns = self._compile_patterns(
            sanitizer_rules.get("leak_check_patterns", [])
        )
        self._shape_anomaly_patterns = self._compile_patterns(
            sanitizer_rules.get("shape_anomaly_patterns", [])
        )

        # Compatibility with existing rule keys.
        self._command_patterns = self._compile_patterns(
            sanitizer_rules.get("command_patterns", [])
        )
        self._encoded_payload_patterns = self._compile_patterns(
            sanitizer_rules.get("encoded_payload_patterns", [])
        )

        redactions = sanitizer_rules.get("redactions", {})
        self._command_replacement = str(redactions.get("command", "[REDACTED:command]"))
        self._payload_replacement = str(
            redactions.get("payload", "[REDACTED:encoded-payload]")
        )
        self._shape_replacement = str(
            redactions.get("shape", "[REDACTED:shape-anomaly]")
        )
        self._block_message = str(
            sanitizer_rules.get(
                "block_message", "[AegisGate] request blocked by security policy."
            )
        )
        self._invisible_chars = set(
            sanitizer_rules.get(
                "unicode_invisible_chars",
                ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"],
            )
        )
        self._bidi_chars = set(
            sanitizer_rules.get(
                "unicode_bidi_chars",
                [
                    "\u202a",
                    "\u202b",
                    "\u202d",
                    "\u202e",
                    "\u202c",
                    "\u2066",
                    "\u2067",
                    "\u2068",
                    "\u2069",
                ],
            )
        )
        level = normalize_security_level()
        self._invisible_char_threshold = apply_count(
            int(sanitizer_rules.get("invisible_char_threshold", 6)),
            level=level,
            minimum=1,
        )
        self._truncate_at = apply_count(
            int(sanitizer_rules.get("truncate_at", 4000)), level=level, minimum=512
        )

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
    def _compile_tagged_patterns(
        items: list[dict] | list[str], default_category: str
    ) -> list[tuple[str, re.Pattern[str]]]:
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
        return any_pattern_hits(patterns, build_haystacks(text))

    def _matched_categories(self, text: str) -> set[str]:
        categories: set[str] = set()
        haystacks = build_haystacks(text)
        for category, pattern in self._strong_intent_patterns:
            if pattern_hits_in(pattern, haystacks):
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

    def _block_request(
        self, req: InternalRequest, ctx: RequestContext, reason: str
    ) -> InternalRequest:
        ctx.request_disposition = "block"
        ctx.disposition_reasons.append(reason)
        ctx.requires_human_review = True
        ctx.risk_score = max(ctx.risk_score, 0.95)
        for msg in req.messages:
            msg.content = self._block_message
        return req

    @staticmethod
    def _is_system_prompt_surface(msg: object) -> bool:
        """Text the client resends verbatim every turn, rather than user input.

        Both halves are the same surface wearing two shapes. ``instructions`` on
        the Responses route reaches the pipeline as a derived scan-only message;
        Chat's ``messages[].role=system`` and the Messages route's top-level
        ``system`` reach it as ordinary forwarded messages. All three are one
        client configuration that does not vary per request, so a leak_check hit
        in any of them means the same thing and has to score the same way.

        Deriving this from ``is_derived_scan_message`` alone — as the first cut
        did — split the decision by protocol: the same system prompt scored 0.6
        through Chat and 0.0 through Responses, so one endpoint cut every stream
        and the other did not.

        ``role`` rather than ``source``: the mappers set ``source`` from a
        caller-supplied field on the chat route, and this must not be something
        a request can claim for itself.
        """
        if is_derived_scan_message(msg):
            return True
        return str(getattr(msg, "role", "")).strip().lower() == "system"

    def _sanitize_shape(self, req: InternalRequest) -> bool:
        any_sanitized = False
        for msg in req.messages:
            updated = msg.content
            updated = apply_rewrite_conservatively(
                updated, self._command_patterns, self._command_replacement
            )
            updated = apply_rewrite_conservatively(
                updated, self._encoded_payload_patterns, self._payload_replacement
            )
            updated = apply_rewrite_conservatively(
                updated, self._shape_anomaly_patterns, self._shape_replacement
            )

            if any(
                char in self._bidi_chars or char in self._invisible_chars
                for char in updated
            ):
                updated = "".join(
                    char
                    for char in updated
                    if char not in self._bidi_chars
                    and char not in self._invisible_chars
                )

            if self._truncate_at > 0 and len(updated) > self._truncate_at:
                updated = f"{updated[: self._truncate_at]} [TRUNCATED]"

            if updated != msg.content:
                msg.content = updated
                any_sanitized = True
        return any_sanitized

    def process_request(
        self, req: InternalRequest, ctx: RequestContext
    ) -> InternalRequest:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "action": "allow",
        }

        discussion_context = False
        strong_intent_categories: set[str] = set()
        has_leak = False
        has_scoring_leak = False
        shape_hits: set[str] = set()

        for msg in req.messages:
            text = msg.content
            if self._matches_any(text, self._discussion_patterns):
                discussion_context = True

            strong_intent_categories.update(self._matched_categories(text))
            if self._matches_any(text, self._leak_check_patterns):
                has_leak = True
                if not self._is_system_prompt_surface(msg):
                    has_scoring_leak = True
            shape_hits.update(self._shape_hits(text))

        if has_scoring_leak:
            action = self._apply_action(ctx, "leak_check", "review")
            if action == "block":
                self._block_request(req, ctx, reason="request_leak_check_failed")
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "action": "block",
                }
                logger.info(
                    "request blocked request_id=%s reason=leak_check", ctx.request_id
                )
                return req
            # review: elevate risk and flag, but allow the request through
            ctx.risk_score = max(ctx.risk_score, 0.6)
            ctx.security_tags.add("request_leak_check")
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "action": "review",
            }
            logger.info("request leak_check review request_id=%s", ctx.request_id)
        elif has_leak:
            # Every hit sits in a system prompt. Record it, do not move the score.
            #
            # The 0.6 above sits over OutputSanitizer's sanitize gate (~0.35),
            # which marks an otherwise clean answer response_disposition=
            # sanitize and makes _stream_block_reason cut the stream. That is a
            # deliberate trade for content the client varies per turn. It is a
            # different trade for text the client resends verbatim on every
            # request: one credential-shaped line in a coding agent's system
            # prompt would sanitize every answer and cut every stream for the
            # life of that configuration. That is the score channel D7 refused
            # to open for the request-phase anomaly detector, for this reason.
            #
            # Redaction still runs on these messages — E1 on the pipeline copy,
            # E3 on the bytes actually forwarded — so this decides how loudly a
            # *post-redaction* residue scores, not whether the credential is
            # protected. The tag keeps it visible in the audit trail.
            ctx.security_tags.add("request_leak_check_system_prompt")
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "action": "observe",
            }
            logger.info(
                "request leak_check observed in a system prompt request_id=%s",
                ctx.request_id,
            )

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
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "action": "block",
                }
                logger.info(
                    "request blocked request_id=%s reason=%s", ctx.request_id, reason
                )
                return req
            # Not a block: elevate risk, tag, and let the request through.
            #
            # Without this the branch was a no-op. ``_apply_action`` only appends a
            # string to ``enforcement_actions``, and every strong-intent category
            # ships as ``review`` — so a request matching secret_exfiltration /
            # privilege_escalation / rule_bypass produced a log line and nothing
            # else. The leak_check branch above is the same shape done right; the
            # two were asymmetric by omission, not by design.
            #
            # The tag is the durable signal and is request-scoped, so it cannot
            # trip the ``response_`` prefix check in _needs_confirmation or
            # _stream_block_reason. The risk is capped under the response-side
            # sanitize gate — see _strong_intent_review_risk for why that is the
            # gate that binds. An operator who wants these categories weighted
            # harder has ``block`` to say so with; inventing a private severity
            # ladder here would make the console's uniform block/review/sanitize
            # wording describe something the runtime does not do, which is the
            # defect this branch already had.
            ctx.risk_score = max(ctx.risk_score, self._strong_intent_review_risk)
            ctx.security_tags.add(reason)
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                # The configured action, not a hardcoded "review": an operator can
                # set these categories to something else, and a report that says
                # review either way is the same class of lie this branch was fixed
                # for.
                "action": action,
                "category": action_key,
            }
            logger.info(
                "request strong_intent %s request_id=%s reason=%s",
                action,
                ctx.request_id,
                reason,
            )

        if shape_hits:
            action = self._apply_action(ctx, "shape_anomaly", "sanitize")
            if action == "block":
                self._block_request(req, ctx, reason="request_shape_anomaly")
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "action": "block",
                }
                logger.info(
                    "request blocked request_id=%s reason=shape_anomaly", ctx.request_id
                )
                return req

            original_text = " ".join(m.content for m in req.messages).strip()
            if self._sanitize_shape(req):
                debug_log_original(
                    "request_sanitizer_sanitized",
                    original_text,
                    reason="request_shape_sanitized",
                    max_len=180,
                )
                ctx.request_disposition = "sanitize"
                ctx.disposition_reasons.append("request_shape_sanitized")
                ctx.security_tags.add("request_sanitized")
                if discussion_context:
                    ctx.security_tags.add("request_discussion_context")
                ctx.enforcement_actions.append(f"{self.name}:sanitize:applied")
                self._report = {
                    "filter": self.name,
                    "hit": True,
                    "risk_score": ctx.risk_score,
                    "action": "sanitize",
                }
                logger.info(
                    "request sanitized request_id=%s signals=%s",
                    ctx.request_id,
                    sorted(shape_hits),
                )

        return req

    def report(self) -> dict:
        return self._report
