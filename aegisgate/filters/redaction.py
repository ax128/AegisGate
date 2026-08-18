"""Request-side redaction using externalized rules.

Placeholder substitution only; requests are never blocked. Relaxing security_level does not affect
it, and the rules stay as written.
"""

from __future__ import annotations

import re
import time
import unicodedata
from typing import Any

from aegisgate.config.security_rules import (
    is_low_false_positive_route,
    load_security_rules,
    select_relaxed_pii_patterns,
)
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest
from aegisgate.filters.base import BaseFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger
from aegisgate.util.masking import mask_for_log
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys, protected_spans_for_text, range_overlaps_protected


_MAX_LOG_MARKERS = 10
_DEFAULT_INVISIBLE_CHARS = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}
_DEFAULT_BIDI_CHARS = {"\u202a", "\u202b", "\u202d", "\u202e", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069"}


class RedactionFilter(BaseFilter):
    name = "redaction"

    def __init__(self, store: KVStore) -> None:
        self.store = store
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "replacements": 0}

        redaction_rules = load_security_rules().get("redaction", {})
        self._prefix_max_len = int(redaction_rules.get("request_prefix_max_len", 12))
        self._normalize_nfkc = bool(redaction_rules.get("normalize_nfkc", True))
        self._strip_invisible_chars = bool(redaction_rules.get("strip_invisible_chars", True))
        self._invisible_chars = set(redaction_rules.get("unicode_invisible_chars", [])) or set(_DEFAULT_INVISIBLE_CHARS)
        self._bidi_chars = set(redaction_rules.get("unicode_bidi_chars", [])) or set(_DEFAULT_BIDI_CHARS)
        self._field_value_min_len = max(8, int(redaction_rules.get("field_value_min_len", 12)))

        compiled_patterns: list[tuple[str, re.Pattern[str]]] = []
        for item in redaction_rules.get("pii_patterns", []):
            pattern_id = str(item.get("id", "PII")).upper()
            regex = item.get("regex")
            if not regex:
                continue
            try:
                compiled_patterns.append((pattern_id, re.compile(regex)))
            except re.error as e:
                logger.warning(
                    "redaction pii_pattern skipped (invalid regex) id=%s error=%s regex_excerpt=%s",
                    pattern_id,
                    e,
                    (regex[:80] + "…") if len(regex) > 80 else regex,
                )
        self._pii_patterns = compiled_patterns
        self._responses_relaxed_pii_patterns = select_relaxed_pii_patterns(
            compiled_patterns,
            redaction_rules=redaction_rules,
        )

        self._strip_table = str.maketrans("", "", "".join(self._invisible_chars | self._bidi_chars))

        self._field_patterns = self._build_field_patterns(redaction_rules.get("field_value_patterns", []))

    def _build_field_patterns(self, items: list[dict] | list[str]) -> list[tuple[str, re.Pattern[str]]]:
        compiled: list[tuple[str, re.Pattern[str]]] = []
        if items:
            for item in items:
                if isinstance(item, dict):
                    pattern_id = str(item.get("id", "FIELD_SECRET")).upper()
                    regex = item.get("regex")
                else:
                    pattern_id = "FIELD_SECRET"
                    regex = item
                if not regex:
                    continue
                try:
                    compiled.append((pattern_id, re.compile(str(regex), re.IGNORECASE)))
                except re.error as e:
                    logger.warning(
                        "redaction field_pattern skipped (invalid regex) id=%s error=%s regex_excerpt=%s",
                        pattern_id,
                        e,
                        (str(regex)[:80] + "…") if len(str(regex)) > 80 else regex,
                    )
            return compiled

        min_len = self._field_value_min_len
        defaults: list[tuple[str, str]] = [
            (
                "FIELD_SECRET",
                rf"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key|secret(?:_key)?)\b\s*[:=]\s*(?:bearer\s+)?[A-Za-z0-9._~+/=-]{{{min_len},}}",
            ),
            (
                "AUTH_BEARER",
                rf"(?i)\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{{{min_len},}}",
            ),
        ]
        for pattern_id, regex in defaults:
            compiled.append((pattern_id, re.compile(regex, re.IGNORECASE)))
        return compiled

    def _normalize_input(self, text: str) -> str:
        normalized = text
        if self._normalize_nfkc:
            normalized = unicodedata.normalize("NFKC", normalized)
        if self._strip_invisible_chars and normalized:
            normalized = normalized.translate(self._strip_table)
        return normalized

    def _request_prefix(self, request_id: str) -> str:
        token = re.sub(r"[^A-Za-z0-9]", "", request_id)
        return (token[: self._prefix_max_len] or "REQ").upper()

    @staticmethod
    def _is_low_false_positive_v1_route(route: str) -> bool:
        return is_low_false_positive_route(route)

    def _persist_mapping(self, ctx: RequestContext, mapping: dict[str, str]) -> None:
        """Store the restoration mapping, honouring storage_failure_action.

        The request text is already redacted by the time this runs, so a storage
        outage only costs response-side restoration — never the redaction itself.
        With the default ``block`` the exception propagates and the pipeline
        rejects the request; with ``forward`` the request goes on redacted but
        non-restorable, and the degradation is tagged for audit.
        """
        try:
            self.store.set_mapping(ctx.session_id, ctx.request_id, mapping)
        except Exception:
            if settings.storage_failure_action != "forward":
                raise
            ctx.security_tags.add("redaction_mapping_persist_failed")
            ctx.enforcement_actions.append(f"{self.name}:mapping_persist_failed:degraded")
            logger.exception(
                "redaction mapping persist failed request_id=%s session_id=%s — forwarding redacted "
                "request without restoration mapping (storage_failure_action=forward)",
                ctx.request_id,
                ctx.session_id,
            )

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "replacements": 0}
        original_text = " ".join(m.content for m in req.messages).strip()

        mapping: dict[str, str] = {}
        value_to_placeholder: dict[str, str] = {}
        log_markers: list[dict[str, Any]] = []
        serial = 0
        request_prefix = self._request_prefix(ctx.request_id)
        active_pii_patterns = (
            self._responses_relaxed_pii_patterns
            if self._is_low_false_positive_v1_route(ctx.route)
            else self._pii_patterns
        )

        # Mutable container so the inner closure can reference the current message role.
        _current_role: list[str] = ["unknown"]

        def replace_in_text(text: str) -> str:
            nonlocal serial
            protected_spans = protected_spans_for_text(text, ctx.redaction_whitelist_keys)

            def _replace_match(match: re.Match[str], kind: str) -> str:
                nonlocal serial
                raw_value = match.group(0)
                if protected_spans and range_overlaps_protected(
                    protected_spans,
                    start=match.start(),
                    end=match.end(),
                ):
                    return raw_value
                existing = value_to_placeholder.get(raw_value)
                if existing:
                    return existing

                serial += 1
                placeholder = f"{{{{AG_{request_prefix}_{kind}_{serial}}}}}"
                mapping[placeholder] = raw_value
                value_to_placeholder[raw_value] = placeholder
                if len(log_markers) < _MAX_LOG_MARKERS:
                    log_markers.append(
                        {
                            "kind": kind,
                            "msg_role": _current_role[0],
                            "masked_value": mask_for_log(raw_value),
                            "value_length": len(raw_value),
                            "marker": placeholder,
                        }
                    )
                return placeholder

            def _apply_pattern(pattern: re.Pattern[str], kind: str, source_text: str) -> str:
                return pattern.sub(lambda match: _replace_match(match, kind), source_text)

            for kind, pattern in active_pii_patterns:
                text = _apply_pattern(pattern, kind, text)
            for kind, pattern in self._field_patterns:
                text = _apply_pattern(pattern, kind, text)
            return text

        ctx.redaction_whitelist_keys = set(normalize_whitelist_keys(ctx.redaction_whitelist_keys))
        for msg in req.messages:
            _current_role[0] = str(msg.role or "unknown")
            normalized = self._normalize_input(msg.content)
            msg.content = replace_in_text(normalized)

        if mapping:
            debug_log_original("redaction_applied", original_text, reason=f"replacements={len(mapping)}", max_len=180)
            # Keep request-scoped mapping in context to avoid extra DB read on the hot path.
            ctx.redaction_mapping = dict(mapping)
            ctx.redaction_created_at = time.time()
            self._persist_mapping(ctx, mapping)
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": 0.2,
                "replacements": len(mapping),
            }
            ctx.security_tags.add("redaction_applied")
            # WARNING level: a request carrying sensitive fields is a security audit event and
            # must stay visible
            logger.warning(
                "redaction request_id=%s session_id=%s route=%s replacements=%d markers=%s truncated=%s",
                ctx.request_id,
                ctx.session_id,
                ctx.route,
                len(mapping),
                log_markers,
                len(mapping) > _MAX_LOG_MARKERS,
            )

        return req

    def report(self) -> dict:
        return self._report
