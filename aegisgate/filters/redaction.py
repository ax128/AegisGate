"""Request-side redaction using externalized rules.

仅做占位替换，不拦截请求；不受 security_level 放宽影响，规则保持原样。
"""

from __future__ import annotations

import re
import time
import unicodedata
from typing import Any

from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest
from aegisgate.filters.base import BaseFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger


_MAX_LOG_MARKERS = 10
_DEFAULT_INVISIBLE_CHARS = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}
_DEFAULT_BIDI_CHARS = {"\u202a", "\u202b", "\u202d", "\u202e", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069"}


def _normalize_for_log(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _mask_for_log(value: str) -> str:
    normalized = _normalize_for_log(value)
    length = len(normalized)
    if length <= 0:
        return ""
    if length == 1:
        return "*"
    if length <= 4:
        return f"{normalized[:1]}{'*' * (length - 2)}{normalized[-1:]}"

    head = 3 if length >= 10 else 2
    tail = 2
    if head + tail >= length:
        head, tail = 1, 1
    return f"{normalized[:head]}{'*' * (length - head - tail)}{normalized[-tail:]}"


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
            normalized = "".join(ch for ch in normalized if ch not in self._invisible_chars and ch not in self._bidi_chars)
        return normalized

    def _request_prefix(self, request_id: str) -> str:
        token = re.sub(r"[^A-Za-z0-9]", "", request_id)
        return (token[: self._prefix_max_len] or "REQ").upper()

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "replacements": 0}
        original_text = " ".join(m.content for m in req.messages).strip()

        mapping: dict[str, str] = {}
        value_to_placeholder: dict[str, str] = {}
        log_markers: list[dict[str, Any]] = []
        serial = 0
        request_prefix = self._request_prefix(ctx.request_id)

        def replace_in_text(text: str) -> str:
            nonlocal serial

            def _replace_match(match: re.Match[str], kind: str) -> str:
                nonlocal serial
                raw_value = match.group(0)
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
                            "redaction_applied": True,
                            "marker": placeholder,
                            "kind": kind,
                            "masked_value": _mask_for_log(raw_value),
                            "value_length": len(raw_value),
                        }
                    )
                return placeholder

            for kind, pattern in self._pii_patterns:
                text = pattern.sub(lambda m, k=kind: _replace_match(m, k), text)
            for kind, pattern in self._field_patterns:
                text = pattern.sub(lambda m, k=kind: _replace_match(m, k), text)
            return text

        for msg in req.messages:
            normalized = self._normalize_input(msg.content)
            msg.content = replace_in_text(normalized)

        if mapping:
            debug_log_original("redaction_applied", original_text, reason=f"replacements={len(mapping)}", max_len=180)
            # Keep request-scoped mapping in context to avoid extra DB read on the hot path.
            ctx.redaction_mapping = dict(mapping)
            ctx.redaction_created_at = time.time()
            self.store.set_mapping(ctx.session_id, ctx.request_id, mapping)
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": 0.2,
                "replacements": len(mapping),
            }
            ctx.security_tags.add("redaction_applied")
            logger.info(
                "redaction replacements=%d request_id=%s redaction_markers=%s truncated=%s",
                len(mapping),
                ctx.request_id,
                log_markers,
                len(mapping) > _MAX_LOG_MARKERS,
            )

        return req

    def report(self) -> dict:
        return self._report
