"""Request-side redaction using externalized rules.

仅做占位替换，不拦截请求；不受 security_level 放宽影响，规则保持原样。
"""

from __future__ import annotations

import re
import time
from typing import Any

from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest
from aegisgate.filters.base import BaseFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger


_MAX_LOG_MARKERS = 10


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

        compiled_patterns: list[tuple[str, re.Pattern[str]]] = []
        for item in redaction_rules.get("pii_patterns", []):
            pattern_id = str(item.get("id", "PII")).upper()
            regex = item.get("regex")
            if not regex:
                continue
            compiled_patterns.append((pattern_id, re.compile(regex)))
        self._pii_patterns = compiled_patterns

    def _request_prefix(self, request_id: str) -> str:
        token = re.sub(r"[^A-Za-z0-9]", "", request_id)
        return (token[: self._prefix_max_len] or "REQ").upper()

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "replacements": 0}
        original_text = " ".join(m.content for m in req.messages).strip()

        mapping: dict[str, str] = {}
        log_markers: list[dict[str, Any]] = []
        serial = 0
        request_prefix = self._request_prefix(ctx.request_id)

        def replace_in_text(text: str) -> str:
            nonlocal serial

            def _replace_match(match: re.Match[str], kind: str) -> str:
                nonlocal serial
                serial += 1
                placeholder = f"{{{{AG_{request_prefix}_{kind}_{serial}}}}}"
                raw_value = match.group(0)
                mapping[placeholder] = raw_value
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
            return text

        for msg in req.messages:
            msg.content = replace_in_text(msg.content)

        if mapping:
            debug_log_original("redaction_applied", original_text, reason=f"replacements={len(mapping)}")
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
