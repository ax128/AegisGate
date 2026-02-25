"""System prompt protection filter.

This filter is intended for untrusted relay scenarios where raw system prompts
should not be exposed upstream.
"""

from __future__ import annotations

import hashlib

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger


class SystemPromptGuard(BaseFilter):
    name = "system_prompt_guard"

    def __init__(self, placeholder: str = "[SYSTEM_PROMPT_PROTECTED]") -> None:
        self.placeholder = placeholder
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "protected_count": 0,
            "fingerprints": [],
        }

    @staticmethod
    def _fingerprint(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "protected_count": 0,
            "fingerprints": [],
        }

        fingerprints: list[str] = []
        protected_count = 0

        for msg in req.messages:
            if msg.role.lower() != "system":
                continue
            if not msg.content.strip():
                continue

            fp = self._fingerprint(msg.content)
            fingerprints.append(fp)
            protected_count += 1

            # Preserve prompt identity for audit/debug without exposing raw content.
            msg.content = f"{self.placeholder}::{fp}"

        if protected_count > 0:
            ctx.security_tags.add("system_prompt_protected")
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": 0.2,
                "protected_count": protected_count,
                "fingerprints": fingerprints,
            }
            logger.info(
                "system prompt protected request_id=%s count=%d",
                ctx.request_id,
                protected_count,
            )

        return req

    def report(self) -> dict:
        return self._report
