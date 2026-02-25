"""Pipeline runtime context."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import time


@dataclass(slots=True)
class RequestContext:
    request_id: str
    session_id: str
    route: str
    tenant_id: str = "default"
    enabled_filters: set[str] = field(default_factory=set)
    risk_score: float = 0.0
    risk_threshold: float = 0.7
    redaction_mapping: dict[str, str] = field(default_factory=dict)
    redaction_created_at: float = field(default_factory=time)
    security_tags: set[str] = field(default_factory=set)
    enforcement_actions: list[str] = field(default_factory=list)
    request_disposition: str = "allow"
    response_disposition: str = "allow"
    disposition_reasons: list[str] = field(default_factory=list)
    untrusted_input_detected: bool = False
    requires_human_review: bool = False
    report_items: list[dict] = field(default_factory=list)

    def add_report(self, item: dict) -> None:
        self.report_items.append(item)
