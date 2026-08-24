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
    # Set once the response pipeline has taken its one-shot consume of the
    # stored redaction mapping. The streaming path runs the response pipeline
    # once per probe, and the consume is read-and-delete, so any repeat can
    # only ever return an empty mapping.
    restoration_store_consumed: bool = False
    security_tags: set[str] = field(default_factory=set)
    enforcement_actions: list[str] = field(default_factory=list)
    request_disposition: str = "allow"
    response_disposition: str = "allow"
    disposition_reasons: list[str] = field(default_factory=list)
    untrusted_input_detected: bool = False
    requires_human_review: bool = False
    redaction_whitelist_keys: set[str] = field(default_factory=set)
    report_items: list[dict] = field(default_factory=list)
    poison_traceback: list[dict] = field(default_factory=list)
    # Exfiltration-chain observations: rule id + span offset/length, never a
    # fragment — the audit sink these reach does not redact (see exfil_evidence).
    exfil_evidence: list[dict] = field(default_factory=list)
    exfil_hit_count: int = 0

    def add_report(self, item: dict) -> None:
        self.report_items.append(item)

    def add_poison_trace(self, item: dict) -> None:
        self.poison_traceback.append(item)
