"""Exfiltration-chain evidence carried on the audit record.

Two things this exists for. The audit stream currently answers "was something
enforced" but not "which capability was observed" — a hit on the exfiltration
rules shows up as a `dangerous_param:<tool>` string with the rule identity
already discarded, so nothing downstream can tell a credential read from an
outbound transfer. And calibrating a new rule needs to know which rule fired,
which the audit record never carried.

**Evidence deliberately carries no text.** ``core/audit.py`` neither redacts nor
truncates what it is handed, and ``audit_log_path`` defaults to on — while the
evidence for these particular rules is, by construction, credential paths and
URLs with keys in them. Recording a fragment here would silently promote a
default-on log to the sensitivity of a default-off one. So an entry is
``rule_id`` plus an offset and a length: enough to find the span again in a
sample that was captured on purpose (``dangerous_response_samples.jsonl``, which
is off by default, needs ``AEGIS_DANGEROUS_RESPONSE_LOG_INCLUDE_RAW`` to hold
text at all, and is where calibration corpora belong), and useless to anyone who
only has the audit file.

An offset is only meaningful against a named channel, so ``channel`` says which
text it indexes — ``response_text`` is the response body, ``tool_call_arguments``
is the tool-call payload, and the two are separate strings even though the
filters scan them concatenated. ``form`` says whether the span survives into the
raw text at all; see :func:`record_hit`.

Dimensions come from the rule id prefix rather than a registry, so a rule added
to ``security_filters.yaml`` through the console classifies itself with no code
change — the same reasoning ``gateway_ui_routes._discover_rule_sections`` uses to
walk the YAML instead of hard-coding a list.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegisgate.core.context import RequestContext

# Longest prefix first: a future ``exfil_chain_egress_*`` must classify as the
# chain it is, not as a bare egress observation.
_DIMENSION_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("exfil_chain_", "chain"),
    ("exfil_collect_", "collection"),
    ("exfil_egress_", "egress"),
    ("exfil_persist_", "persistence"),
)

_EXFIL_PREFIX = "exfil_"

# Cap on how many spans one request records. A response can hold a hundred
# matches of the same rule; the audit line is not the place to enumerate them,
# and the count is kept separately so truncation never reads as "only two hits".
MAX_EVIDENCE_ENTRIES = 20


def is_exfil_rule(rule_id: str) -> bool:
    return str(rule_id).startswith(_EXFIL_PREFIX)


def dimension_for_rule(rule_id: str) -> str | None:
    """Which link of the chain *rule_id* observes, or ``None`` if it is not one."""
    name = str(rule_id)
    for prefix, dimension in _DIMENSION_BY_PREFIX:
        if name.startswith(prefix):
            return dimension
    return None


def record_hit(
    ctx: "RequestContext",
    *,
    rule_id: str,
    filter_name: str,
    channel: str,
    offset: int | None,
    length: int | None,
    form: str = "raw",
) -> None:
    """Record one exfiltration-rule match on *ctx*. No-op for other rules.

    Callers pass the span they already computed; nothing here re-scans, so an
    added call site costs one comparison on the non-matching path.

    *form* names the text the span indexes. Matching runs against several
    normalised variants of the same input (``build_haystacks``), and NFKC plus
    invisible-character stripping do not preserve offsets — so a hit found only
    on a normalised variant has no span in the text an operator holds. That case
    records ``form="normalized"`` with ``offset``/``length`` of ``None`` rather
    than a number that indexes nothing: "we saw this rule fire, we cannot point
    at where" is true, and a fabricated offset is not. Obfuscated payloads are
    exactly the traffic that lands here, so silently dropping the entry instead
    would blind the audit record for the attacks it exists to describe.
    """
    dimension = dimension_for_rule(rule_id)
    if dimension is None:
        return
    # Counted before the cap so ``evidence_truncated`` can say so honestly: a
    # capped list must never read as "only this many hits".
    ctx.exfil_hit_count += 1
    if len(ctx.exfil_evidence) >= MAX_EVIDENCE_ENTRIES:
        return
    ctx.exfil_evidence.append(
        {
            "rule_id": str(rule_id),
            "dimension": dimension,
            "filter": str(filter_name),
            "channel": str(channel),
            "form": str(form),
            "offset": None if offset is None else int(offset),
            "length": None if length is None else int(length),
        }
    )


def _decision(ctx: "RequestContext") -> str:
    """The disposition ladder of the response, named the way the design does.

    Reads what the context already declares rather than deciding anything —
    ``renderers`` and ``stream_utils`` are the two consumers that turn these
    fields into behaviour, and a third opinion here would be a second source of
    truth. Note the label describes the **non-streaming** realisation:
    ``strip_tool_calls`` has no streaming form (the streaming tool-call deltas
    are deliberately left unrewritten so client-side reassembly keeps working),
    so on a streamed response the same context terminates the stream instead.
    """
    if "block" in (ctx.request_disposition, ctx.response_disposition):
        return "block"
    if "sanitize" in (ctx.request_disposition, ctx.response_disposition):
        if "tool_calls_disabled_by_policy" in ctx.security_tags:
            return "strip_tool_calls"
        return "sanitize"
    return "annotate"


def summarize(ctx: "RequestContext") -> dict[str, object] | None:
    """The ``exfil`` block of an audit record, or ``None`` when nothing matched."""
    evidence = ctx.exfil_evidence
    if not evidence:
        return None
    dimensions = sorted({str(item["dimension"]) for item in evidence})
    return {
        "dimensions": dimensions,
        # A chain rule already proves both links; anything else is a single-sided
        # observation, and the design keeps those at annotate on purpose.
        "chain_complete": "chain" in dimensions,
        "decision": _decision(ctx),
        "hit_count": ctx.exfil_hit_count,
        "evidence_truncated": ctx.exfil_hit_count > len(evidence),
        "evidence": list(evidence),
    }
