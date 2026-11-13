"""Pipeline runtime context."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import SupportsIndex
from dataclasses import dataclass, field
from time import time


class PipelineCancelToken:
    """Cancel flag for a single request or response pipeline call."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class _CallTokenState(threading.local):
    bound: bool = False
    token: PipelineCancelToken | None = None


_call_token_state = _CallTokenState()


def bind_pipeline_call_token(token: PipelineCancelToken | None) -> None:
    """Remember this call's token on the worker that is inside it.

    ``_run_phase`` binds the token it copied at entry. In-flight ``process_*``
    writes then see that object, not a token a later call stored on ``ctx``.
    """

    _call_token_state.bound = True
    _call_token_state.token = token


def unbind_pipeline_call_token() -> None:
    _call_token_state.bound = False
    _call_token_state.token = None


def pipeline_call_cancelled(ctx: RequestContext) -> bool:
    """Whether the pipeline call visible to this thread has been cancelled.

    On the worker, the token bound at the start of the call wins. A newer
    token installed on ``ctx`` for the next call must not clear it. Outside a
    call, the token currently stored on ``ctx`` is the one that counts.
    """

    if _call_token_state.bound:
        token = _call_token_state.token
    else:
        token = ctx.pipeline_cancel_token
    return token is not None and token.cancelled


def _worker_must_keep_timeout_disposition() -> bool:
    """Drop disposition writes from a worker whose own call was cancelled.

    The timeout handler runs on the event-loop thread and is not bound, so it
    can still store ``block`` after cancelling the token.
    """

    if not _call_token_state.bound:
        return False
    token = _call_token_state.token
    return token is not None and token.cancelled


class _DispositionReasonList(list[str]):
    """``disposition_reasons`` that ignores appends from a cancelled call."""

    def append(self, item: str) -> None:
        if _worker_must_keep_timeout_disposition():
            return
        super().append(item)

    def extend(self, items: Iterable[str]) -> None:
        if _worker_must_keep_timeout_disposition():
            return
        super().extend(items)

    def insert(self, index: SupportsIndex, item: str) -> None:
        if _worker_must_keep_timeout_disposition():
            return
        super().insert(index, item)

    def __iadd__(self, items: Iterable[str]) -> _DispositionReasonList:  # type: ignore[override, misc]
        if _worker_must_keep_timeout_disposition():
            return self
        super().__iadd__(items)
        return self


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
    # Placeholder tokens RestorationFilter actually restored in this round's
    # ``output_text``, after its volume / partial / exfiltration guards passed.
    # Response renderers may only restore these in the nested protocol fields —
    # a placeholder the guards never saw must stay a placeholder. Tokens only,
    # never plaintext.
    restored_placeholders: set[str] = field(default_factory=set)
    security_tags: set[str] = field(default_factory=set)
    # Explicit per-filter switches from a host-forwarding rule. Empty means "no
    # rule is overriding anything", so every existing branch behaves exactly as
    # before. Applied at one point: ``_apply_filter_mode``.
    forward_filter_overrides: dict[str, bool] = field(default_factory=dict)
    enforcement_actions: list[str] = field(default_factory=list)
    request_disposition: str = "allow"
    response_disposition: str = "allow"
    disposition_reasons: list[str] = field(default_factory=_DispositionReasonList)
    untrusted_input_detected: bool = False
    requires_human_review: bool = False
    redaction_whitelist_keys: set[str] = field(default_factory=set)
    report_items: list[dict] = field(default_factory=list)
    poison_traceback: list[dict] = field(default_factory=list)
    # Exfiltration-chain observations: rule id + span offset/length, never a
    # fragment — the audit sink these reach does not redact (see exfil_evidence).
    exfil_evidence: list[dict] = field(default_factory=list)
    exfil_hit_count: int = 0
    # Streaming probes resubmit joined tool arguments on every later delta.
    # ``(call key, rule id)`` already recorded for this request. The matched
    # text is not part of the identity: an exfil span grows as the secret
    # streams in, and that must not count the same rule again.
    # A declared field: this dataclass is slots=True.
    counted_tool_arg_hits: set[tuple[str, str]] = field(default_factory=set)
    # Set the first time this request's disposition reaches the metrics. A
    # declared field rather than an attribute stuck on in the router, because
    # this dataclass uses slots=True and the assignment would otherwise raise —
    # which, from inside a metrics guard, means the counter silently never moves.
    disposition_counted: bool = False
    # Replaced at the start of every request/response pipeline call, before the
    # worker is submitted. Only that call's timeout handler cancels it.
    # compare/repr stay off so the event object does not leak into equality or logs.
    pipeline_cancel_token: PipelineCancelToken | None = field(
        default=None, compare=False, repr=False
    )

    def __setattr__(self, name: str, value: object) -> None:
        # An in-flight process_* keeps running after wait_for returns. Once this
        # call's token is cancelled, its disposition writes must not replace the
        # timeout handler's block. The handler itself is on another thread.
        if (
            name in {"request_disposition", "response_disposition", "disposition_reasons"}
            and _worker_must_keep_timeout_disposition()
        ):
            return
        object.__setattr__(self, name, value)

    def add_report(self, item: dict) -> None:
        self.report_items.append(item)

    def add_poison_trace(self, item: dict) -> None:
        self.poison_traceback.append(item)
