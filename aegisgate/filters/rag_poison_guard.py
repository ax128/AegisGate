"""RAG poisoning guard for ingestion + retrieval + response propagation."""

from __future__ import annotations

import re
from typing import Any

from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger


class RagPoisonGuard(BaseFilter):
    name = "rag_poison_guard"

    _TEXT_KEYS = ("text", "content", "body", "chunk", "snippet", "input", "value")
    _ID_KEYS = ("id", "doc_id", "document_id", "chunk_id", "source_id")
    _INGESTION_KEYS = ("documents", "document", "chunks", "records", "entries", "knowledge", "knowledge_base", "corpus")
    _RETRIEVAL_KEYS = ("retrieval", "context", "references", "grounding", "citations", "evidence")
    _RETRIEVAL_SOURCES = {"retrieval", "document", "web", "external", "tool", "plugin", "partner_feed"}

    def __init__(self) -> None:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "ingestion_hits": 0,
            "retrieval_hits": 0,
            "propagation_hits": 0,
        }

        rules = load_security_rules()
        guard_rules = rules.get(self.name, {})
        action_map = rules.get("action_map", {}).get(self.name, {})

        self._ingestion_patterns = self._compile_patterns(guard_rules.get("ingestion_poison_patterns", []))
        self._retrieval_patterns = self._compile_patterns(guard_rules.get("retrieval_poison_patterns", []))
        self._propagation_patterns = self._compile_patterns(guard_rules.get("propagation_patterns", []))

        self._ingestion_risk = float(guard_rules.get("ingestion_risk_score", 0.9))
        self._retrieval_risk = float(guard_rules.get("retrieval_risk_score", 0.86))
        self._propagation_risk = float(guard_rules.get("propagation_risk_score", 0.88))
        self._excerpt_max_chars = int(guard_rules.get("traceback_excerpt_max_chars", 180))
        self._action_map = {str(key): str(value) for key, value in action_map.items()}

    @staticmethod
    def _compile_patterns(items: list[dict] | list[str]) -> dict[str, re.Pattern[str]]:
        compiled: dict[str, re.Pattern[str]] = {}
        for idx, item in enumerate(items):
            rule_id = f"rule_{idx + 1}"
            regex: str | None = None
            if isinstance(item, dict):
                rule_id = str(item.get("id") or rule_id)
                regex = item.get("regex")
            else:
                regex = str(item)
            if not regex:
                continue
            compiled[rule_id] = re.compile(regex, re.IGNORECASE)
        return compiled

    def _match_signals(self, text: str, patterns: dict[str, re.Pattern[str]]) -> list[str]:
        if not text:
            return []
        hits: list[str] = []
        for signal, pattern in patterns.items():
            if pattern.search(text):
                hits.append(signal)
        return hits

    def _extract_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            parts = [self._extract_text(item) for item in value]
            return " ".join(part for part in parts if part).strip()
        if isinstance(value, dict):
            for key in self._TEXT_KEYS:
                if key in value:
                    text = self._extract_text(value.get(key))
                    if text:
                        return text
            parts = [self._extract_text(v) for v in value.values()]
            return " ".join(part for part in parts if part).strip()
        return ""

    def _extract_id(self, value: Any, fallback: str) -> str:
        if isinstance(value, dict):
            for key in self._ID_KEYS:
                val = str(value.get(key) or "").strip()
                if val:
                    return val
        return fallback

    def _iter_payload_nodes(self, payload: dict[str, Any], keys: tuple[str, ...]) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        for key in keys:
            node = payload.get(key)
            if node is None:
                continue
            if isinstance(node, list):
                for idx, item in enumerate(node):
                    text = self._extract_text(item)
                    if not text:
                        continue
                    row_id = self._extract_id(item, f"{key}[{idx}]")
                    rows.append((row_id, text))
            else:
                text = self._extract_text(node)
                if not text:
                    continue
                row_id = self._extract_id(node, key)
                rows.append((row_id, text))
        return rows

    def _action_for(self, key: str) -> str:
        return str(self._action_map.get(key, "review")).strip().lower() or "review"

    def _apply_action(self, ctx: RequestContext, *, action_key: str, phase: str) -> None:
        action = self._action_for(action_key)
        ctx.enforcement_actions.append(f"{self.name}:{action_key}:{action}")
        if action == "block":
            if phase == "request":
                ctx.request_disposition = "block"
            else:
                ctx.response_disposition = "block"
            ctx.requires_human_review = True
            ctx.risk_score = max(ctx.risk_score, 0.95)
            return
        if action == "sanitize":
            if phase == "request":
                ctx.request_disposition = "sanitize"
            else:
                ctx.response_disposition = "sanitize"
            ctx.requires_human_review = True
            return
        if action == "review":
            ctx.requires_human_review = True

    def _add_trace(self, ctx: RequestContext, *, phase: str, source: str, item_id: str, signals: list[str], excerpt: str) -> None:
        ctx.add_poison_trace(
            {
                "phase": phase,
                "source": source,
                "item_id": item_id,
                "signals": sorted(set(signals)),
                "excerpt": excerpt[: self._excerpt_max_chars],
            }
        )

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "ingestion_hits": 0,
            "retrieval_hits": 0,
            "propagation_hits": 0,
        }

        raw_payload = req.metadata.get("raw", {}) if isinstance(req.metadata, dict) else {}
        if not isinstance(raw_payload, dict):
            raw_payload = {}

        ingestion_hits = 0
        retrieval_hits = 0

        for item_id, text in self._iter_payload_nodes(raw_payload, self._INGESTION_KEYS):
            signals = self._match_signals(text, self._ingestion_patterns)
            if not signals:
                continue
            ingestion_hits += 1
            ctx.security_tags.add("rag_poison_ingestion")
            ctx.disposition_reasons.append("rag_poison_ingestion")
            ctx.risk_score = max(ctx.risk_score, self._ingestion_risk)
            self._add_trace(
                ctx,
                phase="ingestion",
                source="payload",
                item_id=item_id,
                signals=signals,
                excerpt=text,
            )

        for msg_idx, msg in enumerate(req.messages):
            source = str(msg.source or "").strip().lower()
            if source not in self._RETRIEVAL_SOURCES and not bool(msg.metadata.get("retrieval")):
                continue
            signals = self._match_signals(msg.content, self._retrieval_patterns)
            if not signals:
                continue
            retrieval_hits += 1
            ctx.security_tags.add("rag_poison_retrieval")
            ctx.security_tags.add("indirect_injection_suspected")
            ctx.disposition_reasons.append("rag_poison_retrieval")
            ctx.risk_score = max(ctx.risk_score, self._retrieval_risk)
            item_id = str(msg.metadata.get("doc_id") or msg.metadata.get("source_id") or f"message[{msg_idx}]")
            self._add_trace(
                ctx,
                phase="retrieval",
                source=source or "message",
                item_id=item_id,
                signals=signals,
                excerpt=msg.content,
            )

        for item_id, text in self._iter_payload_nodes(raw_payload, self._RETRIEVAL_KEYS):
            signals = self._match_signals(text, self._retrieval_patterns)
            if not signals:
                continue
            retrieval_hits += 1
            ctx.security_tags.add("rag_poison_retrieval")
            ctx.security_tags.add("indirect_injection_suspected")
            ctx.disposition_reasons.append("rag_poison_retrieval")
            ctx.risk_score = max(ctx.risk_score, self._retrieval_risk)
            self._add_trace(
                ctx,
                phase="retrieval",
                source="payload_context",
                item_id=item_id,
                signals=signals,
                excerpt=text,
            )

        if ingestion_hits > 0:
            self._apply_action(ctx, action_key="ingestion_poison", phase="request")
        if retrieval_hits > 0:
            self._apply_action(ctx, action_key="retrieval_poison", phase="request")

        if ingestion_hits or retrieval_hits:
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "ingestion_hits": ingestion_hits,
                "retrieval_hits": retrieval_hits,
                "propagation_hits": 0,
            }
            logger.info(
                "rag poison guard request hit request_id=%s ingestion_hits=%s retrieval_hits=%s",
                ctx.request_id,
                ingestion_hits,
                retrieval_hits,
            )

        return req

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        propagation_signals = self._match_signals(resp.output_text, self._propagation_patterns)
        if not propagation_signals:
            return resp
        if not ctx.poison_traceback:
            return resp

        ctx.security_tags.add("response_rag_poison_propagation")
        ctx.disposition_reasons.append("response_rag_poison_propagation")
        ctx.risk_score = max(ctx.risk_score, self._propagation_risk)
        self._apply_action(ctx, action_key="poison_propagation", phase="response")
        self._add_trace(
            ctx,
            phase="response",
            source="model_output",
            item_id=resp.request_id,
            signals=propagation_signals,
            excerpt=resp.output_text,
        )
        self._report = {
            "filter": self.name,
            "hit": True,
            "risk_score": ctx.risk_score,
            "ingestion_hits": 0,
            "retrieval_hits": 0,
            "propagation_hits": 1,
        }
        logger.info(
            "rag poison guard response propagation request_id=%s signals=%s",
            ctx.request_id,
            sorted(propagation_signals),
        )
        return resp

    def report(self) -> dict:
        return self._report
