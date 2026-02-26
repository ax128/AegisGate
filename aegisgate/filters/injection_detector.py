"""Prompt injection detector aligned with OWASP guidance.

Detection rules are externalized to YAML to support bilingual customization.
"""

from __future__ import annotations

import base64
import binascii
import re
import string
import unicodedata
from urllib.parse import unquote

from aegisgate.config.security_level import apply_threshold, normalize_security_level
from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger
from aegisgate.util.risk_scoring import clamp01, weighted_nonlinear_score


_DEFAULT_INVISIBLE_CHARS = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}
_DEFAULT_BIDI_CHARS = {"\u202a", "\u202b", "\u202d", "\u202e", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069"}
_WHITESPACE_RE = re.compile(r"\s+")


def _maybe_decode_base64(token: str) -> str | None:
    try:
        raw = base64.b64decode(token, validate=True)
        decoded = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None

    if not decoded:
        return None

    printable_ratio = sum(ch in string.printable for ch in decoded) / len(decoded)
    if printable_ratio < 0.8:
        return None

    return decoded


def _maybe_decode_hex(token: str) -> str | None:
    if len(token) % 2 != 0:
        return None
    try:
        raw = binascii.unhexlify(token)
        decoded = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None
    if not decoded:
        return None
    return decoded


def _is_typoglycemia_variant(word: str, target: str) -> bool:
    if word == target or len(word) != len(target):
        return False
    if len(word) < 4:
        return False
    if word[0] != target[0] or word[-1] != target[-1]:
        return False
    return sorted(word[1:-1]) == sorted(target[1:-1])


class PromptInjectionDetector(BaseFilter):
    name = "injection_detector"

    def __init__(self) -> None:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "signals": {}, "risk_model": {}}

        rules = load_security_rules()
        detector_rules = rules.get("injection_detector", {})
        action_map = rules.get("action_map", {}).get(self.name, {})

        self._base64_candidate_re = re.compile(detector_rules.get("base64_candidate_regex", r"[A-Za-z0-9+/]{24,}={0,2}"))
        self._hex_candidate_re = re.compile(detector_rules.get("hex_candidate_regex", r"\b[0-9a-fA-F]{32,}\b"))
        self._word_re = re.compile(detector_rules.get("word_regex", r"\b[a-z]{4,}\b"))
        self._base64_max_candidates = int(detector_rules.get("base64_max_candidates", 8))
        self._hex_max_candidates = int(detector_rules.get("hex_max_candidates", 8))

        multi_decode = detector_rules.get("multi_stage_decode", {})
        self._multi_decode_enabled = bool(multi_decode.get("enabled", True))
        self._max_decode_depth = max(1, int(multi_decode.get("max_decode_depth", 2)))
        self._url_decode_enabled = bool(multi_decode.get("url_decode_enabled", True))

        self._direct_patterns = self._compile_rule_patterns(detector_rules.get("direct_patterns", []))
        self._system_exfil_patterns = self._compile_rule_patterns(detector_rules.get("system_exfil_patterns", []))
        self._html_md_patterns = self._compile_rule_patterns(detector_rules.get("html_markdown_patterns", []))
        self._remote_content_patterns = self._compile_rule_patterns(detector_rules.get("remote_content_patterns", []))
        self._indirect_injection_patterns = self._compile_rule_patterns(detector_rules.get("indirect_injection_patterns", []))
        self._remote_instruction_patterns = self._compile_rule_patterns(
            detector_rules.get("remote_content_instruction_patterns", [])
        )

        self._typoglycemia_targets = [str(item).lower() for item in detector_rules.get("typoglycemia_targets", [])]
        self._decoded_keywords = [str(item).lower() for item in detector_rules.get("decoded_keywords", [])]
        self._obfuscated_markers = [str(item).lower() for item in detector_rules.get("obfuscated_markers", [])]

        self._confusable_map = {
            str(src): str(dst)
            for src, dst in (detector_rules.get("unicode_confusable_map", {}) or {}).items()
        }
        self._invisible_chars = set(detector_rules.get("unicode_invisible_chars", [])) or set(_DEFAULT_INVISIBLE_CHARS)
        self._bidi_chars = set(detector_rules.get("unicode_bidi_chars", [])) or set(_DEFAULT_BIDI_CHARS)

        scoring_model = detector_rules.get("scoring_model", {})
        level = normalize_security_level()
        self._nonlinear_k = float(scoring_model.get("nonlinear_k", 2.2))
        self._risk_thresholds = {
            "allow": apply_threshold(float(scoring_model.get("thresholds", {}).get("allow", 0.35)), level=level),
            "review": apply_threshold(float(scoring_model.get("thresholds", {}).get("review", 0.7)), level=level),
        }
        self._risk_weights = {
            str(key): float(value)
            for key, value in (scoring_model.get("weights", {"intent": 0.45, "payload": 0.25, "hijack": 0.2, "anomaly": 0.1}).items())
        }

        self._signal_profiles: dict[str, tuple[str, float]] = {}
        for signal_key, profile in (scoring_model.get("signal_profiles", {}) or {}).items():
            bucket = str(profile.get("bucket", "intent"))
            severity = clamp01(float(profile.get("severity", 7)) / 10.0)
            self._signal_profiles[str(signal_key)] = (bucket, severity)

        mitigation = detector_rules.get("false_positive_mitigation", {})
        self._mitigation_enabled = bool(mitigation.get("enabled", True))
        self._max_risk_reduction = clamp01(float(mitigation.get("max_risk_reduction", 0.35)))
        self._non_reducible_categories = {str(item) for item in mitigation.get("non_reducible_categories", [])}
        self._discussion_patterns = self._compile_pattern_list(mitigation.get("discussion_patterns", []))
        self._quoted_instruction_patterns = self._compile_pattern_list(mitigation.get("quoted_instruction_patterns", []))

        self._action_map = {str(key): str(value) for key, value in action_map.items()}

    @staticmethod
    def _compile_rule_patterns(items: list[dict]) -> dict[str, re.Pattern[str]]:
        compiled: dict[str, re.Pattern[str]] = {}
        for item in items:
            rule_id = str(item.get("id", "rule"))
            regex = item.get("regex")
            if not regex:
                continue
            compiled[rule_id] = re.compile(regex, re.IGNORECASE)
        return compiled

    @staticmethod
    def _compile_pattern_list(items: list[str]) -> list[re.Pattern[str]]:
        compiled: list[re.Pattern[str]] = []
        for item in items:
            if not item:
                continue
            compiled.append(re.compile(str(item), re.IGNORECASE))
        return compiled

    def _normalize_text(self, text: str) -> str:
        normalized = unicodedata.normalize("NFKC", text)
        if self._confusable_map:
            normalized = "".join(self._confusable_map.get(char, char) for char in normalized)
        normalized = "".join(char for char in normalized if char not in self._invisible_chars and char not in self._bidi_chars)
        normalized = normalized.lower()
        return _WHITESPACE_RE.sub(" ", normalized).strip()

    def _decode_multistage(self, token: str) -> list[str]:
        if not self._multi_decode_enabled:
            return []

        discovered: set[str] = set()
        frontier = [token]

        for _ in range(self._max_decode_depth):
            next_frontier: list[str] = []
            for candidate in frontier:
                decoded_items: list[str] = []

                base64_decoded = _maybe_decode_base64(candidate)
                if base64_decoded:
                    decoded_items.append(base64_decoded)

                hex_decoded = _maybe_decode_hex(candidate)
                if hex_decoded:
                    decoded_items.append(hex_decoded)

                if self._url_decode_enabled:
                    url_decoded = unquote(candidate)
                    if url_decoded != candidate:
                        decoded_items.append(url_decoded)

                for item in decoded_items:
                    if item not in discovered:
                        discovered.add(item)
                        next_frontier.append(item)
            frontier = next_frontier
            if not frontier:
                break

        return list(discovered)

    def _scan_text(self, text: str) -> tuple[dict[str, list[str]], dict[str, object]]:
        text_raw = text
        text_nfkc = unicodedata.normalize("NFKC", text_raw)
        text_norm = self._normalize_text(text_nfkc)
        condensed = re.sub(r"[\s\W_]+", "", text_norm)

        signals: dict[str, set[str]] = {
            "direct": set(),
            "system_exfil": set(),
            "obfuscated": set(),
            "html_markdown": set(),
            "typoglycemia": set(),
            "remote_content": set(),
            "remote_content_instruction": set(),
            "indirect_injection": set(),
        }

        invisible_hits = sorted({f"U+{ord(char):04X}" for char in text_nfkc if char in self._invisible_chars})
        bidi_hits = sorted({f"U+{ord(char):04X}" for char in text_nfkc if char in self._bidi_chars})
        if invisible_hits:
            signals["unicode_invisible"] = set(invisible_hits)
        if bidi_hits:
            signals["unicode_bidi"] = set(bidi_hits)

        for label, pattern in self._direct_patterns.items():
            if pattern.search(text_norm):
                signals["direct"].add(label)

        for label, pattern in self._system_exfil_patterns.items():
            if pattern.search(text_norm):
                signals["system_exfil"].add(label)

        for label, pattern in self._html_md_patterns.items():
            if pattern.search(text_nfkc):
                signals["html_markdown"].add(label)

        for label, pattern in self._remote_content_patterns.items():
            if pattern.search(text_norm):
                signals["remote_content"].add(label)

        for label, pattern in self._indirect_injection_patterns.items():
            if pattern.search(text_norm):
                signals["indirect_injection"].add(label)

        for label, pattern in self._remote_instruction_patterns.items():
            if pattern.search(text_norm):
                signals["remote_content_instruction"].add(label)

        if any(marker and (marker in text_norm or marker in condensed) for marker in self._obfuscated_markers):
            signals["obfuscated"].add("rule_obfuscation_marker")

        decoded_texts: list[str] = []
        for idx, match in enumerate(self._base64_candidate_re.finditer(text_nfkc)):
            if idx >= self._base64_max_candidates:
                break
            decoded_texts.extend(self._decode_multistage(match.group(0)))

        for idx, match in enumerate(self._hex_candidate_re.finditer(text_nfkc)):
            if idx >= self._hex_max_candidates:
                break
            decoded_texts.extend(self._decode_multistage(match.group(0)))

        for decoded in decoded_texts:
            norm_decoded = self._normalize_text(decoded)
            if any(keyword and keyword in norm_decoded for keyword in self._decoded_keywords):
                signals["obfuscated"].add("encoded_payload")

        for word in self._word_re.findall(text_norm):
            for target in self._typoglycemia_targets:
                if _is_typoglycemia_variant(word, target):
                    signals["typoglycemia"].add(f"{target}->{word}")

        signal_payload = {key: sorted(values) for key, values in signals.items() if values}
        discussion_context = any(pattern.search(text_norm) for pattern in self._discussion_patterns) or any(
            pattern.search(text_nfkc) for pattern in self._quoted_instruction_patterns
        )
        diagnostics = {
            "text_raw_len": len(text_raw),
            "text_norm_len": len(text_norm),
            "unicode_invisible_count": len(invisible_hits),
            "unicode_bidi_count": len(bidi_hits),
            "discussion_context": discussion_context,
        }
        return signal_payload, diagnostics

    @staticmethod
    def _merge_signals(target: dict[str, set[str]], source: dict[str, list[str]]) -> None:
        for key, values in source.items():
            bucket = target.setdefault(key, set())
            bucket.update(values)

    @staticmethod
    def _finalize_signals(signals: dict[str, set[str]]) -> dict[str, list[str]]:
        return {key: sorted(values) for key, values in signals.items() if values}

    def _score_signals(self, signals: dict[str, list[str]]) -> dict[str, object]:
        feature_scores = {key: 0.0 for key in self._risk_weights}
        signal_breakdown: dict[str, dict[str, object]] = {}

        for signal_name, hits in signals.items():
            if not hits:
                continue
            bucket, severity = self._signal_profiles.get(signal_name, ("intent", 0.7))
            feature_scores[bucket] = max(feature_scores.get(bucket, 0.0), severity)
            signal_breakdown[signal_name] = {
                "bucket": bucket,
                "severity": round(severity, 4),
                "hits": len(hits),
            }

        raw, score, contributions = weighted_nonlinear_score(feature_scores, self._risk_weights, self._nonlinear_k)
        return {
            "raw": raw,
            "score": score,
            "k": self._nonlinear_k,
            "feature_scores": {key: round(value, 4) for key, value in feature_scores.items()},
            "weights": self._risk_weights,
            "contributions": contributions,
            "signal_breakdown": signal_breakdown,
        }

    def _apply_action(self, ctx: RequestContext, category: str, contextual_discussion: bool = False) -> None:
        action = self._action_map.get(category)
        if not action:
            return

        if contextual_discussion and action in {"block", "review", "downgrade", "sanitize"}:
            action = "sanitize"

        ctx.enforcement_actions.append(f"{self.name}:{category}:{action}")
        if action == "block":
            ctx.risk_score = max(ctx.risk_score, 0.95)
            ctx.requires_human_review = True
        elif action in {"review", "sanitize"}:
            ctx.risk_score = max(ctx.risk_score, 0.58 if contextual_discussion else 0.85)
            ctx.requires_human_review = not contextual_discussion
        elif action == "downgrade":
            ctx.risk_score = max(ctx.risk_score, 0.62 if contextual_discussion else 0.82)

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "signals": {}, "risk_model": {}}
        merged: dict[str, set[str]] = {}
        diagnostics: dict[str, int] = {
            "text_raw_len": 0,
            "text_norm_len": 0,
            "unicode_invisible_count": 0,
            "unicode_bidi_count": 0,
            "discussion_context_count": 0,
        }

        for msg in req.messages:
            signals, text_diag = self._scan_text(msg.content)
            self._merge_signals(merged, signals)
            diagnostics["text_raw_len"] += int(text_diag["text_raw_len"])
            diagnostics["text_norm_len"] += int(text_diag["text_norm_len"])
            diagnostics["unicode_invisible_count"] += int(text_diag["unicode_invisible_count"])
            diagnostics["unicode_bidi_count"] += int(text_diag["unicode_bidi_count"])
            diagnostics["discussion_context_count"] += int(bool(text_diag.get("discussion_context")))

        signals = self._finalize_signals(merged)
        if signals:
            risk_model = self._score_signals(signals)
            risk_score = float(risk_model["score"])
            contextual_discussion = diagnostics["discussion_context_count"] > 0 and self._mitigation_enabled
            if contextual_discussion and not any(category in self._non_reducible_categories for category in signals):
                mitigation_factor = 1.0 - self._max_risk_reduction
                risk_score = round(risk_score * mitigation_factor, 6)
                ctx.security_tags.add("injection_discussion_context")
                risk_model["mitigation"] = {
                    "applied": True,
                    "factor": mitigation_factor,
                    "max_reduction": self._max_risk_reduction,
                }
            else:
                risk_model["mitigation"] = {"applied": False}

            ctx.risk_score = max(ctx.risk_score, risk_score)
            for category in signals:
                ctx.security_tags.add(f"injection_{category}")
                self._apply_action(ctx, category, contextual_discussion=contextual_discussion)

            if ctx.risk_score >= self._risk_thresholds["review"]:
                ctx.requires_human_review = True

            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "signals": signals,
                "risk_model": risk_model,
                "diagnostics": diagnostics,
            }
            logger.info("injection detected request_id=%s categories=%s", ctx.request_id, sorted(signals.keys()))

        return req

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "signals": {}, "risk_model": {}}
        signals, diagnostics = self._scan_text(resp.output_text)
        if signals:
            risk_model = self._score_signals(signals)
            risk_score = float(risk_model["score"])
            contextual_discussion = bool(diagnostics.get("discussion_context")) and self._mitigation_enabled
            if contextual_discussion and not any(category in self._non_reducible_categories for category in signals):
                mitigation_factor = 1.0 - self._max_risk_reduction
                risk_score = round(risk_score * mitigation_factor, 6)
                ctx.security_tags.add("response_injection_discussion_context")
                risk_model["mitigation"] = {
                    "applied": True,
                    "factor": mitigation_factor,
                    "max_reduction": self._max_risk_reduction,
                }
            else:
                risk_model["mitigation"] = {"applied": False}

            ctx.risk_score = max(ctx.risk_score, risk_score)
            for category in signals:
                ctx.security_tags.add(f"response_injection_{category}")
                self._apply_action(ctx, category, contextual_discussion=contextual_discussion)

            if ctx.risk_score >= self._risk_thresholds["review"]:
                ctx.requires_human_review = True

            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "signals": signals,
                "risk_model": risk_model,
                "diagnostics": diagnostics,
            }
            logger.info(
                "injection-like response detected request_id=%s categories=%s",
                ctx.request_id,
                sorted(signals.keys()),
            )

        return resp

    def report(self) -> dict:
        return self._report
