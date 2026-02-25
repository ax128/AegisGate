"""Points-based anomaly and poisoning detector."""

from __future__ import annotations

import base64
import re
import unicodedata
from collections import Counter
from urllib.parse import unquote

from aegisgate.config.security_level import apply_count, apply_threshold, normalize_security_level
from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger
from aegisgate.util.risk_scoring import points_to_score, weighted_nonlinear_score


class AnomalyDetector(BaseFilter):
    name = "anomaly_detector"

    def __init__(self) -> None:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "signals": [], "risk_model": {}}

        rules = load_security_rules().get(self.name, {})
        repetition_rules = rules.get("repetition", {})
        encoded_rules = rules.get("encoded_payload", {})
        unicode_rules = rules.get("unicode", {})
        scoring = rules.get("scoring_model", {})
        level = normalize_security_level()

        self._repetition_ratio_threshold = apply_threshold(float(repetition_rules.get("repetition_ratio_threshold", 0.35)), level=level)
        self._max_run_threshold = apply_count(int(repetition_rules.get("max_run_length_threshold", 40)), level=level, minimum=5)
        self._repeated_line_threshold = apply_count(int(repetition_rules.get("repeated_line_threshold", 20)), level=level, minimum=3)

        self._base64_min_length = apply_count(int(encoded_rules.get("base64_min_length", 200)), level=level, minimum=32)
        self._hex_min_length = apply_count(int(encoded_rules.get("hex_min_length", 300)), level=level, minimum=32)
        self._url_encoded_min_count = apply_count(int(encoded_rules.get("url_encoded_min_count", 12)), level=level, minimum=3)

        self._invisible_chars = set(unicode_rules.get("invisible_chars", ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"]))
        self._bidi_chars = set(unicode_rules.get("bidi_chars", ["\u202a", "\u202b", "\u202d", "\u202e", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069"]))
        self._invisible_char_threshold = apply_count(int(unicode_rules.get("invisible_char_threshold", 6)), level=level, minimum=1)

        self._command_patterns: list[tuple[str, re.Pattern[str]]] = []
        for item in rules.get("command_patterns", []):
            pattern_id = str(item.get("id", "cmd_rule"))
            regex = item.get("regex")
            if not regex:
                continue
            self._command_patterns.append((pattern_id, re.compile(regex, re.IGNORECASE)))

        self._point_values = {str(key): float(value) for key, value in (rules.get("points", {}) or {}).items()}
        self._point_buckets = {str(key): str(value) for key, value in (rules.get("point_buckets", {}) or {}).items()}
        self._weights = {str(key): float(value) for key, value in (scoring.get("weights", {"payload": 0.7, "anomaly": 0.3}).items())}
        self._points_max = {str(key): float(value) for key, value in (scoring.get("points_max", {"payload": 1.45, "anomaly": 1.3}).items())}
        self._nonlinear_k = float(scoring.get("nonlinear_k", 2.2))
        self._risk_thresholds = {
            "allow": apply_threshold(float(scoring.get("thresholds", {}).get("allow", 0.35)), level=level),
            "review": apply_threshold(float(scoring.get("thresholds", {}).get("review", 0.7)), level=level),
        }

    @staticmethod
    def _max_run_length(text: str) -> int:
        if not text:
            return 0
        max_run = 1
        run = 1
        prev = text[0]
        for char in text[1:]:
            if char == prev:
                run += 1
                if run > max_run:
                    max_run = run
            else:
                run = 1
                prev = char
        return max_run

    @staticmethod
    def _repetition_ratio(text: str) -> float:
        if not text:
            return 0.0
        compact = re.sub(r"\s+", "", text)
        if not compact:
            return 0.0
        counts = Counter(compact)
        return max(counts.values()) / len(compact)

    def _has_base64_payload(self, text: str) -> bool:
        for token in re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", text):
            if len(token) < self._base64_min_length:
                continue
            try:
                base64.b64decode(token, validate=True)
                return True
            except Exception:
                continue
        return False

    def _has_hex_payload(self, text: str) -> bool:
        return re.search(rf"\b[0-9a-fA-F]{{{self._hex_min_length},}}\b", text) is not None

    def _has_url_encoded_payload(self, text: str) -> bool:
        hit_count = len(re.findall(r"%[0-9A-Fa-f]{2}", text))
        if hit_count < self._url_encoded_min_count:
            return False
        return unquote(text) != text

    def _has_high_risk_command(self, text: str) -> tuple[bool, list[str]]:
        matches: list[str] = []
        for pattern_id, pattern in self._command_patterns:
            if pattern.search(text):
                matches.append(pattern_id)
        return bool(matches), sorted(matches)

    def _collect_points(self, text: str) -> tuple[dict[str, float], dict[str, list[str]]]:
        text_nfkc = unicodedata.normalize("NFKC", text)
        points: dict[str, float] = {}
        evidence: dict[str, list[str]] = {}

        repetition_ratio = self._repetition_ratio(text_nfkc)
        if repetition_ratio > self._repetition_ratio_threshold:
            points["repetition_ratio"] = self._point_values.get("repetition_ratio", 0.25)
            evidence["repetition_ratio"] = [f"ratio={repetition_ratio:.4f}"]

        max_run = self._max_run_length(text_nfkc)
        if max_run >= self._max_run_threshold:
            points["max_run_length"] = self._point_values.get("max_run_length", 0.2)
            evidence["max_run_length"] = [f"max_run={max_run}"]

        non_empty_lines = [line.strip() for line in text_nfkc.splitlines() if line.strip()]
        if non_empty_lines:
            most_common_line, count = Counter(non_empty_lines).most_common(1)[0]
            if count >= self._repeated_line_threshold:
                points["repeated_line"] = self._point_values.get("repeated_line", 0.2)
                evidence["repeated_line"] = [f"line_repeat={count}", most_common_line[:80]]

        if self._has_base64_payload(text_nfkc):
            points["base64_payload"] = self._point_values.get("base64_payload", 0.35)
            evidence["base64_payload"] = ["base64_long_segment"]

        if self._has_hex_payload(text_nfkc):
            points["hex_payload"] = self._point_values.get("hex_payload", 0.3)
            evidence["hex_payload"] = ["hex_long_segment"]

        if self._has_url_encoded_payload(text_nfkc):
            points["url_encoded_payload"] = self._point_values.get("url_encoded_payload", 0.2)
            evidence["url_encoded_payload"] = ["dense_url_encoded_segment"]

        invisible_count = sum(1 for char in text_nfkc if char in self._invisible_chars)
        if invisible_count >= self._invisible_char_threshold:
            points["invisible_chars"] = self._point_values.get("invisible_chars", 0.25)
            evidence["invisible_chars"] = [f"invisible_count={invisible_count}"]

        bidi_hits = sorted({f"U+{ord(char):04X}" for char in text_nfkc if char in self._bidi_chars})
        if bidi_hits:
            points["bidi_control"] = self._point_values.get("bidi_control", 0.4)
            evidence["bidi_control"] = bidi_hits

        high_risk_command, command_hits = self._has_high_risk_command(text_nfkc)
        if high_risk_command:
            points["high_risk_command"] = self._point_values.get("high_risk_command", 0.4)
            evidence["high_risk_command"] = command_hits

        return points, evidence

    def _score_points(self, points: dict[str, float]) -> dict[str, object]:
        bucket_points: dict[str, float] = {bucket: 0.0 for bucket in self._weights}
        point_breakdown: dict[str, dict[str, object]] = {}

        for detector, detector_points in points.items():
            bucket = self._point_buckets.get(detector, "anomaly")
            bucket_points[bucket] = bucket_points.get(bucket, 0.0) + detector_points
            point_breakdown[detector] = {
                "bucket": bucket,
                "points": round(detector_points, 4),
            }

        feature_scores = {
            bucket: points_to_score(bucket_points.get(bucket, 0.0), self._points_max.get(bucket, 1.0))
            for bucket in self._weights
        }
        raw, score, contributions = weighted_nonlinear_score(feature_scores, self._weights, self._nonlinear_k)
        return {
            "raw": raw,
            "score": score,
            "k": self._nonlinear_k,
            "bucket_points": {key: round(val, 4) for key, val in bucket_points.items()},
            "feature_scores": {key: round(val, 4) for key, val in feature_scores.items()},
            "weights": self._weights,
            "contributions": contributions,
            "point_breakdown": point_breakdown,
        }

    def _process_text(self, text: str, ctx: RequestContext, phase: str) -> None:
        points, evidence = self._collect_points(text)
        if not points:
            return

        risk_model = self._score_points(points)
        ctx.risk_score = max(ctx.risk_score, float(risk_model["score"]))
        for detector_name in points:
            ctx.security_tags.add(f"{phase}_anomaly_{detector_name}")

        if ctx.risk_score >= self._risk_thresholds["review"]:
            ctx.requires_human_review = True

        self._report = {
            "filter": self.name,
            "hit": True,
            "risk_score": ctx.risk_score,
            "signals": sorted(points.keys()),
            "evidence": evidence,
            "risk_model": risk_model,
        }

    def process_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "signals": [], "risk_model": {}}
        merged_points: dict[str, float] = {}
        merged_evidence: dict[str, list[str]] = {}
        for msg in req.messages:
            points, evidence = self._collect_points(msg.content)
            for key, value in points.items():
                merged_points[key] = max(merged_points.get(key, 0.0), value)
            for key, values in evidence.items():
                merged_evidence.setdefault(key, [])
                merged_evidence[key].extend(values)

        if merged_points:
            risk_model = self._score_points(merged_points)
            ctx.risk_score = max(ctx.risk_score, float(risk_model["score"]))
            for detector_name in merged_points:
                ctx.security_tags.add(f"request_anomaly_{detector_name}")

            if ctx.risk_score >= self._risk_thresholds["review"]:
                ctx.requires_human_review = True

            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "signals": sorted(merged_points.keys()),
                "evidence": merged_evidence,
                "risk_model": risk_model,
            }
            logger.info("anomaly detected on request_id=%s signals=%s", ctx.request_id, sorted(merged_points.keys()))
        return req

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        self._report = {"filter": self.name, "hit": False, "risk_score": 0.0, "signals": [], "risk_model": {}}
        self._process_text(resp.output_text, ctx, phase="response")
        if self._report.get("hit"):
            logger.info(
                "anomaly detected on response request_id=%s signals=%s",
                ctx.request_id,
                self._report.get("signals", []),
            )
        return resp

    def report(self) -> dict:
        return self._report
