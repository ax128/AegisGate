"""Security level helpers for global sensitivity tuning.

Three levels:
- high: full detection; prefer a false block over a miss
- medium (default): relaxed; most "possibly dangerous" instructions pass, only high-risk hits plus
  redaction
- low: very relaxed; essentially redaction only, plus extreme risks (system-prompt leaks, encoding
  attacks, credential leaks) that disposition=block still forces a block on
"""

from __future__ import annotations

from aegisgate.config.settings import settings


_SUPPORTED_LEVELS = {"low", "medium", "high"}


def normalize_security_level(raw: str | None = None) -> str:
    candidate = (raw or settings.security_level or "medium").strip().lower()
    if candidate in _SUPPORTED_LEVELS:
        return candidate
    return "medium"


def threshold_multiplier(level: str | None = None) -> float:
    """A larger multiplier raises the risk threshold, so fewer requests are blocked."""
    current = normalize_security_level(level)
    if current == "high":
        return 0.90
    if current == "low":
        return 1.60   # threshold pushed very high, so risk-based blocking almost never fires
    return 1.30        # medium: most suspicious instructions are not blocked


def count_threshold_multiplier(level: str | None = None) -> float:
    """A larger multiplier requires more hits before firing, so fewer requests are blocked."""
    current = normalize_security_level(level)
    if current == "high":
        return 0.90
    if current == "low":
        return 1.60
    return 1.30


def floor_multiplier(level: str | None = None) -> float:
    """A smaller multiplier lowers the risk floor, so fewer requests are blocked."""
    current = normalize_security_level(level)
    if current == "high":
        return 1.05
    if current == "low":
        return 0.70   # risk floor lowered sharply
    return 0.85        # medium: floor lowered


def apply_threshold(value: float, level: str | None = None) -> float:
    scaled = float(value) * threshold_multiplier(level)
    return min(1.0, max(0.01, scaled))


def apply_count(value: int, level: str | None = None, minimum: int = 1) -> int:
    scaled = int(round(float(value) * count_threshold_multiplier(level)))
    return max(minimum, scaled)


def apply_floor(value: float, level: str | None = None) -> float:
    scaled = float(value) * floor_multiplier(level)
    return min(1.0, max(0.0, scaled))
