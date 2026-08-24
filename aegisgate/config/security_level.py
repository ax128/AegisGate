"""Security level helpers for global sensitivity tuning.

Three levels, with ``medium`` as the neutral middle:

- high: full detection; thresholds tightened, score floors raised — prefer a false block over a miss
- medium (default): the policy YAML's declared ``risk_threshold``, unscaled
- low: very relaxed; the threshold is pushed past the clamp, so risk-based blocking effectively
  never fires and protection comes from the disposition-setting filters plus redaction

The levels never change *which* filters run — only how the resolved thresholds
and per-filter score floors are scaled.
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
    """A larger multiplier raises the risk threshold, so fewer requests are blocked.

    ``medium`` is neutral: it uses the policy YAML's declared ``risk_threshold``
    unchanged, and the other two tiers adjust around it. It used to be 1.30,
    which collapsed the three tiers into two on every shipped policy —
    ``apply_threshold`` clamps to 1.0, and 0.85 × 1.30 and 0.85 × 1.60 both land
    there. ``low`` and ``medium`` were therefore identical, and since the highest
    score an ``action_map`` ``block`` assigns is 0.95, the score-based block path
    could never fire at either tier.

    Only this multiplier changed. ``count_threshold_multiplier`` and
    ``floor_multiplier`` keep their shape: neither is clamped at a ceiling, so
    neither produced the tier collapse, and each is a separate knob worth
    assessing on its own evidence.
    """
    current = normalize_security_level(level)
    if current == "high":
        return 0.90
    if current == "low":
        return 1.60   # threshold pushed very high, so risk-based blocking almost never fires
    return 1.00        # medium: the policy's declared threshold, as declared


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
