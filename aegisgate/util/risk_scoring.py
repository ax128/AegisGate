"""Reusable risk scoring helpers."""

from __future__ import annotations

import math


def clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def points_to_score(points: float, points_max: float) -> float:
    if points_max <= 0:
        return 0.0
    return clamp01(points / points_max)


def weighted_nonlinear_score(
    feature_scores: dict[str, float],
    weights: dict[str, float],
    k: float = 2.2,
) -> tuple[float, float, dict[str, float]]:
    """Return (raw, final_score, contribution_breakdown)."""

    normalized_weights = {str(name): max(0.0, float(weight)) for name, weight in weights.items()}
    total_weight = sum(normalized_weights.values())
    if total_weight <= 0.0:
        normalized_weights = {"default": 1.0}
        total_weight = 1.0

    raw = 0.0
    contributions: dict[str, float] = {}

    for name, weight in normalized_weights.items():
        scaled_weight = weight / total_weight
        signal_score = clamp01(float(feature_scores.get(name, 0.0)))
        contribution = scaled_weight * signal_score
        contributions[name] = round(contribution, 6)
        raw += contribution

    raw = clamp01(raw)
    score = 1.0 - math.exp(-max(0.0, k) * raw)
    return round(raw, 6), round(clamp01(score), 6), contributions
