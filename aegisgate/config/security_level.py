"""Security level helpers for global sensitivity tuning."""

from __future__ import annotations

from aegisgate.config.settings import settings


_SUPPORTED_LEVELS = {"low", "medium", "high"}


def normalize_security_level(raw: str | None = None) -> str:
    candidate = (raw or settings.security_level or "medium").strip().lower()
    if candidate in _SUPPORTED_LEVELS:
        return candidate
    return "medium"


def threshold_multiplier(level: str | None = None) -> float:
    current = normalize_security_level(level)
    if current == "high":
        return 0.85
    if current == "low":
        return 1.2
    return 1.0


def count_threshold_multiplier(level: str | None = None) -> float:
    current = normalize_security_level(level)
    if current == "high":
        return 0.8
    if current == "low":
        return 1.25
    return 1.0


def floor_multiplier(level: str | None = None) -> float:
    current = normalize_security_level(level)
    if current == "high":
        return 1.08
    if current == "low":
        return 0.92
    return 1.0


def apply_threshold(value: float, level: str | None = None) -> float:
    scaled = float(value) * threshold_multiplier(level)
    return min(1.0, max(0.01, scaled))


def apply_count(value: int, level: str | None = None, minimum: int = 1) -> int:
    scaled = int(round(float(value) * count_threshold_multiplier(level)))
    return max(minimum, scaled)


def apply_floor(value: float, level: str | None = None) -> float:
    scaled = float(value) * floor_multiplier(level)
    return min(1.0, max(0.0, scaled))
