"""Security level helpers for global sensitivity tuning.

三档整体已放宽：high/medium/low 均比旧版更少误拦，机制成熟前建议用 medium 或 low。
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
    """乘数越大，风险阈值越高，越少拦截。三档整体放宽。"""
    current = normalize_security_level(level)
    if current == "high":
        return 0.95   # 原 0.85，放宽
    if current == "low":
        return 1.35   # 原 1.2，更宽松
    return 1.15       # 原 1.0，medium 也放宽


def count_threshold_multiplier(level: str | None = None) -> float:
    """乘数越大，需命中数量越多才触发，越少拦截。"""
    current = normalize_security_level(level)
    if current == "high":
        return 0.95   # 原 0.8
    if current == "low":
        return 1.4    # 原 1.25
    return 1.15       # 原 1.0


def floor_multiplier(level: str | None = None) -> float:
    """乘数越小，风险地板越低，越少拦截。"""
    current = normalize_security_level(level)
    if current == "high":
        return 1.02   # 原 1.08，降低
    if current == "low":
        return 0.85   # 原 0.92，更低
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
