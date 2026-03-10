"""Security level helpers for global sensitivity tuning.

三档定位：
- high：全量检测，宁可误拦不放过
- medium（默认）：宽松，大部分"可能危险"指令不拦截，仅高危 + 脱敏
- low：极宽松，基本只脱敏 + 极端危险指令（系统提示泄露/编码攻击/凭据泄露）disposition=block 强制拦截
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
    """乘数越大，风险阈值越高，越少拦截。"""
    current = normalize_security_level(level)
    if current == "high":
        return 0.90
    if current == "low":
        return 1.60   # 阈值推到很高，几乎不触发 risk-based 拦截
    return 1.30        # medium: 大部分可疑指令不拦截


def count_threshold_multiplier(level: str | None = None) -> float:
    """乘数越大，需命中数量越多才触发，越少拦截。"""
    current = normalize_security_level(level)
    if current == "high":
        return 0.90
    if current == "low":
        return 1.60
    return 1.30


def floor_multiplier(level: str | None = None) -> float:
    """乘数越小，风险地板越低，越少拦截。"""
    current = normalize_security_level(level)
    if current == "high":
        return 1.05
    if current == "low":
        return 0.70   # 风险地板大幅降低
    return 0.85        # medium: 地板降低


def apply_threshold(value: float, level: str | None = None) -> float:
    scaled = float(value) * threshold_multiplier(level)
    return min(1.0, max(0.01, scaled))


def apply_count(value: int, level: str | None = None, minimum: int = 1) -> int:
    scaled = int(round(float(value) * count_threshold_multiplier(level)))
    return max(minimum, scaled)


def apply_floor(value: float, level: str | None = None) -> float:
    scaled = float(value) * floor_multiplier(level)
    return min(1.0, max(0.0, scaled))
