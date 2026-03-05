"""
调试用原文摘要：拦截/脱敏/block 处记录「原文」时统一截断，只展示重要部分。
仅在 AEGIS_LOG_LEVEL=debug 时由调用方打 DEBUG 日志；本模块只提供截断与格式化。

环境变量（可选）：
- AEGIS_DEBUG_EXCERPT_MAX_LEN: 覆盖默认截断长度。设为 0 表示不截断，打印完整内容（日志会很长）。
"""

from __future__ import annotations

import logging
import os

from aegisgate.util.logger import logger

# 除「收到转发请求」外，其余原文展示最大长度（字符）
DEFAULT_EXCERPT_MAX_LEN = 500


def excerpt_for_debug(text: str, max_len: int = DEFAULT_EXCERPT_MAX_LEN) -> str:
    """
    将原文截断为可读摘要，便于 DEBUG 日志。不修改原字符串。
    max_len <= 0 表示不截断，返回全文。
    """
    if not text:
        return ""
    s = str(text).strip()
    if max_len <= 0 or len(s) <= max_len:
        return s
    return f"{s[:max_len]} ... [truncated, total {len(s)} chars]"


def debug_log_original(
    label: str,
    original_text: str,
    *,
    reason: str | None = None,
    max_len: int = DEFAULT_EXCERPT_MAX_LEN,
) -> None:
    """
    仅当 DEBUG 开启时，打一条「原文」摘要日志。
    label: 如 "request_blocked", "response_sanitized"
    original_text: 原文内容（会被截断，除非 max_len<=0 或设置了 AEGIS_DEBUG_EXCERPT_MAX_LEN=0）
    reason: 可选，拦截/处理原因
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    env_max = os.environ.get("AEGIS_DEBUG_EXCERPT_MAX_LEN")
    if env_max is not None:
        try:
            max_len = int(env_max)
        except ValueError:
            pass
    original_len = len(original_text or "")
    excerpt = excerpt_for_debug(original_text, max_len=max_len)
    excerpt_len = len(excerpt)
    truncated = "[truncated" in excerpt if isinstance(excerpt, str) else False
    # 诊断：便于排查「为何仍被截断」
    logger.debug(
        "debug_excerpt label=%s AEGIS_DEBUG_EXCERPT_MAX_LEN=%s max_len_used=%s original_len=%s excerpt_len=%s truncated=%s",
        label,
        env_max,
        max_len,
        original_len,
        excerpt_len,
        truncated,
    )
    if reason:
        logger.debug("%s original_excerpt request_id=see_context reason=%s excerpt=%s", label, reason, excerpt)
    else:
        logger.debug("%s original_excerpt request_id=see_context excerpt=%s", label, excerpt)
