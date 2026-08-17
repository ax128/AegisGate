"""
Log excerpt helpers: truncate uniformly wherever block/redaction/sanitize paths log content, so
only the important part is shown.

- debug_log_original: DEBUG level, logs an excerpt of the original text
- info_log_sanitized: INFO level, logs an excerpt of the processed (masked/split) content

Environment variables (optional):
- AEGIS_DEBUG_EXCERPT_MAX_LEN: override the default truncation length. Only positive integers are
  accepted; invalid values, 0, and negatives fall back to the caller's default, so the full
  original text is never logged by accident.
"""

from __future__ import annotations

import logging
import os

from aegisgate.util.logger import logger

# Maximum length (characters) for showing original text, except for the "forward request received" log
DEFAULT_EXCERPT_MAX_LEN = 500


def _resolve_max_len(default: int) -> int:
    """Read AEGIS_DEBUG_EXCERPT_MAX_LEN env override once per call site."""
    env_max = os.environ.get("AEGIS_DEBUG_EXCERPT_MAX_LEN")
    if env_max is not None:
        try:
            resolved = int(env_max)
            if resolved > 0:
                return resolved
        except ValueError:
            pass
    return default


def excerpt_for_debug(text: str, max_len: int = DEFAULT_EXCERPT_MAX_LEN) -> str:
    """
    Truncate the original text into a readable excerpt for DEBUG logs. The input string is not
    modified. max_len <= 0 means no truncation and returns the full text.
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
    Log an excerpt of the original text, only when DEBUG is enabled.
    label: e.g. "request_blocked", "response_sanitized"
    original_text: the original content (always truncated; the env var cannot disable truncation)
    reason: optional block/processing reason
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    max_len = _resolve_max_len(max_len)
    excerpt = excerpt_for_debug(original_text, max_len=max_len)
    if reason:
        logger.debug(
            "%s original_excerpt request_id=see_context reason=%s excerpt=%s",
            label,
            reason,
            excerpt,
        )
    else:
        logger.debug(
            "%s original_excerpt request_id=see_context excerpt=%s", label, excerpt
        )


# Default truncation length for processed content (shorter than the original, since masked content is safer)
DEFAULT_SANITIZED_EXCERPT_MAX_LEN = 800


def info_log_sanitized(
    label: str,
    sanitized_text: str,
    *,
    request_id: str = "",
    reason: str | None = None,
    max_len: int = DEFAULT_SANITIZED_EXCERPT_MAX_LEN,
) -> None:
    """
    INFO-level log: record an excerpt of the processed (masked/split) content.
    Used for audit trails, to confirm the gateway really did act on the dangerous content.
    """
    if not logger.isEnabledFor(logging.INFO):
        return
    max_len = _resolve_max_len(max_len)
    excerpt = excerpt_for_debug(sanitized_text, max_len=max_len)
    rid = request_id or "see_context"
    if reason:
        logger.info(
            "%s sanitized_output request_id=%s reason=%s output=%s",
            label,
            rid,
            reason,
            excerpt,
        )
    else:
        logger.info("%s sanitized_output request_id=%s output=%s", label, rid, excerpt)
