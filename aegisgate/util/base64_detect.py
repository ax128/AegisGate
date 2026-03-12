"""Detect base64-encoded binary blobs that should not be redacted."""

from __future__ import annotations

import re

_BASE64_DATA_URI_PREFIX = re.compile(
    r"^data:[a-zA-Z0-9_.+-]+/[a-zA-Z0-9_.+-]+;base64,", re.ASCII
)
_MIN_BASE64_BLOB_LEN = 256
_BASE64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r"
)
_BASE64_RATIO_THRESHOLD = 0.92


def looks_like_base64_blob(text: str) -> bool:
    """Return True if *text* is a data-URI or a long raw-base64 blob.

    Binary payloads (images, audio, …) must not be redacted because
    PII-style regexes match random byte sequences inside them.
    """
    if _BASE64_DATA_URI_PREFIX.match(text):
        return True
    if len(text) >= _MIN_BASE64_BLOB_LEN:
        sample = text[:512]
        base64_count = sum(1 for ch in sample if ch in _BASE64_CHARS)
        if base64_count / len(sample) > _BASE64_RATIO_THRESHOLD:
            return True
    return False
