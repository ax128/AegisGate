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

# The probe runs on a bounded prefix so its cost stays flat for multi-MB media
# payloads. The window mirrors the ratio test above, which only samples the
# first 512 characters: whatever made the string look like base64 is in the
# prefix, and so is the credential marker (a PEM header, a JWT header segment,
# an `sk-`/`AKIA` token) whenever the string is the credential.
_CREDENTIAL_PROBE_MAX_CHARS = 4096
# Every alternative of _HIGH_CONFIDENCE_CREDENTIAL_RE starts with one of these
# literals, so a window without any of them cannot match and skips the regex.
_CREDENTIAL_HINTS = (
    "-----BEGIN",
    "eyJ",
    "sk-",
    "rk-",
    "pk-",
    "AKIA",
    "ghp_",
    "xox",
    "xprv",
)
# Credential shapes that must never be waved through by the blob heuristic.
# A PEM key body, a long JWT and most API tokens are themselves base64-ish, so
# the ratio test below classifies them as binary and would skip redaction
# entirely — exactly the values that must not reach the upstream in cleartext.
_HIGH_CONFIDENCE_CREDENTIAL_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY[A-Z ]{0,16}-----"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|\b(?:sk|rk|pk)-[A-Za-z0-9\-_]{10,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bghp_[A-Za-z0-9]{20,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    r"|\bxprv[1-9A-HJ-NP-Za-km-z]{60,120}\b"
)


def contains_high_confidence_credential(text: str) -> bool:
    """Return True if *text* carries a credential shape with no false-positive risk.

    Used to override the binary-blob heuristic; keep the pattern set narrow so a
    genuine media payload is not dragged back into the redaction path.
    """
    window = text[:_CREDENTIAL_PROBE_MAX_CHARS]
    if not any(hint in window for hint in _CREDENTIAL_HINTS):
        return False
    return bool(_HIGH_CONFIDENCE_CREDENTIAL_RE.search(window))


def looks_like_base64_blob(text: str) -> bool:
    """Return True if *text* is a data-URI or a long raw-base64 blob.

    Binary payloads (images, audio, …) must not be redacted because
    PII-style regexes match random byte sequences inside them.  A blob that
    still carries a high-confidence credential is never skipped: the whole
    point of the request-side redaction is to keep those from being forwarded.
    """
    if _BASE64_DATA_URI_PREFIX.match(text):
        return not contains_high_confidence_credential(text)
    if len(text) >= _MIN_BASE64_BLOB_LEN:
        sample = text[:512]
        base64_count = sum(1 for ch in sample if ch in _BASE64_CHARS)
        if base64_count / len(sample) > _BASE64_RATIO_THRESHOLD:
            return not contains_high_confidence_credential(text)
    return False
