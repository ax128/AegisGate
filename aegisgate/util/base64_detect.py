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

# Every alternative of _HIGH_CONFIDENCE_CREDENTIAL_RE starts with one of these
# literals, so the probe locates candidate offsets with str.find (memchr-backed,
# ~4ns/char) and only runs the regex anchored at those offsets.  Scanning the
# *whole* string this way costs about 45ms on a 12MB blob, versus ~860ms for a
# plain regex search over the same input — and unlike a fixed prefix window it
# cannot be stepped over by padding the front of the string.
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
#
# The JWT segment lengths are capped so an anchored probe stays O(1): without a
# ceiling, `eyJ` followed by megabytes of segment characters and no dot makes a
# single probe walk the rest of the string.  Real JWT segments are far below the
# cap.
_HIGH_CONFIDENCE_CREDENTIAL_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY[A-Z ]{0,16}-----"
    r"|\beyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}"
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

    The whole string is probed, not a prefix: a credential that trails a long
    base64 attachment inside the same message is exactly the case the blob
    heuristic used to wave through.
    """
    for hint in _CREDENTIAL_HINTS:
        start = 0
        while True:
            pos = text.find(hint, start)
            if pos < 0:
                break
            # `match` still honours \b against the character before *pos*, so
            # anchoring here is equivalent to a search that happens to start
            # at this offset.
            if _HIGH_CONFIDENCE_CREDENTIAL_RE.match(text, pos):
                return True
            start = pos + 1
    return False


def looks_like_base64_blob(text: str) -> bool:
    """Return True if *text* is a data-URI or a long raw-base64 blob.

    Binary payloads (images, audio, …) must not be redacted because
    PII-style regexes match random byte sequences inside them.  A blob that
    still carries a high-confidence credential is never skipped — anywhere in
    the string, not just in its prefix: the whole point of the request-side
    redaction is to keep those from being forwarded.
    """
    if _BASE64_DATA_URI_PREFIX.match(text):
        return not contains_high_confidence_credential(text)
    if len(text) >= _MIN_BASE64_BLOB_LEN:
        sample = text[:512]
        base64_count = sum(1 for ch in sample if ch in _BASE64_CHARS)
        if base64_count / len(sample) > _BASE64_RATIO_THRESHOLD:
            return not contains_high_confidence_credential(text)
    return False
