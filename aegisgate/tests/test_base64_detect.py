"""Tests for aegisgate.util.base64_detect — binary blob detection."""

from __future__ import annotations

import base64

from aegisgate.util.base64_detect import looks_like_base64_blob


def test_detects_data_uri():
    data_uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg"
    assert looks_like_base64_blob(data_uri) is True


def test_detects_data_uri_with_different_mime():
    data_uri = "data:audio/wav;base64,UklGRiQAAABXQVZF"
    assert looks_like_base64_blob(data_uri) is True


def test_rejects_short_non_base64():
    assert looks_like_base64_blob("hello world") is False


def test_rejects_normal_text():
    text = "This is a normal sentence about programming."
    assert looks_like_base64_blob(text) is False


def test_detects_long_base64_blob():
    # Generate 512 bytes of random-looking base64
    raw = b"A" * 400
    b64 = base64.b64encode(raw).decode("ascii")
    assert len(b64) >= 256
    assert looks_like_base64_blob(b64) is True


def test_rejects_long_non_base64():
    # Long text that is NOT base64-like
    text = "This is a long sentence. " * 30
    assert len(text) >= 256
    assert looks_like_base64_blob(text) is False


def test_rejects_just_below_threshold():
    text = "a" * 255  # Just below _MIN_BASE64_BLOB_LEN
    assert looks_like_base64_blob(text) is False
