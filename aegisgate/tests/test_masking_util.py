"""Tests for aegisgate.util.masking — value masking for safe log output."""

from __future__ import annotations

from aegisgate.util.masking import mask_for_log


def test_mask_empty_string():
    assert mask_for_log("") == ""


def test_mask_single_char():
    assert mask_for_log("x") == "*"


def test_mask_two_chars():
    result = mask_for_log("ab")
    assert len(result) == 2
    assert result[0] == "a"
    assert result[-1] == "b"


def test_mask_three_chars():
    result = mask_for_log("abc")
    assert result == "a*c"


def test_mask_four_chars():
    result = mask_for_log("abcd")
    assert result[0] == "a"
    assert result[-1] == "d"
    assert "*" in result


def test_mask_short_string_five_chars():
    result = mask_for_log("abcde")
    assert result[0:2] == "ab"
    assert result[-2:] == "de"
    assert "*" in result


def test_mask_long_string():
    result = mask_for_log("1234567890abcdef")
    # First 3 and last 2 should be visible
    assert result[:3] == "123"
    assert result[-2:] == "ef"
    assert "*" in result


def test_mask_normalizes_whitespace():
    result = mask_for_log("  hello  world  ")
    # After normalization: "hello world" (11 chars)
    assert result[:3] == "hel"
    assert result[-2:] == "ld"


def test_mask_whitespace_only():
    assert mask_for_log("   ") == ""
