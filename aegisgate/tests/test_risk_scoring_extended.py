"""Extended tests for aegisgate.util.risk_scoring — boundary conditions."""

from __future__ import annotations

from aegisgate.util.risk_scoring import clamp01, points_to_score, weighted_nonlinear_score


# ---------- clamp01 ----------

def test_clamp01_negative():
    assert clamp01(-0.5) == 0.0


def test_clamp01_above_one():
    assert clamp01(1.5) == 1.0


def test_clamp01_zero():
    assert clamp01(0.0) == 0.0


def test_clamp01_one():
    assert clamp01(1.0) == 1.0


def test_clamp01_mid():
    assert clamp01(0.5) == 0.5


# ---------- points_to_score ----------

def test_points_to_score_normal():
    assert points_to_score(5, 10) == 0.5


def test_points_to_score_zero_max():
    assert points_to_score(5, 0) == 0.0


def test_points_to_score_negative_max():
    assert points_to_score(5, -1) == 0.0


def test_points_to_score_exceeds_max():
    assert points_to_score(15, 10) == 1.0


# ---------- weighted_nonlinear_score ----------

def test_weighted_nonlinear_score_basic():
    raw, score, contribs = weighted_nonlinear_score(
        {"a": 0.5, "b": 0.5},
        {"a": 1.0, "b": 1.0},
    )
    assert 0.0 <= raw <= 1.0
    assert 0.0 <= score <= 1.0
    assert "a" in contribs
    assert "b" in contribs


def test_weighted_nonlinear_score_all_zero():
    raw, score, contribs = weighted_nonlinear_score(
        {"a": 0.0},
        {"a": 1.0},
    )
    assert raw == 0.0
    assert score == 0.0


def test_weighted_nonlinear_score_all_one():
    raw, score, contribs = weighted_nonlinear_score(
        {"a": 1.0},
        {"a": 1.0},
    )
    assert raw == 1.0
    assert score > 0.8


def test_weighted_nonlinear_score_zero_weights():
    """When all weights are zero, should use default weight."""
    raw, score, contribs = weighted_nonlinear_score(
        {"a": 0.5},
        {"a": 0.0, "b": 0.0},
    )
    # Should not crash, uses default weight
    assert 0.0 <= score <= 1.0


def test_weighted_nonlinear_score_missing_features():
    raw, score, contribs = weighted_nonlinear_score(
        {},  # No feature scores
        {"a": 1.0, "b": 1.0},
    )
    assert raw == 0.0
    assert score == 0.0
