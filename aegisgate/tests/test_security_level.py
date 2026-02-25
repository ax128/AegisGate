from aegisgate.config.security_level import (
    apply_count,
    apply_floor,
    apply_threshold,
    normalize_security_level,
)


def test_normalize_security_level_defaults_to_medium():
    assert normalize_security_level("invalid") == "medium"


def test_apply_threshold_varies_by_level():
    base = 0.7
    assert apply_threshold(base, level="high") < base
    assert apply_threshold(base, level="medium") == base
    assert apply_threshold(base, level="low") > base


def test_apply_count_varies_by_level():
    base = 100
    assert apply_count(base, level="high") < base
    assert apply_count(base, level="medium") == base
    assert apply_count(base, level="low") > base


def test_apply_floor_varies_by_level():
    base = 0.9
    assert apply_floor(base, level="high") > base
    assert apply_floor(base, level="medium") == base
    assert apply_floor(base, level="low") < base
