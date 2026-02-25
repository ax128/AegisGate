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
    # high 最严（阈值最低），low 最松（阈值最高）；三档整体已放宽
    th_high = apply_threshold(base, level="high")
    th_med = apply_threshold(base, level="medium")
    th_low = apply_threshold(base, level="low")
    assert th_high < th_med < th_low


def test_apply_count_varies_by_level():
    base = 100
    c_high = apply_count(base, level="high")
    c_med = apply_count(base, level="medium")
    c_low = apply_count(base, level="low")
    assert c_high < c_med < c_low


def test_apply_floor_varies_by_level():
    base = 0.9
    # high 地板最高（易拦），low 地板最低（少拦）
    f_high = apply_floor(base, level="high")
    f_med = apply_floor(base, level="medium")
    f_low = apply_floor(base, level="low")
    assert f_high > f_med > f_low
