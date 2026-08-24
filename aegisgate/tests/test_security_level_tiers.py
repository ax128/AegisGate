"""The three security levels must stay three distinct levels.

``apply_threshold`` clamps to 1.0. With ``medium`` at ×1.30 and ``low`` at ×1.60,
every shipped policy (``risk_threshold`` 0.85 or 0.50 × 1.60) pushed both tiers
to the clamp, so ``low`` and ``medium`` were identical — and since the highest
score an ``action_map`` ``block`` assigns is 0.95, the score-based block path in
``OutputSanitizer``/``RestorationFilter`` could never fire at either.

Nothing in the suite pinned any of that, so the collapse was invisible: the
multiplier could be changed in either direction with the whole suite green.
These tests are the missing pin.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aegisgate.config.security_level import (
    apply_count,
    apply_floor,
    apply_threshold,
    count_threshold_multiplier,
    floor_multiplier,
    normalize_security_level,
    threshold_multiplier,
)

_POLICY_DIR = Path(__file__).resolve().parents[1] / "policies" / "rules"
_LEVELS = ("high", "medium", "low")

# The highest score any action_map "block" entry assigns. Filters that set a
# disposition directly (injection_detector, rag_poison_guard) bypass the
# threshold entirely; the ones that only raise the score (restoration,
# sanitizer) are the ones this ceiling matters for.
_ACTION_MAP_BLOCK_SCORE = 0.95


def _shipped_policies() -> dict[str, float]:
    out: dict[str, float] = {}
    for name in ("default", "strict", "permissive"):
        data = yaml.safe_load((_POLICY_DIR / f"{name}.yaml").read_text(encoding="utf-8"))
        out[name] = float(data["risk_threshold"])
    return out


# ── the tier model ──────────────────────────────────────────────────────


def test_medium_is_neutral() -> None:
    """``medium`` means "the policy's declared threshold", not a scaled one."""
    assert threshold_multiplier("medium") == 1.0
    assert apply_threshold(0.85, "medium") == pytest.approx(0.85)


def test_high_tightens_and_low_loosens() -> None:
    assert threshold_multiplier("high") < threshold_multiplier("medium")
    assert threshold_multiplier("low") > threshold_multiplier("medium")


@pytest.mark.parametrize("policy,base", _shipped_policies().items())
def test_every_shipped_policy_has_three_distinct_thresholds(
    policy: str, base: float
) -> None:
    """The defect: 0.85 × 1.30 and 0.85 × 1.60 both clamped to 1.0."""
    resolved = {level: apply_threshold(base, level) for level in _LEVELS}
    assert len(set(resolved.values())) == 3, (
        f"{policy} (risk_threshold={base}) collapses to {resolved} — "
        f"two security levels are indistinguishable"
    )
    assert resolved["high"] < resolved["medium"] < resolved["low"]


@pytest.mark.parametrize("policy,base", _shipped_policies().items())
def test_score_based_blocking_reachable_at_medium_and_high(
    policy: str, base: float
) -> None:
    """An ``action_map`` ``block`` must actually be able to block.

    The console renders block/review/sanitize/pass as one uniform vocabulary. If
    a ``block`` that only raises the score to 0.95 sits under a threshold of
    1.0, the console is describing something the runtime never does.
    """
    for level in ("high", "medium"):
        assert _ACTION_MAP_BLOCK_SCORE >= apply_threshold(base, level), (
            f"{policy} at {level}: a block-action score of "
            f"{_ACTION_MAP_BLOCK_SCORE} never reaches the "
            f"{apply_threshold(base, level)} threshold"
        )


@pytest.mark.parametrize("policy", ["default", "permissive"])
def test_low_stays_effectively_unblocking_on_the_default_policies(policy: str) -> None:
    """``low`` is documented as "essentially redaction only" — keep it that way.

    Scoped to the policies a deployment gets without asking for anything:
    ``strict`` at ``low`` resolves to 0.80 and *does* block on a 0.95 action,
    which is right — someone who selected ``strict`` did not ask for blocking to
    be switched off. Protection at ``low`` on the default policies comes from
    the filters that set a disposition directly and from
    AEGIS_STRICT_COMMAND_BLOCK_ENABLED, not from the score.
    """
    base = _shipped_policies()[policy]
    assert apply_threshold(base, "low") > _ACTION_MAP_BLOCK_SCORE


def test_low_is_the_loosest_tier_for_every_policy() -> None:
    """The invariant that holds regardless of which policy is selected."""
    for policy, base in _shipped_policies().items():
        assert apply_threshold(base, "low") > apply_threshold(base, "medium"), policy


# ── the other two multipliers were deliberately left alone ──────────────


def test_count_and_floor_multipliers_still_separate_the_tiers() -> None:
    """Neither is clamped at a ceiling, so neither caused the collapse.

    They keep their existing shape on purpose: changing them is a separate knob
    with its own evidence, and bundling it here would make the blocking-rate
    change impossible to attribute.
    """
    counts = {level: count_threshold_multiplier(level) for level in _LEVELS}
    floors = {level: floor_multiplier(level) for level in _LEVELS}
    assert len(set(counts.values())) == 3
    assert len(set(floors.values())) == 3
    assert counts["medium"] == 1.30
    assert floors["medium"] == 0.85


def test_apply_count_and_floor_still_differ_across_levels() -> None:
    assert len({apply_count(10, level) for level in _LEVELS}) == 3
    assert len({apply_floor(0.5, level) for level in _LEVELS}) == 3


# ── invariants that must survive any future retuning ────────────────────


def test_threshold_stays_in_range() -> None:
    for level in _LEVELS:
        for base in (0.0, 0.01, 0.5, 0.85, 1.0, 5.0):
            value = apply_threshold(base, level)
            assert 0.01 <= value <= 1.0


def test_unknown_level_falls_back_to_medium() -> None:
    for raw in (None, "", "  ", "MEDIUM", "banana", "HIGH "):
        assert normalize_security_level(raw) in _LEVELS
    assert normalize_security_level("banana") == "medium"
    assert normalize_security_level("HIGH ") == "high"


def test_builtin_fallback_policy_matches_default_yaml() -> None:
    """The empty-config-dir path must not silently pick a different tier story."""
    from aegisgate.policies.policy_engine import _BUILTIN_DEFAULT_POLICY

    default = yaml.safe_load((_POLICY_DIR / "default.yaml").read_text(encoding="utf-8"))
    assert _BUILTIN_DEFAULT_POLICY["risk_threshold"] == default["risk_threshold"]
    for level in _LEVELS:
        assert apply_threshold(
            _BUILTIN_DEFAULT_POLICY["risk_threshold"], level
        ) == apply_threshold(default["risk_threshold"], level)
