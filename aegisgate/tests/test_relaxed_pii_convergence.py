"""V1 and V2 must resolve request-side PII redaction from one configurable set.

V2 used to carry a hard-coded 15-id frozenset that shadowed
``redaction.relaxed_pii_ids``: editing the YAML moved V1 and left V2 alone, and
nothing in the configuration surface revealed it. These tests pin the two
properties that make the convergence real — V2 follows the YAML, and the field
layer is not gated by the PII set on either side — plus the no-coverage-lost
condition that made it safe to do.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from aegisgate.adapters.v2_proxy import router as v2_router
from aegisgate.config.security_rules import (
    DEFAULT_RELAXED_PII_IDS,
    invalidate_security_rules_cache,
)
from aegisgate.config.settings import settings

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SHIPPED_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"

# The id set V2 ran before the convergence. Kept verbatim so "nothing lost
# coverage" is checked against the real historical value rather than a
# restatement of whatever the code does now.
_V2_SET_BEFORE_CONVERGENCE = frozenset(
    {
        "TOKEN",
        "JWT",
        "URL_TOKEN_QUERY",
        "COOKIE_SESSION",
        "PRIVATE_KEY_PEM",
        "AWS_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "EXCHANGE_API_SECRET",
        "CRYPTO_WIF_KEY",
        "CRYPTO_XPRV",
        "CRYPTO_SEED_PHRASE",
        "FIELD_SECRET",
        "AUTH_BEARER",
    }
)

_RULES_TEMPLATE = """\
version: 3
redaction:
  field_value_min_len: 12
{relaxed}
  pii_patterns:
    - id: TOKEN
      regex: 'sk-[A-Za-z0-9]{{10,}}'
    - id: EMAIL
      regex: '[a-z]+@[a-z]+\\.com'
    - id: COOKIE_SESSION
      regex: 'sid=[a-z0-9]{{8,}}'
"""


def _write_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relaxed: str) -> None:
    path = tmp_path / "security_filters.yaml"
    path.write_text(_RULES_TEMPLATE.format(relaxed=relaxed), encoding="utf-8")
    monkeypatch.setattr(settings, "security_rules_path", str(path), raising=False)
    invalidate_security_rules_cache()
    for name in (
        "_v2_redaction_patterns",
        "_v2_relaxed_redaction_patterns",
        "_pii_pattern_ids",
    ):
        getattr(v2_router, name).cache_clear()


@pytest.fixture(autouse=True)
def _restore_rules_cache():
    yield
    invalidate_security_rules_cache()
    for name in (
        "_v2_redaction_patterns",
        "_v2_relaxed_redaction_patterns",
        "_pii_pattern_ids",
    ):
        getattr(v2_router, name).cache_clear()


# ── the convergence itself ──────────────────────────────────────────────


def test_v2_follows_relaxed_pii_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_rules(
        tmp_path, monkeypatch, "  relaxed_pii_ids:\n    - TOKEN\n    - COOKIE_SESSION\n"
    )
    assert "COOKIE_SESSION" in v2_router.v2_effective_pii_ids()
    assert "EMAIL" not in v2_router.v2_effective_pii_ids()

    _write_rules(tmp_path, monkeypatch, "  relaxed_pii_ids:\n    - TOKEN\n")
    assert "COOKIE_SESSION" not in v2_router.v2_effective_pii_ids()


def test_v2_honours_the_all_wildcard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``relaxed_pii_ids: ["*"]`` documented "run everything" — it now does on V2 too."""
    _write_rules(tmp_path, monkeypatch, '  relaxed_pii_ids: ["*"]\n')
    effective = v2_router.v2_effective_pii_ids()
    assert {"TOKEN", "EMAIL", "COOKIE_SESSION"} <= effective


def test_v2_field_layer_is_not_gated_by_the_pii_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shrinking the PII set to nothing must not disable field redaction."""
    _write_rules(tmp_path, monkeypatch, "  relaxed_pii_ids: []\n")
    effective = v2_router.v2_effective_pii_ids()
    assert {"FIELD_SECRET", "AUTH_BEARER"} <= effective
    assert "TOKEN" not in effective


def test_the_old_hard_coded_constant_is_gone() -> None:
    assert not hasattr(v2_router, "V2_RELAXED_PII_IDS")
    assert not hasattr(v2_router, "_V2_RELAXED_PII_IDS")


# ── the condition that made the merge safe ──────────────────────────────


def test_no_side_lost_coverage_against_the_shipped_rules() -> None:
    """Neither V1 nor V2 runs fewer patterns than it did before the merge.

    The merge direction was chosen from this: V2's set was V1's plus
    COOKIE_SESSION, so folding that one id into the shared default let both
    sides converge upward. If someone later narrows the default, this fails.
    """
    shipped = yaml.safe_load(_SHIPPED_RULES.read_text(encoding="utf-8"))
    declared_ids = {
        str(item.get("id", "")).upper()
        for item in shipped["redaction"]["pii_patterns"]
        if isinstance(item, dict)
    }
    # Only the ids that exist as pii_patterns are comparable; FIELD_SECRET and
    # AUTH_BEARER come from field_value_patterns and are always-on on both sides.
    old_v2_pii = _V2_SET_BEFORE_CONVERGENCE & declared_ids
    assert old_v2_pii <= DEFAULT_RELAXED_PII_IDS, (
        "the shared default no longer covers everything V2 used to redact: "
        f"{sorted(old_v2_pii - DEFAULT_RELAXED_PII_IDS)}"
    )


def test_cookie_session_is_in_the_shared_default() -> None:
    """The one id the merge moved. Dropping it is a V2 coverage regression."""
    assert "COOKIE_SESSION" in DEFAULT_RELAXED_PII_IDS


def test_shipped_rules_declare_every_default_relaxed_id() -> None:
    """A default id with no matching pattern is a silent no-op."""
    shipped = yaml.safe_load(_SHIPPED_RULES.read_text(encoding="utf-8"))
    declared = {
        str(item.get("id", "")).upper()
        for item in shipped["redaction"]["pii_patterns"]
        if isinstance(item, dict)
    }
    assert DEFAULT_RELAXED_PII_IDS <= declared, (
        f"relaxed default references undeclared ids: "
        f"{sorted(DEFAULT_RELAXED_PII_IDS - declared)}"
    )


# ── end-to-end through the real redaction entry point ───────────────────


def test_v2_redacts_a_cookie_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_rules(
        tmp_path, monkeypatch, "  relaxed_pii_ids:\n    - TOKEN\n    - COOKIE_SESSION\n"
    )
    redacted, count, hits, _ = v2_router._redact_text("sid=abc12345xyz")
    assert count == 1
    assert "COOKIE_SESSION" in {h.upper() for h in hits}
    assert "abc12345xyz" not in redacted


def test_removing_an_id_from_the_yaml_stops_v2_redacting_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The behaviour the hard-coded set made impossible."""
    _write_rules(tmp_path, monkeypatch, "  relaxed_pii_ids:\n    - TOKEN\n")
    redacted, count, _, _ = v2_router._redact_text("sid=abc12345xyz")
    assert count == 0
    assert redacted == "sid=abc12345xyz"


def test_hot_reload_clears_every_rules_derived_cache() -> None:
    """A cache left out of the invalidation list serves the previous rules file."""
    import inspect

    from aegisgate.core.hot_reload import _clear_v2_lru_caches

    cached = {
        name
        for name, obj in inspect.getmembers(v2_router)
        if hasattr(obj, "cache_clear") and name.startswith("_")
    }
    rules_derived = {
        name
        for name in cached
        if re.search(r"pattern|redaction|pii", name)
    }
    source = inspect.getsource(_clear_v2_lru_caches)
    missing = {name for name in rules_derived if name not in source}
    assert not missing, (
        f"rules-derived caches not cleared on hot reload: {sorted(missing)}"
    )
