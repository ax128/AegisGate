"""The forward path must pick its pattern set from the route, not the role.

``_sanitize_text_for_upstream_with_hits`` used to fall back to
``role in _RESPONSES_RELAXED_REDACTION_ROLES`` whenever a caller omitted
``relaxed_patterns`` — and that frozenset held *every* role a real request
carries, so "derive from role" meant "always relaxed", on every route. The
pipeline picks by route, so on any route not on the low-false-positive list the
two layers disagreed: scoring saw the full set while the pass that actually
rewrote the outbound body saw the relaxed one.

Multipart was the surface where that mattered. ``/v1/files`` and
``/v1/images/*`` are not low-false-positive routes, so form fields were scored
with 56 patterns and forwarded having been rewritten with 13.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from aegisgate.adapters.openai_compat import sanitize
from aegisgate.config.security_rules import is_low_false_positive_route

_SANITIZE_SRC = Path(sanitize.__file__).read_text(encoding="utf-8")
_ROUTER_SRC = (
    Path(sanitize.__file__).parent / "router.py"
).read_text(encoding="utf-8")

# A value only the full set catches: EMAIL is a shipped pii_pattern and is not
# in the credential-only relaxed default.
_FULL_ONLY = "reach me at alice@example.com please"
# A credential in the relaxed default, so both sets catch it. Deliberately a
# pii_patterns id: field_value_patterns are a separate layer that the V1 forward
# path filters through the relaxed set too, so AUTH_BEARER/FIELD_SECRET are off
# there by default — a real asymmetry, but R8 item 3's, not this change's.
_RELAXED_TOO = "token sk-abcdefghijklmnopqrstuvwxyz1234"


# ── the fallback is gone ────────────────────────────────────────────────


def test_relaxed_patterns_is_required() -> None:
    """A caller that forgets it must fail loudly, not silently get "relaxed"."""
    sig = inspect.signature(sanitize._sanitize_text_for_upstream_with_hits)
    param = sig.parameters["relaxed_patterns"]
    assert param.default is inspect.Parameter.empty
    assert param.kind is inspect.Parameter.KEYWORD_ONLY


def test_structured_node_walker_also_requires_it() -> None:
    sig = inspect.signature(sanitize._sanitize_structured_node)
    assert sig.parameters["relaxed_patterns"].default is inspect.Parameter.empty


def test_the_role_derived_set_is_gone() -> None:
    assert not hasattr(sanitize, "_RESPONSES_RELAXED_REDACTION_ROLES")
    assert "_RESPONSES_RELAXED_REDACTION_ROLES" not in _SANITIZE_SRC


def test_entry_points_take_a_route_not_a_bool() -> None:
    """Route in, pattern set out — the mapping has one implementation.

    Passing a bool would put the route→set mapping at each call site, which is
    how the forward and pipeline layers drifted apart to begin with.
    """
    for name in (
        "_sanitize_chat_messages_for_upstream_with_hits",
        "_sanitize_messages_system_for_upstream_with_hits",
        "_sanitize_instructions_for_upstream_with_hits",
        "_sanitize_tool_definitions_for_upstream_with_hits",
        "_sanitize_responses_input_for_upstream_with_hits",
    ):
        sig = inspect.signature(getattr(sanitize, name))
        assert "route" in sig.parameters, name
        assert sig.parameters["route"].default is inspect.Parameter.empty, name


# ── the behaviour that changed ──────────────────────────────────────────


@pytest.mark.parametrize(
    "route", ["/v1/files", "/v1/images/edits", "/v1/images/variations"]
)
def test_multipart_routes_are_not_low_false_positive(route: str) -> None:
    """The premise of the change: these routes score with the full set."""
    assert is_low_false_positive_route(route) is False


def test_full_set_catches_what_relaxed_does_not() -> None:
    """Guards the fixture: if EMAIL ever joins the relaxed default, this tells us."""
    relaxed, _ = sanitize._sanitize_text_for_upstream_with_hits(
        _FULL_ONLY, role="user", path="p", field="f", relaxed_patterns=True
    )
    full, _ = sanitize._sanitize_text_for_upstream_with_hits(
        _FULL_ONLY, role="user", path="p", field="f", relaxed_patterns=False
    )
    assert "alice@example.com" in relaxed
    assert "alice@example.com" not in full


def test_credentials_are_caught_by_both_sets() -> None:
    """The convergence must not weaken the relaxed surfaces."""
    for relaxed in (True, False):
        cleaned, _ = sanitize._sanitize_text_for_upstream_with_hits(
            _RELAXED_TOO, role="user", path="p", field="f", relaxed_patterns=relaxed
        )
        assert "sk-abcdefghijklmnopqrstuvwxyz1234" not in cleaned


def test_multipart_forward_now_uses_the_route(monkeypatch: pytest.MonkeyPatch) -> None:
    """The multipart call site passes the route, not a hard-coded role verdict."""
    assert 'relaxed_patterns=is_low_false_positive_route(request_path)' in _ROUTER_SRC


def test_role_no_longer_changes_the_outcome() -> None:
    """Same text, same route verdict, different roles — identical result.

    Before, role was the only input that decided this.
    """
    outputs = {
        sanitize._sanitize_text_for_upstream_with_hits(
            _FULL_ONLY, role=role, path="p", field="f", relaxed_patterns=False
        )[0]
        for role in ("user", "system", "developer", "assistant", "tool", "unknown")
    }
    assert len(outputs) == 1
    assert "alice@example.com" not in outputs.pop()


# ── the two layers now agree ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("route", "expect_relaxed"),
    [
        ("/v1/chat/completions", True),
        ("/v1/responses", True),
        ("/v1/messages", True),
        ("/v1/files", False),
        ("/v1/images/edits", False),
        ("/v1/embeddings", False),
    ],
)
def test_forward_layer_matches_the_pipeline_verdict(
    route: str, expect_relaxed: bool
) -> None:
    """One rule decides for both layers, so they cannot disagree by construction."""
    assert is_low_false_positive_route(route) is expect_relaxed

    sanitized, _ = sanitize._sanitize_chat_messages_for_upstream_with_hits(
        [{"role": "user", "content": _FULL_ONLY}], route=route
    )
    forwarded = sanitized[0]["content"]
    assert ("alice@example.com" in forwarded) is expect_relaxed


def test_no_forward_call_site_omits_the_pattern_set() -> None:
    """Every call in both modules passes it — omission is now a TypeError anyway.

    Kept as a readable inventory: a new call site that guesses instead of
    threading the route shows up here as a diff, not as a runtime surprise.
    """
    for src, label in ((_SANITIZE_SRC, "sanitize.py"), (_ROUTER_SRC, "router.py")):
        calls = src.count("_sanitize_text_for_upstream_with_hits(")
        passes = src.count("relaxed_patterns=")
        # sanitize.py declares the function too, hence the -1 there.
        declared = 1 if label == "sanitize.py" else 0
        assert passes >= calls - declared, (
            f"{label}: {calls - declared} calls but only {passes} pattern-set args"
        )
