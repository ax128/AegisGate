"""R8.3: field-rule semantics are the same on every redaction layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisgate.adapters.openai_compat import sanitize
from aegisgate.adapters.v2_proxy import router as v2_router
from aegisgate.config.field_patterns import (
    FIELD_FALLBACK_TEMPLATES,
    compile_field_value_patterns,
    field_pattern_entries,
)
from aegisgate.config.security_rules import invalidate_security_rules_cache
from aegisgate.config.settings import settings
from aegisgate.core.rules_write import compile_redaction_layers
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.kv import KVStore


class _MemoryKVStore(KVStore):
    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        return None

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return {}

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return {}

    def prune_pending_confirmations(self, now_ts: int) -> int:
        return 0

    def clear_all_pending_confirmations(self) -> int:
        return 0

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _REPO_ROOT / "aegisgate"
_SKIP_DIR_NAMES = {"tests", "__pycache__", ".pytest_cache"}
_FALLBACK_NEEDLE = r"password|passwd|client[_-]?secret"


def _clear_runtime_caches() -> None:
    invalidate_security_rules_cache()
    sanitize._responses_function_output_redaction_patterns.cache_clear()
    sanitize._responses_relaxed_redaction_patterns.cache_clear()
    sanitize._field_value_pattern_ids.cache_clear()
    sanitize._credential_only_patterns.cache_clear()
    for name in (
        "_v2_redaction_patterns",
        "_v2_relaxed_redaction_patterns",
        "_pii_pattern_ids",
    ):
        getattr(v2_router, name).cache_clear()


@pytest.fixture(autouse=True)
def _restore_caches():
    _clear_runtime_caches()
    yield
    _clear_runtime_caches()


def _write_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    path = tmp_path / "security_filters.yaml"
    path.write_text(body, encoding="utf-8")
    monkeypatch.setattr(settings, "security_rules_path", str(path), raising=False)
    _clear_runtime_caches()


# ── the leak that made this item real ───────────────────────────────────


def test_chat_forward_relaxed_set_redacts_labelled_api_key() -> None:
    """Conversation forward used to drop FIELD_SECRET via relaxed_pii_ids."""
    cleaned, hits = sanitize._sanitize_text_for_upstream_with_hits(
        "api_key: supersecretvalue12345",
        role="user",
        path="messages[0].content",
        field="content",
        relaxed_patterns=True,
    )
    assert "supersecretvalue12345" not in cleaned
    assert any(hit["pattern"] == "FIELD_SECRET" for hit in hits)


def test_chat_forward_relaxed_set_redacts_authorization_bearer() -> None:
    cleaned, hits = sanitize._sanitize_text_for_upstream_with_hits(
        "Authorization: Bearer supersecretvalue12345",
        role="user",
        path="messages[0].content",
        field="content",
        relaxed_patterns=True,
    )
    assert "supersecretvalue12345" not in cleaned
    assert any(hit["pattern"] == "AUTH_BEARER" for hit in hits)


def test_relaxed_pii_still_leaves_email_on_the_conversation_route() -> None:
    """Closing the field hole must not widen the PII relaxed default."""
    cleaned, hits = sanitize._sanitize_text_for_upstream_with_hits(
        "reach me at alice@example.com please",
        role="user",
        path="p",
        field="f",
        relaxed_patterns=True,
    )
    assert "alice@example.com" in cleaned
    assert hits == []


# ── explicit list replaces fallback ─────────────────────────────────────


def test_an_explicit_field_list_replaces_the_code_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_rules(
        tmp_path,
        monkeypatch,
        """\
version: 3
redaction:
  field_value_min_len: 12
  field_value_patterns:
    - id: CUSTOM_FIELD
      regex: 'custom-[0-9]{4}'
  pii_patterns:
    - id: TOKEN
      regex: 'sk-[A-Za-z0-9]{10,}'
""",
    )
    pipeline_ids = {pid for pid, _ in RedactionFilter(_MemoryKVStore())._field_patterns}
    forward_ids = set(sanitize._field_value_pattern_ids())
    v2_ids = {pid for pid, _ in v2_router._v2_redaction_patterns()}
    assert pipeline_ids == {"CUSTOM_FIELD"}
    assert forward_ids == {"CUSTOM_FIELD"}
    assert "CUSTOM_FIELD" in v2_ids
    assert "FIELD_SECRET" not in pipeline_ids | forward_ids | v2_ids
    assert "AUTH_BEARER" not in pipeline_ids | forward_ids
    assert "field_secret" not in v2_ids
    assert "auth_bearer" not in v2_ids


def test_field_value_min_len_below_the_floor_becomes_eight_on_every_layer() -> None:
    data = {
        "redaction": {
            "field_value_min_len": 4,
            "pii_patterns": [{"id": "SEED", "regex": "seed-pattern"}],
        }
    }
    signature, failures = compile_redaction_layers(data)
    assert failures == []
    for layer in ("v1_pipeline", "v1_forward", "v2_request"):
        regex = dict(signature[layer])["FIELD_SECRET"]
        assert "{8,}" in regex
        assert "{12,}" not in regex
        assert "{4,}" not in regex


def test_compile_redaction_layers_field_ids_match_across_layers() -> None:
    data = {
        "redaction": {
            "pii_patterns": [{"id": "SEED", "regex": "seed-pattern"}],
            "field_value_patterns": [{"regex": "explicit-field"}, "legacy-field"],
        }
    }
    signature, failures = compile_redaction_layers(data)
    assert failures == []
    field_ids = {
        layer: [name for name, _ in entries if name.upper() != "SEED"]
        for layer, entries in signature.items()
    }
    assert field_ids["v1_pipeline"] == ["FIELD_SECRET_1", "FIELD_SECRET_2"]
    assert field_ids["v1_forward"] == ["FIELD_SECRET_1", "FIELD_SECRET_2"]
    assert field_ids["v2_request"] == ["FIELD_SECRET_1", "FIELD_SECRET_2"]


def test_unlabelled_and_legacy_entries_share_the_positional_id() -> None:
    entries = field_pattern_entries(
        {"field_value_patterns": [{"regex": "a+"}, "legacy-x"]}
    )
    assert [pattern_id for pattern_id, _ in entries] == [
        "FIELD_SECRET_1",
        "FIELD_SECRET_2",
    ]


def test_runtime_sites_call_the_shared_compiler() -> None:
    for relative in (
        "filters/redaction.py",
        "adapters/openai_compat/sanitize.py",
        "adapters/v2_proxy/router.py",
        "core/rules_write.py",
    ):
        text = (_SRC_ROOT / relative).read_text(encoding="utf-8")
        assert "compile_field_value_patterns" in text or "field_pattern_entries" in text, relative


def test_fallback_field_templates_live_in_one_module() -> None:
    hits: list[str] = []
    for path in _SRC_ROOT.rglob("*.py"):
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if _FALLBACK_NEEDLE in path.read_text(encoding="utf-8"):
            hits.append(str(path.relative_to(_SRC_ROOT)))
    assert hits == ["config/field_patterns.py"]


def test_compile_helper_matches_the_templates() -> None:
    compiled = {pid: pat.pattern for pid, pat in compile_field_value_patterns({})}
    expected = {
        pattern_id: template.format(min_len=12)
        for pattern_id, template in FIELD_FALLBACK_TEMPLATES
    }
    assert compiled == expected
