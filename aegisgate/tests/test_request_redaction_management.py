"""Tests for managing request-side redaction from the console.

Two things make this more than CRUD.

First, ``enabled`` finally means something. Shipping the runtime half without
the UI half would leave a rule disabled with no way to bring it back; shipping
the UI half first would grey out a row whose pattern still redacts traffic. Both
land here, and every compile site plus the panel read one shared predicate.

Second, ``relaxed_pii_ids`` has three modes and the conversions between them are
not symmetric. "Use the code default" is the *absence* of the key, so switching
back deletes it rather than writing today's set — writing it would freeze a value
that is supposed to track the code. Going the other way materialises a snapshot
and must be asked for explicitly, because it is the same freeze in reverse.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.config.security_rules import DEFAULT_RELAXED_PII_IDS, rule_enabled
from aegisgate.config.settings import settings
from aegisgate.core import gateway_ui_routes, gw_tokens, rules_write
from aegisgate.storage.kv import KVStore

_SETTINGS = "/__ui__/api/request_redaction/settings"

_RULES = """\
version: 3
redaction:
  # the policy this file documents
  request_prefix_max_len: 12
  normalize_nfkc: true
  strip_invisible_chars: true
  field_value_min_len: 12
  relaxed_pii_ids:
    - TOKEN
    - FIELD_SECRET
    - LEFTOVER_RULE
  pii_patterns:
    - id: TOKEN
      regex: 'sk-[A-Za-z0-9]{10,}'
    - id: EMAIL
      regex: 'a@b'
action_map:
  sanitizer:
    dangerous_command: block
"""

_AUDIT: list[dict] = []


class _MemoryKVStore(KVStore):
    """Enough of the store for RedactionFilter's constructor."""

    def set_mapping(self, session_id, request_id, mapping) -> None:  # pragma: no cover
        return None

    def get_mapping(self, session_id, request_id) -> dict[str, str]:  # pragma: no cover
        return {}

    def consume_mapping(self, session_id, request_id) -> dict[str, str]:  # pragma: no cover
        return {}


@pytest.fixture()
def rules_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "security_filters.yaml"
    path.write_text(_RULES, encoding="utf-8")
    monkeypatch.setattr(settings, "security_rules_path", str(path), raising=False)
    monkeypatch.setattr(rules_write, "write_audit", lambda payload: _AUDIT.append(payload))
    monkeypatch.setattr(gw_tokens, "list_tokens", lambda: {})
    _AUDIT.clear()
    return path


@pytest.fixture()
def client(rules_file: Path):
    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    with TestClient(app) as c:
        c.rules_path = rules_file  # type: ignore[attr-defined]
        yield c


def _etag(client) -> str:
    return client.get(_SETTINGS).headers["etag"]


def _patch(client, body: dict, etag: str | None = None):
    return client.patch(_SETTINGS, json=body, headers={"If-Match": etag or _etag(client)})


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _comments(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("#")
    ]


# ---------------------------------------------------------------------------


class TestIfMatchIsRequired:
    """New endpoint, no client predates the header — so it is demanded, not honoured."""

    @pytest.mark.parametrize("headers", [{}, {"If-Match": "*"}])
    def test_missing_or_wildcard_is_refused(self, client, headers) -> None:
        response = client.patch(
            _SETTINGS, json={"relaxed": {"operation": "set_mode", "mode": "all"}}, headers=headers
        )
        assert response.status_code == 428
        assert response.json()["error"] == "if_match_required"

    def test_a_stale_validator_is_a_conflict(self, client, rules_file: Path) -> None:
        stale = _etag(client)
        assert _patch(client, {"values": {"normalize_nfkc": False}}, stale).status_code == 200
        response = _patch(client, {"values": {"strip_invisible_chars": False}}, stale)
        assert response.status_code == 409
        assert response.json()["error"] == "etag_mismatch"

    def test_the_existing_rules_endpoints_keep_their_contract(self, client) -> None:
        """v4 §4.3: demanding If-Match there would break every script that omits it."""
        assert client.post(
            "/__ui__/api/rules/injection_detector.direct_patterns",
            json={"id": "NO_HEADER", "regex": "n"},
        ).status_code == 201


class TestRelaxedModes:
    def test_switching_to_default_deletes_the_key(self, client, rules_file: Path) -> None:
        """Writing today's default set back would freeze it — the opposite of the point."""
        before = _comments(rules_file)
        assert _patch(
            client, {"relaxed": {"operation": "set_mode", "mode": "default"}}
        ).status_code == 200
        assert "relaxed_pii_ids" not in _yaml(rules_file)["redaction"]
        assert client.get(_SETTINGS).json()["relaxed_mode"] == "default"
        assert _comments(rules_file) == before

    def test_switching_to_all_writes_the_wildcard(self, client, rules_file: Path) -> None:
        assert _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all"}}).status_code == 200
        assert _yaml(rules_file)["redaction"]["relaxed_pii_ids"] == ["*"]
        body = client.get(_SETTINGS).json()
        assert body["relaxed_mode"] == "all"
        assert all(rule["relaxed_editable"] is False for rule in body["pii_rules"])

    def test_custom_cannot_be_requested_through_set_mode(self, client) -> None:
        response = _patch(client, {"relaxed": {"operation": "set_mode", "mode": "custom"}})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_mode"

    def test_the_wildcard_cannot_be_smuggled_in_as_a_member(self, client) -> None:
        response = _patch(
            client, {"relaxed": {"operation": "set_membership", "id": "*", "enabled": True}}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "unknown_pii_id"

    def test_editing_a_row_under_all_is_refused(self, client) -> None:
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all"}})
        response = _patch(
            client, {"relaxed": {"operation": "set_membership", "id": "EMAIL", "enabled": True}}
        )
        assert response.status_code == 409
        assert response.json()["error"] == "relaxed_all_readonly"


class TestMaterialize:
    def test_all_to_custom_expands_the_full_configured_set(self, client, rules_file: Path) -> None:
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all"}})
        response = _patch(
            client,
            {"relaxed": {"operation": "materialize_custom", "source": "current", "confirm": True}},
        )
        assert response.status_code == 200
        written = _yaml(rules_file)["redaction"]["relaxed_pii_ids"]
        # The full configured set: PII ids plus the field ids, code fallbacks
        # included — the same set that decides "is this a known id?".
        assert set(written) == {"TOKEN", "EMAIL", "FIELD_SECRET", "AUTH_BEARER"}

    def test_expansion_without_confirmation_is_refused(self, client) -> None:
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all"}})
        response = _patch(
            client, {"relaxed": {"operation": "materialize_custom", "source": "current"}}
        )
        assert response.status_code == 409
        assert response.json()["error"] == "confirm_required"

    def test_default_to_custom_needs_an_explicit_conversion(self, client, rules_file: Path) -> None:
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "default"}})
        refused = _patch(
            client, {"relaxed": {"operation": "set_membership", "id": "EMAIL", "enabled": True}}
        )
        assert refused.status_code == 409
        assert refused.json()["error"] == "materialize_required"
        assert sorted(refused.json()["would_materialize"]) == sorted(DEFAULT_RELAXED_PII_IDS)
        assert "relaxed_pii_ids" not in _yaml(rules_file)["redaction"]

        accepted = _patch(
            client,
            {
                "relaxed": {
                    "operation": "set_membership",
                    "id": "EMAIL",
                    "enabled": True,
                    "confirm_materialize": True,
                }
            },
        )
        assert accepted.status_code == 200
        written = _yaml(rules_file)["redaction"]["relaxed_pii_ids"]
        assert set(written) == set(DEFAULT_RELAXED_PII_IDS) | {"EMAIL"}

    def test_materialising_an_already_custom_list_is_refused(self, client) -> None:
        response = _patch(
            client,
            {"relaxed": {"operation": "materialize_custom", "source": "current", "confirm": True}},
        )
        assert response.status_code == 409
        assert response.json()["error"] == "already_custom"


class TestMembershipIsIncremental:
    def test_unoperated_field_and_dangling_members_are_preserved(
        self, client, rules_file: Path
    ) -> None:
        """The panel edits PII rows; it must not quietly drop the rest of the list."""
        assert _patch(
            client, {"relaxed": {"operation": "set_membership", "id": "EMAIL", "enabled": True}}
        ).status_code == 200
        written = _yaml(rules_file)["redaction"]["relaxed_pii_ids"]
        assert "FIELD_SECRET" in written  # a field id, not editable from this panel
        assert "LEFTOVER_RULE" in written  # unresolved, removable only on purpose
        assert "EMAIL" in written

    def test_removing_a_member_leaves_the_others_alone(self, client, rules_file: Path) -> None:
        assert _patch(
            client, {"relaxed": {"operation": "set_membership", "id": "TOKEN", "enabled": False}}
        ).status_code == 200
        written = _yaml(rules_file)["redaction"]["relaxed_pii_ids"]
        assert written == ["FIELD_SECRET", "LEFTOVER_RULE"]

    def test_an_unknown_id_is_refused(self, client) -> None:
        response = _patch(
            client, {"relaxed": {"operation": "set_membership", "id": "NEVER_HEARD", "enabled": True}}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "unknown_pii_id"

    def test_a_dangling_member_cannot_be_dropped_by_set_membership(self, client) -> None:
        response = _patch(
            client,
            {"relaxed": {"operation": "set_membership", "id": "LEFTOVER_RULE", "enabled": False}},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "unknown_pii_id"

    def test_removing_a_dangling_member_has_its_own_operation(
        self, client, rules_file: Path
    ) -> None:
        response = _patch(
            client,
            {"relaxed": {"operation": "remove_unresolved", "id": "LEFTOVER_RULE", "confirm": True}},
        )
        assert response.status_code == 200
        assert "LEFTOVER_RULE" not in _yaml(rules_file)["redaction"]["relaxed_pii_ids"]

    def test_remove_unresolved_refuses_a_configured_id(self, client) -> None:
        response = _patch(
            client, {"relaxed": {"operation": "remove_unresolved", "id": "TOKEN", "confirm": True}}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "id_not_unresolved"

    def test_emptying_the_list_needs_a_second_confirmation(
        self, client, rules_file: Path
    ) -> None:
        rules_file.write_text(
            _RULES.replace("    - FIELD_SECRET\n    - LEFTOVER_RULE\n", ""), encoding="utf-8"
        )
        refused = _patch(
            client, {"relaxed": {"operation": "set_membership", "id": "TOKEN", "enabled": False}}
        )
        assert refused.status_code == 409
        assert refused.json()["error"] == "confirm_empty_required"
        assert _yaml(rules_file)["redaction"]["relaxed_pii_ids"] == ["TOKEN"]

        accepted = _patch(
            client,
            {
                "relaxed": {
                    "operation": "set_membership",
                    "id": "TOKEN",
                    "enabled": False,
                    "confirm_empty": True,
                }
            },
        )
        assert accepted.status_code == 200
        assert _yaml(rules_file)["redaction"]["relaxed_pii_ids"] == []
        assert any(event.get("relaxed_operation") == "set_membership" for event in _AUDIT)


class TestNormalizationConflicts:
    def test_a_case_only_duplicate_blocks_membership_writes(
        self, client, rules_file: Path
    ) -> None:
        rules_file.write_text(
            _RULES.replace("    - id: EMAIL\n", "    - id: Token\n"), encoding="utf-8"
        )
        response = _patch(
            client, {"relaxed": {"operation": "set_membership", "id": "TOKEN", "enabled": False}}
        )
        assert response.status_code == 409
        assert response.json()["error"] == "id_normalization_conflict"
        # Nothing was chosen on the admin's behalf.
        assert _yaml(rules_file)["redaction"]["relaxed_pii_ids"][0] == "TOKEN"


class TestScalarValues:
    def test_the_three_values_are_written(self, client, rules_file: Path) -> None:
        response = _patch(
            client,
            {
                "values": {
                    "normalize_nfkc": False,
                    "strip_invisible_chars": False,
                    "request_prefix_max_len": 20,
                }
            },
        )
        assert response.status_code == 200
        redaction = _yaml(rules_file)["redaction"]
        assert redaction["normalize_nfkc"] is False
        assert redaction["request_prefix_max_len"] == 20

    @pytest.mark.parametrize("value", [0, -1, 65, "12", 1.5, True])
    def test_out_of_range_and_wrong_types_are_refused_before_the_write(
        self, client, rules_file: Path, value
    ) -> None:
        before = rules_file.read_bytes()
        response = _patch(client, {"values": {"request_prefix_max_len": value}})
        assert response.status_code == 400
        assert response.json()["error"] in {"out_of_range", "invalid_type"}
        assert rules_file.read_bytes() == before

    def test_a_bool_must_be_a_json_bool(self, client) -> None:
        response = _patch(client, {"values": {"normalize_nfkc": "true"}})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_type"

    def test_unknown_fields_are_refused(self, client) -> None:
        assert _patch(client, {"values": {"nope": 1}}).status_code == 400
        assert _patch(client, {"nope": {}}).status_code == 400
        assert _patch(client, {"relaxed": {"operation": "nope"}}).status_code == 400
        assert (
            _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all", "x": 1}}).status_code
            == 400
        )

    def test_several_fields_land_in_one_write(self, client, rules_file: Path) -> None:
        before = len(list(rules_file.parent.glob(f"{rules_file.name}.bak-*")))
        assert _patch(
            client,
            {
                "values": {"request_prefix_max_len": 16},
                "relaxed": {"operation": "set_mode", "mode": "all"},
            },
        ).status_code == 200
        redaction = _yaml(rules_file)["redaction"]
        assert redaction["request_prefix_max_len"] == 16
        assert redaction["relaxed_pii_ids"] == ["*"]
        # One transaction, therefore exactly one backup.
        assert len(list(rules_file.parent.glob(f"{rules_file.name}.bak-*"))) == before + 1


class TestCommentsSurviveEveryOperation:
    def test_mode_changes_keep_the_file_documented(self, client, rules_file: Path) -> None:
        before = _comments(rules_file)
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "default"}})
        _patch(
            client,
            {
                "relaxed": {
                    "operation": "set_membership",
                    "id": "EMAIL",
                    "enabled": True,
                    "confirm_materialize": True,
                }
            },
        )
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all"}})
        _patch(client, {"values": {"request_prefix_max_len": 30}})
        assert _comments(rules_file) == before


class TestEnabledFlag:
    def test_the_flag_is_written_as_a_real_bool(self, client, rules_file: Path) -> None:
        """Through the string-extras path it would land as the YAML scalar "False"."""
        assert client.patch(
            "/__ui__/api/rules/redaction.pii_patterns/EMAIL", json={"enabled": False}
        ).status_code == 200
        rules = _yaml(rules_file)["redaction"]["pii_patterns"]
        entry = next(item for item in rules if item["id"] == "EMAIL")
        assert entry["enabled"] is False
        assert "enabled: false" in rules_file.read_text(encoding="utf-8")

    def test_a_non_bool_is_refused(self, client) -> None:
        response = client.patch(
            "/__ui__/api/rules/redaction.pii_patterns/EMAIL", json={"enabled": "false"}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_type"

    def test_disabling_then_re_enabling_round_trips(self, client, rules_file: Path) -> None:
        client.patch("/__ui__/api/rules/redaction.pii_patterns/EMAIL", json={"enabled": False})
        assert client.get(_SETTINGS).json()["pii_rules"]
        client.patch("/__ui__/api/rules/redaction.pii_patterns/EMAIL", json={"enabled": True})
        body = client.get(_SETTINGS).json()
        email = next(rule for rule in body["pii_rules"] if rule["id"] == "EMAIL")
        assert email["enabled"] is True
        assert email["effective_surfaces"]["v1_pipeline_other"] is True

    def test_disabling_keeps_the_relaxed_membership(self, client, rules_file: Path) -> None:
        client.patch("/__ui__/api/rules/redaction.pii_patterns/TOKEN", json={"enabled": False})
        assert "TOKEN" in _yaml(rules_file)["redaction"]["relaxed_pii_ids"]
        token = next(
            rule for rule in client.get(_SETTINGS).json()["pii_rules"] if rule["id"] == "TOKEN"
        )
        assert token["relaxed_member"] is True
        assert token["enabled"] is False


class TestEnabledRuntimeSemantics:
    """All three compile sites honour the flag, and they agree with the panel."""

    def test_the_predicate_is_fail_safe(self) -> None:
        assert rule_enabled({"id": "X"}) is True
        assert rule_enabled({"id": "X", "enabled": None}) is True
        assert rule_enabled({"id": "X", "enabled": True}) is True
        assert rule_enabled({"id": "X", "enabled": False}) is False
        # Anything that is not an explicit boolean false keeps redacting.
        assert rule_enabled({"id": "X", "enabled": "false"}) is True
        assert rule_enabled({"id": "X", "enabled": 0}) is True
        # A legacy bare-string entry has no flag to read.
        assert rule_enabled("legacy-pattern") is True

    def test_the_v1_pipeline_skips_a_disabled_rule(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aegisgate.filters.redaction import RedactionFilter

        rules_file.write_text(
            _RULES.replace(
                "    - id: EMAIL\n      regex: 'a@b'\n",
                "    - id: EMAIL\n      regex: 'a@b'\n      enabled: false\n",
            ),
            encoding="utf-8",
        )
        compiled = {pid for pid, _ in RedactionFilter(_MemoryKVStore())._pii_patterns}
        assert "EMAIL" not in compiled
        assert "TOKEN" in compiled

    def test_the_v1_forward_path_skips_a_disabled_rule(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aegisgate.adapters.openai_compat import sanitize

        rules_file.write_text(
            _RULES.replace(
                "    - id: EMAIL\n      regex: 'a@b'\n",
                "    - id: EMAIL\n      regex: 'a@b'\n      enabled: false\n",
            ),
            encoding="utf-8",
        )
        sanitize._responses_function_output_redaction_patterns.cache_clear()
        try:
            compiled = {pid for pid, _ in sanitize._responses_function_output_redaction_patterns()}
        finally:
            sanitize._responses_function_output_redaction_patterns.cache_clear()
        assert "EMAIL" not in compiled
        assert "TOKEN" in compiled

    def test_v2_skips_a_disabled_rule(self, rules_file: Path) -> None:
        from aegisgate.adapters.v2_proxy import router as v2_router

        rules_file.write_text(
            _RULES.replace(
                "    - id: EMAIL\n      regex: 'a@b'\n",
                "    - id: EMAIL\n      regex: 'a@b'\n      enabled: false\n",
            ),
            encoding="utf-8",
        )
        v2_router._v2_redaction_patterns.cache_clear()
        try:
            compiled = {pid for pid, _ in v2_router._v2_redaction_patterns()}
        finally:
            v2_router._v2_redaction_patterns.cache_clear()
        assert "email" not in compiled
        assert "token" in compiled

    def test_a_legacy_string_field_entry_is_never_asked_for_the_flag(
        self, rules_file: Path
    ) -> None:
        from aegisgate.adapters.v2_proxy import router as v2_router
        from aegisgate.filters.redaction import RedactionFilter

        rules_file.write_text(
            _RULES.replace(
                "  pii_patterns:",
                "  field_value_patterns:\n    - 'legacy-[0-9]{6,}'\n  pii_patterns:",
            ),
            encoding="utf-8",
        )
        assert {pid for pid, _ in RedactionFilter(_MemoryKVStore())._field_patterns} == {
            "FIELD_SECRET"
        }
        v2_router._v2_redaction_patterns.cache_clear()
        try:
            assert "field_secret_1" in {pid for pid, _ in v2_router._v2_redaction_patterns()}
        finally:
            v2_router._v2_redaction_patterns.cache_clear()

    def test_a_disabled_rule_stays_a_configured_id(self, rules_file: Path) -> None:
        """Otherwise every relaxed member naming it starts reporting as unknown."""
        from aegisgate.config.security_rules import configured_redaction_pattern_ids

        rules = yaml.safe_load(
            _RULES.replace(
                "    - id: TOKEN\n      regex: 'sk-[A-Za-z0-9]{10,}'\n",
                "    - id: TOKEN\n      regex: 'sk-[A-Za-z0-9]{10,}'\n      enabled: false\n",
            )
        )["redaction"]
        assert "TOKEN" in configured_redaction_pattern_ids(rules)


class TestDeleteSettlesRelaxedMembership:
    """v4 §3.B: no ``409 rule_referenced``; branch on the relaxed mode instead."""

    def test_a_custom_list_member_is_removed_in_the_same_write(
        self, client, rules_file: Path
    ) -> None:
        response = client.delete("/__ui__/api/rules/redaction.pii_patterns/TOKEN")
        assert response.status_code == 200
        assert response.json()["relaxed_member_removed"] is True
        redaction = _yaml(rules_file)["redaction"]
        assert all(rule["id"] != "TOKEN" for rule in redaction["pii_patterns"])
        assert "TOKEN" not in redaction["relaxed_pii_ids"]
        assert redaction["relaxed_pii_ids"] == ["FIELD_SECRET", "LEFTOVER_RULE"]

    def test_confirm_referenced_keeps_the_dangling_entry(self, client, rules_file: Path) -> None:
        response = client.delete(
            "/__ui__/api/rules/redaction.pii_patterns/TOKEN?confirm_referenced=true"
        )
        assert response.status_code == 200
        assert response.json()["relaxed_dangling"] is True
        assert "TOKEN" in _yaml(rules_file)["redaction"]["relaxed_pii_ids"]

    def test_default_mode_deletes_without_forcing_a_migration(
        self, client, rules_file: Path
    ) -> None:
        """Materialising the code default to allow a delete is the freeze we promised not to do."""
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "default"}})
        response = client.delete("/__ui__/api/rules/redaction.pii_patterns/TOKEN")
        assert response.status_code == 200
        assert response.json()["relaxed_dangling"] is True
        assert "无害悬空引用" in response.json()["note"]
        assert "relaxed_pii_ids" not in _yaml(rules_file)["redaction"]
        assert any(event.get("relaxed_dangling") for event in _AUDIT)

    def test_emptying_the_list_by_deleting_needs_confirmation(
        self, client, rules_file: Path
    ) -> None:
        rules_file.write_text(
            _RULES.replace("    - FIELD_SECRET\n    - LEFTOVER_RULE\n", ""), encoding="utf-8"
        )
        refused = client.delete("/__ui__/api/rules/redaction.pii_patterns/TOKEN")
        assert refused.status_code == 409
        assert refused.json()["error"] == "confirm_empty_required"
        assert _yaml(rules_file)["redaction"]["relaxed_pii_ids"] == ["TOKEN"]

        accepted = client.delete(
            "/__ui__/api/rules/redaction.pii_patterns/TOKEN?confirm_empty=true"
        )
        assert accepted.status_code == 200
        assert _yaml(rules_file)["redaction"]["relaxed_pii_ids"] == []

    def test_the_all_mode_delete_produces_no_dangling_id(self, client, rules_file: Path) -> None:
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all"}})
        assert client.delete("/__ui__/api/rules/redaction.pii_patterns/TOKEN").status_code == 200
        assert _yaml(rules_file)["redaction"]["relaxed_pii_ids"] == ["*"]

    def test_the_delete_consequence_is_decided_server_side(self, client) -> None:
        rules = {rule["id"]: rule for rule in client.get(_SETTINGS).json()["pii_rules"]}
        assert rules["TOKEN"]["relaxed_reference"] == "custom_list"
        assert rules["EMAIL"]["relaxed_reference"] == "none"
        assert rules["TOKEN"]["relaxed_removal_empties_list"] is False


class TestProbeAndAuditOnPanelWrites:
    def test_a_catastrophic_regex_cannot_be_added_from_the_panel(
        self, client, rules_file: Path
    ) -> None:
        before = rules_file.read_bytes()
        response = client.post(
            "/__ui__/api/rules/redaction.pii_patterns",
            json={"id": "REDOS", "regex": "(a+)+$"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "regex_probe_timeout"
        assert rules_file.read_bytes() == before

    def test_every_settings_write_is_audited(self, client) -> None:
        _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all"}})
        event = _AUDIT[-1]
        assert event["event"] == "ui_request_redaction_settings_updated"
        assert event["relaxed_operation"] == "set_mode"
        assert event["relaxed_mode_before"] == "custom"
        assert event["relaxed_mode_after"] == "all"
        assert event["result"] == "ok"

    def test_disabling_a_rule_is_audited(self, client) -> None:
        client.patch("/__ui__/api/rules/redaction.pii_patterns/EMAIL", json={"enabled": False})
        event = _AUDIT[-1]
        assert event["event"] == "ui_rule_updated"
        assert event["rule_id"] == "EMAIL"
        assert "enabled" in event["fields"]

    def test_the_audit_carries_no_pattern_text(self, client) -> None:
        client.post(
            "/__ui__/api/rules/redaction.pii_patterns",
            json={"id": "AUDIT_CHECK", "regex": "sk-live-[0-9]{20}"},
        )
        assert "sk-live-" not in yaml.safe_dump(_AUDIT[-1], allow_unicode=True)


class TestPanelResponseAfterAWrite:
    def test_the_patch_returns_the_refreshed_panel(self, client) -> None:
        body = _patch(client, {"relaxed": {"operation": "set_mode", "mode": "all"}}).json()
        assert body["ok"] is True
        assert body["relaxed_mode"] == "all"
        assert body["pii_rules"]

    def test_the_response_etag_is_usable_for_the_next_write(self, client) -> None:
        first = _patch(client, {"values": {"normalize_nfkc": False}})
        second = client.patch(
            _SETTINGS,
            json={"values": {"strip_invisible_chars": False}},
            headers={"If-Match": first.headers["etag"]},
        )
        assert second.status_code == 200
