"""Tests for the read-only request-side redaction panel.

The panel's whole reason to exist is that six execution surfaces disagree with
each other and the console never said so. Two claims in particular were wrong
before this: that ``relaxed_pii_ids`` governs "the V1 chat routes" (it also
governs the V1 multipart *forward* path, which is what actually rewrites an
upload's form fields), and that exact-value redaction applies to "V1 and V2
alike".

So these tests pin the payload the browser renders — not the pixels. The rule
they enforce throughout is that the server computes and the panel displays: a
second implementation of "is this rule live on this surface?" in JavaScript would
be free to drift from the one the request path runs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.adapters.v2_proxy.router import v2_effective_pii_ids
from aegisgate.config.settings import settings
from aegisgate.core import gateway_ui_routes, gw_tokens, rules_write
from aegisgate.core.request_redaction_settings import build_settings_payload

_WWW = Path(__file__).resolve().parents[2] / "www"
_INDEX = _WWW / "index.html"
_APP_JS = _WWW / "assets" / "app.js"

_RULES = """\
version: 3
redaction:
  # documented policy
  request_prefix_max_len: 12
  normalize_nfkc: true
  strip_invisible_chars: true
  field_value_min_len: 12
  relaxed_pii_ids:
    - TOKEN
    - LEFTOVER_RULE
  pii_patterns:
    - id: TOKEN
      regex: 'sk-[A-Za-z0-9]{10,}'
    - id: EMAIL
      regex: 'a@b'
    - id: COOKIE_SESSION
      regex: 'sid=[a-z0-9]{8,}'
    - id: RETIRED
      regex: 'retired'
      enabled: false
"""


@pytest.fixture()
def rules_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "security_filters.yaml"
    path.write_text(_RULES, encoding="utf-8")
    monkeypatch.setattr(settings, "security_rules_path", str(path), raising=False)
    monkeypatch.setattr(rules_write, "write_audit", lambda payload: None)
    monkeypatch.setattr(gw_tokens, "list_tokens", lambda: {})
    return path


@pytest.fixture()
def payload(rules_file: Path) -> dict:
    return build_settings_payload()


@pytest.fixture()
def client(rules_file: Path):
    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    with TestClient(app) as c:
        c.rules_path = rules_file  # type: ignore[attr-defined]
        yield c


def _rule(payload: dict, rule_id: str) -> dict:
    return next(rule for rule in payload["pii_rules"] if rule["id"] == rule_id)


class TestEndpoint:
    def test_the_etag_is_the_rules_file_etag(self, client) -> None:
        response = client.get("/__ui__/api/request_redaction/settings")
        assert response.status_code == 200
        rules_etag = client.get("/__ui__/api/rules/pii_patterns").headers["etag"]
        assert response.headers["etag"] == rules_etag

    def test_env_backed_switches_carry_their_own_etag_in_the_body(self, client) -> None:
        """The four master switches live in .env, not in the rules file.

        Folding their ETag into this resource's would make an unrelated .env edit
        look like a rules conflict.
        """
        body = client.get("/__ui__/api/request_redaction/settings").json()
        assert body["env_etag"]
        assert body["env_etag"] != client.get(
            "/__ui__/api/request_redaction/settings"
        ).headers["etag"]


class TestEffectiveSurfaces:
    def test_the_relaxed_set_governs_e1_e3_e4_and_e6(self, payload: dict) -> None:
        """E6 joined the list when V2 stopped carrying its own hard-coded set."""
        governed = payload["relaxed_governed_surfaces"]
        assert governed == [
            "v1_pipeline_chat",
            "v1_forward_chat",
            "v1_forward_multipart",
            "v2_request",
        ]

    def test_multipart_forward_is_governed_by_the_relaxed_set(self, payload: dict) -> None:
        """E4 is the surface v3 of this spec missed entirely.

        The multipart routes are not on the low-false-positive allowlist, so E2
        scores them with the *full* set — but the forward path hard-codes
        ``role="user"``, so what actually gets rewritten uses the relaxed set.
        Dropping an id from ``relaxed_pii_ids`` silently turns off its redaction
        on uploaded form fields.
        """
        surface = next(s for s in payload["surfaces"] if s["code"] == "E4")
        assert surface["id"] == "v1_forward_multipart"
        assert surface["pattern_set"] == "relaxed"

        email = _rule(payload, "EMAIL")  # not in the custom relaxed list
        assert email["effective_surfaces"]["v1_forward_multipart"] is False
        assert email["effective_surfaces"]["v1_pipeline_other"] is True

    def test_chat_forward_notes_the_role_fallback(self, payload: dict) -> None:
        surface = next(s for s in payload["surfaces"] if s["code"] == "E3")
        assert "常规角色 relaxed" in surface["note"]
        assert "非常规角色" in surface["note"]

    def test_generic_json_uses_the_full_set(self, payload: dict) -> None:
        surface = next(s for s in payload["surfaces"] if s["code"] == "E5")
        assert surface["pattern_set"] == "full"
        assert _rule(payload, "EMAIL")["effective_surfaces"]["v1_forward_generic"] is True

    def test_relaxed_membership_moves_every_relaxed_surface_including_v2(
        self, rules_file: Path
    ) -> None:
        """V2 used to be absent from this set — that was the whole divergence."""
        before = build_settings_payload()
        rules_file.write_text(
            _RULES.replace("    - TOKEN\n", "    - TOKEN\n    - EMAIL\n"), encoding="utf-8"
        )
        after = build_settings_payload()

        moved = {
            key
            for key in before["pii_rules"][0]["effective_surfaces"]
            if _rule(before, "EMAIL")["effective_surfaces"][key]
            != _rule(after, "EMAIL")["effective_surfaces"][key]
        }
        assert moved == {
            "v1_pipeline_chat",
            "v1_forward_chat",
            "v1_forward_multipart",
            "v2_request",
        }

    def test_v2_now_follows_the_relaxed_set(self, rules_file: Path) -> None:
        """Dropping an id from relaxed_pii_ids must take it off V2 too.

        Before the convergence this asserted the opposite: V2 carried its own
        hard-coded list, so editing the YAML changed V1 and left V2 running the
        pattern, with nothing in the config surface to reveal it.
        """
        with_cookie = _RULES.replace(
            "    - TOKEN\n", "    - TOKEN\n    - COOKIE_SESSION\n"
        )
        rules_file.write_text(with_cookie, encoding="utf-8")
        before = _rule(build_settings_payload(), "COOKIE_SESSION")["effective_surfaces"]
        assert before["v2_request"] is True

        rules_file.write_text(_RULES, encoding="utf-8")
        after = _rule(build_settings_payload(), "COOKIE_SESSION")["effective_surfaces"]
        assert after["v2_request"] is False
        assert after["v1_pipeline_chat"] is False

    def test_the_v2_set_is_resolved_from_the_live_rules(self, payload: dict) -> None:
        assert payload["v2_effective_ids"] == sorted(v2_effective_pii_ids())
        # The field layer is unconditional on V2, exactly as on the V1 pipeline.
        assert payload["v2_field_ids_in_set"] == ["AUTH_BEARER", "FIELD_SECRET"]


class TestMasterSwitchOverlay:
    def test_enable_redaction_greys_only_the_pipeline_surfaces(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "enable_redaction", False, raising=False)
        overlay = build_settings_payload()["master_switch_overlay"]
        assert overlay["v1_pipeline_chat"]["active"] is False
        assert overlay["v1_pipeline_other"]["active"] is False
        # The forward path has no switch at all — that is what "mandatory
        # baseline" means, and the panel must keep showing it as live.
        for surface in ("v1_forward_chat", "v1_forward_multipart", "v1_forward_generic"):
            assert overlay[surface]["switch"] is None
            assert overlay[surface]["active"] is True

    def test_v2_switch_greys_only_e6(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "v2_enable_request_redaction", False, raising=False)
        overlay = build_settings_payload()["master_switch_overlay"]
        assert overlay["v2_request"]["active"] is False
        assert overlay["v1_pipeline_chat"]["active"] is True

    def test_each_switch_states_the_layer_it_really_controls(self, payload: dict) -> None:
        scopes = payload["master_switch_scopes"]
        assert "不控制" in scopes["enable_redaction"]
        assert "[REDACTED:ID]" in scopes["enable_restoration"]

    def test_the_forward_path_really_survives_enable_redaction_off(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The overlay claims E3/E4/E5 keep running. Check the claim, not the copy."""
        from aegisgate.adapters.openai_compat import sanitize

        monkeypatch.setattr(settings, "enable_redaction", False, raising=False)
        sanitize._responses_function_output_redaction_patterns.cache_clear()
        sanitize._responses_relaxed_redaction_patterns.cache_clear()
        try:
            cleaned, hits = sanitize._sanitize_text_for_upstream_with_hits(
                "key sk-ABCdef123456 trailing",
                role="user",
                path="messages[0].content",
                field="content",
            )
        finally:
            sanitize._responses_function_output_redaction_patterns.cache_clear()
            sanitize._responses_relaxed_redaction_patterns.cache_clear()
        assert "sk-ABCdef123456" not in cleaned
        assert "[REDACTED:TOKEN]" in cleaned
        assert hits

    def test_no_switch_was_added_for_forward_path_redaction(self) -> None:
        """v4 §6.1: this release must not ship a way to turn E3/E4/E5 off."""
        source = (Path(__file__).resolve().parents[1] / "config" / "settings.py").read_text(
            encoding="utf-8"
        )
        assert "enable_request_egress_redaction" not in source


class TestEnabledSemantics:
    """``enabled: false`` now actually stops the rule being compiled."""

    def test_a_disabled_rule_leaves_every_surface(self, payload: dict) -> None:
        assert payload["enabled_semantics_active"] is True
        assert payload["pending_enabled_false_ids"] == []
        retired = _rule(payload, "RETIRED")
        assert retired["enabled"] is False
        assert retired["enabled_runtime"] is False
        assert not any(retired["effective_surfaces"].values())

    def test_disabling_does_not_touch_relaxed_membership(self, payload: dict) -> None:
        """v4 §2.3: the two controls write one dimension each."""
        retired = _rule(payload, "RETIRED")
        assert retired["relaxed_member"] is False
        token = _rule(payload, "TOKEN")
        assert token["relaxed_member"] is True


class TestFieldRules:
    def test_the_three_layers_report_their_own_floor(self, payload: dict) -> None:
        floors = {layer["id"]: layer["floor"] for layer in payload["field"]["layers"]}
        assert floors == {"v1_pipeline": 8, "v1_forward": 8, "v2_request": 12}

    def test_the_layers_report_their_differing_fallback_ids(self, payload: dict) -> None:
        by_id = {layer["id"]: layer for layer in payload["field"]["layers"]}
        assert by_id["v1_pipeline"]["explicit_default_id"] == "FIELD_SECRET"
        assert by_id["v1_forward"]["explicit_default_id"] == "FIELD_SECRET_{idx}"
        assert by_id["v2_request"]["fallback_ids"] == ["field_secret", "auth_bearer"]
        # V2 compiles field entries through the same loop as pii_patterns, so a
        # mapping without an id gets that loop's default rather than a
        # FIELD_SECRET one; only the legacy bare-string form is numbered.
        assert by_id["v2_request"]["explicit_default_id"] == "rule"
        assert by_id["v2_request"]["legacy_string_id"] == "field_secret_{idx}"

    def test_the_v2_layer_states_that_its_fallback_is_not_an_alternative(
        self, payload: dict
    ) -> None:
        """V1 uses the fallback instead of an explicit list; V2 uses both."""
        by_id = {layer["id"]: layer for layer in payload["field"]["layers"]}
        assert "同时" in by_id["v2_request"]["note"]

    def test_relaxed_filtering_differs_across_layers(self, payload: dict) -> None:
        by_id = {layer["id"]: layer for layer in payload["field"]["layers"]}
        assert by_id["v1_pipeline"]["relaxed_filtered"] is False
        assert by_id["v1_forward"]["relaxed_filtered"] is True

    def test_the_section_offers_no_toggle(self, payload: dict) -> None:
        """A per-rule switch here would be a lie: disabling a YAML field rule
        does not stop the V2 fallback from running."""
        assert payload["field"]["editable"] is False

    def test_an_explicit_list_is_flagged_as_disabling_min_len(
        self, rules_file: Path
    ) -> None:
        rules_file.write_text(
            _RULES.replace(
                "  pii_patterns:",
                "  field_value_patterns:\n    - 'legacy-[0-9]{6,}'\n  pii_patterns:",
            ),
            encoding="utf-8",
        )
        field = build_settings_payload()["field"]
        assert field["mode"] == "explicit_yaml"
        assert field["explicit_disables_min_len"] is True
        assert field["explicit_rules"][0]["legacy_string"] is True
        assert field["explicit_rules"][0]["id"] == "FIELD_SECRET_1"


class TestCoverageMatrix:
    def test_multipart_file_content_has_its_own_row(self, payload: dict) -> None:
        row = next(
            row
            for row in payload["coverage_matrix"]
            if row["surface"] == "V1 multipart 文件内容"
        )
        assert row["pii_form"] == "不脱敏、不扫描"
        assert row["exact_value"] == "不生效"
        assert "[BINARY_CONTENT]" in row["note"]

    def test_generic_json_and_multipart_fields_are_not_restorable(self, payload: dict) -> None:
        for surface in ("V1 通用 /v1/<subpath> JSON", "V1 multipart 表单字段"):
            row = next(row for row in payload["coverage_matrix"] if row["surface"] == surface)
            assert row["restorable"] is False
            assert row["pii_form"] == "[REDACTED:ID]"

    def test_v2_exact_value_names_both_switches(self, payload: dict) -> None:
        row = next(
            row for row in payload["coverage_matrix"] if row["surface"].startswith("V2 文本型")
        )
        assert "enable_exact_value_redaction" in row["exact_value"]
        assert "v2_enable_request_redaction" in row["exact_value"]

    def test_the_old_v1_v2_alike_copy_is_gone(self, client) -> None:
        assert "V1/V2 均适用" not in _INDEX.read_text(encoding="utf-8")
        description = client.get("/__ui__/api/redact_values").json()["description"]
        assert "V1/V2 均适用" not in description
        assert "扁平消息文本" in description


class TestExemptions:
    def test_a_denylisted_key_is_marked_v1_ignored_v2_effective(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            gw_tokens,
            "list_tokens",
            lambda: {
                "gw_abcdef123456": {
                    "upstream_base": "https://api.example.com",
                    "whitelist_key": ["access_token", "order_id"],
                }
            },
        )
        keys = build_settings_payload()["exemptions"]["field_whitelist"]["tokens"][0]["keys"]
        by_key = {entry["key"]: entry for entry in keys}
        assert by_key["access_token"]["v1_effective"] is False
        assert by_key["access_token"]["v2_effective"] is True
        assert "token" in by_key["access_token"]["denylist_hits"]
        assert by_key["order_id"]["v1_effective"] is True

    def test_the_upstream_bypass_reports_both_preconditions(self, payload: dict) -> None:
        upstream = payload["exemptions"]["upstream_whitelist"]
        assert "allow_public_upstream_whitelist" in upstream
        assert "requires_internal_client" in upstream
        assert "client_is_internal" in upstream["note"]

    def test_the_field_whitelist_is_not_described_as_a_whole_request_bypass(
        self, payload: dict
    ) -> None:
        for row in payload["exemptions"]["surface_matrix"]:
            assert "整请求" not in row["field_whitelist"]

    def test_each_route_family_reports_its_own_bypass_support(self, payload: dict) -> None:
        matrix = {row["surface"]: row for row in payload["exemptions"]["surface_matrix"]}
        assert matrix["V1 multipart 表单字段"]["upstream_whitelist"] == "不适用"
        assert matrix["V2"]["passthrough"] == "不适用"
        assert "不过 denylist" in matrix["V2"]["field_whitelist"]

    def test_the_client_supplied_header_is_not_listed_as_a_source(self, payload: dict) -> None:
        note = payload["exemptions"]["field_whitelist"]["note"]
        assert "剥离" in note
        assert payload["exemptions"]["field_whitelist"]["client_header_is_stripped"] is True


class TestResolverSelfCheck:
    def test_the_resolved_path_and_its_self_check_are_reported(self, payload: dict) -> None:
        assert payload["rules_file_path"].endswith("security_filters.yaml")
        assert payload["rules_file_resolver_consistent"] is True
        assert payload["shadow_rules_files"] == []


class TestValidatorFreshness:
    """The ETag must never be newer than the payload it validates."""

    def test_the_payload_carries_the_validator_it_was_built_against(
        self, client, rules_file: Path
    ) -> None:
        response = client.get("/__ui__/api/request_redaction/settings")
        assert response.json()["rules_etag"] == response.headers["ETag"]

    def test_a_write_after_the_read_makes_the_next_save_a_conflict(
        self, client, rules_file: Path
    ) -> None:
        """Reading the validator first means a racing write costs a 409, not an
        overwrite of something the console never showed."""
        before = client.get("/__ui__/api/request_redaction/settings").headers["ETag"]
        rules_file.write_text(
            rules_file.read_text(encoding="utf-8") + "\n# someone else\n", encoding="utf-8"
        )
        assert client.get("/__ui__/api/request_redaction/settings").headers["ETag"] != before


class TestNoClientSideDerivation:
    """The badge must be a render of the server's answer, not a second opinion."""

    def test_badges_read_effective_surfaces_directly(self) -> None:
        js = _APP_JS.read_text(encoding="utf-8")
        assert "rule.effective_surfaces[surface.id]" in js

    def test_the_panel_never_recomputes_relaxed_membership(self) -> None:
        js = _APP_JS.read_text(encoding="utf-8")
        panel = js[js.index("// ─── Request-side redaction"):]
        # Reading `relaxed_member` / `relaxed_reference` to draw a column or word
        # a dialog is fine; testing membership against an id list in the browser
        # is the drift this forbids — including in the confirmation copy, where a
        # wrong consequence is worse than none.
        assert "default_relaxed_ids.includes" not in panel
        assert "v2_effective_ids.includes" not in panel
        assert "relaxed_ids_resolved.includes" not in panel
        assert "relaxed_ids_explicit.some" not in panel
        assert "relaxed_ids_explicit.filter" not in panel

    def test_the_stats_card_states_the_real_measure(self) -> None:
        js = _APP_JS.read_text(encoding="utf-8")
        assert "管道层去重后的敏感值替换数（含 PII 与 field 规则，统计期内）" in js
        assert "唯一敏感值个数" in js
        assert "不含 V1 转发层替换、V2 替换与精确值替换" in js


class TestEntriesAfterTheMove:
    def test_the_exact_value_entry_moved_into_the_panel(self) -> None:
        """Its own sidebar entry is gone; the bookmark still lands on the block."""
        html = _INDEX.read_text(encoding="utf-8")
        assert 'href="#redact-values"' not in html
        assert re.search(r'<div id="redact-values" class="panel', html)
        assert re.search(r'<section id="redact-values"', html) is None

    def test_the_moved_block_sits_inside_the_panel(self) -> None:
        html = _INDEX.read_text(encoding="utf-8")
        panel = html[
            html.index('<section id="request-redaction"') : html.index('<section id="rules"')
        ]
        assert 'id="redact-values"' in panel
        # A nested <section> would compete with the panel in the scroll spy,
        # which selects `main section[id]`.
        assert panel.count("<section") == 1

    def test_the_rules_entry_survives_and_follows_the_new_one(self) -> None:
        html = _INDEX.read_text(encoding="utf-8")
        assert 'href="#rules"' in html
        assert html.index('href="#request-redaction"') < html.index('href="#rules"')

    def test_the_pii_group_is_hidden_from_the_rules_workbench(self, client) -> None:
        sections = {s["id"]: s for s in client.get("/__ui__/api/rules").json()["sections"]}
        assert sections["redaction.pii_patterns"]["hidden"] is True
        assert sections["injection_detector.direct_patterns"]["hidden"] is False

    def test_the_crud_endpoints_stay_open_for_the_panel(self, client) -> None:
        """Hidden in the workbench, still driven by the panel."""
        assert client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "STILL_EDITABLE", "regex": "s"}
        ).status_code == 201
        ids = [item["id"] for item in client.get("/__ui__/api/rules/pii_patterns").json()["items"]]
        assert "STILL_EDITABLE" in ids


class TestCollisionBlocking:
    def test_case_only_duplicates_block_writes(self, rules_file: Path) -> None:
        rules_file.write_text(
            _RULES.replace("    - id: EMAIL\n", "    - id: Token\n"), encoding="utf-8"
        )
        payload = build_settings_payload()
        assert payload["write_blocked"] is True
        assert payload["normalized_collisions"][0]["normalized"] == "TOKEN"

    def test_a_dangling_relaxed_member_is_reported_without_blocking(
        self, payload: dict
    ) -> None:
        assert payload["unresolved_ids"] == ["LEFTOVER_RULE"]
        assert payload["write_blocked"] is False


class TestRelaxedModes:
    @pytest.mark.parametrize(
        "value,mode",
        [("", "default"), ('  relaxed_pii_ids: ["*"]\n', "all")],
    )
    def test_modes_are_reported_from_the_file(
        self, rules_file: Path, value: str, mode: str
    ) -> None:
        rules_file.write_text(
            _RULES.replace(
                "  relaxed_pii_ids:\n    - TOKEN\n    - LEFTOVER_RULE\n", value
            ),
            encoding="utf-8",
        )
        payload = build_settings_payload()
        assert payload["relaxed_mode"] == mode
        if mode == "default":
            assert payload["relaxed_ids_resolved"] == payload["default_relaxed_ids"]
        else:
            assert payload["relaxed_ids_resolved"] is None
            assert all(rule["relaxed_editable"] is False for rule in payload["pii_rules"])

    def test_all_mode_puts_every_enabled_rule_on_the_relaxed_surfaces(
        self, rules_file: Path
    ) -> None:
        rules_file.write_text(
            _RULES.replace(
                "  relaxed_pii_ids:\n    - TOKEN\n    - LEFTOVER_RULE\n",
                '  relaxed_pii_ids: ["*"]\n',
            ),
            encoding="utf-8",
        )
        for rule in build_settings_payload()["pii_rules"]:
            # "*" is about membership; a disabled rule is not compiled at all.
            assert rule["effective_surfaces"]["v1_forward_multipart"] is rule["enabled"]


class TestMalformedEntries:
    def test_a_bare_string_pii_entry_is_surfaced(self, rules_file: Path) -> None:
        rules_file.write_text(
            _RULES.replace("    - id: EMAIL\n      regex: 'a@b'\n", "    - 'bare-string'\n"),
            encoding="utf-8",
        )
        payload = build_settings_payload()
        assert payload["malformed_pii_entries"][0]["value"] == "bare-string"
        assert all(rule["id"] != "bare-string" for rule in payload["pii_rules"])

    def test_an_uncompilable_regex_is_flagged(self, rules_file: Path) -> None:
        rules_file.write_text(_RULES.replace("'a@b'", "'([unclosed'"), encoding="utf-8")
        assert _rule(build_settings_payload(), "EMAIL")["regex_status"] == "invalid"


def test_the_shipped_rules_file_renders(monkeypatch: pytest.MonkeyPatch) -> None:
    """A smoke test against the real 56-rule policy, not just the fixture."""
    real = Path(__file__).resolve().parents[1] / "policies" / "rules" / "security_filters.yaml"
    monkeypatch.setattr(settings, "security_rules_path", str(real), raising=False)
    monkeypatch.setattr(gw_tokens, "list_tokens", lambda: {})
    payload = build_settings_payload()
    expected = yaml.safe_load(real.read_text(encoding="utf-8"))["redaction"]["pii_patterns"]
    assert len(payload["pii_rules"]) == len(expected)
    assert payload["relaxed_mode"] == "default"
