"""Tests for comment-preserving edits to security_filters.yaml.

Editing one rule through the console used to rewrite the whole file: PyYAML's
``safe_load`` → ``dump`` round trip drops every comment and re-flows indentation
and quoting, turning a one-line change into ~1250 lines of diff and erasing all
80 comment lines. The comments document the security policy, so the loss is real.

The patch path is text surgery on YAML, which is fragile by nature — so the
guarantee these tests protect is twofold: comments survive, *and* the resulting
document is always semantically exactly what the caller asked for, falling back
to the old dump when it cannot be.
"""

from __future__ import annotations

import difflib
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.core import gateway_ui_routes
from aegisgate.core.rules_editor import (
    RuleEdit,
    apply_edit,
    apply_scalar_update,
    render_rules_yaml,
    render_scalar_updates,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REAL_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"

_SAMPLE = """\
# top comment
version: 3
redaction:
  # keep this note
  request_prefix_max_len: 12
  pii_patterns:
    # explains the list
    - id: EMAIL
      regex: 'a@b'
    - id: TOKEN
      regex: 'sk-x'
action_map:
  sanitizer:
    # what to do
    dangerous_command: block
"""


def _comment_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip().startswith("#")]


def _changed_lines(before: str, after: str) -> list[str]:
    return [
        line
        for line in difflib.unified_diff(
            before.splitlines(), after.splitlines(), lineterm="", n=0
        )
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]


class TestSampleDocument:
    def test_update_touches_only_the_edited_line(self) -> None:
        expected = yaml.safe_load(_SAMPLE)
        for rule in expected["redaction"]["pii_patterns"]:
            if rule["id"] == "EMAIL":
                rule["regex"] = "changed@pattern"
        out = render_rules_yaml(
            _SAMPLE,
            expected,
            RuleEdit(["redaction", "pii_patterns"], "update", "EMAIL", {"regex": "changed@pattern"}),
        )
        assert _comment_lines(out) == _comment_lines(_SAMPLE)
        assert len(_changed_lines(_SAMPLE, out)) == 2  # one removed, one added
        assert yaml.safe_load(out) == expected

    def test_add_appends_without_disturbing_anything_else(self) -> None:
        expected = yaml.safe_load(_SAMPLE)
        expected["redaction"]["pii_patterns"].append({"id": "NEW", "regex": "(?i)n"})
        out = render_rules_yaml(
            _SAMPLE,
            expected,
            RuleEdit(["redaction", "pii_patterns"], "add", "NEW", {"regex": "(?i)n"}),
        )
        assert _comment_lines(out) == _comment_lines(_SAMPLE)
        assert _changed_lines(_SAMPLE, out) == ["+    - id: NEW", "+      regex: '(?i)n'"]
        assert yaml.safe_load(out) == expected

    def test_delete_removes_only_that_rule(self) -> None:
        expected = yaml.safe_load(_SAMPLE)
        expected["redaction"]["pii_patterns"] = [
            r for r in expected["redaction"]["pii_patterns"] if r["id"] != "TOKEN"
        ]
        out = render_rules_yaml(
            _SAMPLE, expected, RuleEdit(["redaction", "pii_patterns"], "delete", "TOKEN")
        )
        assert _comment_lines(out) == _comment_lines(_SAMPLE)
        assert _changed_lines(_SAMPLE, out) == ["-    - id: TOKEN", "-      regex: 'sk-x'"]
        assert yaml.safe_load(out) == expected

    def test_action_map_scalar_update(self) -> None:
        expected = yaml.safe_load(_SAMPLE)
        expected["action_map"]["sanitizer"]["dangerous_command"] = "sanitize"
        out = render_scalar_updates(
            _SAMPLE, expected, [(["action_map", "sanitizer", "dangerous_command"], "sanitize")]
        )
        assert _comment_lines(out) == _comment_lines(_SAMPLE)
        assert _changed_lines(_SAMPLE, out) == [
            "-    dangerous_command: block",
            "+    dangerous_command: sanitize",
        ]
        assert yaml.safe_load(out) == expected

    def test_adding_a_metadata_field_to_an_existing_rule(self) -> None:
        expected = yaml.safe_load(_SAMPLE)
        for rule in expected["redaction"]["pii_patterns"]:
            if rule["id"] == "EMAIL":
                rule["kind"] = "pii"
        out = render_rules_yaml(
            _SAMPLE, expected, RuleEdit(["redaction", "pii_patterns"], "update", "EMAIL", {"kind": "pii"})
        )
        assert _comment_lines(out) == _comment_lines(_SAMPLE)
        assert yaml.safe_load(out) == expected


class TestRealRulesFile:
    """The file that actually ships, with 80 comment lines and 32 rule groups."""

    @pytest.fixture()
    def source(self) -> str:
        return _REAL_RULES.read_text(encoding="utf-8")

    def test_baseline_shows_what_a_plain_dump_would_destroy(self, source: str) -> None:
        dumped = yaml.dump(
            yaml.safe_load(source), allow_unicode=True, default_flow_style=False, sort_keys=False
        )
        assert len(_comment_lines(source)) >= 80
        assert _comment_lines(dumped) == []

    @pytest.mark.parametrize(
        "path,rule_id",
        [
            (["redaction", "pii_patterns"], "EMAIL"),
            (["injection_detector", "direct_patterns"], None),
            (["request_sanitizer", "leak_check_patterns"], None),
            (["sanitizer", "force_block_command_patterns"], None),
            (["post_restore_guard", "secret_patterns"], None),
            (["anomaly_detector", "command_patterns"], None),
        ],
    )
    def test_update_across_groups_keeps_every_comment(
        self, source: str, path: list[str], rule_id: str | None
    ) -> None:
        expected = yaml.safe_load(source)
        node = expected
        for key in path:
            node = node[key]
        target = rule_id or node[0]["id"]
        for rule in node:
            if rule["id"] == target:
                rule["regex"] = "patched-by-test"
        out = render_rules_yaml(
            source, expected, RuleEdit(path, "update", target, {"regex": "patched-by-test"})
        )
        assert _comment_lines(out) == _comment_lines(source)
        assert yaml.safe_load(out) == expected
        assert len(_changed_lines(source, out)) == 2

    def test_add_and_delete_round_trip_restores_the_file_byte_for_byte(self, source: str) -> None:
        added = yaml.safe_load(source)
        added["redaction"]["pii_patterns"].append({"id": "ROUND_TRIP", "regex": "'rt'"})
        step1 = render_rules_yaml(
            source, added, RuleEdit(["redaction", "pii_patterns"], "add", "ROUND_TRIP", {"regex": "'rt'"})
        )
        removed = yaml.safe_load(step1)
        removed["redaction"]["pii_patterns"] = [
            r for r in removed["redaction"]["pii_patterns"] if r["id"] != "ROUND_TRIP"
        ]
        step2 = render_rules_yaml(
            step1, removed, RuleEdit(["redaction", "pii_patterns"], "delete", "ROUND_TRIP")
        )
        assert step2 == source

    def test_a_regex_with_yaml_indicators_survives(self, source: str) -> None:
        nasty = "*[a-z]{2,}: #yes | > %x @y `z` 'quoted'"
        expected = yaml.safe_load(source)
        expected["redaction"]["pii_patterns"].append({"id": "NASTY", "regex": nasty})
        out = render_rules_yaml(
            source, expected, RuleEdit(["redaction", "pii_patterns"], "add", "NASTY", {"regex": nasty})
        )
        assert _comment_lines(out) == _comment_lines(source)
        reloaded = yaml.safe_load(out)
        assert any(
            r["id"] == "NASTY" and r["regex"] == nasty
            for r in reloaded["redaction"]["pii_patterns"]
        )


class TestFallbackSafety:
    """When the patch cannot be trusted, correctness wins over comments."""

    def test_unknown_path_falls_back_to_a_correct_dump(self) -> None:
        expected = yaml.safe_load(_SAMPLE)
        out = render_rules_yaml(
            _SAMPLE, expected, RuleEdit(["nope", "missing"], "delete", "X")
        )
        assert yaml.safe_load(out) == expected
        assert _comment_lines(out) == []  # dumped, comments gone — but correct

    def test_unknown_rule_id_falls_back(self) -> None:
        expected = yaml.safe_load(_SAMPLE)
        out = render_rules_yaml(
            _SAMPLE, expected, RuleEdit(["redaction", "pii_patterns"], "delete", "NOT_THERE")
        )
        assert yaml.safe_load(out) == expected

    def test_patch_is_rejected_when_it_disagrees_with_the_expected_document(self) -> None:
        """The safety net: a patch that would produce the wrong document is dropped."""
        wrong = yaml.safe_load(_SAMPLE)
        wrong["version"] = 999  # the edit descriptor says nothing about this
        out = render_rules_yaml(
            _SAMPLE,
            wrong,
            RuleEdit(["redaction", "pii_patterns"], "update", "EMAIL", {"regex": "x"}),
        )
        assert yaml.safe_load(out) == wrong

    def test_scalar_update_on_a_missing_key_falls_back(self) -> None:
        expected = yaml.safe_load(_SAMPLE)
        expected["action_map"]["brand_new"] = {"threat": "block"}
        out = render_scalar_updates(
            _SAMPLE, expected, [(["action_map", "brand_new", "threat"], "block")]
        )
        assert yaml.safe_load(out) == expected

    def test_apply_edit_returns_none_rather_than_guessing(self) -> None:
        assert apply_edit(_SAMPLE, RuleEdit(["version"], "add", "X", {"regex": "x"})) is None
        assert apply_scalar_update(_SAMPLE, ["action_map", "missing", "k"], "block") is None


class TestRoutesKeepComments:
    @pytest.fixture()
    def client(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        rules_copy = tmp_path / "security_filters.yaml"
        rules_copy.write_text(_REAL_RULES.read_text(encoding="utf-8"), encoding="utf-8")
        monkeypatch.setattr(
            gateway_ui_routes.settings, "security_rules_path", str(rules_copy), raising=False
        )
        app = FastAPI()
        gateway_ui_routes.register_ui_routes(app)
        with TestClient(app) as c:
            c.rules_path = rules_copy  # type: ignore[attr-defined]
            yield c

    def test_add_through_the_api_keeps_comments(self, client) -> None:
        before = client.rules_path.read_text(encoding="utf-8")
        assert client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "API_ADD", "regex": "(?i)api"}
        ).status_code == 201
        after = client.rules_path.read_text(encoding="utf-8")
        assert _comment_lines(after) == _comment_lines(before)
        assert len(_changed_lines(before, after)) == 2

    def test_update_through_the_api_keeps_comments(self, client) -> None:
        client.post("/__ui__/api/rules/pii_patterns", json={"id": "API_UPD", "regex": "a"})
        before = client.rules_path.read_text(encoding="utf-8")
        assert client.patch(
            "/__ui__/api/rules/pii_patterns/API_UPD", json={"regex": "b"}
        ).status_code == 200
        after = client.rules_path.read_text(encoding="utf-8")
        assert _comment_lines(after) == _comment_lines(before)
        assert _changed_lines(before, after) == ["-      regex: 'a'", "+      regex: 'b'"]

    def test_delete_through_the_api_keeps_comments(self, client) -> None:
        client.post("/__ui__/api/rules/pii_patterns", json={"id": "API_DEL", "regex": "a"})
        before = client.rules_path.read_text(encoding="utf-8")
        assert client.delete("/__ui__/api/rules/pii_patterns/API_DEL").status_code == 200
        after = client.rules_path.read_text(encoding="utf-8")
        assert _comment_lines(after) == _comment_lines(before)

    def test_action_map_patch_keeps_comments(self, client) -> None:
        current = client.get("/__ui__/api/rules_action_map").json()["action_map"]
        category = next(iter(current))
        threat = next(iter(current[category]))
        new_action = "sanitize" if current[category][threat] != "sanitize" else "block"

        before = client.rules_path.read_text(encoding="utf-8")
        assert client.patch(
            "/__ui__/api/rules_action_map", json={category: {threat: new_action}}
        ).status_code == 200
        after = client.rules_path.read_text(encoding="utf-8")
        assert _comment_lines(after) == _comment_lines(before)
        assert len(_changed_lines(before, after)) == 2
        assert (
            client.get("/__ui__/api/rules_action_map").json()["action_map"][category][threat]
            == new_action
        )

    def test_a_full_edit_cycle_never_loses_a_comment(self, client) -> None:
        before = client.rules_path.read_text(encoding="utf-8")
        for index in range(5):
            client.post(
                "/__ui__/api/rules/command_patterns",
                json={"id": f"CYCLE_{index}", "regex": f"c{index}", "kind": "test"},
            )
            client.patch(
                f"/__ui__/api/rules/command_patterns/CYCLE_{index}", json={"regex": f"c{index}x"}
            )
            client.delete(f"/__ui__/api/rules/command_patterns/CYCLE_{index}")
        after = client.rules_path.read_text(encoding="utf-8")
        assert _comment_lines(after) == _comment_lines(before)
        assert yaml.safe_load(after) == yaml.safe_load(before)
