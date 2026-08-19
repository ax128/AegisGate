"""Tests for the console rule workbench: section discovery and the regex probe.

Before this, ``_RULES_SECTIONS`` hard-coded 5 of the 32 rule groups in
security_filters.yaml, so 119 of 228 rules had no console entry at all. Sections
are now discovered by walking the YAML, which means the discovery itself — and
the fact that a dotted path from a request cannot address an arbitrary node — is
what these tests pin down.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.core import gateway_ui_routes
from aegisgate.core.regex_probe import (
    MAX_REGEX_LEN,
    MAX_SAMPLE_LEN,
    MAX_SAMPLES,
    ProbeInputError,
    normalize_probe_input,
    probe,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RULES_YAML = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"

# The five ids the console used before dotted paths; existing clients and the
# boundary-access tests still address rules through them.
_LEGACY_IDS = {
    "pii_patterns": "redaction.pii_patterns",
    "tool_injection": "injection_detector.tool_call_injection_patterns",
    "command_patterns": "anomaly_detector.command_patterns",
    "direct_patterns": "injection_detector.direct_patterns",
    "system_exfil_patterns": "injection_detector.system_exfil_patterns",
}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Serve routes against a scratch copy of the real rules file."""
    rules_copy = tmp_path / "security_filters.yaml"
    rules_copy.write_text(_RULES_YAML.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(
        gateway_ui_routes.settings, "security_rules_path", str(rules_copy), raising=False
    )
    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    with TestClient(app) as c:
        c.rules_path = rules_copy  # type: ignore[attr-defined]
        yield c


class TestSectionDiscovery:
    def test_finds_every_rule_group_in_the_yaml(self, client) -> None:
        data = yaml.safe_load(_RULES_YAML.read_text(encoding="utf-8"))

        expected: set[str] = set()

        def walk(node: object, path: list[str]) -> None:
            if not isinstance(node, dict):
                return
            for key, value in node.items():
                current = path + [str(key)]
                if (
                    isinstance(value, list)
                    and value
                    and all(isinstance(entry, dict) for entry in value)
                    and any("regex" in entry or "id" in entry for entry in value)
                ):
                    expected.add(".".join(current))
                elif isinstance(value, dict):
                    walk(value, current)

        walk(data, [])
        served = {s["id"] for s in client.get("/__ui__/api/rules").json()["sections"]}
        assert expected <= served
        assert len(served) >= 32

    def test_total_rule_count_matches_the_file(self, client) -> None:
        payload = client.get("/__ui__/api/rules").json()
        assert payload["total_rules"] == sum(s["count"] for s in payload["sections"])
        assert payload["total_rules"] >= 228

    def test_every_section_carries_a_label_and_filter(self, client) -> None:
        for section in client.get("/__ui__/api/rules").json()["sections"]:
            assert section["label"]
            assert section["filter"]
            assert section["filter_label"]

    def test_previously_invisible_groups_are_now_addressable(self, client) -> None:
        """The 27 groups the old hard-coded map left out."""
        for section_id in (
            "request_sanitizer.leak_check_patterns",
            "sanitizer.force_block_command_patterns",
            "post_restore_guard.secret_patterns",
            "rag_poison_guard.ingestion_poison_patterns",
            "privilege_guard.blocked_patterns",
            "injection_detector.html_markdown_patterns",
        ):
            response = client.get(f"/__ui__/api/rules/{section_id}")
            assert response.status_code == 200, section_id
            assert response.json()["items"]


class TestLegacyAliases:
    @pytest.mark.parametrize("legacy,dotted", sorted(_LEGACY_IDS.items()))
    def test_legacy_id_resolves_to_its_dotted_section(self, client, legacy, dotted) -> None:
        body = client.get(f"/__ui__/api/rules/{legacy}").json()
        assert body["section"] == dotted
        assert body["items"] == client.get(f"/__ui__/api/rules/{dotted}").json()["items"]

    def test_legacy_id_still_accepts_writes(self, client) -> None:
        created = client.post(
            "/__ui__/api/rules/command_patterns",
            json={"id": "LEGACY_ALIAS_RULE", "regex": "legacy-alias-probe"},
        )
        assert created.status_code == 201
        assert client.delete(
            "/__ui__/api/rules/command_patterns/LEGACY_ALIAS_RULE"
        ).status_code == 200


class TestPathSafety:
    def test_unknown_section_is_rejected(self, client) -> None:
        assert client.get("/__ui__/api/rules/does.not.exist").status_code == 404

    def test_non_rule_node_is_not_addressable(self, client) -> None:
        """`redaction.request_prefix_max_len` is a scalar, not a rule list."""
        assert client.get("/__ui__/api/rules/redaction.request_prefix_max_len").status_code == 404

    def test_scalar_write_target_is_rejected(self, client) -> None:
        response = client.post(
            "/__ui__/api/rules/redaction.normalize_nfkc", json={"id": "X", "regex": "x"}
        )
        assert response.status_code == 404

    def test_readonly_section_is_listable_but_not_writable(self, client) -> None:
        listing = client.get("/__ui__/api/rules/tool_call_guard.parameter_rules")
        assert listing.status_code == 200
        assert listing.json()["readonly"] is True
        assert listing.json()["items"]

        for response in (
            client.post(
                "/__ui__/api/rules/tool_call_guard.parameter_rules",
                json={"id": "X", "regex": "x"},
            ),
            client.patch(
                "/__ui__/api/rules/tool_call_guard.parameter_rules/X", json={"regex": "y"}
            ),
            client.delete("/__ui__/api/rules/tool_call_guard.parameter_rules/X"),
        ):
            assert response.status_code == 403
            assert response.json()["error"] == "section_readonly"


class TestRuleCrud:
    def test_create_update_delete_round_trip(self, client) -> None:
        section = "sanitizer.system_leak_patterns"
        assert client.post(
            f"/__ui__/api/rules/{section}", json={"id": "WB_TMP", "regex": "alpha"}
        ).status_code == 201
        assert client.post(
            f"/__ui__/api/rules/{section}", json={"id": "WB_TMP", "regex": "alpha"}
        ).status_code == 409

        updated = client.patch(f"/__ui__/api/rules/{section}/WB_TMP", json={"regex": "beta"})
        assert updated.json()["item"]["regex"] == "beta"

        on_disk = yaml.safe_load(client.rules_path.read_text(encoding="utf-8"))
        stored = [r for r in on_disk["sanitizer"]["system_leak_patterns"] if r["id"] == "WB_TMP"]
        assert stored and stored[0]["regex"] == "beta"

        assert client.delete(f"/__ui__/api/rules/{section}/WB_TMP").status_code == 200
        assert client.delete(f"/__ui__/api/rules/{section}/WB_TMP").status_code == 404

    def test_invalid_regex_is_rejected_before_writing(self, client) -> None:
        before = client.rules_path.read_text(encoding="utf-8")
        response = client.post(
            "/__ui__/api/rules/sanitizer.system_leak_patterns",
            json={"id": "WB_BAD", "regex": "(unclosed"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_regex"
        assert client.rules_path.read_text(encoding="utf-8") == before

    def test_category_metadata_survives_an_edit(self, client) -> None:
        """strong_intent_patterns carries `category`; editing the regex through the
        console must not silently drop it."""
        section = "request_sanitizer.strong_intent_patterns"
        original = client.get(f"/__ui__/api/rules/{section}").json()["items"][0]
        assert "category" in original

        client.patch(
            f"/__ui__/api/rules/{section}/{original['id']}",
            json={"regex": original["regex"]},
        )
        after = client.get(f"/__ui__/api/rules/{section}").json()["items"][0]
        assert after["category"] == original["category"]

    def test_editable_metadata_can_be_written(self, client) -> None:
        section = "anomaly_detector.command_patterns"
        client.post(
            f"/__ui__/api/rules/{section}",
            json={"id": "WB_KIND", "regex": "kind-probe", "kind": "sql_injection"},
        )
        items = client.get(f"/__ui__/api/rules/{section}").json()["items"]
        assert next(i for i in items if i["id"] == "WB_KIND")["kind"] == "sql_injection"
        client.delete(f"/__ui__/api/rules/{section}/WB_KIND")


class TestRegexProbeInput:
    def test_rejects_empty_regex(self) -> None:
        with pytest.raises(ProbeInputError):
            normalize_probe_input("", ["x"])

    def test_rejects_uncompilable_regex(self) -> None:
        with pytest.raises(ProbeInputError):
            normalize_probe_input("(unclosed", ["x"])

    def test_rejects_oversized_regex(self) -> None:
        with pytest.raises(ProbeInputError):
            normalize_probe_input("a" * (MAX_REGEX_LEN + 1), ["x"])

    def test_rejects_too_many_samples(self) -> None:
        with pytest.raises(ProbeInputError):
            normalize_probe_input("a", ["x"] * (MAX_SAMPLES + 1))

    def test_rejects_oversized_sample(self) -> None:
        with pytest.raises(ProbeInputError):
            normalize_probe_input("a", ["x" * (MAX_SAMPLE_LEN + 1)])

    def test_accepts_a_bare_string_sample(self) -> None:
        _, samples = normalize_probe_input("a", "single")
        assert samples == ["single"]


class TestRegexProbeExecution:
    def test_reports_spans_for_each_match(self) -> None:
        result = probe(r"\d+", ["a1b22c", "none"])
        first, second = result["results"]
        assert first["spans"] == [[1, 2], [3, 5]]
        assert first["matches"] == ["1", "22"]
        assert second["matched"] is False

    def test_catastrophic_backtracking_is_killed_not_survived(self) -> None:
        """This is the whole reason matching runs in a child process."""
        started = time.monotonic()
        result = probe(r"(a+)+$", ["a" * 60 + "b"], timeout=1.0)
        elapsed = time.monotonic() - started
        assert result["timed_out"] is True
        assert elapsed < 5.0, "probe did not return promptly after the timeout"

    def test_child_receives_a_precompiled_pattern(self) -> None:
        """The child must not call re.compile: forking a multi-threaded gateway
        and then taking the re-cache lock is the one deadlock shape worth ruling
        out, so compilation happens in the parent."""
        import inspect

        from aegisgate.core import regex_probe

        signature = inspect.signature(regex_probe._probe_worker)
        assert list(signature.parameters) == ["pattern", "samples", "conn"]
        assert "re.compile" not in inspect.getsource(regex_probe._probe_worker)

    def test_start_method_never_re_runs_the_parent_main_module(self) -> None:
        """spawn/forkserver re-run __main__ in the child, which breaks under
        several ways of launching the gateway."""
        from aegisgate.core.regex_probe import _probe_context

        assert _probe_context().get_start_method() in {"fork", "spawn"}

    def test_uncompilable_pattern_is_reported_not_raised(self) -> None:
        result = probe("(unclosed", ["x"])
        assert result["error"]
        assert result["results"] == []

    def test_match_count_is_capped(self) -> None:
        result = probe("a", ["a" * 100])
        assert result["results"][0]["truncated"] is True
        assert result["results"][0]["match_count"] == 20


class TestRegexProbeRoute:
    def test_returns_hit_spans(self, client) -> None:
        body = client.post(
            "/__ui__/api/rules_test",
            json={"regex": r"(?i)\bsk-[a-z0-9]{6,}\b", "samples": ["token sk-abc123def here"]},
        ).json()
        assert body["timed_out"] is False
        assert body["results"][0]["spans"] == [[6, 18]]

    def test_reports_a_runaway_pattern_instead_of_hanging(self, client) -> None:
        body = client.post(
            "/__ui__/api/rules_test",
            json={"regex": r"(a+)+$", "samples": ["a" * 60 + "b"]},
        ).json()
        assert body["timed_out"] is True
        assert "回溯" in body["detail"]

    def test_bad_input_is_rejected(self, client) -> None:
        response = client.post(
            "/__ui__/api/rules_test", json={"regex": "(bad", "samples": ["x"]}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_probe_input"

    def test_probe_never_writes_to_the_rules_file(self, client) -> None:
        before = client.rules_path.read_text(encoding="utf-8")
        client.post("/__ui__/api/rules_test", json={"regex": "x", "samples": ["x"]})
        assert client.rules_path.read_text(encoding="utf-8") == before
