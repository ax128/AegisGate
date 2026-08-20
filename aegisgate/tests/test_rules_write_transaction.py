"""Tests for the serialized, verified rules-file write transaction.

Three separate problems used to share one symptom — "the console said saved, the
gateway kept enforcing the old policy":

* the console, the rules loader and the hot-reload watcher each resolved
  ``security_rules_path`` differently, so the console could edit a file nothing
  reads;
* nothing serialized writes to that file, and ``If-Match`` was checked against an
  ETag computed before the bytes that got written were read;
* the reload that follows a write swallowed every failure, and a failed write
  restored the previous bytes unconditionally, discarding whatever a concurrent
  writer had already committed.

What follows pins each of those down, plus the pre-existing V2 crash on a legacy
string ``field_value_patterns`` entry that the new editor's compatibility
promise depends on.
"""

from __future__ import annotations

import fnmatch
import threading
import time
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.config.security_rules import resolve_rules_file
from aegisgate.config.settings import settings
from aegisgate.core import gateway_ui_routes, hot_reload, rules_write
from aegisgate.core.rules_write import (
    RulesChange,
    RulesSnapshot,
    RulesWriteError,
    compile_redaction_layers,
    create_backup,
    rules_file_lock,
    write_rules_file,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REAL_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"

_MINI_RULES = """\
version: 3
redaction:
  # keep me
  field_value_min_len: 12
  pii_patterns:
    - id: SEED
      regex: 'seed-pattern'
action_map:
  sanitizer:
    dangerous_command: block
"""


@pytest.fixture()
def rules_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "rules" / "security_filters.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(_MINI_RULES, encoding="utf-8")
    monkeypatch.setattr(settings, "security_rules_path", str(path), raising=False)
    monkeypatch.setattr(rules_write, "write_audit", lambda payload: _AUDIT.append(payload))
    _AUDIT.clear()
    return path


_AUDIT: list[dict] = []


@pytest.fixture()
def client(rules_file: Path):
    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    with TestClient(app) as c:
        c.rules_path = rules_file  # type: ignore[attr-defined]
        yield c


def _noop_change(snapshot: RulesSnapshot, marker: str) -> RulesChange:
    data = snapshot.data
    data["redaction"]["pii_patterns"].append({"id": marker, "regex": marker})
    from aegisgate.core.rules_editor import RuleEdit, render_rules_yaml

    return RulesChange(
        expected=data,
        text=render_rules_yaml(
            snapshot.text,
            data,
            RuleEdit(["redaction", "pii_patterns"], "add", marker, {"regex": marker}),
        ),
        changed_top_keys=("redaction",),
    )


# ---------------------------------------------------------------------------


class TestUnifiedPathResolution:
    """One resolver, so the console cannot edit a file the runtime never reads."""

    @pytest.fixture()
    def bootstrap_layout(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """A deployment where the rules live somewhere ``cwd`` knows nothing about."""
        runtime = tmp_path / "runtime"
        runtime.mkdir()
        (runtime / "security_filters.yaml").write_text(_MINI_RULES, encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        monkeypatch.chdir(workdir)
        monkeypatch.setenv("AEGIS_BOOTSTRAP_RULES_DIR", str(runtime))
        monkeypatch.setattr(
            settings, "security_rules_path", "aegis-test-rules/security_filters.yaml",
            raising=False,
        )
        return runtime

    def test_loader_console_and_watcher_agree(self, bootstrap_layout: Path) -> None:
        expected = (bootstrap_layout / "security_filters.yaml").resolve()
        assert resolve_rules_file() == expected

        watcher = hot_reload.build_watcher()
        watched = {
            watch.label: watch.path for watch, _ in watcher._watches  # noqa: SLF001
        }
        assert watched["security_filters.yaml"] == expected

    def test_console_write_lands_on_the_file_the_runtime_reads(
        self, bootstrap_layout: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(rules_write, "write_audit", lambda payload: None)
        app = FastAPI()
        gateway_ui_routes.register_ui_routes(app)
        with TestClient(app) as client:
            created = client.post(
                "/__ui__/api/rules/pii_patterns",
                json={"id": "SHADOW_CHECK", "regex": "shadow-check"},
            )
        assert created.status_code == 201
        assert "SHADOW_CHECK" in (bootstrap_layout / "security_filters.yaml").read_text(
            encoding="utf-8"
        )
        # The old console resolved the relative path against cwd and created it.
        assert not (Path.cwd() / "aegis-test-rules").exists()

    def test_a_missing_target_directory_is_an_error_not_a_mkdir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "absent" / "security_filters.yaml"
        monkeypatch.setattr(settings, "security_rules_path", str(target), raising=False)
        monkeypatch.setattr(rules_write, "write_audit", lambda payload: None)
        app = FastAPI()
        gateway_ui_routes.register_ui_routes(app)
        with TestClient(app) as client:
            response = client.post(
                "/__ui__/api/rules/pii_patterns", json={"id": "X", "regex": "x"}
            )
        assert response.status_code == 500
        assert response.json()["error"] == "rules_dir_missing"
        assert not target.parent.exists()


class TestPatchOrFail:
    """An unpatchable file shape is a refused write, never a silent dump."""

    def test_inline_list_is_updated_in_place(self, rules_file: Path) -> None:
        from aegisgate.core.rules_editor import LeafOp, render_leaf_ops

        rules_file.write_text(
            _MINI_RULES.replace(
                "  field_value_min_len: 12\n",
                "  field_value_min_len: 12\n  relaxed_pii_ids: [TOKEN, JWT]\n",
            ),
            encoding="utf-8",
        )
        source = rules_file.read_text(encoding="utf-8")
        expected = yaml.safe_load(source)
        expected["redaction"]["relaxed_pii_ids"] = ["TOKEN"]
        out = render_leaf_ops(
            source, expected, [LeafOp(["redaction", "relaxed_pii_ids"], "set", ["TOKEN"])]
        )
        assert out is not None
        assert yaml.safe_load(out) == expected
        assert "# keep me" in out

    def test_unpatchable_shape_is_rejected_without_touching_the_file(
        self, client, rules_file: Path
    ) -> None:
        rules_file.write_text(
            "version: 3\nredaction:\n  pii_patterns: [{id: SEED, regex: seed}]\n",
            encoding="utf-8",
        )
        before = rules_file.read_bytes()
        response = client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "NOPE", "regex": "nope"}
        )
        assert response.status_code == 422
        assert response.json()["error"] == "rules_patch_unsupported"
        assert rules_file.read_bytes() == before

    def test_a_patch_that_would_touch_another_section_is_refused(
        self, rules_file: Path
    ) -> None:
        def build(snapshot: RulesSnapshot) -> RulesChange:
            data = snapshot.data
            data["action_map"]["sanitizer"]["dangerous_command"] = "review"
            return RulesChange(
                expected=data,
                text=snapshot.text.replace(
                    "dangerous_command: block", "dangerous_command: review"
                ),
                changed_top_keys=("redaction",),  # lying about the target section
            )

        before = rules_file.read_bytes()
        with pytest.raises(RulesWriteError) as exc:
            write_rules_file(build, if_match=None, event="test")
        assert exc.value.code == "rules_patch_collateral_change"
        assert rules_file.read_bytes() == before


class TestTypeAndBoundValidation:
    """Bad types are caught by the pre-write compile, before anything is written."""

    def test_non_integer_field_value_min_len_is_rejected(
        self, client, rules_file: Path
    ) -> None:
        rules_file.write_text(
            _MINI_RULES.replace("field_value_min_len: 12", "field_value_min_len: 'abc'"),
            encoding="utf-8",
        )
        before = rules_file.read_bytes()
        response = client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "T", "regex": "t"}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_field_value_min_len"
        assert rules_file.read_bytes() == before

    def test_a_write_that_introduces_a_bare_string_pii_entry_is_rejected(
        self, rules_file: Path
    ) -> None:
        """The console must not be able to write the shape that breaks a layer."""

        from aegisgate.core.rules_editor import LeafOp, render_leaf_ops

        def build(snapshot: RulesSnapshot) -> RulesChange:
            data = snapshot.data
            data["redaction"]["pii_patterns"].append("legacy-string")
            ops = [LeafOp(["redaction", "pii_patterns"], "set", data["redaction"]["pii_patterns"])]
            return RulesChange(
                expected=data,
                text=render_leaf_ops(snapshot.text, data, ops),
                changed_top_keys=("redaction",),
            )

        before = rules_file.read_bytes()
        with pytest.raises(RulesWriteError) as exc:
            write_rules_file(build, if_match=None, event="test")
        assert exc.value.code == "invalid_pii_pattern_entry"
        assert rules_file.read_bytes() == before

    def test_a_pre_existing_bare_string_entry_does_not_block_unrelated_writes(
        self, client, rules_file: Path
    ) -> None:
        """Otherwise one bad entry locks the console out of the whole file.

        Every layer skips a non-mapping entry, so there is nothing to protect by
        refusing here — and the entry has no id, so a refusal would also block
        the only edits that could clean the file up.
        """
        rules_file.write_text(
            _MINI_RULES.replace(
                "    - id: SEED\n      regex: 'seed-pattern'\n",
                "    - id: SEED\n      regex: 'seed-pattern'\n    - 'legacy-string'\n",
            ),
            encoding="utf-8",
        )
        response = client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "T", "regex": "t"}
        )
        assert response.status_code == 201
        patterns = yaml.safe_load(rules_file.read_text(encoding="utf-8"))["redaction"][
            "pii_patterns"
        ]
        assert "legacy-string" in patterns
        assert {"id": "T", "regex": "t"} in patterns

    def test_candidate_compile_covers_all_three_layers(self) -> None:
        signature, failures = compile_redaction_layers(yaml.safe_load(_MINI_RULES))
        assert set(signature) == {"v1_pipeline", "v1_forward", "v2_request"}
        assert failures == []
        # V2 lowercases ids and floors field_value_min_len at 12; V1 at 8.
        assert ("SEED", "seed-pattern") in signature["v1_pipeline"]
        assert ("seed", "seed-pattern") in signature["v2_request"]

    def test_the_candidate_mirrors_each_layer_s_own_field_rules(self) -> None:
        """The three layers do not read ``field_value_patterns`` the same way."""
        data = yaml.safe_load(_MINI_RULES)
        data["redaction"]["field_value_patterns"] = [{"regex": "explicit-field"}, "legacy-field"]
        signature, failures = compile_redaction_layers(data)
        assert failures == []

        ids = {layer: [name for name, _ in entries] for layer, entries in signature.items()}
        # V1 pipeline: one fixed id for every explicit entry, mapping or legacy
        # string, and no code fallback because the list is not empty.
        assert ids["v1_pipeline"] == ["SEED", "FIELD_SECRET", "FIELD_SECRET"]
        # V1 forward: the same entries, positionally numbered.
        assert ids["v1_forward"] == ["SEED", "FIELD_SECRET_1", "FIELD_SECRET_2"]
        # V2: the two code fallbacks are compiled *as well as* the explicit list,
        # and a mapping without an id falls to the shared loop's own default.
        assert ids["v2_request"] == [
            "seed",
            "field_secret",
            "auth_bearer",
            "rule",
            "field_secret_2",
        ]

    def test_the_candidate_field_floors_differ_between_v1_and_v2(self) -> None:
        data = yaml.safe_load(_MINI_RULES)
        data["redaction"]["field_value_min_len"] = 4
        signature, _ = compile_redaction_layers(data)
        pipeline = dict(signature["v1_pipeline"])["FIELD_SECRET"]
        v2 = dict(signature["v2_request"])["field_secret"]
        assert "{8,}" in pipeline
        assert "{12,}" in v2


class TestServerSideProbe:
    """The caller picks the samples in the tester; the save path does not."""

    def test_catastrophic_regex_is_refused_despite_a_harmless_sample(
        self, client, rules_file: Path
    ) -> None:
        before = rules_file.read_bytes()
        response = client.post(
            "/__ui__/api/rules/pii_patterns",
            json={"id": "REDOS", "regex": "(a+)+$", "samples": ["hello"]},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "regex_probe_timeout"
        assert rules_file.read_bytes() == before

    def test_a_regex_over_the_length_cap_is_refused(self, client, rules_file: Path) -> None:
        response = client.post(
            "/__ui__/api/rules/pii_patterns",
            json={"id": "LONG", "regex": "a" * 600},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "regex_too_long"

    def test_untouched_rules_are_not_re_probed(self, client, rules_file: Path) -> None:
        """A pre-existing pattern must not block an unrelated edit."""
        probed: list[str] = []
        original = rules_write.probe

        def spy(regex, samples, *args, **kwargs):
            probed.append(regex)
            return original(regex, samples, *args, **kwargs)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(rules_write, "probe", spy)
            assert client.post(
                "/__ui__/api/rules/pii_patterns", json={"id": "FRESH", "regex": "fresh"}
            ).status_code == 201
        assert probed == ["fresh"]


class TestSharedWriteLock:
    """One lock per rules file, shared by every section."""

    def test_every_section_shares_one_lock(self, rules_file: Path) -> None:
        assert rules_file_lock(rules_file) is rules_file_lock(rules_file)

    def test_writes_to_different_sections_do_not_interleave(self, rules_file: Path) -> None:
        inside = threading.Event()
        overlapped: list[bool] = []
        busy = threading.Lock()
        active = {"count": 0}

        def slow_build(marker: str):
            def build(snapshot: RulesSnapshot) -> RulesChange:
                with busy:
                    active["count"] += 1
                    overlapped.append(active["count"] > 1)
                inside.set()
                time.sleep(0.05)
                with busy:
                    active["count"] -= 1
                return _noop_change(snapshot, marker)

            return build

        def run(marker: str) -> None:
            write_rules_file(slow_build(marker), if_match=None, event="test")

        first = threading.Thread(target=run, args=("LOCK_A",))
        second = threading.Thread(target=run, args=("LOCK_B",))
        first.start()
        inside.wait(2.0)
        second.start()
        first.join(10)
        second.join(10)

        assert overlapped == [False, False]
        ids = {
            rule["id"]
            for rule in yaml.safe_load(rules_file.read_text(encoding="utf-8"))["redaction"][
                "pii_patterns"
            ]
        }
        assert {"LOCK_A", "LOCK_B"} <= ids

    def test_etag_is_recomputed_inside_the_lock(self, client, rules_file: Path) -> None:
        stale = client.get("/__ui__/api/rules/pii_patterns").headers["etag"]
        assert client.post(
            "/__ui__/api/rules/pii_patterns",
            json={"id": "FIRST", "regex": "first"},
            headers={"If-Match": stale},
        ).status_code == 201
        second = client.post(
            "/__ui__/api/rules/pii_patterns",
            json={"id": "SECOND", "regex": "second"},
            headers={"If-Match": stale},
        )
        assert second.status_code == 409
        assert second.json()["error"] == "etag_mismatch"

    def test_a_specific_if_match_can_be_required(self, rules_file: Path) -> None:
        for header in (None, "*"):
            with pytest.raises(RulesWriteError) as exc:
                write_rules_file(
                    lambda snapshot: _noop_change(snapshot, "REQ"),
                    if_match=header,
                    event="test",
                    require_if_match=True,
                )
            assert exc.value.status == 428
            assert exc.value.code == "if_match_required"

    def test_existing_endpoints_still_accept_a_missing_if_match(self, client) -> None:
        """The documented contract for /rules/{section}: honoured when present."""
        assert client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "NO_HEADER", "regex": "n"}
        ).status_code == 201


class TestRollback:
    def test_a_failed_reload_restores_the_previous_bytes(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        before = rules_file.read_bytes()
        monkeypatch.setattr(
            rules_write,
            "_reload_rules",
            lambda: {"ok": False, "layers": {"v2_lru": "failed"}, "errors": []},
        )
        with pytest.raises(RulesWriteError) as exc:
            write_rules_file(
                lambda snapshot: _noop_change(snapshot, "ROLLBACK"), if_match=None, event="test"
            )
        assert exc.value.status == 500
        assert exc.value.extra["rollback"] == "restored"
        assert any("hot_reload_failed" in p for p in exc.value.extra["problems"])
        assert rules_file.read_bytes() == before
        assert _AUDIT[-1]["result"] == "failed"
        assert _AUDIT[-1]["rollback"] == "restored"

    def test_a_concurrent_write_is_never_overwritten_by_the_rollback(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        other = _MINI_RULES.replace("seed-pattern", "someone-elses-commit")

        def failing_reload() -> dict:
            # Stands in for another writer landing between the write and the
            # verification that follows it.
            rules_file.write_text(other, encoding="utf-8")
            return {"ok": False, "layers": {"pipeline": "failed"}, "errors": []}

        monkeypatch.setattr(rules_write, "_reload_rules", failing_reload)
        with pytest.raises(RulesWriteError) as exc:
            write_rules_file(
                lambda snapshot: _noop_change(snapshot, "CONFLICT"), if_match=None, event="test"
            )
        assert exc.value.status == 409
        assert exc.value.code == "concurrent_write_detected"
        assert exc.value.extra["rollback"] == "not_restored_concurrent_write"
        assert rules_file.read_text(encoding="utf-8") == other
        assert _AUDIT[-1]["rollback"] == "not_restored_concurrent_write"


class TestAppliedVerification:
    """Step 12 has to ask a question whose answer can be "no"."""

    def test_a_loader_still_serving_the_old_document_fails_the_write(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cache that kept the previous rules is the failure this exists for."""
        stale = yaml.safe_load(_MINI_RULES)
        monkeypatch.setattr(rules_write, "_reload_rules", lambda: {"ok": True, "layers": {}})
        monkeypatch.setattr(
            "aegisgate.config.security_rules.load_security_rules", lambda *a, **k: stale
        )
        before = rules_file.read_bytes()
        with pytest.raises(RulesWriteError) as exc:
            write_rules_file(
                lambda snapshot: _noop_change(snapshot, "STALE"), if_match=None, event="test"
            )
        assert any(p.startswith("loader_stale:") for p in exc.value.extra["problems"])
        assert exc.value.extra["rollback"] == "restored"
        assert rules_file.read_bytes() == before

    def test_a_reload_drops_the_mtime_keyed_cache_instead_of_trusting_the_clock(
        self, rules_file: Path
    ) -> None:
        """Two saves can share one filesystem timestamp tick."""
        from aegisgate.config import security_rules

        security_rules.load_security_rules()
        rules_file.write_text(
            _MINI_RULES.replace("seed-pattern", "second-save"), encoding="utf-8"
        )
        # Pin the mtime the loader would key on, so only an explicit
        # invalidation can produce the new document.
        stat = rules_file.stat()
        import os

        os.utime(rules_file, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        security_rules.invalidate_security_rules_cache()
        rules = security_rules.load_security_rules()
        assert rules["redaction"]["pii_patterns"][0]["regex"] == "second-save"


class TestBackups:
    def test_writes_in_the_same_millisecond_get_distinct_names(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(rules_write, "_backup_stamp", lambda: "20260101T000000.000Z")
        first = create_backup(rules_file, b"one", 0o600)
        second = create_backup(rules_file, b"two", 0o600)
        assert first != second
        assert first.read_bytes() == b"one"
        assert second.read_bytes() == b"two"

    def test_backups_are_invisible_to_the_policy_glob_and_to_git(
        self, client, rules_file: Path
    ) -> None:
        assert client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "BACKED_UP", "regex": "b"}
        ).status_code == 201
        backups = list(rules_file.parent.glob(f"{rules_file.name}.bak-*"))
        assert backups
        for backup in backups:
            assert not fnmatch.fnmatch(backup.name, "*.yaml")
        assert not list(rules_file.parent.glob("*.yaml.bak-*.yaml"))

        ignore = (_REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        assert "*.yaml.bak-*" in [line.strip() for line in ignore]

    def test_the_backup_holds_the_bytes_from_before_the_write(
        self, client, rules_file: Path
    ) -> None:
        before = rules_file.read_bytes()
        assert client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "PRE_WRITE", "regex": "p"}
        ).status_code == 201
        backup = next(iter(rules_file.parent.glob(f"{rules_file.name}.bak-*")))
        assert backup.read_bytes() == before


class TestStructuredHotReload:
    def test_every_required_layer_is_reported(self) -> None:
        result = hot_reload.reload_security_rules()
        assert set(result["layers"]) >= set(hot_reload.REQUIRED_SECURITY_RULE_RELOAD_LAYERS)
        assert result["ok"] is True
        assert result["errors"] == []

    def test_a_failing_layer_is_named_rather_than_swallowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom() -> None:
            raise RuntimeError("v2 caches unavailable")

        monkeypatch.setattr(hot_reload, "_clear_v2_lru_caches", boom)
        result = hot_reload.reload_security_rules()
        assert result["ok"] is False
        assert result["layers"]["v2_lru"] == "failed"
        assert result["errors"][0]["layer"] == "v2_lru"

    def test_a_broken_yaml_skips_the_cache_clears(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom() -> None:
            raise ValueError("bad yaml")

        monkeypatch.setattr(
            "aegisgate.config.security_rules.load_security_rules", boom
        )
        result = hot_reload.reload_security_rules()
        assert result["ok"] is False
        assert result["layers"]["yaml"] == "failed"
        assert result["layers"]["v2_lru"] == "skipped"


class TestAudit:
    def test_a_successful_write_is_audited(self, client, rules_file: Path) -> None:
        assert client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "AUDITED", "regex": "a"}
        ).status_code == 201
        event = _AUDIT[-1]
        assert event["event"] == "ui_rule_added"
        assert event["rule_id"] == "AUDITED"
        assert event["section"] == "redaction.pii_patterns"
        assert event["result"] == "ok"
        assert event["backup"]

    def test_a_delete_is_audited(self, client) -> None:
        assert client.delete("/__ui__/api/rules/pii_patterns/SEED").status_code == 200
        event = _AUDIT[-1]
        assert event["event"] == "ui_rule_deleted"
        assert event["operation"] == "delete"

    def test_the_audit_record_carries_no_pattern_text(self, client) -> None:
        client.post(
            "/__ui__/api/rules/pii_patterns",
            json={"id": "SECRETISH", "regex": "sk-live-[0-9]{20}"},
        )
        assert "sk-live-" not in yaml.safe_dump(_AUDIT[-1], allow_unicode=True)


class TestV2LegacyFieldEntry:
    """§5.7: one legacy string entry used to raise on every single V2 request."""

    def test_a_string_field_entry_compiles_instead_of_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aegisgate.adapters.v2_proxy import router as v2_router

        rules = {
            "redaction": {
                "pii_patterns": [{"id": "EMAIL", "regex": "a@b"}],
                "field_value_patterns": ["legacy-[0-9]{4}"],
            }
        }
        monkeypatch.setattr(v2_router, "load_security_rules", lambda: rules)
        v2_router._v2_redaction_patterns.cache_clear()
        v2_router._v2_relaxed_redaction_patterns.cache_clear()
        try:
            compiled = dict(
                (pattern_id, pattern.pattern)
                for pattern_id, pattern in v2_router._v2_redaction_patterns()
            )
        finally:
            v2_router._v2_redaction_patterns.cache_clear()
            v2_router._v2_relaxed_redaction_patterns.cache_clear()
        assert compiled["field_secret_1"] == "legacy-[0-9]{4}"
        assert compiled["email"] == "a@b"

    def test_the_public_constant_mirrors_the_private_one(self) -> None:
        from aegisgate.adapters.v2_proxy import router as v2_router

        assert v2_router.V2_RELAXED_PII_IDS is v2_router._V2_RELAXED_PII_IDS
        assert {"FIELD_SECRET", "AUTH_BEARER"} <= v2_router.V2_RELAXED_PII_IDS


class TestRealRulesFileStillPatches:
    def test_the_shipped_file_survives_an_add_update_delete_cycle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "security_filters.yaml"
        path.write_text(_REAL_RULES.read_text(encoding="utf-8"), encoding="utf-8")
        monkeypatch.setattr(settings, "security_rules_path", str(path), raising=False)
        monkeypatch.setattr(rules_write, "write_audit", lambda payload: None)
        before = path.read_text(encoding="utf-8")

        app = FastAPI()
        gateway_ui_routes.register_ui_routes(app)
        with TestClient(app) as client:
            assert client.post(
                "/__ui__/api/rules/pii_patterns",
                json={"id": "CYCLE_RULE", "regex": "cycle-[0-9]{4}"},
            ).status_code == 201
            assert client.patch(
                "/__ui__/api/rules/pii_patterns/CYCLE_RULE",
                json={"regex": "cycle-[0-9]{5}"},
            ).status_code == 200
            assert client.delete(
                "/__ui__/api/rules/pii_patterns/CYCLE_RULE"
            ).status_code == 200

        after = path.read_text(encoding="utf-8")
        assert yaml.safe_load(after) == yaml.safe_load(before)
        assert [line for line in after.splitlines() if line.strip().startswith("#")] == [
            line for line in before.splitlines() if line.strip().startswith("#")
        ]
