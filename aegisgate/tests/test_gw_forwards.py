"""P0 acceptance: the ``config/gw_forwards.json`` loader and its fail-closed tables."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from aegisgate.config import settings as settings_module
from aegisgate.core import gw_forwards


@pytest.fixture()
def forwards_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "gw_forwards.json"
    monkeypatch.setattr(settings_module.settings, "gw_forwards_path", str(path), raising=False)
    monkeypatch.setattr(settings_module.settings, "enable_gateway_forward", True, raising=False)
    monkeypatch.setattr(
        settings_module.settings, "forward_allow_public_baseline_off", False, raising=False
    )
    monkeypatch.setattr(
        settings_module.settings, "enable_request_hmac_auth", False, raising=False
    )
    gw_forwards.load(replace=True)
    yield path
    monkeypatch.setattr(
        settings_module.settings, "enable_gateway_forward", False, raising=False
    )
    monkeypatch.setattr(
        settings_module.settings, "enable_request_hmac_auth", False, raising=False
    )
    gw_forwards.load(replace=True)


def _write(path: Path, forwards: dict) -> None:
    path.write_text(
        json.dumps({"version": 1, "forwards": forwards}), encoding="utf-8"
    )


def _entry(**overrides) -> dict:
    entry = {
        "enabled": True,
        "upstream_base": "https://api.xxx.com",
        "expose": "internal",
        "filters": {"mode": "policy"},
    }
    entry.update(overrides)
    return entry


class TestLoad:
    def test_valid_rule_loads(self, forwards_path: Path) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        rule = gw_forwards.get("api.ag.com")
        assert rule is not None
        assert rule.upstream_base == "https://api.xxx.com"
        assert rule.expose == "internal"
        assert rule.baseline_off is False
        assert gw_forwards.denied_reason("api.ag.com") is None

    def test_host_normalized_on_load(self, forwards_path: Path) -> None:
        _write(forwards_path, {"API.Ag.com.": _entry()})
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is not None

    def test_disabled_rule_stays_in_live_table(self, forwards_path: Path) -> None:
        _write(forwards_path, {"api.ag.com": _entry(enabled=False)})
        gw_forwards.load(replace=True)
        rule = gw_forwards.get("api.ag.com")
        assert rule is not None and rule.enabled is False

    def test_unknown_filter_key_denies_only_that_host(self, forwards_path: Path) -> None:
        _write(
            forwards_path,
            {
                "bad.ag.com": _entry(filters={"mode": "custom", "custom": {"nope": True}}),
                "good.ag.com": _entry(),
            },
        )
        gw_forwards.load(replace=True)
        assert gw_forwards.get("bad.ag.com") is None
        reason, _detail = gw_forwards.denied_reason("bad.ag.com")
        assert reason == gw_forwards.REASON_RULE_INVALID
        assert gw_forwards.get("good.ag.com") is not None

    def test_ip_literal_host_denied(self, forwards_path: Path) -> None:
        _write(forwards_path, {"127.0.0.1": _entry()})
        gw_forwards.load(replace=True)
        assert gw_forwards.denied_reason("127.0.0.1")[0] == gw_forwards.REASON_RULE_INVALID

    def test_port_in_host_denied(self, forwards_path: Path) -> None:
        _write(forwards_path, {"api.ag.com:443": _entry()})
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is None
        # The deny entry is keyed like the router keys a request (port removed),
        # so the host answers 403 instead of falling back to the default stack.
        assert gw_forwards.denied_reason("api.ag.com")[0] == gw_forwards.REASON_RULE_INVALID

    @pytest.mark.parametrize(
        "overrides",
        [
            {"expose": ["public"]},
            {"expose": {"x": 1}},
            {"filters": {"mode": ["custom"]}},
        ],
    )
    def test_unhashable_field_denies_the_host_without_aborting(
        self, forwards_path: Path, overrides: dict
    ) -> None:
        _write(forwards_path, {"api.ag.com": _entry(**overrides), "good.ag.com": _entry()})
        gw_forwards.load(replace=True)
        assert gw_forwards.denied_reason("api.ag.com")[0] == gw_forwards.REASON_RULE_INVALID
        assert gw_forwards.get("good.ag.com") is not None

    def test_duplicate_normalized_hosts_deny_both(self, forwards_path: Path) -> None:
        _write(
            forwards_path,
            {
                "API.ag.com": _entry(expose="public", upstream_base="https://a.up.com"),
                "api.ag.com.": _entry(upstream_base="https://b.up.com"),
            },
        )
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is None
        assert gw_forwards.denied_reason("api.ag.com")[0] == gw_forwards.REASON_RULE_INVALID

    def test_llm_upstream_base_carries_the_v1_prefix(self, forwards_path: Path) -> None:
        from aegisgate.adapters.openai_compat.upstream import _build_upstream_url

        _write(forwards_path, {"api.ag.com": _entry(upstream_base="http://127.0.0.1:8317")})
        gw_forwards.load(replace=True)
        rule = gw_forwards.get("api.ag.com")
        assert rule.llm_upstream_base == "http://127.0.0.1:8317/v1"
        assert (
            _build_upstream_url("/v1/chat/completions", rule.llm_upstream_base)
            == "http://127.0.0.1:8317/v1/chat/completions"
        )

    def test_custom_requires_mode_custom(self, forwards_path: Path) -> None:
        _write(
            forwards_path,
            {"api.ag.com": _entry(filters={"mode": "policy", "custom": {"redaction": True}})},
        )
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is None

    def test_missing_file_clears_on_replace(self, forwards_path: Path) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is not None
        forwards_path.unlink()
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is None
        assert gw_forwards.denied_reason("api.ag.com") is None

    def test_version_mismatch_denies_previous_hosts(
        self, forwards_path: Path
    ) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        forwards_path.write_text(
            json.dumps({"version": 2, "forwards": {"api.ag.com": _entry()}}),
            encoding="utf-8",
        )
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is None
        reason, _ = gw_forwards.denied_reason("api.ag.com")
        assert reason == gw_forwards.REASON_CONFIG_INVALID

    def test_parse_failure_denies_previous_and_recovers(
        self, forwards_path: Path
    ) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        forwards_path.write_text("{ not json", encoding="utf-8")
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is None
        assert gw_forwards.denied_reason("api.ag.com")[0] == gw_forwards.REASON_CONFIG_INVALID
        # Repairing the file restores the rule.
        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is not None
        assert gw_forwards.denied_reason("api.ag.com") is None

    def test_repeated_parse_failure_stays_closed(self, forwards_path: Path) -> None:
        _write(
            forwards_path,
            {
                "api.ag.com": _entry(),
                "bad.ag.com": _entry(filters={"mode": "custom", "custom": {"nope": True}}),
            },
        )
        gw_forwards.load(replace=True)
        for broken in ("{ not json", "{ still not json"):
            forwards_path.write_text(broken, encoding="utf-8")
            gw_forwards.load(replace=True)
            # Both the live host and the host that was already denied stay denied,
            # however many broken saves in a row the watcher sees.
            for host in ("api.ag.com", "bad.ag.com"):
                assert gw_forwards.get(host) is None
                assert gw_forwards.denied_reason(host)[0] == gw_forwards.REASON_CONFIG_INVALID


class TestBaselineGate:
    def test_internal_baseline_off_is_legal(self, forwards_path: Path) -> None:
        _write(
            forwards_path,
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"redaction": False}}
                )
            },
        )
        gw_forwards.load(replace=True)
        rule = gw_forwards.get("api.ag.com")
        assert rule is not None and rule.baseline_off is True

    def test_public_baseline_off_refused_without_gate(
        self, forwards_path: Path
    ) -> None:
        _write(
            forwards_path,
            {
                "api.ag.com": _entry(
                    expose="public",
                    filters={"mode": "custom", "custom": {"redaction": False}},
                )
            },
        )
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is None
        assert gw_forwards.denied_reason("api.ag.com")[0] == gw_forwards.REASON_RULE_INVALID

    def test_public_baseline_off_allowed_with_gate(
        self, forwards_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            settings_module.settings,
            "forward_allow_public_baseline_off",
            True,
            raising=False,
        )
        _write(
            forwards_path,
            {
                "api.ag.com": _entry(
                    expose="public",
                    filters={"mode": "custom", "custom": {"exact_value_redaction": False}},
                )
            },
        )
        gw_forwards.load(replace=True)
        rule = gw_forwards.get("api.ag.com")
        assert rule is not None and rule.baseline_off is True

    def test_public_without_baseline_off_is_legal(self, forwards_path: Path) -> None:
        _write(forwards_path, {"api.ag.com": _entry(expose="public")})
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is not None


class TestHmacConflict:
    def test_hmac_and_forward_refuse_to_load(
        self, forwards_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        monkeypatch.setattr(
            settings_module.settings, "enable_request_hmac_auth", True, raising=False
        )
        gw_forwards.load(replace=True)
        assert gw_forwards.get("api.ag.com") is None
        assert gw_forwards.denied_reason("api.ag.com")[0] == gw_forwards.REASON_CONFIG_INVALID

    def test_hmac_conflict_refuses_writes_and_keeps_the_file(
        self, forwards_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        monkeypatch.setattr(
            settings_module.settings, "enable_request_hmac_auth", True, raising=False
        )
        gw_forwards.load(replace=True)
        before = forwards_path.read_bytes()
        rule, _ = gw_forwards.validate_rule("new.ag.com", _entry())
        with pytest.raises(gw_forwards.ForwardWriteRefused):
            gw_forwards.upsert(rule)
        assert forwards_path.read_bytes() == before
        assert gw_forwards.get("new.ag.com") is None


class TestSave:
    def test_upsert_writes_0600_and_round_trips(self, forwards_path: Path) -> None:
        rule, reason = gw_forwards.validate_rule("api.ag.com", _entry())
        assert rule is not None, reason
        gw_forwards.upsert(rule)
        mode = stat.S_IMODE(forwards_path.stat().st_mode)
        assert mode == 0o600
        data = json.loads(forwards_path.read_text(encoding="utf-8"))
        assert data["version"] == 1
        assert data["forwards"]["api.ag.com"]["upstream_base"] == "https://api.xxx.com"

    def test_upsert_preserves_invalid_entry(self, forwards_path: Path) -> None:
        _write(
            forwards_path,
            {"bad.ag.com": _entry(filters={"mode": "custom", "custom": {"nope": True}})},
        )
        gw_forwards.load(replace=True)
        rule, reason = gw_forwards.validate_rule("good.ag.com", _entry())
        assert rule is not None, reason
        gw_forwards.upsert(rule)
        data = json.loads(forwards_path.read_text(encoding="utf-8"))
        # The entry the operator has not fixed yet is preserved verbatim.
        assert "bad.ag.com" in data["forwards"]

    def test_delete_removes_host(self, forwards_path: Path) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        assert gw_forwards.delete("api.ag.com") is True
        assert gw_forwards.get("api.ag.com") is None
        assert gw_forwards.delete("api.ag.com") is False

    def test_write_merges_onto_disk_not_memory(self, forwards_path: Path) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        # A hand edit the watcher has not reloaded yet.
        _write(forwards_path, {"api.ag.com": _entry(), "hand.ag.com": _entry()})
        rule, _ = gw_forwards.validate_rule("new.ag.com", _entry())
        gw_forwards.upsert(rule)
        data = json.loads(forwards_path.read_text(encoding="utf-8"))
        assert set(data["forwards"]) == {"api.ag.com", "hand.ag.com", "new.ag.com"}

    def test_write_refused_while_file_is_unparseable(self, forwards_path: Path) -> None:
        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        forwards_path.write_text("{ half-edited", encoding="utf-8")
        gw_forwards.load(replace=True)
        rule, _ = gw_forwards.validate_rule("new.ag.com", _entry())
        with pytest.raises(gw_forwards.ForwardWriteRefused):
            gw_forwards.upsert(rule)
        assert forwards_path.read_text(encoding="utf-8") == "{ half-edited"

    def test_stale_if_match_is_refused_under_the_lock(self, forwards_path: Path) -> None:
        from aegisgate.core.ui_etag import etag_for_file

        _write(forwards_path, {"api.ag.com": _entry()})
        gw_forwards.load(replace=True)
        stale = etag_for_file(forwards_path)
        rule, _ = gw_forwards.validate_rule("one.ag.com", _entry())
        new_etag = gw_forwards.upsert(rule, if_match=stale)
        assert new_etag == etag_for_file(forwards_path)
        other, _ = gw_forwards.validate_rule("two.ag.com", _entry())
        with pytest.raises(gw_forwards.ForwardEtagMismatch):
            gw_forwards.upsert(other, if_match=stale)
        assert gw_forwards.get("two.ag.com") is None

    def test_replace_renames_in_one_write(self, forwards_path: Path) -> None:
        _write(forwards_path, {"old.ag.com": _entry(), "taken.ag.com": _entry()})
        gw_forwards.load(replace=True)
        renamed, _ = gw_forwards.validate_rule("new.ag.com", _entry(note="moved"))
        gw_forwards.replace("OLD.ag.com", renamed)
        data = json.loads(forwards_path.read_text(encoding="utf-8"))
        assert set(data["forwards"]) == {"new.ag.com", "taken.ag.com"}
        assert gw_forwards.get("new.ag.com").note == "moved"
        clash, _ = gw_forwards.validate_rule("taken.ag.com", _entry())
        with pytest.raises(gw_forwards.ForwardHostExists):
            gw_forwards.replace("new.ag.com", clash)
        with pytest.raises(gw_forwards.ForwardNotFound):
            gw_forwards.replace("missing.ag.com", renamed)

    def test_create_refuses_a_host_already_in_the_file(self, forwards_path: Path) -> None:
        _write(
            forwards_path,
            {"api.ag.com:443": _entry()},  # invalid, but it still owns the host
        )
        gw_forwards.load(replace=True)
        rule, _ = gw_forwards.validate_rule("api.ag.com", _entry())
        with pytest.raises(gw_forwards.ForwardHostExists):
            gw_forwards.create(rule)

    def test_upsert_replaces_raw_keys_routing_to_the_same_host(
        self, forwards_path: Path
    ) -> None:
        _write(forwards_path, {"API.ag.com:443": _entry()})
        gw_forwards.load(replace=True)
        rule, _ = gw_forwards.validate_rule("api.ag.com", _entry())
        gw_forwards.upsert(rule)
        data = json.loads(forwards_path.read_text(encoding="utf-8"))
        assert list(data["forwards"]) == ["api.ag.com"]
        assert gw_forwards.get("api.ag.com") is not None
        assert gw_forwards.denied_reason("api.ag.com") is None


class TestCopyConsistencyGuards:
    def test_custom_filter_names_equal_feature_flags_fields(self) -> None:
        from aegisgate.config.feature_flags import FeatureFlags

        assert gw_forwards._allowed_filter_names() == frozenset(
            FeatureFlags.__dataclass_fields__
        )

    def test_startup_pinned_flags_are_immutable(self) -> None:
        from aegisgate.core.hot_reload import _IMMUTABLE_FIELDS

        assert "enable_gateway_forward" in _IMMUTABLE_FIELDS
        assert "forward_allow_public_baseline_off" in _IMMUTABLE_FIELDS
