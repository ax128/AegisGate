"""Tests for the console config table: coverage, restart-required flags, coercion.

The console reports "已保存，配置已热重载" after every save. For fields listed in
``hot_reload._IMMUTABLE_FIELDS`` that claim was false — they are written to
``config/.env`` but the running process keeps the startup value. These tests pin
the contract that makes the console tell the truth instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisgate.config.settings import Settings
from aegisgate.core import gateway_ui_config as ui_config
from aegisgate.core.gateway_ui_config import (
    _UI_CONFIG_FIELDS,
    _UI_CONFIG_SECTIONS,
    _coerce_config_value,
    _restart_required_fields,
    _ui_config_field_map,
    _ui_config_payload,
)
from aegisgate.core.hot_reload import _IMMUTABLE_FIELDS

# Deliberately not exposed in the console; see the comment above _UI_CONFIG_FIELDS.
_NOT_EXPOSED = {
    "app_name",
    "gateway_key",
    "require_confirmation_on_block",
    "internal_forwarding_kernel_rollout",
}


class TestFieldTableIntegrity:
    def test_every_field_exists_on_settings(self) -> None:
        unknown = [
            item["field"]
            for item in _UI_CONFIG_FIELDS
            if item["field"] not in Settings.model_fields
        ]
        assert unknown == []

    def test_env_names_match_pydantic_prefix(self) -> None:
        """A typo here silently writes a variable the gateway never reads."""
        mismatched = [
            (item["field"], item["env"])
            for item in _UI_CONFIG_FIELDS
            if item["env"] != "AEGIS_" + str(item["field"]).upper()
        ]
        assert mismatched == []

    def test_declared_type_matches_the_model_annotation(self) -> None:
        expected = {bool: {"bool"}, int: {"int"}, float: {"float"}, str: {"string", "enum"}}
        mismatched = []
        for item in _UI_CONFIG_FIELDS:
            annotation = Settings.model_fields[str(item["field"])].annotation
            allowed = expected.get(annotation)
            if allowed is not None and item["type"] not in allowed:
                mismatched.append((item["field"], annotation, item["type"]))
        assert mismatched == []

    def test_every_settings_field_is_exposed_or_explicitly_excluded(self) -> None:
        exposed = {str(item["field"]) for item in _UI_CONFIG_FIELDS}
        missing = set(Settings.model_fields) - exposed - _NOT_EXPOSED
        assert missing == set(), f"new settings need a console entry: {sorted(missing)}"

    def test_no_duplicate_fields(self) -> None:
        fields = [str(item["field"]) for item in _UI_CONFIG_FIELDS]
        assert len(fields) == len(set(fields))

    def test_every_field_lands_in_a_declared_section(self) -> None:
        section_ids = {section["id"] for section in _UI_CONFIG_SECTIONS}
        orphans = [
            item["field"] for item in _UI_CONFIG_FIELDS if item["section"] not in section_ids
        ]
        assert orphans == []

    def test_every_field_has_a_group(self) -> None:
        assert all(str(item.get("group") or "") for item in _UI_CONFIG_FIELDS)

    def test_enum_fields_declare_options(self) -> None:
        for item in _UI_CONFIG_FIELDS:
            if item["type"] == "enum":
                assert isinstance(item.get("options"), list) and item["options"], item["field"]

    def test_enum_default_is_one_of_its_options(self) -> None:
        for item in _UI_CONFIG_FIELDS:
            if item["type"] != "enum":
                continue
            default = Settings.model_fields[str(item["field"])].default
            assert default in item["options"], (item["field"], default)

    def test_depends_on_targets_an_exposed_field(self) -> None:
        exposed = {str(item["field"]) for item in _UI_CONFIG_FIELDS}
        for item in _UI_CONFIG_FIELDS:
            for dep in (item.get("depends_on") or {}):
                assert dep in exposed, (item["field"], dep)


class TestRestartRequired:
    def test_derived_from_hot_reload_immutable_fields(self) -> None:
        """Derived, not hand-listed, so the two can never drift apart."""
        assert _restart_required_fields() == frozenset(_IMMUTABLE_FIELDS)

    def test_payload_flags_the_pinned_fields(self) -> None:
        items = {str(i["field"]): i for i in _ui_config_payload()["items"]}
        for field in ("security_level", "enforce_loopback_only", "trusted_proxy_ips",
                      "v2_block_internal_targets", "xff_strict_internal"):
            assert items[field]["requires_restart"] is True, field

    def test_hot_reloadable_fields_are_not_flagged(self) -> None:
        items = {str(i["field"]): i for i in _ui_config_payload()["items"]}
        for field in ("log_level", "risk_score_threshold", "enable_redaction"):
            assert items[field]["requires_restart"] is False, field

    def test_pending_value_surfaces_the_env_value_not_the_stale_memory_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bug this guards: .env says high, the process still runs medium,
        and the form used to silently redraw itself as medium."""
        env_path = tmp_path / ".env"
        env_path.write_text("AEGIS_SECURITY_LEVEL=high\n", encoding="utf-8")
        monkeypatch.setattr(ui_config, "_ENV_PATH", env_path)
        monkeypatch.setattr(ui_config.settings, "security_level", "medium", raising=False)

        item = next(
            i for i in _ui_config_payload()["items"] if i["field"] == "security_level"
        )
        assert item["pending_value"] == "high"
        assert item["value"] == "high"

    def test_no_pending_marker_when_env_matches_runtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_path = tmp_path / ".env"
        env_path.write_text("AEGIS_SECURITY_LEVEL=medium\n", encoding="utf-8")
        monkeypatch.setattr(ui_config, "_ENV_PATH", env_path)
        monkeypatch.setattr(ui_config.settings, "security_level", "medium", raising=False)

        item = next(
            i for i in _ui_config_payload()["items"] if i["field"] == "security_level"
        )
        assert "pending_value" not in item


class TestSensitiveFields:
    def test_secret_value_is_masked_not_echoed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ui_config.settings, "request_hmac_secret", "super-secret-value", raising=False
        )
        item = next(
            i for i in _ui_config_payload()["items"] if i["field"] == "request_hmac_secret"
        )
        assert item["value"] == ""
        assert item["has_value"] is True
        assert "super-secret-value" not in item["masked"]

    def test_unset_secret_reports_no_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ui_config.settings, "request_hmac_secret", "", raising=False)
        item = next(
            i for i in _ui_config_payload()["items"] if i["field"] == "request_hmac_secret"
        )
        assert item["has_value"] is False
        assert item["masked"] == ""


class TestCoercion:
    def _meta(self, field: str) -> dict:
        return _ui_config_field_map()[field]

    def test_float_field_keeps_the_fraction(self) -> None:
        assert _coerce_config_value(self._meta("semantic_gray_low"), "0.35") == 0.35

    def test_int_field_accepts_a_round_float_round_trip(self) -> None:
        """The browser sends 600.0 back for an int-typed field; that must not 400."""
        assert _coerce_config_value(self._meta("upstream_max_connections"), "300.0") == 300

    def test_int_field_rejects_a_real_fraction(self) -> None:
        with pytest.raises(ValueError):
            _coerce_config_value(self._meta("upstream_max_connections"), "300.5")

    def test_range_is_enforced(self) -> None:
        meta = self._meta("risk_score_threshold")
        assert _coerce_config_value(meta, "0.7") == 0.7
        with pytest.raises(ValueError):
            _coerce_config_value(meta, "1.5")
        with pytest.raises(ValueError):
            _coerce_config_value(meta, "-0.1")

    def test_port_range_is_enforced(self) -> None:
        meta = self._meta("port")
        assert _coerce_config_value(meta, "18080") == 18080
        with pytest.raises(ValueError):
            _coerce_config_value(meta, "70000")

    def test_enum_rejects_unknown_option(self) -> None:
        with pytest.raises(ValueError):
            _coerce_config_value(self._meta("storage_backend"), "cassandra")

    def test_bool_parsing(self) -> None:
        meta = self._meta("enable_redaction")
        assert _coerce_config_value(meta, "true") is True
        assert _coerce_config_value(meta, "off") is False


class TestSections:
    def test_payload_carries_section_metadata(self) -> None:
        payload = _ui_config_payload()
        assert [s["id"] for s in payload["sections"]] == [
            s["id"] for s in _UI_CONFIG_SECTIONS
        ]
        assert all(s.get("label") and s.get("icon") for s in payload["sections"])

    def test_every_section_has_at_least_one_field(self) -> None:
        used = {str(item["section"]) for item in _UI_CONFIG_FIELDS}
        empty = [s["id"] for s in _UI_CONFIG_SECTIONS if s["id"] not in used]
        assert empty == []


class TestConfigRoute:
    """Route-level contract. ``reload_settings`` is stubbed: hot-reload has its own
    tests, and what matters here is what the console is told about the save."""

    @pytest.fixture()
    def client(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from aegisgate.core import gateway_ui_routes
        from aegisgate.core import hot_reload

        env_path = tmp_path / ".env"
        env_path.write_text("AEGIS_LOG_LEVEL=info\n", encoding="utf-8")
        monkeypatch.setattr(ui_config, "_ENV_PATH", env_path)
        monkeypatch.setattr(hot_reload, "reload_settings", lambda: None)
        monkeypatch.setattr(gateway_ui_routes, "write_audit", lambda payload: None)

        app = FastAPI()
        gateway_ui_routes.register_ui_routes(app)
        with TestClient(app) as client:
            client.env_path = env_path  # type: ignore[attr-defined]
            yield client

    def test_get_returns_items_and_sections(self, client) -> None:
        payload = client.get("/__ui__/api/config").json()
        assert len(payload["items"]) == len(_UI_CONFIG_FIELDS)
        assert [s["id"] for s in payload["sections"]] == [s["id"] for s in _UI_CONFIG_SECTIONS]

    def test_hot_reloadable_save_reports_no_restart(self, client) -> None:
        body = client.post("/__ui__/api/config", json={"values": {"log_level": "debug"}}).json()
        assert body["restart_required"] == []
        assert "AEGIS_LOG_LEVEL=debug" in client.env_path.read_text(encoding="utf-8")

    def test_pinned_save_reports_restart_required(self, client) -> None:
        """The F1 regression: this used to answer "已热重载" with an empty list."""
        response = client.post("/__ui__/api/config", json={"values": {"security_level": "high"}})
        body = response.json()
        assert body["restart_required"] == ["security_level"]
        assert "AEGIS_SECURITY_LEVEL=high" in client.env_path.read_text(encoding="utf-8")

    def test_pinned_save_echoes_the_pending_value_not_the_stale_one(
        self, client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ui_config.settings, "security_level", "medium", raising=False)
        body = client.post("/__ui__/api/config", json={"values": {"security_level": "high"}}).json()
        item = next(i for i in body["config"]["items"] if i["field"] == "security_level")
        assert item["value"] == "high"
        assert item["pending_value"] == "high"

    def test_empty_secret_submission_is_ignored(self, client) -> None:
        body = client.post(
            "/__ui__/api/config", json={"values": {"request_hmac_secret": ""}}
        ).json()
        assert body["updated"] == {}
        assert "AEGIS_REQUEST_HMAC_SECRET" not in client.env_path.read_text(encoding="utf-8")

    def test_secret_value_is_not_echoed_in_the_save_response(self, client) -> None:
        body = client.post(
            "/__ui__/api/config", json={"values": {"request_hmac_secret": "s3cr3t-value"}}
        ).json()
        assert body["updated"]["request_hmac_secret"] == "***"
        assert "s3cr3t-value" in client.env_path.read_text(encoding="utf-8")

    def test_out_of_range_value_is_rejected(self, client) -> None:
        response = client.post(
            "/__ui__/api/config", json={"values": {"risk_score_threshold": "1.9"}}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_field_value"
        assert "AEGIS_RISK_SCORE_THRESHOLD" not in client.env_path.read_text(encoding="utf-8")

    def test_unknown_field_is_rejected(self, client) -> None:
        response = client.post("/__ui__/api/config", json={"values": {"nope": "1"}})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_field"

    def test_bootstrap_serves_section_metadata(self, client) -> None:
        sections = client.get("/__ui__/api/bootstrap").json()["config_sections"]
        assert isinstance(sections, list)
        assert [s["id"] for s in sections] == [s["id"] for s in _UI_CONFIG_SECTIONS]
