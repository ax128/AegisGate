"""P5 acceptance: the gateway-forwarding console API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.config import settings as settings_module
from aegisgate.core import gateway_ui_config, gateway_ui_routes, gw_forwards, hot_reload


@pytest.fixture()
def ctx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "gw_forwards.json"
    monkeypatch.setattr(settings_module.settings, "gw_forwards_path", str(path), raising=False)
    monkeypatch.setattr(settings_module.settings, "enable_gateway_forward", True, raising=False)
    monkeypatch.setattr(
        settings_module.settings, "forward_allow_public_baseline_off", False, raising=False
    )
    monkeypatch.setattr(
        settings_module.settings, "enable_request_hmac_auth", False, raising=False
    )
    monkeypatch.setattr(gateway_ui_config, "_ENV_PATH", tmp_path / ".env")
    monkeypatch.setattr(hot_reload, "reload_settings", lambda: None)
    audits: list[dict] = []
    monkeypatch.setattr(gateway_ui_routes, "write_audit", lambda payload: audits.append(payload))
    gw_forwards.load(replace=True)

    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    with TestClient(app) as client:
        client.audits = audits  # type: ignore[attr-defined]
        yield client, path, audits
    gw_forwards.load(replace=True)


def _rule_body(**overrides) -> dict:
    body = {
        "host": "api.ag.com",
        "enabled": True,
        "upstream_base": "https://api.xxx.com",
        "note": "sub2api",
        "expose": "internal",
        "filters": {"mode": "policy"},
    }
    body.update(overrides)
    return body


class TestList:
    def test_empty_list_has_global_state(self, ctx) -> None:
        client, _path, _audits = ctx
        response = client.get("/__ui__/api/forwards")
        assert response.status_code == 200
        payload = response.json()
        assert payload["items"] == []
        assert payload["denied"] == []
        assert payload["enable_gateway_forward"] is True
        assert payload["public_baseline_off_allowed"] is False
        assert set(payload["global_filters"]) == gw_forwards._allowed_filter_names()
        assert response.headers["ETag"]

    def test_denied_entries_are_listed_with_reason(self, ctx) -> None:
        client, path, _audits = ctx
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "forwards": {
                        "bad.ag.com": _rule_body(
                            host="bad.ag.com",
                            filters={"mode": "custom", "custom": {"nope": True}},
                        )
                    },
                }
            ),
            encoding="utf-8",
        )
        gw_forwards.load(replace=True)
        payload = client.get("/__ui__/api/forwards").json()
        assert payload["items"] == []
        assert payload["denied"][0]["host"] == "bad.ag.com"
        assert payload["denied"][0]["reason"] == "forward_rule_invalid"


class TestCreate:
    def test_create_writes_and_lists(self, ctx) -> None:
        client, path, audits = ctx
        response = client.post("/__ui__/api/forwards", json=_rule_body())
        assert response.status_code == 201
        assert response.json()["host"] == "api.ag.com"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["forwards"]["api.ag.com"]["upstream_base"] == "https://api.xxx.com"
        items = client.get("/__ui__/api/forwards").json()["items"]
        assert items[0]["host"] == "api.ag.com"
        assert audits and audits[-1]["event"] == "ui_forward_create"

    def test_create_duplicate_is_409(self, ctx) -> None:
        client, _path, _audits = ctx
        client.post("/__ui__/api/forwards", json=_rule_body())
        response = client.post("/__ui__/api/forwards", json=_rule_body())
        assert response.status_code == 409

    def test_unknown_filter_name_is_400(self, ctx) -> None:
        client, _path, _audits = ctx
        response = client.post(
            "/__ui__/api/forwards",
            json=_rule_body(filters={"mode": "custom", "custom": {"nope": True}}),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_forward_rule"

    @pytest.mark.parametrize("body", [["not", "an", "object"], "text", 3])
    def test_non_object_body_is_400(self, ctx, body) -> None:
        client, _path, _audits = ctx
        response = client.post("/__ui__/api/forwards", json=body)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_json"

    def test_unhashable_field_is_400_not_500(self, ctx) -> None:
        client, _path, _audits = ctx
        response = client.post("/__ui__/api/forwards", json=_rule_body(expose=["public"]))
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_forward_rule"

    def test_internal_baseline_off_is_audited(self, ctx) -> None:
        client, _path, audits = ctx
        response = client.post(
            "/__ui__/api/forwards",
            json=_rule_body(filters={"mode": "custom", "custom": {"redaction": False}}),
        )
        assert response.status_code == 201
        assert audits[-1]["event"] == "ui_forward_create"
        assert audits[-1]["baseline_off"] is True

    def test_create_refused_under_hmac_conflict_keeps_the_file(
        self, ctx, monkeypatch
    ) -> None:
        client, path, _audits = ctx
        path.write_text(
            json.dumps({"version": 1, "forwards": {"old.ag.com": _rule_body(host="old.ag.com")}}),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            settings_module.settings, "enable_request_hmac_auth", True, raising=False
        )
        gw_forwards.load(replace=True)
        before = path.read_bytes()
        response = client.post("/__ui__/api/forwards", json=_rule_body())
        assert response.status_code == 409
        assert response.json()["error"] == "forward_table_locked"
        assert path.read_bytes() == before

    def test_create_refused_while_file_is_unparseable(self, ctx) -> None:
        client, path, _audits = ctx
        path.write_text("{ half-edited", encoding="utf-8")
        gw_forwards.load(replace=True)
        response = client.post("/__ui__/api/forwards", json=_rule_body())
        assert response.status_code == 409
        assert response.json()["error"] == "forward_table_locked"
        assert path.read_text(encoding="utf-8") == "{ half-edited"

    def test_public_baseline_off_is_400_and_points_at_the_flag(self, ctx) -> None:
        client, _path, _audits = ctx
        response = client.post(
            "/__ui__/api/forwards",
            json=_rule_body(
                expose="public",
                filters={"mode": "custom", "custom": {"redaction": False}},
            ),
        )
        assert response.status_code == 400
        assert "AEGIS_FORWARD_ALLOW_PUBLIC_BASELINE_OFF" in response.json()["detail"]


class TestUpdateDelete:
    def test_update_replaces_rule(self, ctx) -> None:
        client, _path, audits = ctx
        client.post("/__ui__/api/forwards", json=_rule_body())
        response = client.patch(
            "/__ui__/api/forwards/api.ag.com",
            json=_rule_body(upstream_base="https://api2.xxx.com"),
        )
        assert response.status_code == 200
        assert gw_forwards.get("api.ag.com").upstream_base == "https://api2.xxx.com"
        assert audits[-1]["event"] == "ui_forward_update"

    def test_stale_if_match_is_409(self, ctx) -> None:
        client, _path, _audits = ctx
        first = client.get("/__ui__/api/forwards")
        stale = first.headers["ETag"]
        client.post("/__ui__/api/forwards", json=_rule_body())
        response = client.patch(
            "/__ui__/api/forwards/api.ag.com",
            json=_rule_body(),
            headers={"If-Match": stale},
        )
        assert response.status_code == 409
        assert response.json()["error"] == "etag_mismatch"

    def test_rename_moves_the_rule_in_one_write(self, ctx) -> None:
        client, path, audits = ctx
        client.post("/__ui__/api/forwards", json=_rule_body())
        response = client.patch(
            "/__ui__/api/forwards/api.ag.com", json=_rule_body(host="new.ag.com")
        )
        assert response.status_code == 200
        assert response.headers["ETag"]
        assert set(json.loads(path.read_text(encoding="utf-8"))["forwards"]) == {"new.ag.com"}
        assert audits[-1]["previous_host"] == "api.ag.com"

    def test_rename_onto_an_existing_host_is_409(self, ctx) -> None:
        client, _path, _audits = ctx
        client.post("/__ui__/api/forwards", json=_rule_body())
        client.post("/__ui__/api/forwards", json=_rule_body(host="taken.ag.com"))
        response = client.patch(
            "/__ui__/api/forwards/api.ag.com", json=_rule_body(host="taken.ag.com")
        )
        assert response.status_code == 409
        assert response.json()["error"] == "forward_host_exists"
        assert gw_forwards.get("api.ag.com") is not None

    def test_update_of_missing_host_is_404(self, ctx) -> None:
        client, _path, _audits = ctx
        response = client.patch("/__ui__/api/forwards/missing.ag.com", json=_rule_body())
        assert response.status_code == 404

    def test_failed_write_leaves_the_old_rule_in_place(self, ctx, monkeypatch) -> None:
        client, _path, _audits = ctx
        client.post("/__ui__/api/forwards", json=_rule_body())

        def disk_full(_payload: bytes) -> None:
            raise OSError("no space left on device")

        monkeypatch.setattr(gw_forwards, "_atomic_write", disk_full)
        response = client.patch(
            "/__ui__/api/forwards/api.ag.com", json=_rule_body(upstream_base="https://api2.xxx.com")
        )
        assert response.status_code == 500
        assert gw_forwards.get("api.ag.com").upstream_base == "https://api.xxx.com"

    def test_delete_removes(self, ctx) -> None:
        client, _path, _audits = ctx
        client.post("/__ui__/api/forwards", json=_rule_body())
        response = client.delete("/__ui__/api/forwards/api.ag.com")
        assert response.status_code == 200
        assert gw_forwards.get("api.ag.com") is None
        assert client.delete("/__ui__/api/forwards/api.ag.com").status_code == 404


class TestProbe:
    def test_probe_reuses_module_level_impl(self, ctx, monkeypatch) -> None:
        client, _path, audits = ctx
        called: list[str] = []

        async def fake_probe(upstream_base: str) -> dict:
            called.append(upstream_base)
            return {"reachable": True, "status_code": 200, "elapsed_ms": 1}

        monkeypatch.setattr(gateway_ui_routes, "_probe_upstream", fake_probe)
        response = client.post(
            "/__ui__/api/forwards/probe",
            json={"upstream_base": "https://api.xxx.com"},
        )
        assert response.status_code == 200
        assert response.json()["reachable"] is True
        assert called == ["https://api.xxx.com"]
        assert audits[-1]["event"] == "ui_forward_probe"

    def test_probe_refuses_metadata_target(self, ctx) -> None:
        client, _path, _audits = ctx
        response = client.post(
            "/__ui__/api/forwards/probe",
            json={"upstream_base": "http://169.254.169.254"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "probe_target_forbidden"


class TestSharedValidationGuard:
    def test_console_uses_the_loader_validator(self, monkeypatch) -> None:
        sentinel = object()
        calls: list[tuple] = []

        def fake_validate(host, raw):
            calls.append((host, raw))
            return sentinel, None

        monkeypatch.setattr(gw_forwards, "validate_rule", fake_validate)
        rule, reason = gateway_ui_routes._forward_rule_from_body("api.ag.com", _rule_body())
        assert rule is sentinel
        assert reason is None
        assert calls and calls[0][0] == "api.ag.com"


_INDEX = Path(__file__).resolve().parents[2] / "www" / "index.html"
_APP_JS = Path(__file__).resolve().parents[2] / "www" / "assets" / "app.js"


class TestConsoleMarkup:
    def test_nav_and_section_and_modal_exist(self) -> None:
        html = _INDEX.read_text(encoding="utf-8")
        assert 'href="#forwards"' in html
        assert '<section id="forwards"' in html
        assert 'id="forward-modal"' in html
        assert 'id="forward-filter-list"' in html

    def test_panel_uses_the_forwards_api(self) -> None:
        js = _APP_JS.read_text(encoding="utf-8")
        assert '"/__ui__/api/forwards"' in js
        assert "/__ui__/api/forwards/probe" in js
        assert "resource: \"forwards\"" in js

    def test_baseline_off_needs_a_second_confirmation(self) -> None:
        js = _APP_JS.read_text(encoding="utf-8")
        assert "FORWARD_BASELINE_FILTERS" in js
        assert "确认关闭基线脱敏" in js
        assert "原文直达上游" in js

    def test_public_gate_locks_only_the_off_choice(self) -> None:
        js = _APP_JS.read_text(encoding="utf-8")
        body = js.split("function renderForwardFilters", 1)[1].split("\nfunction ", 1)[0]
        # Disabling the whole select dropped an explicit "on" from the saved rule.
        assert '${offLocked ? "disabled" : ""}>关</option>' in body
        assert 'data-filter="${escapeHtml(name)}" ${' not in body

    def test_filter_choices_are_tri_state(self) -> None:
        js = _APP_JS.read_text(encoding="utf-8")
        # "follow policy" must stay expressible, otherwise every save would
        # override all 13 filters and the config's "missing key = no override"
        # semantics would be unreachable from the console.
        assert "跟随策略" in js
        assert "forwardState.globalFilters" in js
