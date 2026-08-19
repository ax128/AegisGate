"""Tests for If-Match / ETag on the console's whole-file writes.

Rules YAML, ``config/.env``, compose files and the exact-value list are all
edited read-modify-write. The write is atomic but was unconditional, so two tabs
saving in sequence meant the second silently discarded the first — and for the
rules file that is a security policy rolled back with no trace.

``If-Match`` is honoured when present, not demanded: existing clients that never
send it keep working. These tests pin both halves of that contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.core import gateway_ui_config, gateway_ui_routes, hot_reload
from aegisgate.core.ui_etag import ABSENT_ETAG, etag_for_bytes, etag_for_file

_RULES_YAML = """
redaction:
  pii_patterns:
  - id: SEED
    regex: seed-pattern
action_map:
  sanitizer:
    dangerous_command: block
"""


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    env_path = tmp_path / ".env"
    env_path.write_text("AEGIS_LOG_LEVEL=info\n", encoding="utf-8")
    rules_path = tmp_path / "security_filters.yaml"
    rules_path.write_text(_RULES_YAML, encoding="utf-8")

    monkeypatch.setattr(gateway_ui_config, "_ENV_PATH", env_path)
    monkeypatch.setattr(
        gateway_ui_routes.settings, "security_rules_path", str(rules_path), raising=False
    )
    monkeypatch.setattr(hot_reload, "reload_settings", lambda: None)
    monkeypatch.setattr(gateway_ui_routes, "write_audit", lambda payload: None)

    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    with TestClient(app) as c:
        c.env_path = env_path  # type: ignore[attr-defined]
        c.rules_path = rules_path  # type: ignore[attr-defined]
        yield c


class TestEtagHelpers:
    def test_absent_file_has_a_distinct_etag(self, tmp_path: Path) -> None:
        assert etag_for_file(tmp_path / "nope") == ABSENT_ETAG

    def test_etag_is_quoted_and_content_derived(self, tmp_path: Path) -> None:
        path = tmp_path / "f"
        path.write_bytes(b"one")
        first = etag_for_file(path)
        assert first.startswith('"') and first.endswith('"')
        path.write_bytes(b"two")
        assert etag_for_file(path) != first

    def test_same_bytes_give_the_same_etag(self) -> None:
        assert etag_for_bytes(b"same") == etag_for_bytes(b"same")


class TestConfigConcurrency:
    def test_get_returns_an_etag(self, client) -> None:
        assert client.get("/__ui__/api/config").headers.get("etag")

    def test_etag_changes_after_a_write(self, client) -> None:
        before = client.get("/__ui__/api/config").headers["etag"]
        client.post("/__ui__/api/config", json={"values": {"log_level": "debug"}})
        assert client.get("/__ui__/api/config").headers["etag"] != before

    def test_write_without_if_match_still_works(self, client) -> None:
        """Backward compatibility: scripts that never send If-Match are unaffected."""
        assert client.post(
            "/__ui__/api/config", json={"values": {"log_level": "debug"}}
        ).status_code == 200

    def test_stale_if_match_is_rejected_with_409(self, client) -> None:
        stale = client.get("/__ui__/api/config").headers["etag"]
        client.post("/__ui__/api/config", json={"values": {"log_level": "debug"}})

        response = client.post(
            "/__ui__/api/config",
            json={"values": {"log_level": "warning"}},
            headers={"If-Match": stale},
        )
        assert response.status_code == 409
        assert response.json()["error"] == "etag_mismatch"
        assert response.json()["current_etag"]
        # the losing write must not have touched the file
        assert "AEGIS_LOG_LEVEL=debug" in client.env_path.read_text(encoding="utf-8")

    def test_fresh_if_match_is_accepted(self, client) -> None:
        current = client.get("/__ui__/api/config").headers["etag"]
        assert client.post(
            "/__ui__/api/config",
            json={"values": {"log_level": "warning"}},
            headers={"If-Match": current},
        ).status_code == 200

    def test_wildcard_if_match_is_accepted(self, client) -> None:
        assert client.post(
            "/__ui__/api/config",
            json={"values": {"log_level": "warning"}},
            headers={"If-Match": "*"},
        ).status_code == 200

    def test_unquoted_and_weak_validators_are_tolerated(self, client) -> None:
        current = client.get("/__ui__/api/config").headers["etag"]
        assert client.post(
            "/__ui__/api/config",
            json={"values": {"log_level": "warning"}},
            headers={"If-Match": current.strip('"')},
        ).status_code == 200
        current = client.get("/__ui__/api/config").headers["etag"]
        assert client.post(
            "/__ui__/api/config",
            json={"values": {"log_level": "error"}},
            headers={"If-Match": f"W/{current}"},
        ).status_code == 200

    def test_a_list_of_validators_matches_on_any(self, client) -> None:
        current = client.get("/__ui__/api/config").headers["etag"]
        assert client.post(
            "/__ui__/api/config",
            json={"values": {"log_level": "warning"}},
            headers={"If-Match": f'"deadbeef", {current}'},
        ).status_code == 200


class TestRulesConcurrency:
    def test_lost_update_is_prevented(self, client) -> None:
        """The scenario this exists for: two tabs, both editing rules."""
        tab_a = client.get("/__ui__/api/rules/pii_patterns").headers["etag"]
        tab_b = client.get("/__ui__/api/rules/pii_patterns").headers["etag"]
        assert tab_a == tab_b

        assert client.post(
            "/__ui__/api/rules/pii_patterns",
            json={"id": "FROM_A", "regex": "a"},
            headers={"If-Match": tab_a},
        ).status_code == 201

        rejected = client.post(
            "/__ui__/api/rules/pii_patterns",
            json={"id": "FROM_B", "regex": "b"},
            headers={"If-Match": tab_b},
        )
        assert rejected.status_code == 409

        ids = {i["id"] for i in client.get("/__ui__/api/rules/pii_patterns").json()["items"]}
        assert "FROM_A" in ids
        assert "FROM_B" not in ids

    def test_delete_honours_if_match(self, client) -> None:
        stale = client.get("/__ui__/api/rules/pii_patterns").headers["etag"]
        client.post("/__ui__/api/rules/pii_patterns", json={"id": "TMP", "regex": "t"})

        assert client.delete(
            "/__ui__/api/rules/pii_patterns/SEED", headers={"If-Match": stale}
        ).status_code == 409

        fresh = client.get("/__ui__/api/rules/pii_patterns").headers["etag"]
        assert client.delete(
            "/__ui__/api/rules/pii_patterns/SEED", headers={"If-Match": fresh}
        ).status_code == 200

    def test_patch_honours_if_match(self, client) -> None:
        stale = client.get("/__ui__/api/rules/pii_patterns").headers["etag"]
        client.post("/__ui__/api/rules/pii_patterns", json={"id": "TMP2", "regex": "t"})
        assert client.patch(
            "/__ui__/api/rules/pii_patterns/SEED",
            json={"regex": "changed"},
            headers={"If-Match": stale},
        ).status_code == 409

    def test_action_map_shares_the_rules_file_validator(self, client) -> None:
        """Both endpoints write security_filters.yaml, so one must invalidate
        the other's ETag."""
        action_etag = client.get("/__ui__/api/rules_action_map").headers["etag"]
        client.post("/__ui__/api/rules/pii_patterns", json={"id": "TMP3", "regex": "t"})
        assert client.patch(
            "/__ui__/api/rules_action_map",
            json={"sanitizer": {"dangerous_command": "sanitize"}},
            headers={"If-Match": action_etag},
        ).status_code == 409

    def test_writes_without_if_match_are_unaffected(self, client) -> None:
        assert client.post(
            "/__ui__/api/rules/pii_patterns", json={"id": "NO_HEADER", "regex": "n"}
        ).status_code == 201
        assert client.delete("/__ui__/api/rules/pii_patterns/NO_HEADER").status_code == 200


class TestComposeConcurrency:
    def test_stale_put_is_rejected(self, client, tmp_path: Path, monkeypatch) -> None:
        compose_dir = tmp_path / "compose"
        compose_dir.mkdir()
        (compose_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        monkeypatch.setattr(
            gateway_ui_routes.settings, "compose_dir", str(compose_dir), raising=False
        )
        stale = client.get("/__ui__/api/compose/docker-compose.yml").headers["etag"]
        assert client.put(
            "/__ui__/api/compose/docker-compose.yml", json={"content": "services: {a: {}}\n"}
        ).status_code == 200
        response = client.put(
            "/__ui__/api/compose/docker-compose.yml",
            json={"content": "services: {b: {}}\n"},
            headers={"If-Match": stale},
        )
        assert response.status_code == 409
        assert "a" in (compose_dir / "docker-compose.yml").read_text(encoding="utf-8")


class TestRedactValuesConcurrency:
    def test_positional_delete_is_guarded(self, client, tmp_path: Path, monkeypatch) -> None:
        """Deleting "row 3" from a stale view would otherwise remove whatever
        now happens to sit at row 3."""
        monkeypatch.setenv("AEGIS_CONFIG_DIR", str(tmp_path))
        from aegisgate.config import redact_values

        monkeypatch.setattr(redact_values, "_cached_path", None, raising=False)
        monkeypatch.setattr(redact_values, "_cached_values", None, raising=False)

        client.post("/__ui__/api/redact_values", json={"value": "first-secret-value"})
        stale = client.get("/__ui__/api/redact_values").headers["etag"]
        client.post("/__ui__/api/redact_values", json={"value": "second-secret-value"})

        assert client.request(
            "DELETE", "/__ui__/api/redact_values/0", headers={"If-Match": stale}
        ).status_code == 409
        assert client.get("/__ui__/api/redact_values").json()["count"] == 2
