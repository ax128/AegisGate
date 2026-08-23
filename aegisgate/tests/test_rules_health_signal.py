"""A rules file that stops parsing has to be visible from outside the process.

Keeping the last good document in memory when a reload fails is what stops one
config typo from failing every request — but it also means a process running a
policy the file no longer describes is indistinguishable, from the outside, from
a healthy one. The reload logs an ERROR and returns ``ok: False``, and both of
those reach exactly nobody who is not already looking.

Two halves are pinned here: the loader records *why* the file does not parse, and
``/ready`` reports it.

``/ready`` reports it **without** failing readiness, which is the deliberate part.
Gating on this would undo the reason the last-good behaviour exists: every replica
reads the same file, so they would all leave rotation together and a typo would
become a full outage instead of a warning. The check sits in the body — plus a
``degraded_checks`` list, so a non-gating problem is visible to anyone reading
only the top of the response — and the log carries the detail.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from aegisgate.config import security_rules
from aegisgate.config.security_rules import (
    invalidate_security_rules_cache,
    load_security_rules,
    security_rules_load_error,
)
from aegisgate.core import gateway, hot_reload

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REAL_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"

_BROKEN = "redaction:\n  pii_patterns:\n   - id: X\n  bad: : :\n"


@pytest.fixture()
def rules_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "security_filters.yaml"
    shutil.copy(_REAL_RULES, path)
    monkeypatch.setattr(
        security_rules.settings, "security_rules_path", str(path), raising=False
    )
    invalidate_security_rules_cache()
    yield path
    invalidate_security_rules_cache()


def _rewrite(path: Path, text: str) -> None:
    """Write *text* and push mtime forward so the mtime-keyed cache really misses."""
    import os

    before = path.stat().st_mtime_ns
    path.write_text(text, encoding="utf-8")
    after = before + 1_000_000_000
    os.utime(path, ns=(after, after))


class TestLoaderRecordsWhyTheFileDoesNotParse:
    def test_a_readable_file_reports_nothing(self, rules_file: Path) -> None:
        load_security_rules()

        assert security_rules_load_error() is None

    def test_a_broken_file_is_recorded_while_the_process_keeps_working(
        self, rules_file: Path
    ) -> None:
        before = len(load_security_rules()["redaction"]["pii_patterns"])

        _rewrite(rules_file, _BROKEN)
        result = hot_reload.reload_security_rules()

        assert result["ok"] is False
        # Still serving — that is the behaviour this signal exists to make visible,
        # not one it should change.
        assert len(load_security_rules()["redaction"]["pii_patterns"]) == before
        reason = security_rules_load_error()
        assert reason is not None and "Error" in reason

    def test_a_cache_hit_does_not_clear_it(self, rules_file: Path) -> None:
        load_security_rules()
        _rewrite(rules_file, _BROKEN)
        hot_reload.reload_security_rules()

        # Every later read is a cache hit against the same broken file. A hit
        # means nothing changed on disk, so it must not read as "fixed".
        for _ in range(3):
            load_security_rules()
        assert security_rules_load_error() is not None

    def test_fixing_the_file_clears_it(self, rules_file: Path) -> None:
        load_security_rules()
        _rewrite(rules_file, _BROKEN)
        hot_reload.reload_security_rules()
        assert security_rules_load_error() is not None

        _rewrite(rules_file, _REAL_RULES.read_text(encoding="utf-8"))
        hot_reload.reload_security_rules()

        assert security_rules_load_error() is None

    def test_broken_before_anything_was_ever_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The case the watcher alone cannot cover.

        It only fires when a file *changes*, so a file already broken at startup
        never triggers a callback. The loader records the failure wherever it
        happens, which covers this one too.
        """
        path = tmp_path / "security_filters.yaml"
        path.write_text(_BROKEN, encoding="utf-8")
        monkeypatch.setattr(
            security_rules.settings, "security_rules_path", str(path), raising=False
        )
        invalidate_security_rules_cache()
        try:
            with pytest.raises(Exception):
                load_security_rules()

            assert security_rules_load_error() is not None
        finally:
            invalidate_security_rules_cache()


def _ready_body(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(gateway.app.state, "ready", True, raising=False)
    response = gateway.ready()
    body = json.loads(bytes(response.body).decode("utf-8"))
    body["_status_code"] = response.status_code
    return body


class TestReadyReportsItWithoutFailingReadiness:
    def test_a_readable_file_is_ok(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        load_security_rules()

        body = _ready_body(monkeypatch)

        assert body["checks"]["security_rules"] == "ok"
        assert "security_rules" not in body["degraded_checks"]

    def test_a_broken_file_is_reported_but_still_ready(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        load_security_rules()
        _rewrite(rules_file, _BROKEN)
        hot_reload.reload_security_rules()

        body = _ready_body(monkeypatch)

        assert body["checks"]["security_rules"].startswith("stale: ")
        assert "security_rules" in body["degraded_checks"]
        # The deliberate part. Every replica reads the same file, so gating here
        # would pull them all out of rotation together — turning the config typo
        # this signal is meant to surface into the outage it is meant to prevent.
        assert body["_status_code"] == 200
        assert body["status"] == "ready"

    def test_a_gating_check_still_fails_readiness(
        self, rules_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The non-gating carve-out must not have disarmed the rest of the probe."""
        from aegisgate.adapters.openai_compat import pipeline_runtime

        def _boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("storage down")

        monkeypatch.setattr(pipeline_runtime.store, "get_mapping", _boom)
        load_security_rules()

        body = _ready_body(monkeypatch)

        assert body["_status_code"] == 503
        assert body["status"] == "degraded"
        assert body["checks"]["storage"].startswith("error: ")
        assert "storage" in body["degraded_checks"]
