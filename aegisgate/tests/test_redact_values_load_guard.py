"""Exact-value redaction: what the *read* side does with a file it did not write.

``save_redact_values`` is the only writer and it validates every entry, so the
load path used to trust the decoded payload completely. It is not the only way
bytes reach that file though — a hand-edited copy, a restored backup, one
written by an older build, or one encrypted under a key that has since been
rotated — and each of those had a distinct way of going wrong:

* an empty string passes ``"" in text`` and ``text.replace("", ...)`` fires
  between every character, so one entry quietly shreds every message that goes
  upstream, raising nothing;
* a non-string entry reaches ``sorted(..., key=len)`` and raises ``TypeError``
  inside a request filter, which the pipeline reads as a filter crash;
* ``InvalidToken`` is not a ``ValueError``, so the "treating as empty" handler
  never saw ciphertext this key cannot open — rotating the Fernet key was enough
  to make every request fail.

The contract these pin down: a file this module cannot trust degrades to *no
exact-value redaction*, loudly logged, never to mangled text and never to an
exception on the request path.

Degrading quietly has its own cost, though, and the console is where it lands: an
unreadable file and an empty one both arrive as ``[]``, so the panel rendered
"nothing configured yet" over values that were still on disk, and the add button
it offered would have saved a one-entry list straight over them. Hence
``redact_values_degraded()`` and the write guard that reads it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from aegisgate.config import redact_values
from aegisgate.config.redact_values import (
    _MIN_VALUE_LENGTH,
    load_redact_values,
    redact_values_degraded,
    replace_exact_values,
    save_redact_values,
)

_GOOD_VALUE = "SUPERSECRETVALUE123"
_SAMPLE = f"my key is {_GOOD_VALUE} ok"


class _WarningRecorder:
    """The aegisgate logger does not propagate, so caplog cannot see it."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def warning(self, message: str, *args: Any) -> None:
        self.messages.append(message % args if args else message)

    def __getattr__(self, name: str) -> Any:  # pragma: no cover - unused levels
        return lambda *args, **kwargs: None

    @property
    def text(self) -> str:
        return "\n".join(self.messages)


@pytest.fixture()
def values_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Fernet, _WarningRecorder]:
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(tmp_path))
    fernet = Fernet(Fernet.generate_key())
    monkeypatch.setattr(redact_values, "_get_fernet", lambda: fernet)
    recorder = _WarningRecorder()
    monkeypatch.setattr(redact_values, "logger", recorder)
    # The path is memoised on (AEGIS_CONFIG_DIR, cwd) and the values on mtime.
    monkeypatch.setattr(redact_values, "_cached_path", None, raising=False)
    monkeypatch.setattr(redact_values, "_cached_values", None, raising=False)
    monkeypatch.setattr(redact_values, "_cached_mtime_ns", 0, raising=False)
    monkeypatch.setattr(redact_values, "_load_degraded", False, raising=False)
    return tmp_path / "redact_values.enc.json", fernet, recorder


def _write(path: Path, fernet: Fernet, payload: object) -> None:
    blob = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    path.write_text(fernet.encrypt(blob).decode("utf-8"), encoding="utf-8")
    redact_values._cached_values = None
    redact_values._cached_mtime_ns = 0


def test_the_round_trip_this_module_is_for_still_works(values_file) -> None:
    _path, _fernet, _log = values_file
    save_redact_values([_GOOD_VALUE])

    assert load_redact_values() == [_GOOD_VALUE]
    assert replace_exact_values(_SAMPLE) == ("my key is [REDACTED:EXACT_VALUE] ok", 1)


def test_an_empty_entry_cannot_shred_the_message(values_file) -> None:
    path, fernet, log = values_file
    _write(path, fernet, {"values": ["", _GOOD_VALUE]})

    # Dropped, not honoured: `"" in text` is always true, so keeping it would
    # put a placeholder between every character of every request.
    assert load_redact_values() == [_GOOD_VALUE]
    replaced, count = replace_exact_values(_SAMPLE)
    assert replaced == "my key is [REDACTED:EXACT_VALUE] ok"
    assert count == 1
    assert "dropped 1 invalid entries" in log.text
    # The entries are the secrets this module exists to keep out of logs.
    assert _GOOD_VALUE not in log.text


@pytest.mark.parametrize(
    ("bad_entry", "why"),
    [
        (12345, "a number reaches sorted(key=len) and raises TypeError"),
        (None, "null survives JSON and is not a string"),
        ({"v": _GOOD_VALUE}, "a nested object is not a string either"),
        ("short", f"below the {_MIN_VALUE_LENGTH}-character floor the writer enforces"),
    ],
)
def test_unusable_entries_are_dropped_not_raised(values_file, bad_entry, why) -> None:
    path, fernet, _log = values_file
    _write(path, fernet, {"values": [bad_entry, _GOOD_VALUE]})

    assert load_redact_values() == [_GOOD_VALUE], why
    assert replace_exact_values(_SAMPLE)[1] == 1


def test_a_mapping_payload_does_not_become_its_own_keys(values_file) -> None:
    path, fernet, log = values_file
    # ``list({"a": 1})`` is ``["a"]``: the old code promoted mapping *keys* into
    # redaction values, and a one-character value matches nearly everything.
    _write(path, fernet, {"values": {"a": 1}})

    assert load_redact_values() == []
    assert replace_exact_values(_SAMPLE) == (_SAMPLE, 0)
    assert "must be a list" in log.text


def test_ciphertext_this_key_cannot_open_degrades_instead_of_raising(
    values_file,
) -> None:
    path, _fernet, log = values_file
    stranger = Fernet(Fernet.generate_key())
    blob = json.dumps({"values": [_GOOD_VALUE]}).encode("utf-8")
    path.write_text(stranger.encrypt(blob).decode("utf-8"), encoding="utf-8")
    redact_values._cached_values = None
    redact_values._cached_mtime_ns = 0

    # InvalidToken is not a ValueError. It used to escape load_redact_values,
    # surface as a filter crash, and block every request until the file was
    # rebuilt — triggered by nothing more than a Fernet key rotation.
    assert load_redact_values() == []
    assert replace_exact_values(_SAMPLE) == (_SAMPLE, 0)
    assert "InvalidToken" in log.text


def test_garbage_that_is_not_ciphertext_at_all_degrades_too(values_file) -> None:
    path, _fernet, log = values_file
    path.write_text("this is not a fernet token", encoding="utf-8")
    redact_values._cached_values = None
    redact_values._cached_mtime_ns = 0

    assert load_redact_values() == []
    assert "treating as empty" in log.text


def test_degraded_distinguishes_unreadable_from_simply_empty(values_file) -> None:
    path, fernet, _log = values_file

    # Never written: nothing is being hidden, and a write here discards nothing.
    assert load_redact_values() == []
    assert redact_values_degraded() is False

    # Written and empty: same answer, for the same reason.
    save_redact_values([])
    assert load_redact_values() == []
    assert redact_values_degraded() is False

    # Readable, with entries this build refuses: the file was understood, the
    # surviving values are loaded, and a save would keep them.
    _write(path, fernet, {"values": ["short", _GOOD_VALUE]})
    assert load_redact_values() == [_GOOD_VALUE]
    assert redact_values_degraded() is False

    # Contents unreadable — the only case where an empty list is a lie.
    path.write_text("not a fernet token", encoding="utf-8")
    redact_values._cached_values = None
    redact_values._cached_mtime_ns = 0
    assert load_redact_values() == []
    assert redact_values_degraded() is True


def test_a_successful_save_clears_the_flag(values_file) -> None:
    path, _fernet, _log = values_file
    path.write_text("not a fernet token", encoding="utf-8")
    redact_values._cached_values = None
    redact_values._cached_mtime_ns = 0
    load_redact_values()
    assert redact_values_degraded() is True

    save_redact_values([_GOOD_VALUE])

    # Whatever was unreadable, the bytes now on disk are ours.
    assert redact_values_degraded() is False
    assert load_redact_values() == [_GOOD_VALUE]


class TestConsoleRefusesToOverwriteAnUnreadableFile:
    """The console edits this list read-modify-write.

    ``load`` returning ``[]`` for a file it could not decrypt meant the next save
    wrote a one-entry list over values that were still there — not recoverable,
    and nothing in the UI had said anything was wrong. The panel now renders the
    degraded state instead of an invitation to add, and both write endpoints
    refuse while it holds.
    """

    @pytest.fixture()
    def client(self, values_file, monkeypatch: pytest.MonkeyPatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from aegisgate.core import gateway_ui_routes

        monkeypatch.setattr(gateway_ui_routes, "write_audit", lambda payload: None)
        app = FastAPI()
        gateway_ui_routes.register_ui_routes(app)
        with TestClient(app) as c:
            c.values_file = values_file  # type: ignore[attr-defined]
            yield c

    @staticmethod
    def _break(path: Path) -> None:
        """Leave bytes on disk that this key cannot open."""
        stranger = Fernet(Fernet.generate_key())
        blob = json.dumps({"values": [_GOOD_VALUE, "SECOND-SECRET-VALUE"]}).encode("utf-8")
        path.write_text(stranger.encrypt(blob).decode("utf-8"), encoding="utf-8")
        redact_values._cached_values = None
        redact_values._cached_mtime_ns = 0

    def test_list_reports_degraded_instead_of_looking_empty(self, client) -> None:
        path, _fernet, _log = client.values_file
        self._break(path)

        body = client.get("/__ui__/api/redact_values").json()

        assert body["count"] == 0
        assert body["degraded"] is True
        assert body["degraded_detail"]

    def test_add_is_refused_and_the_file_is_left_alone(self, client) -> None:
        path, _fernet, _log = client.values_file
        self._break(path)
        before = path.read_bytes()

        response = client.post(
            "/__ui__/api/redact_values", json={"value": "NEW-SECRET-VALUE-123"}
        )

        # Asserted first because it is the consequence that matters: the two
        # values nobody can currently read are still on disk, so restoring the
        # key restores them. Without the guard this save returned 200 and
        # replaced them with a one-entry list.
        assert path.read_bytes() == before
        assert response.status_code == 409
        assert response.json()["error"] == "values_file_unreadable"

    def test_delete_is_refused_with_the_real_reason(self, client) -> None:
        path, _fernet, _log = client.values_file
        self._break(path)
        before = path.read_bytes()

        response = client.request("DELETE", "/__ui__/api/redact_values/0")

        # Not "index out of range", which describes the wrong problem to someone
        # staring at a list that should not be empty.
        assert response.status_code == 409
        assert response.json()["error"] == "values_file_unreadable"
        assert path.read_bytes() == before

    def test_a_genuinely_empty_list_still_accepts_writes(self, client) -> None:
        # The guard must not fire on the ordinary first-use path, which is the
        # other reading of an empty list.
        assert client.get("/__ui__/api/redact_values").json()["degraded"] is False

        assert client.post(
            "/__ui__/api/redact_values", json={"value": "FIRST-SECRET-VALUE"}
        ).status_code == 200

        body = client.get("/__ui__/api/redact_values").json()
        assert body["count"] == 1
        assert body["degraded"] is False

    def test_restoring_the_key_restores_both_the_values_and_writes(
        self, client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path, fernet, _log = client.values_file
        blob = json.dumps({"values": [_GOOD_VALUE]}).encode("utf-8")
        readable = fernet.encrypt(blob).decode("utf-8")

        self._break(path)
        assert client.get("/__ui__/api/redact_values").json()["degraded"] is True

        path.write_text(readable, encoding="utf-8")
        redact_values._cached_values = None
        redact_values._cached_mtime_ns = 0

        body = client.get("/__ui__/api/redact_values").json()
        assert body["degraded"] is False
        assert body["count"] == 1
        assert client.post(
            "/__ui__/api/redact_values", json={"value": "SECOND-SECRET-VALUE"}
        ).status_code == 200
