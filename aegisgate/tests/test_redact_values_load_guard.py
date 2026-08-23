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
