import pytest

from aegisgate.storage.sqlite_store import SqliteKVStore, json_loads


class _FakeConnection:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def rollback(self) -> None:
        self._events.append("rollback")

    def close(self) -> None:
        self._events.append("close")


def test_managed_connection_closes_connection_after_success(monkeypatch):
    store = SqliteKVStore.__new__(SqliteKVStore)
    events: list[str] = []
    monkeypatch.setattr(store, "_connect", lambda: _FakeConnection(events))

    with store._managed_connection() as conn:
        assert isinstance(conn, _FakeConnection)

    assert events == ["close"]


def test_managed_connection_closes_connection_after_error(monkeypatch):
    store = SqliteKVStore.__new__(SqliteKVStore)
    events: list[str] = []
    monkeypatch.setattr(store, "_connect", lambda: _FakeConnection(events))

    with pytest.raises(RuntimeError, match="boom"):
        with store._managed_connection():
            raise RuntimeError("boom")

    assert events == ["rollback", "close"]


def test_json_loads_returns_empty_dict_for_invalid_payload():
    assert json_loads("{not-json") == {}
