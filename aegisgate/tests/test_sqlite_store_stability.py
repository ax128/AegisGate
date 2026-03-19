import pytest

from aegisgate.storage.sqlite_store import SqliteKVStore


class _FakeConnection:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def __enter__(self):
        self._events.append("enter")
        return self

    def __exit__(self, exc_type, exc, tb):
        self._events.append("exit")
        return False

    def close(self) -> None:
        self._events.append("close")


def test_managed_connection_closes_connection_after_success(monkeypatch):
    store = SqliteKVStore.__new__(SqliteKVStore)
    events: list[str] = []
    monkeypatch.setattr(store, "_connect", lambda: _FakeConnection(events))

    with store._managed_connection() as conn:
        assert isinstance(conn, _FakeConnection)

    assert events == ["enter", "exit", "close"]


def test_managed_connection_closes_connection_after_error(monkeypatch):
    store = SqliteKVStore.__new__(SqliteKVStore)
    events: list[str] = []
    monkeypatch.setattr(store, "_connect", lambda: _FakeConnection(events))

    with pytest.raises(RuntimeError, match="boom"):
        with store._managed_connection():
            raise RuntimeError("boom")

    assert events == ["enter", "exit", "close"]
