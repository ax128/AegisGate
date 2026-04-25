from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegisgate.storage import postgres_store
from aegisgate.storage.postgres_store import PostgresKVStore
from aegisgate.storage.sqlite_store import SqliteKVStore


def test_prune_expired_mappings_removes_old_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "aegisgate.db"
    store = SqliteKVStore(db_path=str(db_path))
    store.set_mapping("S1", "R1", {"{{X}}": "secret"})

    old_ts = int(time.time()) - 1000
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE mapping_store SET created_at = ? WHERE session_id = ? AND request_id = ?",
            (old_ts, "S1", "R1"),
        )
        conn.commit()
    finally:
        conn.close()

    removed = store.prune_expired_mappings(max_age_seconds=300)
    assert removed >= 1

    fresh = SqliteKVStore(db_path=str(db_path))
    assert fresh.get_mapping("S1", "R1") == {}


def test_prune_expired_mappings_preserves_recent_rows(tmp_path: Path) -> None:
    """C-03: freshly inserted rows must NOT be pruned by prune_expired_mappings.

    The minimum safety window enforced by prune_expired_mappings is 300 s,
    so rows with created_at = now() survive regardless of the max_age argument.
    """
    db_path = tmp_path / "aegisgate.db"
    store = SqliteKVStore(db_path=str(db_path))
    store.set_mapping("S2", "R2", {"{{Y}}": "fresh-secret"})

    # The store sets created_at = now(); prune with a tiny max_age
    # to ensure the 300-s safety floor protects the new row.
    removed = store.prune_expired_mappings(max_age_seconds=1)
    assert removed == 0, "freshly inserted row must not be pruned"

    fresh = SqliteKVStore(db_path=str(db_path))
    assert fresh.get_mapping("S2", "R2") == {"{{Y}}": "fresh-secret"}


class _FakePostgresCache:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], dict[str, str]] = {}

    def set(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        self.values[(session_id, request_id)] = dict(mapping)


class _FakePostgresCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []
        self.rowcount = 0

    def __enter__(self) -> "_FakePostgresCursor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def execute(self, sql: str, params: tuple[object, ...] | None = None) -> None:
        self.executed.append((sql, params))


class _FakePostgresConnection:
    def __init__(self, cursor: _FakePostgresCursor) -> None:
        self.cursor_obj = cursor
        self.commits = 0

    def cursor(self) -> _FakePostgresCursor:
        return self.cursor_obj

    def commit(self) -> None:
        self.commits += 1


def _fake_postgres_store(
    cursor: _FakePostgresCursor, conn: _FakePostgresConnection
) -> PostgresKVStore:
    store = PostgresKVStore.__new__(PostgresKVStore)
    store._cache = _FakePostgresCache()
    store.max_cache_entries = 5000

    @contextmanager
    def connect():
        yield conn

    store._connect = connect
    store._sql = lambda template: template.format(
        mt="mapping_store", pt="pending_confirmation", schema="public"
    )
    return store


def test_postgres_set_mapping_writes_created_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = _FakePostgresCursor()
    conn = _FakePostgresConnection(cursor)
    store = _fake_postgres_store(cursor, conn)
    monkeypatch.setattr(postgres_store, "encrypt_mapping", lambda mapping: "payload")

    store.set_mapping("S1", "R1", {"{{X}}": "secret"})

    assert cursor.executed
    sql, params = cursor.executed[-1]
    assert "created_at" in sql
    assert params is not None
    assert len(params) == 4
    assert isinstance(params[3], int)


def test_postgres_prune_expired_mappings_deletes_old_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = _FakePostgresCursor()
    cursor.rowcount = 2
    conn = _FakePostgresConnection(cursor)
    store = _fake_postgres_store(cursor, conn)
    now = int(time.time())
    monkeypatch.setattr(
        postgres_store, "time", SimpleNamespace(time=lambda: now), raising=False
    )

    removed = store.prune_expired_mappings(max_age_seconds=300)

    assert removed == 2
    sql, params = cursor.executed[-1]
    assert "DELETE FROM mapping_store" in sql
    assert "created_at" in sql
    assert params == (now - 300,)
    assert conn.commits == 1
