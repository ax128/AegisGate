"""One SQLite connection per thread, and a close() that can actually reach them."""

from __future__ import annotations

import sqlite3
import threading

import pytest

from aegisgate.storage._helpers import LRUMappingCache
from aegisgate.storage.sqlite_store import SqliteKVStore


def test_same_thread_reuses_one_connection(tmp_path) -> None:
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    seen = set()
    for _ in range(5):
        with store._managed_connection() as conn:
            seen.add(id(conn))
    assert len(seen) == 1
    store.close()


def test_close_releases_connections_from_every_thread(tmp_path) -> None:
    """The reason check_same_thread=False is not optional here."""
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    ready = threading.Barrier(3)

    def work() -> None:
        store.set_mapping("s", f"r{threading.get_ident()}", {"k": "v"})
        ready.wait()

    threads = [threading.Thread(target=work) for _ in range(2)]
    for thread in threads:
        thread.start()
    ready.wait()
    for thread in threads:
        thread.join()
    assert len(store._connections) == 2
    store.close()  # crosses threads; must not raise
    assert not store._connections


def test_operations_after_close_fall_back_instead_of_raising(tmp_path) -> None:
    """gateway.py closes the store before the executors, so in-flight work still
    arrives here — it must behave exactly as it did before pooling."""
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    store.close()
    store.set_mapping("s", "r", {"k": "v"})
    store._cache = LRUMappingCache(store.max_cache_entries)  # force the DB, not the cache
    assert store.get_mapping("s", "r") == {"k": "v"}


def test_checkout_racing_close_falls_back_too(tmp_path) -> None:
    """The gap between _checkout() returning and taking the per-connection lock.

    close() can complete inside it, so re-checking _closed only in _checkout is
    not enough: the caller would then operate on a handle close() already shut,
    and ProgrammingError is not what _with_retry retries on. This is the exact
    ordering gateway.py produces — the store is closed while the filter-pipeline
    executor is still draining.
    """
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    store.set_mapping("warm", "up", {"k": "v"})  # put this thread in the pool
    store._cache = LRUMappingCache(store.max_cache_entries)  # else get() never checks out

    entered = threading.Event()
    released = threading.Event()
    real_checkout = store._checkout

    def slow_checkout():
        entry = real_checkout()
        entered.set()
        released.wait(5)  # park in the gap
        return entry

    store._checkout = slow_checkout
    result: list = []
    worker = threading.Thread(target=lambda: result.append(store.get_mapping("warm", "up")))
    worker.start()
    entered.wait(5)
    store.close()  # shut the connection while the caller sits in the gap
    released.set()
    worker.join(5)
    assert result == [{"k": "v"}], "the racing caller did not fall back"


def test_connection_is_reusable_after_a_failed_transaction(tmp_path) -> None:
    """A failed op must not hand the next one a connection in a dirty state."""
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    with pytest.raises(RuntimeError):
        with store._managed_connection() as conn:
            conn.execute("INSERT INTO mapping_store VALUES ('a','b','c',1)")
            raise RuntimeError("boom")
    store.set_mapping("s", "r", {"k": "v"})  # same connection, must still work
    assert store.get_mapping("s", "r") == {"k": "v"}
    with store._managed_connection() as conn:
        assert not conn.in_transaction  # rolled back cleanly
    store.close()


def test_a_stray_transaction_ends_when_the_block_exits(tmp_path) -> None:
    """Not "the next caller survives it" — nobody holds the write lock in between.

    Before pooling, the finally that closed the connection ended the transaction
    at once. Rolling back only on the *next* checkout would let an idle worker
    thread sit on SQLite's write lock indefinitely, and every other thread and
    process would burn _with_retry's five attempts on "database is locked".
    """
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    with store._managed_connection() as conn:
        conn.execute("INSERT INTO mapping_store VALUES ('a','b','c',1)")  # implicit BEGIN
        assert conn.in_transaction
    with store._managed_connection() as conn:
        assert not conn.in_transaction  # ended on exit, not on the next checkout
    store.consume_mapping("a", "b")  # BEGIN IMMEDIATE must not raise
    store.close()


def test_the_pool_lock_is_reentrant(tmp_path) -> None:
    """_managed_connection yields while holding the per-connection lock, so a
    plain Lock would turn any nested store call into a permanent hang with no
    timeout, no exception and no log line. No caller nests today; this pins the
    property so adding one is a normal bug rather than a hung worker thread."""
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    store.set_mapping("s", "r", {"k": "v"})
    with store._managed_connection():
        store.set_mapping("s2", "r2", {"k": "v"})  # same thread, must not hang
    store.close()


def test_init_db_does_not_pool_the_constructing_thread(tmp_path) -> None:
    """The thread that builds the store is not necessarily a serving thread, so
    _init_db uses its own throwaway connection rather than seeding the pool."""
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    assert store._connections == {}
    store.close()


def test_close_is_idempotent_and_final(tmp_path) -> None:
    """A closed store never re-opens its pool: the only callers are shutdown and
    swap()'s overflow eviction, and an evicted backend has already been dropped
    from the candidate list, so nothing routes new work to it."""
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    store.set_mapping("s", "r", {"k": "v"})
    store.close()
    store.close()  # must not raise
    store.set_mapping("s2", "r2", {"k": "v"})
    assert store._connections == {}, "a closed store re-populated its pool"


class _RollbackFails:
    """A connection whose rollback raises.

    A stub rather than a monkeypatched sqlite3.Connection: `rollback` is a
    read-only attribute on the real object, so the failure this test is about
    cannot be induced on one.
    """

    def __init__(self, in_transaction: bool = False) -> None:
        self.in_transaction = in_transaction
        self.closed = False

    def rollback(self) -> None:
        raise sqlite3.OperationalError("rollback failed")

    def execute(self, *args: object, **kwargs: object) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def test_a_broken_rollback_evicts_the_connection(tmp_path) -> None:
    """If rollback fails the handle is unusable; the next call must reconnect
    rather than keep handing out a dead one."""
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    store.set_mapping("s", "r", {"k": "v"})
    key = threading.get_ident()
    real_conn, _lock = store._connections[key]
    real_conn.close()

    broken = _RollbackFails()
    store._connections[key] = (broken, threading.RLock())  # type: ignore[assignment]

    with pytest.raises(RuntimeError):
        with store._managed_connection() as active:
            assert active is broken
            raise RuntimeError("boom")

    assert key not in store._connections, "the unusable connection stayed in the pool"
    assert broken.closed, "the evicted connection was not closed"
    store.set_mapping("s3", "r3", {"k": "v"})  # reconnects
    store._cache = LRUMappingCache(store.max_cache_entries)
    assert store.get_mapping("s3", "r3") == {"k": "v"}
    store.close()


def test_an_uncleanable_pooled_connection_falls_back_rather_than_raising(tmp_path) -> None:
    """The defensive pre-check has to fail safe too.

    _managed_connection rolls back a stray transaction before handing the
    connection over. If that rollback itself fails the handle is unusable — and
    raising there would surface a pool-internal error to a caller that only
    asked to read a mapping. Evict and serve the call the pre-pooling way.
    """
    store = SqliteKVStore(db_path=str(tmp_path / "t.db"))
    store.set_mapping("s", "r", {"k": "v"})
    key = threading.get_ident()
    real_conn, _lock = store._connections[key]
    real_conn.close()

    broken = _RollbackFails(in_transaction=True)
    store._connections[key] = (broken, threading.RLock())  # type: ignore[assignment]

    store._cache = LRUMappingCache(store.max_cache_entries)
    assert store.get_mapping("s", "r") == {"k": "v"}, "the call did not fall back"
    assert key not in store._connections
    assert broken.closed
    store.close()
