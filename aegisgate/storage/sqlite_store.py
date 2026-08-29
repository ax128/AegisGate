"""SQLite-backed mapping store with concurrency optimizations."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, TypeVar

from aegisgate.storage._helpers import LRUMappingCache, MIN_MAPPING_TTL_SECONDS
from aegisgate.storage.crypto import (
    decrypt_mapping,
    encrypt_mapping,
)
from aegisgate.storage.kv import KVStore
from aegisgate.util.logger import logger


T = TypeVar("T")


class SqliteKVStore(KVStore):
    def __init__(
        self, db_path: str = "logs/aegisgate.db", max_cache_entries: int = 5000
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.max_cache_entries = max_cache_entries
        self._cache = LRUMappingCache(max_cache_entries)

        # One connection per thread. Connections cannot be shared between
        # threads, and the request path runs on the filter-pipeline pool
        # (8-32 workers) with the loop thread and the prune task alongside it.
        self._conn_lock = threading.Lock()  # guards the dict and _closed only
        self._connections: dict[int, tuple[sqlite3.Connection, threading.RLock]] = {}
        self._closed = False

        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        # check_same_thread=False so close() can reach a connection another
        # thread opened — with the default it raises ProgrammingError, which is
        # what makes "close every thread's connection" impossible. Safety comes
        # from the per-connection lock instead: the pool is keyed by thread id,
        # so the only cross-thread access is close(), and that takes the lock.
        #
        # The pool is bounded without a cap: thread ids are reused once a thread
        # dies, and the threads that reach here are pool workers that live until
        # shutdown — filter-pipeline <= 32, store-io 4, the loop thread, the
        # prune task. It converges on that count rather than growing.
        #
        # Bounded per store, and there can be more than one store: RuntimeStoreProxy
        # keeps up to _MAX_RETIRED_BACKENDS retired backends alive and reads fall
        # through every one of them, so each storage-settings hot reload adds a
        # store whose pool then fills with the same threads. Before pooling these
        # handles were transient; now the idle footprint is roughly
        # (retired + 1) * threads connections, each holding the db, -wal and -shm.
        # That is a real change in fd usage even though it is bounded, and it is
        # the first thing to look at if a long-lived process starts running out.
        conn = sqlite3.connect(self.db_path, timeout=5.0, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _checkout(self) -> tuple[sqlite3.Connection, threading.RLock] | None:
        """The pooled entry for this thread, or None when the caller should use a
        throwaway connection (the pre-pooling behaviour)."""
        key = threading.get_ident()
        with self._conn_lock:
            if self._closed:
                return None
            entry = self._connections.get(key)
            if entry is not None:
                return entry
        conn = self._connect()
        with self._conn_lock:
            if self._closed:  # closed while we were connecting
                conn.close()
                return None
            entry = self._connections.setdefault(key, (conn, threading.RLock()))
        if entry[0] is not conn:
            conn.close()  # someone on this thread won the race
        return entry

    def _discard(self, key: int, conn: sqlite3.Connection) -> None:
        """Evict a connection whose rollback failed; the next call reconnects.

        Only ever called while holding that connection's own lock, so close() is
        either already past it or still waiting — either way nobody else is
        using the handle. Compare identity before removing: the thread id could
        have been recycled onto a different entry, and evicting someone else's
        live connection is worse than leaking this one.
        """
        with self._conn_lock:
            entry = self._connections.get(key)
            if entry is not None and entry[0] is conn:
                del self._connections[key]
        try:
            conn.close()
        except sqlite3.Error:
            pass

    @contextmanager
    def _throwaway(self) -> Iterator[sqlite3.Connection]:
        """Exactly the pre-pooling path, kept in one place so both callers agree."""
        conn = self._connect()
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def _managed_connection(self) -> Iterator[sqlite3.Connection]:
        entry = self._checkout()
        if entry is None:
            with self._throwaway() as conn:
                yield conn
            return

        conn, use_lock = entry
        with use_lock:
            # Re-check under the per-connection lock. _checkout can hand back an
            # entry and then lose the CPU while close() runs to completion — it
            # takes this same lock, shuts the handle and releases. Without this
            # second look the next statement would hit a closed connection, and
            # ProgrammingError is not a message _with_retry retries on.
            # gateway.py closes the store before draining the executors, so this
            # ordering is the expected one, not a rare interleaving.
            if self._closed:
                with self._throwaway() as fresh:
                    yield fresh
                return
            try:
                if conn.in_transaction:
                    # Defence in depth against a path that got past the finally
                    # below. Inheriting an open transaction would make
                    # consume_mapping's BEGIN IMMEDIATE fail with a message
                    # _with_retry does not treat as retryable.
                    conn.rollback()
            except sqlite3.Error:
                # The handle cannot be cleaned up, so it cannot be handed to the
                # caller. Drop it and serve this call the pre-pooling way rather
                # than raising: the caller asked to store a mapping, not to be
                # told about the pool's internal state.
                self._discard(threading.get_ident(), conn)
                with self._throwaway() as fresh:
                    yield fresh
                return
            try:
                yield conn
            except Exception:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    self._discard(threading.get_ident(), conn)  # unusable, drop it
                raise
            finally:
                # End any transaction *here*, not at the next checkout. Before
                # pooling, the finally that closed the connection ended it
                # immediately; deferring the rollback to this thread's next
                # store call would leave SQLite's write lock held by an idle
                # worker for an unbounded time, and every other thread and
                # process would spend _with_retry's five attempts on "database
                # is locked" while it sat there. A clean operation leaves
                # in_transaction False and this is a no-op.
                #
                # The whole probe is inside the try, not just the rollback: the
                # except branch above may already have discarded (and closed)
                # this handle, and reading .in_transaction on a closed
                # connection raises ProgrammingError — from a finally, that
                # would replace the original exception with a confusing one.
                # sqlite3.ProgrammingError is a sqlite3.Error, so this catches
                # that case too, and _discard is safe to reach twice.
                try:
                    if conn.in_transaction:
                        conn.rollback()
                except sqlite3.Error:
                    self._discard(threading.get_ident(), conn)

    def close(self) -> None:
        """Close every pooled connection, including ones other threads opened.

        New behaviour: the base class's close() is a no-op, so
        close_runtime_dependencies() and RuntimeStoreProxy.swap()'s overflow
        path did nothing here before. They now really release handles — and
        because gateway.py closes the store before it shuts the executors down,
        anything still in flight falls back to a throwaway connection (in
        _checkout, or in _managed_connection's re-check for callers already past
        it), which is what every operation did before pooling.

        This blocks its caller: it waits on each per-connection lock so it never
        closes a handle another thread is mid-statement on. The caller is the
        lifespan shutdown, so a slow in-flight statement slows shutdown.

        A closed store never re-opens its pool. That is deliberate: the only
        callers are shutdown and swap()'s overflow eviction, and an evicted
        backend has already been dropped from _backend_candidates, so nothing
        routes new work to it. A future caller needing a store to come back to
        life wants a new instance, not a _closed flag that flips back.
        """
        with self._conn_lock:
            self._closed = True
            entries = list(self._connections.values())
            self._connections.clear()
        for conn, use_lock in entries:
            with use_lock:  # waits for an in-flight operation
                try:
                    conn.close()
                except sqlite3.Error as exc:
                    logger.warning("sqlite connection close failed error=%s", exc)

    def _init_db(self) -> None:
        # Its own throwaway connection: this runs during construction, and the
        # constructing thread is not necessarily one of the serving threads, so
        # seeding the pool with it would leave an entry nobody reuses.
        with self._throwaway() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mapping_store (
                  session_id TEXT NOT NULL,
                  request_id TEXT NOT NULL,
                  payload TEXT NOT NULL,
                  created_at INTEGER NOT NULL DEFAULT 0,
                  PRIMARY KEY (session_id, request_id)
                )
                """
            )
            # C-03: Migrate existing mapping_store tables that lack created_at.
            mapping_cols = {
                str(row[1]).lower()
                for row in conn.execute("PRAGMA table_info(mapping_store)").fetchall()
            }
            if "created_at" not in mapping_cols:
                conn.execute(
                    "ALTER TABLE mapping_store ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0"
                )
            conn.execute(
                "UPDATE mapping_store SET created_at = ? WHERE created_at = 0",
                (int(time.time()),),
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_mapping_store_created_at ON mapping_store(created_at)"
            )
            conn.commit()
        logger.info("sqlite store initialized path=%s", self.db_path)

    def _with_retry(self, fn: Callable[[], T], retries: int = 5) -> T:
        for attempt in range(retries):
            try:
                return fn()
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == retries - 1:
                    raise
                sleep_seconds = 0.01 * (attempt + 1)
                time.sleep(sleep_seconds)
        raise RuntimeError("unreachable retry state")

    def set_mapping(
        self, session_id: str, request_id: str, mapping: dict[str, str]
    ) -> None:
        import time as _time
        self._cache.set(session_id, request_id, mapping)
        payload = encrypt_mapping(mapping)
        now_ts = int(_time.time())

        def _write() -> None:
            with self._managed_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO mapping_store (session_id, request_id, payload, created_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(session_id, request_id)
                    DO UPDATE SET payload=excluded.payload, created_at=excluded.created_at
                    """,
                    (session_id, request_id, payload, now_ts),
                )
                conn.commit()

        self._with_retry(_write)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        cached = self._cache.get(session_id, request_id)
        if cached is not None:
            return cached

        with self._managed_connection() as conn:
            row = conn.execute(
                "SELECT payload FROM mapping_store WHERE session_id = ? AND request_id = ?",
                (session_id, request_id),
            ).fetchone()

        if not row:
            return {}

        mapping = decrypt_mapping(row[0])
        self._cache.set(session_id, request_id, mapping)
        return mapping

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        cached = self._cache.pop(session_id, request_id)
        if cached is not None:

            def _delete_cached_row() -> None:
                with self._managed_connection() as conn:
                    conn.execute(
                        "DELETE FROM mapping_store WHERE session_id = ? AND request_id = ?",
                        (session_id, request_id),
                    )
                    conn.commit()

            self._with_retry(_delete_cached_row)
            return cached

        def _read_and_delete() -> tuple[str] | None:
            with self._managed_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT payload FROM mapping_store WHERE session_id = ? AND request_id = ?",
                    (session_id, request_id),
                ).fetchone()
                if row:
                    conn.execute(
                        "DELETE FROM mapping_store WHERE session_id = ? AND request_id = ?",
                        (session_id, request_id),
                    )
                conn.commit()
                return row

        row = self._with_retry(_read_and_delete)
        if not row:
            return {}
        return decrypt_mapping(row[0])

    def prune_expired_mappings(self, max_age_seconds: int = 86400) -> int:
        """C-03: Remove mapping_store rows older than max_age_seconds.

        Should be called periodically (e.g. hourly) to prevent indefinite
        accumulation of stale PII mappings.
        """
        import time as _time
        cutoff = int(_time.time()) - max(MIN_MAPPING_TTL_SECONDS, max_age_seconds)

        def _prune() -> int:
            with self._managed_connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM mapping_store WHERE created_at > 0 AND created_at < ?",
                    (cutoff,),
                )
                conn.commit()
                return int(cursor.rowcount or 0)

        removed = self._with_retry(_prune)
        if removed > 0:
            self._cache = LRUMappingCache(self.max_cache_entries)
        return removed

