"""SQLite-backed mapping store with concurrency optimizations."""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, TypeVar

from aegisgate.storage._helpers import LRUMappingCache
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

        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _managed_connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._managed_connection() as conn:
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
        cutoff = int(_time.time()) - max(300, max_age_seconds)

        def _prune() -> int:
            with self._managed_connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM mapping_store WHERE created_at > 0 AND created_at < ?",
                    (cutoff,),
                )
                conn.commit()
                return int(cursor.rowcount or 0)

        return self._with_retry(_prune)

