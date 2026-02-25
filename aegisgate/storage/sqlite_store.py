"""SQLite-backed mapping store with concurrency optimizations."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, TypeVar

from aegisgate.storage.crypto import decrypt_mapping, encrypt_mapping
from aegisgate.storage.kv import KVStore
from aegisgate.util.logger import logger


T = TypeVar("T")


class SqliteKVStore(KVStore):
    def __init__(self, db_path: str = "logs/aegisgate.db", max_cache_entries: int = 5000) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.max_cache_entries = max_cache_entries
        self._cache: OrderedDict[tuple[str, str], dict[str, str]] = OrderedDict()
        self._cache_lock = threading.Lock()

        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mapping_store (
                  session_id TEXT NOT NULL,
                  request_id TEXT NOT NULL,
                  payload TEXT NOT NULL,
                  PRIMARY KEY (session_id, request_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_confirmation (
                  confirm_id TEXT PRIMARY KEY,
                  session_id TEXT NOT NULL,
                  route TEXT NOT NULL,
                  request_id TEXT NOT NULL,
                  model TEXT NOT NULL,
                  upstream_base TEXT NOT NULL,
                  pending_request_payload TEXT NOT NULL,
                  pending_request_hash TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  summary TEXT NOT NULL,
                  status TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL,
                  retained_until INTEGER NOT NULL,
                  updated_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pending_session_status
                ON pending_confirmation (session_id, status, created_at DESC)
                """
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

    def _cache_set(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        key = (session_id, request_id)
        with self._cache_lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = dict(mapping)
            while len(self._cache) > self.max_cache_entries:
                self._cache.popitem(last=False)

    def _cache_get(self, session_id: str, request_id: str) -> dict[str, str] | None:
        key = (session_id, request_id)
        with self._cache_lock:
            data = self._cache.get(key)
            if data is None:
                return None
            self._cache.move_to_end(key)
            return dict(data)

    def _cache_pop(self, session_id: str, request_id: str) -> dict[str, str] | None:
        key = (session_id, request_id)
        with self._cache_lock:
            data = self._cache.pop(key, None)
            return dict(data) if data is not None else None

    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        self._cache_set(session_id, request_id, mapping)
        payload = encrypt_mapping(mapping)

        def _write() -> None:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO mapping_store (session_id, request_id, payload)
                    VALUES (?, ?, ?)
                    ON CONFLICT(session_id, request_id)
                    DO UPDATE SET payload=excluded.payload
                    """,
                    (session_id, request_id, payload),
                )
                conn.commit()

        self._with_retry(_write)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        cached = self._cache_get(session_id, request_id)
        if cached is not None:
            return cached

        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM mapping_store WHERE session_id = ? AND request_id = ?",
                (session_id, request_id),
            ).fetchone()

        if not row:
            return {}

        mapping = decrypt_mapping(row[0])
        self._cache_set(session_id, request_id, mapping)
        return mapping

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        cached = self._cache_pop(session_id, request_id)
        if cached is not None:

            def _delete_cached_row() -> None:
                with self._connect() as conn:
                    conn.execute(
                        "DELETE FROM mapping_store WHERE session_id = ? AND request_id = ?",
                        (session_id, request_id),
                    )
                    conn.commit()

            self._with_retry(_delete_cached_row)
            return cached

        def _read_and_delete() -> tuple[str] | None:
            with self._connect() as conn:
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

    def save_pending_confirmation(
        self,
        *,
        confirm_id: str,
        session_id: str,
        route: str,
        request_id: str,
        model: str,
        upstream_base: str,
        pending_request_payload: dict[str, Any],
        pending_request_hash: str,
        reason: str,
        summary: str,
        created_at: int,
        expires_at: int,
        retained_until: int,
    ) -> None:
        payload = json_dumps(pending_request_payload)

        def _write() -> None:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO pending_confirmation (
                      confirm_id, session_id, route, request_id, model, upstream_base,
                      pending_request_payload, pending_request_hash, reason, summary,
                      status, created_at, expires_at, retained_until, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        confirm_id,
                        session_id,
                        route,
                        request_id,
                        model,
                        upstream_base,
                        payload,
                        pending_request_hash,
                        reason,
                        summary,
                        "pending",
                        created_at,
                        expires_at,
                        retained_until,
                        created_at,
                    ),
                )
                conn.commit()

        self._with_retry(_write)

    def get_latest_pending_confirmation(self, session_id: str, now_ts: int) -> dict[str, Any] | None:
        def _read() -> tuple | None:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT
                      confirm_id, session_id, route, request_id, model, upstream_base,
                      pending_request_payload, pending_request_hash, reason, summary,
                      status, created_at, expires_at, retained_until, updated_at
                    FROM pending_confirmation
                    WHERE session_id = ? AND status = 'pending'
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (session_id,),
                ).fetchone()
            return row

        row = self._with_retry(_read)
        if not row:
            return None
        record = _pending_row_to_dict(row)
        if int(record["expires_at"]) <= int(now_ts):
            self.update_pending_confirmation_status(confirm_id=str(record["confirm_id"]), status="expired", now_ts=now_ts)
            return None
        return record

    def get_pending_confirmation(self, confirm_id: str) -> dict[str, Any] | None:
        def _read() -> tuple | None:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT
                      confirm_id, session_id, route, request_id, model, upstream_base,
                      pending_request_payload, pending_request_hash, reason, summary,
                      status, created_at, expires_at, retained_until, updated_at
                    FROM pending_confirmation
                    WHERE confirm_id = ?
                    LIMIT 1
                    """,
                    (confirm_id,),
                ).fetchone()
            return row

        row = self._with_retry(_read)
        if not row:
            return None
        return _pending_row_to_dict(row)

    def update_pending_confirmation_status(self, *, confirm_id: str, status: str, now_ts: int) -> None:
        def _write() -> None:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE pending_confirmation
                    SET status = ?, updated_at = ?
                    WHERE confirm_id = ?
                    """,
                    (status, now_ts, confirm_id),
                )
                conn.commit()

        self._with_retry(_write)

    def prune_pending_confirmations(self, now_ts: int) -> int:
        def _delete() -> int:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM pending_confirmation
                    WHERE retained_until <= ?
                    """,
                    (now_ts,),
                )
                conn.commit()
                return int(cursor.rowcount or 0)

        return self._with_retry(_delete)

    def clear_all_pending_confirmations(self) -> int:
        """启动时清空所有待确认记录，重启后仅新请求的确认有效。"""
        def _delete() -> int:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM pending_confirmation")
                conn.commit()
                return int(cursor.rowcount or 0)
        return self._with_retry(_delete)


def json_dumps(data: dict[str, Any]) -> str:
    import json

    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_loads(data: str) -> dict[str, Any]:
    import json

    loaded = json.loads(data)
    if isinstance(loaded, dict):
        return loaded
    return {}


def _pending_row_to_dict(row: tuple) -> dict[str, Any]:
    return {
        "confirm_id": row[0],
        "session_id": row[1],
        "route": row[2],
        "request_id": row[3],
        "model": row[4],
        "upstream_base": row[5],
        "pending_request_payload": json_loads(row[6]),
        "pending_request_hash": row[7],
        "reason": row[8],
        "summary": row[9],
        "status": row[10],
        "created_at": row[11],
        "expires_at": row[12],
        "retained_until": row[13],
        "updated_at": row[14],
    }
