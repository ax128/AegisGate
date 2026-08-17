"""PostgreSQL-backed mapping and pending-confirmation store."""

from __future__ import annotations

import re
import time
from contextlib import contextmanager
from typing import Any, Iterator

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

from aegisgate.storage._helpers import LRUMappingCache
from aegisgate.storage.crypto import (
    decrypt_mapping,
    encrypt_mapping,
)
from aegisgate.storage.kv import KVStore

psycopg_module: Any
psycopg_sql_module: Any
try:
    import psycopg as psycopg_module
    from psycopg import sql as psycopg_sql_module
except ImportError:  # pragma: no cover - optional dependency
    psycopg_module = None
    psycopg_sql_module = None

_ConnectionPool: Any
try:
    from psycopg_pool import ConnectionPool as _ConnectionPool
except ImportError:
    _ConnectionPool = None


class PostgresKVStore(KVStore):
    def __init__(
        self,
        *,
        dsn: str,
        schema: str = "public",
        max_cache_entries: int = 5000,
    ) -> None:
        if psycopg_module is None:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "psycopg package is not installed, cannot use PostgresKVStore"
            )
        if not dsn.strip():
            raise RuntimeError("postgres dsn is empty")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", schema):
            raise RuntimeError("postgres schema contains invalid characters")

        self.dsn = dsn
        self.schema = schema
        self.max_cache_entries = max_cache_entries
        self._cache = LRUMappingCache(max_cache_entries)

        # Pre-build SQL-safe qualified table identifiers.
        if psycopg_sql_module is not None:
            _id = psycopg_sql_module.Identifier
            self._mapping_table = psycopg_sql_module.SQL("{}.{}").format(
                _id(schema), _id("mapping_store")
            )
            self._pending_table = psycopg_sql_module.SQL("{}.{}").format(
                _id(schema), _id("pending_confirmation")
            )
            self._schema_id = _id(schema)
        else:  # pragma: no cover - fallback when psycopg.sql unavailable
            self._mapping_table = psycopg_sql_module  # will fail at _init_db
            self._pending_table = psycopg_sql_module
            self._schema_id = psycopg_sql_module

        self._pool = None
        if _ConnectionPool is not None:
            try:
                self._pool = _ConnectionPool(
                    dsn,
                    min_size=2,
                    max_size=10,
                    max_idle=300.0,
                )
            except Exception:
                logger.warning(
                    "postgres: connection pool creation failed, falling back to per-call connections"
                )
                self._pool = None

        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[Any]:
        """Yield a psycopg connection from the pool or a fresh one."""
        if self._pool is not None:
            with self._pool.connection() as conn:
                yield conn
        else:
            conn = psycopg_module.connect(self.dsn)
            try:
                yield conn
            finally:
                conn.close()

    def close(self) -> None:
        """Shut down the connection pool if one is active."""
        if self._pool is not None:
            try:
                self._pool.close()
            except Exception:
                pass
            self._pool = None

    def _sql(self, template: str) -> Any:
        """Build a SQL composable by substituting {mt}/{pt}/{schema} placeholders."""
        S = psycopg_sql_module.SQL
        return S(template).format(
            mt=self._mapping_table,
            pt=self._pending_table,
            schema=self._schema_id,
        )

    def _init_db(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(self._sql("CREATE SCHEMA IF NOT EXISTS {schema}"))
                cur.execute(
                    self._sql(
                        """
                    CREATE TABLE IF NOT EXISTS {mt} (
                      session_id TEXT NOT NULL,
                      request_id TEXT NOT NULL,
                      payload TEXT NOT NULL,
                      created_at BIGINT NOT NULL DEFAULT 0,
                      PRIMARY KEY (session_id, request_id)
                    )
                    """
                    )
                )
                cur.execute(
                    self._sql(
                        """
                    ALTER TABLE {mt}
                    ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0
                    """
                    )
                )
                cur.execute(
                    self._sql(
                        """
                    CREATE INDEX IF NOT EXISTS idx_mapping_store_created_at
                    ON {mt} (created_at)
                    """
                    )
                )
                cur.execute(
                    self._sql("UPDATE {mt} SET created_at = %s WHERE created_at = 0"),
                    (int(time.time()),),
                )
                cur.execute(
                    self._sql(
                        """
                    CREATE TABLE IF NOT EXISTS {pt} (
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
                      created_at BIGINT NOT NULL,
                      expires_at BIGINT NOT NULL,
                      retained_until BIGINT NOT NULL,
                      updated_at BIGINT NOT NULL,
                      tenant_id TEXT NOT NULL DEFAULT 'default'
                    )
                    """
                    )
                )
                cur.execute(
                    self._sql(
                        """
                    ALTER TABLE {pt}
                    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default'
                    """
                    )
                )
                cur.execute(
                    self._sql(
                        """
                    CREATE INDEX IF NOT EXISTS idx_pending_session_status
                    ON {pt} (session_id, status, created_at DESC)
                    """
                    )
                )
                cur.execute(
                    self._sql(
                        """
                    CREATE INDEX IF NOT EXISTS idx_pending_tenant_session_route_status
                    ON {pt} (tenant_id, session_id, route, status, created_at DESC)
                    """
                    )
                )
                cur.execute(
                    self._sql(
                        """
                    CREATE INDEX IF NOT EXISTS idx_pending_retained_until
                    ON {pt} (retained_until)
                    """
                    )
                )
            conn.commit()

    def set_mapping(
        self, session_id: str, request_id: str, mapping: dict[str, str]
    ) -> None:
        self._cache.set(session_id, request_id, mapping)
        payload = encrypt_mapping(mapping)
        created_at = int(time.time())
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    self._sql(
                        """
                        INSERT INTO {mt} (session_id, request_id, payload, created_at)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (session_id, request_id)
                        DO UPDATE SET
                          payload = EXCLUDED.payload,
                          created_at = EXCLUDED.created_at
                        """
                    ),
                    (session_id, request_id, payload, created_at),
                )
            conn.commit()

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        cached = self._cache.get(session_id, request_id)
        if cached is not None:
            return cached

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    self._sql(
                        "SELECT payload FROM {mt} WHERE session_id = %s AND request_id = %s"
                    ),
                    (session_id, request_id),
                )
                row = cur.fetchone()
        if not row:
            return {}
        mapping = decrypt_mapping(str(row[0]))
        self._cache.set(session_id, request_id, mapping)
        return mapping

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        cached = self._cache.pop(session_id, request_id)
        if cached is not None:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        self._sql(
                            "DELETE FROM {mt} WHERE session_id = %s AND request_id = %s"
                        ),
                        (session_id, request_id),
                    )
                conn.commit()
            return cached

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    self._sql(
                        """
                        SELECT payload FROM {mt}
                        WHERE session_id = %s AND request_id = %s
                        FOR UPDATE
                        """
                    ),
                    (session_id, request_id),
                )
                row = cur.fetchone()
                if row:
                    cur.execute(
                        self._sql(
                            "DELETE FROM {mt} WHERE session_id = %s AND request_id = %s"
                        ),
                        (session_id, request_id),
                    )
            conn.commit()
        if not row:
            return {}
        return decrypt_mapping(str(row[0]))

    def prune_expired_mappings(self, max_age_seconds: int) -> int:
        ttl = max(300, int(max_age_seconds))
        cutoff = int(time.time()) - ttl
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    self._sql(
                        "DELETE FROM {mt} WHERE created_at > 0 AND created_at < %s"
                    ),
                    (cutoff,),
                )
                removed = int(cur.rowcount or 0)
            conn.commit()
        if removed > 0:
            self._cache = LRUMappingCache(self.max_cache_entries)
        return removed

    def prune_pending_confirmations(self, now_ts: int) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    self._sql("DELETE FROM {pt} WHERE retained_until <= %s"),
                    (int(now_ts),),
                )
                removed = int(cur.rowcount or 0)
                # Recover stale "executing" records back to "pending"
                timeout = int(settings.confirmation_executing_timeout_seconds)
                if timeout > 0:
                    recover_before = int(now_ts) - max(5, timeout)
                    cur.execute(
                        self._sql(
                            "UPDATE {pt} SET status = 'pending', updated_at = %s"
                            " WHERE status = 'executing' AND updated_at <= %s"
                        ),
                        (now_ts, recover_before),
                    )
            conn.commit()
        return removed

    def clear_all_pending_confirmations(self) -> int:
        """Clear every pending-confirmation record at startup; after a restart only confirmations for new requests count."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(self._sql("DELETE FROM {pt}"))
                removed = int(cur.rowcount or 0)
            conn.commit()
        return removed
