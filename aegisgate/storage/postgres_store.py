"""PostgreSQL-backed mapping and pending-confirmation store."""

from __future__ import annotations

import json
import re
import threading
from collections import OrderedDict
from typing import Any

from aegisgate.storage.crypto import decrypt_mapping, encrypt_mapping
from aegisgate.storage.kv import KVStore

try:
    import psycopg
except Exception:  # pragma: no cover - optional dependency
    psycopg = None


def _json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _json_loads(data: str) -> dict[str, Any]:
    loaded = json.loads(data)
    if isinstance(loaded, dict):
        return loaded
    return {}


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


class PostgresKVStore(KVStore):
    def __init__(
        self,
        *,
        dsn: str,
        schema: str = "public",
        max_cache_entries: int = 5000,
    ) -> None:
        if psycopg is None:  # pragma: no cover - optional dependency
            raise RuntimeError("psycopg package is not installed, cannot use PostgresKVStore")
        if not dsn.strip():
            raise RuntimeError("postgres dsn is empty")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", schema):
            raise RuntimeError("postgres schema contains invalid characters")

        self.dsn = dsn
        self.schema = schema
        self.max_cache_entries = max_cache_entries
        self._cache: OrderedDict[tuple[str, str], dict[str, str]] = OrderedDict()
        self._cache_lock = threading.Lock()

        self._init_db()

    def _connect(self):
        return psycopg.connect(self.dsn)

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

    def _init_db(self) -> None:
        mapping_table = f"{self.schema}.mapping_store"
        pending_table = f"{self.schema}.pending_confirmation"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"CREATE SCHEMA IF NOT EXISTS {self.schema}")
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {mapping_table} (
                      session_id TEXT NOT NULL,
                      request_id TEXT NOT NULL,
                      payload TEXT NOT NULL,
                      PRIMARY KEY (session_id, request_id)
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {pending_table} (
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
                cur.execute(
                    f"""
                    ALTER TABLE {pending_table}
                    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default'
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_pending_session_status
                    ON {pending_table} (session_id, status, created_at DESC)
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_pending_tenant_session_route_status
                    ON {pending_table} (tenant_id, session_id, route, status, created_at DESC)
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_pending_retained_until
                    ON {pending_table} (retained_until)
                    """
                )
            conn.commit()

    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        self._cache_set(session_id, request_id, mapping)
        payload = encrypt_mapping(mapping)
        mapping_table = f"{self.schema}.mapping_store"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {mapping_table} (session_id, request_id, payload)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (session_id, request_id)
                    DO UPDATE SET payload = EXCLUDED.payload
                    """,
                    (session_id, request_id, payload),
                )
            conn.commit()

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        cached = self._cache_get(session_id, request_id)
        if cached is not None:
            return cached

        mapping_table = f"{self.schema}.mapping_store"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT payload FROM {mapping_table} WHERE session_id = %s AND request_id = %s",
                    (session_id, request_id),
                )
                row = cur.fetchone()
        if not row:
            return {}
        mapping = decrypt_mapping(str(row[0]))
        self._cache_set(session_id, request_id, mapping)
        return mapping

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        cached = self._cache_pop(session_id, request_id)
        mapping_table = f"{self.schema}.mapping_store"
        if cached is not None:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"DELETE FROM {mapping_table} WHERE session_id = %s AND request_id = %s",
                        (session_id, request_id),
                    )
                conn.commit()
            return cached

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT payload FROM {mapping_table}
                    WHERE session_id = %s AND request_id = %s
                    FOR UPDATE
                    """,
                    (session_id, request_id),
                )
                row = cur.fetchone()
                if row:
                    cur.execute(
                        f"DELETE FROM {mapping_table} WHERE session_id = %s AND request_id = %s",
                        (session_id, request_id),
                    )
            conn.commit()
        if not row:
            return {}
        return decrypt_mapping(str(row[0]))

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
        tenant_id: str = "default",
    ) -> None:
        pending_table = f"{self.schema}.pending_confirmation"
        payload = _json_dumps(pending_request_payload)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {pending_table} (
                      confirm_id, session_id, route, request_id, model, upstream_base,
                      pending_request_payload, pending_request_hash, reason, summary,
                      status, created_at, expires_at, retained_until, updated_at, tenant_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (confirm_id)
                    DO UPDATE SET
                      status = EXCLUDED.status,
                      route = EXCLUDED.route,
                      request_id = EXCLUDED.request_id,
                      model = EXCLUDED.model,
                      upstream_base = EXCLUDED.upstream_base,
                      pending_request_payload = EXCLUDED.pending_request_payload,
                      pending_request_hash = EXCLUDED.pending_request_hash,
                      reason = EXCLUDED.reason,
                      summary = EXCLUDED.summary,
                      created_at = EXCLUDED.created_at,
                      expires_at = EXCLUDED.expires_at,
                      retained_until = EXCLUDED.retained_until,
                      updated_at = EXCLUDED.updated_at,
                      tenant_id = EXCLUDED.tenant_id
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
                        int(created_at),
                        int(expires_at),
                        int(retained_until),
                        int(created_at),
                        tenant_id,
                    ),
                )
            conn.commit()

    def get_latest_pending_confirmation(
        self,
        session_id: str,
        now_ts: int,
        *,
        tenant_id: str = "default",
    ) -> dict[str, Any] | None:
        pending_table = f"{self.schema}.pending_confirmation"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT
                      confirm_id, session_id, route, request_id, model, upstream_base,
                      pending_request_payload, pending_request_hash, reason, summary,
                      status, created_at, expires_at, retained_until, updated_at, tenant_id
                    FROM {pending_table}
                    WHERE session_id = %s AND tenant_id = %s AND status = 'pending'
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (session_id, tenant_id),
                )
                row = cur.fetchone()
        if not row:
            return None
        record = self._row_to_pending_record(row)
        if int(record.get("expires_at", 0)) <= int(now_ts):
            self.update_pending_confirmation_status(
                confirm_id=str(record["confirm_id"]),
                status="expired",
                now_ts=now_ts,
            )
            return None
        return record

    def get_single_pending_confirmation(
        self,
        *,
        session_id: str,
        route: str,
        now_ts: int,
        tenant_id: str = "default",
        recover_executing_before: int | None = None,
    ) -> dict[str, Any] | None:
        pending_table = f"{self.schema}.pending_confirmation"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT
                      confirm_id, session_id, route, request_id, model, upstream_base,
                      pending_request_payload, pending_request_hash, reason, summary,
                      status, created_at, expires_at, retained_until, updated_at, tenant_id
                    FROM {pending_table}
                    WHERE session_id = %s AND route = %s AND tenant_id = %s AND expires_at > %s
                      AND status IN ('pending', 'executing')
                    ORDER BY created_at DESC
                    LIMIT 6
                    """,
                    (session_id, route, tenant_id, int(now_ts)),
                )
                rows = cur.fetchall()
        matches: list[dict[str, Any]] = []
        for row in rows:
            record = self._row_to_pending_record(row)
            if str(record.get("status")) == "pending":
                matches.append(record)
            elif (
                str(record.get("status")) == "executing"
                and recover_executing_before is not None
                and int(record.get("updated_at", 0)) <= int(recover_executing_before)
            ):
                changed = self.compare_and_update_pending_confirmation_status(
                    confirm_id=str(record.get("confirm_id", "")),
                    expected_status="executing",
                    new_status="pending",
                    now_ts=now_ts,
                )
                if changed:
                    record["status"] = "pending"
                    record["updated_at"] = int(now_ts)
                    matches.append(record)
            if len(matches) > 1:
                return None
        if len(matches) == 1:
            return matches[0]
        return None

    def compare_and_update_pending_confirmation_status(
        self,
        *,
        confirm_id: str,
        expected_status: str,
        new_status: str,
        now_ts: int,
    ) -> bool:
        pending_table = f"{self.schema}.pending_confirmation"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE {pending_table}
                    SET status = %s, updated_at = %s
                    WHERE confirm_id = %s AND status = %s
                    """,
                    (new_status, int(now_ts), confirm_id, expected_status),
                )
                changed = int(cur.rowcount or 0)
            conn.commit()
        return changed == 1

    def get_pending_confirmation(self, confirm_id: str) -> dict[str, Any] | None:
        pending_table = f"{self.schema}.pending_confirmation"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT
                      confirm_id, session_id, route, request_id, model, upstream_base,
                      pending_request_payload, pending_request_hash, reason, summary,
                      status, created_at, expires_at, retained_until, updated_at, tenant_id
                    FROM {pending_table}
                    WHERE confirm_id = %s
                    """,
                    (confirm_id,),
                )
                row = cur.fetchone()
        if not row:
            return None
        return self._row_to_pending_record(row)

    def _row_to_pending_record(self, row: Any) -> dict[str, Any]:
        return {
            "confirm_id": str(row[0]),
            "session_id": str(row[1]),
            "route": str(row[2]),
            "request_id": str(row[3]),
            "model": str(row[4]),
            "upstream_base": str(row[5]),
            "pending_request_payload": _json_loads(str(row[6])),
            "pending_request_hash": str(row[7]),
            "reason": str(row[8]),
            "summary": str(row[9]),
            "status": str(row[10]),
            "created_at": _to_int(row[11]),
            "expires_at": _to_int(row[12]),
            "retained_until": _to_int(row[13]),
            "updated_at": _to_int(row[14]),
            "tenant_id": str(row[15]) if len(row) > 15 else "default",
        }

    def update_pending_confirmation_status(self, *, confirm_id: str, status: str, now_ts: int) -> None:
        pending_table = f"{self.schema}.pending_confirmation"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE {pending_table}
                    SET status = %s, updated_at = %s
                    WHERE confirm_id = %s
                    """,
                    (status, int(now_ts), confirm_id),
                )
            conn.commit()

    def prune_pending_confirmations(self, now_ts: int) -> int:
        pending_table = f"{self.schema}.pending_confirmation"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"DELETE FROM {pending_table} WHERE retained_until <= %s",
                    (int(now_ts),),
                )
                removed = int(cur.rowcount or 0)
            conn.commit()
        return removed

    def clear_all_pending_confirmations(self) -> int:
        """启动时清空所有待确认记录，重启后仅新请求的确认有效。"""
        pending_table = f"{self.schema}.pending_confirmation"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"DELETE FROM {pending_table}")
                removed = int(cur.rowcount or 0)
            conn.commit()
        return removed
