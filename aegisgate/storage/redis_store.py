"""Redis-backed mapping and pending-confirmation store."""

from __future__ import annotations

import json
from typing import Any

from aegisgate.config.settings import settings
from aegisgate.storage.crypto import decrypt_mapping, encrypt_mapping
from aegisgate.storage.kv import KVStore

try:
    import redis
except Exception:  # pragma: no cover - optional dependency
    redis = None


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


def _to_str(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class RedisKVStore(KVStore):
    def __init__(self, *, redis_url: str, key_prefix: str = "aegisgate") -> None:
        if redis is None:  # pragma: no cover - depends on optional package
            raise RuntimeError("redis package is not installed, cannot use RedisKVStore")
        self.client = redis.Redis.from_url(redis_url, decode_responses=False)
        self.key_prefix = key_prefix.strip() or "aegisgate"

    def _mapping_key(self, session_id: str, request_id: str) -> str:
        return f"{self.key_prefix}:mapping:{session_id}:{request_id}"

    def _pending_key(self, confirm_id: str) -> str:
        return f"{self.key_prefix}:pending:{confirm_id}"

    def _pending_session_key(self, tenant_id: str, session_id: str) -> str:
        return f"{self.key_prefix}:pending:session:{tenant_id}:{session_id}"

    def _pending_retention_key(self) -> str:
        return f"{self.key_prefix}:pending:retention"

    def _iter_pending_session_ids(self, *, tenant_id: str, session_id: str):
        session_idx = self._pending_session_key(tenant_id, session_id)
        batch = max(50, int(settings.redis_pending_scan_batch_size))
        max_entries = int(settings.redis_pending_scan_max_entries)
        offset = 0
        scanned = 0
        while True:
            if max_entries > 0 and scanned >= max_entries:
                break
            size = batch
            if max_entries > 0:
                size = min(size, max_entries - scanned)
                if size <= 0:
                    break
            chunk = self.client.zrevrange(session_idx, offset, offset + size - 1)
            if not chunk:
                break
            for raw_id in chunk:
                yield _to_str(raw_id)
            got = len(chunk)
            scanned += got
            offset += got
            if got < size:
                break

    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        payload = encrypt_mapping(mapping)
        self.client.set(self._mapping_key(session_id, request_id), payload)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        payload = self.client.get(self._mapping_key(session_id, request_id))
        if not payload:
            return {}
        return decrypt_mapping(_to_str(payload))

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        key = self._mapping_key(session_id, request_id)
        for _ in range(5):
            pipe = self.client.pipeline()
            try:
                pipe.watch(key)
                payload = pipe.get(key)
                pipe.multi()
                pipe.delete(key)
                pipe.execute()
                if not payload:
                    return {}
                return decrypt_mapping(_to_str(payload))
            except redis.WatchError:
                continue
            finally:
                pipe.reset()
        payload = self.client.get(key)
        if payload:
            self.client.delete(key)
        if not payload:
            return {}
        return decrypt_mapping(_to_str(payload))

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
        key = self._pending_key(confirm_id)
        session_idx = self._pending_session_key(tenant_id, session_id)
        retention_idx = self._pending_retention_key()
        payload = _json_dumps(pending_request_payload)
        mapping = {
            "confirm_id": confirm_id,
            "session_id": session_id,
            "tenant_id": tenant_id,
            "route": route,
            "request_id": request_id,
            "model": model,
            "upstream_base": upstream_base,
            "pending_request_payload": payload,
            "pending_request_hash": pending_request_hash,
            "reason": reason,
            "summary": summary,
            "status": "pending",
            "created_at": str(created_at),
            "expires_at": str(expires_at),
            "retained_until": str(retained_until),
            "updated_at": str(created_at),
        }
        pipe = self.client.pipeline()
        pipe.hset(key, mapping=mapping)
        pipe.zadd(session_idx, {confirm_id: created_at})
        pipe.zadd(retention_idx, {confirm_id: retained_until})
        pipe.execute()

    def get_latest_pending_confirmation(
        self,
        session_id: str,
        now_ts: int,
        *,
        tenant_id: str = "default",
        recover_executing_before: int | None = None,
    ) -> dict[str, Any] | None:
        for confirm_id in self._iter_pending_session_ids(tenant_id=tenant_id, session_id=session_id):
            record = self.get_pending_confirmation(confirm_id)
            if not record:
                continue
            if str(record.get("tenant_id", "default")) != tenant_id:
                continue
            status = str(record.get("status", ""))
            if _to_int(record.get("expires_at", 0)) <= int(now_ts):
                self.update_pending_confirmation_status(confirm_id=confirm_id, status="expired", now_ts=now_ts)
                continue
            if status == "pending":
                return record
            if (
                status == "executing"
                and recover_executing_before is not None
                and _to_int(record.get("updated_at", 0)) <= int(recover_executing_before)
            ):
                changed = self.compare_and_update_pending_confirmation_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="pending",
                    now_ts=now_ts,
                )
                if changed:
                    record["status"] = "pending"
                    record["updated_at"] = int(now_ts)
                    return record
        return None

    def get_single_pending_confirmation(
        self,
        *,
        session_id: str,
        route: str,
        now_ts: int,
        tenant_id: str = "default",
        recover_executing_before: int | None = None,
    ) -> dict[str, Any] | None:
        matches: list[dict[str, Any]] = []
        for confirm_id in self._iter_pending_session_ids(tenant_id=tenant_id, session_id=session_id):
            record = self.get_pending_confirmation(confirm_id)
            if not record:
                continue
            if str(record.get("tenant_id", "default")) != tenant_id:
                continue
            if str(record.get("route", "")) != route:
                continue
            if _to_int(record.get("expires_at", 0)) <= int(now_ts):
                self.update_pending_confirmation_status(confirm_id=confirm_id, status="expired", now_ts=now_ts)
                continue
            status = str(record.get("status", ""))
            if status == "pending":
                matches.append(record)
            elif (
                status == "executing"
                and recover_executing_before is not None
                and _to_int(record.get("updated_at", 0)) <= int(recover_executing_before)
            ):
                changed = self.compare_and_update_pending_confirmation_status(
                    confirm_id=confirm_id,
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
        key = self._pending_key(confirm_id)
        for _ in range(5):
            pipe = self.client.pipeline()
            try:
                pipe.watch(key)
                current = _to_str(pipe.hget(key, "status") or "")
                if current != expected_status:
                    return False
                session_id = _to_str(pipe.hget(key, "session_id") or "")
                tenant_id = _to_str(pipe.hget(key, "tenant_id") or "default")
                pipe.multi()
                pipe.hset(key, mapping={"status": new_status, "updated_at": str(now_ts)})
                if new_status in {"executed", "canceled", "expired"} and session_id:
                    pipe.zrem(self._pending_session_key(tenant_id, session_id), confirm_id)
                pipe.execute()
                return True
            except redis.WatchError:
                continue
            finally:
                pipe.reset()
        return False

    def get_pending_confirmation(self, confirm_id: str) -> dict[str, Any] | None:
        key = self._pending_key(confirm_id)
        raw = self.client.hgetall(key)
        if not raw:
            return None
        row = {(_to_str(k)): _to_str(v) for k, v in raw.items()}
        return {
            "confirm_id": row.get("confirm_id", confirm_id),
            "session_id": row.get("session_id", ""),
            "tenant_id": row.get("tenant_id", "default"),
            "route": row.get("route", ""),
            "request_id": row.get("request_id", ""),
            "model": row.get("model", ""),
            "upstream_base": row.get("upstream_base", ""),
            "pending_request_payload": _json_loads(row.get("pending_request_payload", "{}")),
            "pending_request_hash": row.get("pending_request_hash", ""),
            "reason": row.get("reason", ""),
            "summary": row.get("summary", ""),
            "status": row.get("status", ""),
            "created_at": _to_int(row.get("created_at", 0)),
            "expires_at": _to_int(row.get("expires_at", 0)),
            "retained_until": _to_int(row.get("retained_until", 0)),
            "updated_at": _to_int(row.get("updated_at", 0)),
        }

    def update_pending_confirmation_status(self, *, confirm_id: str, status: str, now_ts: int) -> None:
        key = self._pending_key(confirm_id)
        session_id = _to_str(self.client.hget(key, "session_id") or "")
        tenant_id = _to_str(self.client.hget(key, "tenant_id") or "default")
        pipe = self.client.pipeline()
        pipe.hset(key, mapping={"status": status, "updated_at": str(now_ts)})
        if status in {"executed", "canceled", "expired"} and session_id:
            pipe.zrem(self._pending_session_key(tenant_id, session_id), confirm_id)
        pipe.execute()

    def prune_pending_confirmations(self, now_ts: int) -> int:
        retention_idx = self._pending_retention_key()
        candidate_ids = self.client.zrangebyscore(retention_idx, min="-inf", max=now_ts)
        if not candidate_ids:
            return 0

        removed = 0
        pipe = self.client.pipeline()
        for raw_id in candidate_ids:
            confirm_id = _to_str(raw_id)
            key = self._pending_key(confirm_id)
            session_id = _to_str(self.client.hget(key, "session_id") or "")
            tenant_id = _to_str(self.client.hget(key, "tenant_id") or "default")
            pipe.delete(key)
            pipe.zrem(retention_idx, confirm_id)
            if session_id:
                pipe.zrem(self._pending_session_key(tenant_id, session_id), confirm_id)
            removed += 1
        pipe.execute()
        return removed

    def clear_all_pending_confirmations(self) -> int:
        """启动时清空所有待确认记录，重启后仅新请求的确认有效。"""
        retention_idx = self._pending_retention_key()
        all_ids = self.client.zrange(retention_idx, 0, -1)
        if not all_ids:
            return 0
        pipe = self.client.pipeline()
        for raw_id in all_ids:
            confirm_id = _to_str(raw_id)
            key = self._pending_key(confirm_id)
            session_id = _to_str(self.client.hget(key, "session_id") or "")
            tenant_id = _to_str(self.client.hget(key, "tenant_id") or "default")
            pipe.delete(key)
            pipe.zrem(retention_idx, confirm_id)
            if session_id:
                pipe.zrem(self._pending_session_key(tenant_id, session_id), confirm_id)
        pipe.execute()
        return len(all_ids)
