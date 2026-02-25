"""Redis-backed mapping and pending-confirmation store."""

from __future__ import annotations

import json
from typing import Any

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

    def _pending_session_key(self, session_id: str) -> str:
        return f"{self.key_prefix}:pending:session:{session_id}"

    def _pending_retention_key(self) -> str:
        return f"{self.key_prefix}:pending:retention"

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
    ) -> None:
        key = self._pending_key(confirm_id)
        session_idx = self._pending_session_key(session_id)
        retention_idx = self._pending_retention_key()
        payload = _json_dumps(pending_request_payload)
        mapping = {
            "confirm_id": confirm_id,
            "session_id": session_id,
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

    def get_latest_pending_confirmation(self, session_id: str, now_ts: int) -> dict[str, Any] | None:
        session_idx = self._pending_session_key(session_id)
        candidate_ids = self.client.zrevrange(session_idx, 0, 50)
        for raw_id in candidate_ids:
            confirm_id = _to_str(raw_id)
            record = self.get_pending_confirmation(confirm_id)
            if not record:
                continue
            if record.get("status") != "pending":
                continue
            if _to_int(record.get("expires_at", 0)) <= int(now_ts):
                self.update_pending_confirmation_status(confirm_id=confirm_id, status="expired", now_ts=now_ts)
                continue
            return record
        return None

    def get_pending_confirmation(self, confirm_id: str) -> dict[str, Any] | None:
        key = self._pending_key(confirm_id)
        raw = self.client.hgetall(key)
        if not raw:
            return None
        row = {(_to_str(k)): _to_str(v) for k, v in raw.items()}
        return {
            "confirm_id": row.get("confirm_id", confirm_id),
            "session_id": row.get("session_id", ""),
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
        pipe = self.client.pipeline()
        pipe.hset(key, mapping={"status": status, "updated_at": str(now_ts)})
        if status in {"executed", "canceled", "expired"} and session_id:
            pipe.zrem(self._pending_session_key(session_id), confirm_id)
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
            pipe.delete(key)
            pipe.zrem(retention_idx, confirm_id)
            if session_id:
                pipe.zrem(self._pending_session_key(session_id), confirm_id)
            removed += 1
        pipe.execute()
        return removed
