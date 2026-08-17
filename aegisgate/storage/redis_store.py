"""Redis-backed mapping and pending-confirmation store."""

from __future__ import annotations

from typing import Any

from aegisgate.config.settings import settings
from aegisgate.storage.crypto import (
    decrypt_mapping,
    encrypt_mapping,
)
from aegisgate.storage.kv import KVStore

redis_module: Any
try:
    import redis as redis_module
except ImportError:  # pragma: no cover - optional dependency
    redis_module = None


def _to_str(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class RedisKVStore(KVStore):
    def __init__(self, *, redis_url: str, key_prefix: str = "aegisgate") -> None:
        if redis_module is None:  # pragma: no cover - depends on optional package
            raise RuntimeError(
                "redis package is not installed, cannot use RedisKVStore"
            )
        self.client: Any = redis_module.Redis.from_url(
            redis_url, decode_responses=False
        )
        self.key_prefix = key_prefix.strip() or "aegisgate"

    def close(self) -> None:
        # Hot-reload can swap Redis backends repeatedly; close pooled sockets
        # so old clients do not accumulate across reloads or shutdown.
        close_method = getattr(self.client, "close", None)
        if callable(close_method):
            close_method()
        connection_pool = getattr(self.client, "connection_pool", None)
        disconnect = getattr(connection_pool, "disconnect", None)
        if callable(disconnect):
            disconnect()

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

    def set_mapping(
        self, session_id: str, request_id: str, mapping: dict[str, str]
    ) -> None:
        from aegisgate.config.settings import settings as _settings
        payload = encrypt_mapping(mapping)
        # C-03/H-19: Always set a TTL so redaction mappings cannot accumulate
        # indefinitely in Redis memory.  Use pending_data_ttl_seconds with a
        # small safety buffer so in-flight restorations are not cut short.
        ttl = max(3600, int(_settings.pending_data_ttl_seconds) + 300)
        self.client.set(self._mapping_key(session_id, request_id), payload, ex=ttl)

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
            except redis_module.WatchError:
                continue
            finally:
                pipe.reset()
        payload = self.client.get(key)
        if payload:
            self.client.delete(key)
        if not payload:
            return {}
        return decrypt_mapping(_to_str(payload))

    def prune_pending_confirmations(self, now_ts: int) -> int:
        retention_idx = self._pending_retention_key()
        candidate_ids = self.client.zrangebyscore(retention_idx, min="-inf", max=now_ts)

        removed = 0
        if candidate_ids:
            pipe = self.client.pipeline()
            for raw_id in candidate_ids:
                confirm_id = _to_str(raw_id)
                key = self._pending_key(confirm_id)
                session_id = _to_str(self.client.hget(key, "session_id") or "")
                tenant_id = _to_str(self.client.hget(key, "tenant_id") or "default")
                pipe.delete(key)
                pipe.zrem(retention_idx, confirm_id)
                if session_id:
                    pipe.zrem(
                        self._pending_session_key(tenant_id, session_id), confirm_id
                    )
                removed += 1
            pipe.execute()

        # Recover stale "executing" records back to "pending"
        timeout = int(settings.confirmation_executing_timeout_seconds)
        if timeout > 0:
            recover_before = int(now_ts) - max(5, timeout)
            pattern = f"{self.key_prefix}:pending:*"
            cursor = 0
            while True:
                cursor, keys = self.client.scan(cursor=cursor, match=pattern, count=200)
                for key in keys:
                    try:
                        status = _to_str(self.client.hget(key, "status") or "")
                    except Exception:
                        # Skip non-hash keys (session index / retention sorted sets)
                        # matched by the broad SCAN pattern.
                        continue
                    if status != "executing":
                        continue
                    try:
                        updated_at = int(
                            _to_str(self.client.hget(key, "updated_at") or "0")
                        )
                    except Exception:
                        continue
                    if updated_at <= recover_before:
                        self.client.hset(
                            key,
                            mapping={"status": "pending", "updated_at": str(now_ts)},
                        )
                if cursor == 0:
                    break

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
