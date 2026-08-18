"""Redis-backed mapping and pending-confirmation store."""

from __future__ import annotations

from typing import Any

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
