"""Storage backend selection helpers."""

from __future__ import annotations

from aegisgate.config.settings import settings
from aegisgate.storage.postgres_store import PostgresKVStore
from aegisgate.storage.redis_store import RedisKVStore
from aegisgate.storage.sqlite_store import SqliteKVStore


def create_store():
    backend = settings.storage_backend.strip().lower()
    if backend == "redis":
        return RedisKVStore(redis_url=settings.redis_url, key_prefix=settings.redis_key_prefix)
    if backend in {"postgres", "postgresql"}:
        return PostgresKVStore(
            dsn=settings.postgres_dsn,
            schema=settings.postgres_schema,
        )
    return SqliteKVStore()
