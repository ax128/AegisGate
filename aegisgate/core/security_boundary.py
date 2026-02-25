"""Security boundary helpers for gateway authentication and replay defense."""

from __future__ import annotations

import hmac
import time
from collections import OrderedDict
from hashlib import sha256
from threading import Lock

from aegisgate.config.settings import settings

try:
    import redis
except Exception:  # pragma: no cover - optional dependency
    redis = None


class NonceReplayCache:
    """Thread-safe nonce cache with TTL and max-size control."""

    def __init__(self, max_entries: int = 50000) -> None:
        self.max_entries = max(1000, int(max_entries))
        self._cache: OrderedDict[str, int] = OrderedDict()
        self._lock = Lock()

    def _prune(self, now_ts: int, window_seconds: int) -> None:
        expiry = now_ts - max(1, int(window_seconds))
        keys_to_drop: list[str] = []
        for nonce, seen_ts in self._cache.items():
            if seen_ts >= expiry:
                break
            keys_to_drop.append(nonce)
        for nonce in keys_to_drop:
            self._cache.pop(nonce, None)

        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def check_and_store(self, nonce: str, now_ts: int, window_seconds: int) -> bool:
        """Return True if nonce is replayed in valid window, otherwise store and return False."""

        with self._lock:
            self._prune(now_ts, window_seconds)
            if nonce in self._cache:
                seen_ts = self._cache[nonce]
                if now_ts - seen_ts <= window_seconds:
                    return True
                self._cache.pop(nonce, None)
            self._cache[nonce] = now_ts
            self._cache.move_to_end(nonce)
            return False


class RedisNonceReplayCache:
    """Redis-backed nonce replay cache for multi-instance deployments."""

    def __init__(self, redis_url: str, key_prefix: str = "aegisgate") -> None:
        if redis is None:  # pragma: no cover - depends on optional package
            raise RuntimeError("redis package is not installed, cannot use RedisNonceReplayCache")
        self.client = redis.Redis.from_url(redis_url, decode_responses=True)
        self.key_prefix = key_prefix.strip() or "aegisgate"

    def _key(self, nonce: str) -> str:
        return f"{self.key_prefix}:nonce:{nonce}"

    def check_and_store(self, nonce: str, now_ts: int, window_seconds: int) -> bool:
        ttl = max(1, int(window_seconds))
        key = self._key(nonce)
        # NX ensures first writer succeeds; repeated nonce in window indicates replay.
        created = self.client.set(name=key, value=str(now_ts), ex=ttl, nx=True)
        return not bool(created)


def build_nonce_cache():
    backend = settings.nonce_cache_backend.strip().lower()
    if backend == "redis":
        return RedisNonceReplayCache(redis_url=settings.redis_url, key_prefix=settings.redis_key_prefix)
    return NonceReplayCache(max_entries=settings.request_nonce_cache_size)


def build_signature_payload(timestamp: str, nonce: str, body: bytes) -> bytes:
    return timestamp.encode("utf-8") + b"." + nonce.encode("utf-8") + b"." + body


def compute_hmac_sha256(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, sha256).hexdigest()


def verify_hmac_signature(secret: str, payload: bytes, presented: str) -> bool:
    normalized = presented.strip()
    if normalized.lower().startswith("sha256="):
        normalized = normalized.split("=", 1)[1].strip()
    expected = compute_hmac_sha256(secret, payload)
    return hmac.compare_digest(expected, normalized)


def now_ts() -> int:
    return int(time.time())
