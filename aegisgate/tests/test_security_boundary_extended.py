"""Extended tests for aegisgate.core.security_boundary — nonce cache and HMAC edge cases."""

from __future__ import annotations

from aegisgate.core.security_boundary import (
    NonceReplayCache,
    build_nonce_cache,
    now_ts,
    verify_hmac_signature,
)


# ---------- NonceReplayCache overflow pruning ----------

def test_nonce_cache_prunes_when_exceeds_max():
    cache = NonceReplayCache(max_entries=1000)  # min is 1000
    now = 1000000

    # Fill beyond max
    for i in range(1005):
        cache.check_and_store(f"nonce-{i}", now_ts=now, window_seconds=600)

    # Next check triggers pruning
    cache.check_and_store("overflow-nonce", now_ts=now, window_seconds=600)
    assert len(cache._cache) <= cache.max_entries + 1


def test_nonce_cache_prunes_expired_entries():
    cache = NonceReplayCache(max_entries=50000)
    now = 1000000

    # Add old entries
    for i in range(10):
        cache.check_and_store(f"old-{i}", now_ts=now - 1000, window_seconds=100)

    # Prune by checking with new timestamp
    cache.check_and_store("new-1", now_ts=now, window_seconds=100)
    # Old entries should be pruned since they are < expiry
    assert "old-0" not in cache._cache


def test_nonce_replay_reuse_after_expiry():
    cache = NonceReplayCache(max_entries=50000)
    now = 1000000

    assert cache.check_and_store("n1", now_ts=now, window_seconds=10) is False
    # Same nonce after window expires => not replayed, popped and re-stored
    assert cache.check_and_store("n1", now_ts=now + 20, window_seconds=10) is False


# ---------- verify_hmac_signature edge cases ----------

def test_verify_rejects_sha256_prefix_without_value():
    payload = b"test"
    assert verify_hmac_signature("secret", payload, "sha256=") is False


def test_verify_rejects_sha256_prefix_whitespace_only():
    assert verify_hmac_signature("secret", b"test", "sha256=   ") is False


def test_verify_handles_plain_hex():
    from aegisgate.core.security_boundary import compute_hmac_sha256
    payload = b"test"
    sig = compute_hmac_sha256("secret", payload)
    assert verify_hmac_signature("secret", payload, sig) is True


def test_verify_handles_leading_trailing_whitespace():
    from aegisgate.core.security_boundary import compute_hmac_sha256
    payload = b"test"
    sig = compute_hmac_sha256("secret", payload)
    assert verify_hmac_signature("secret", payload, f"  {sig}  ") is True


# ---------- now_ts ----------

def test_now_ts_returns_int():
    ts = now_ts()
    assert isinstance(ts, int)
    assert ts > 0


# ---------- build_nonce_cache factory ----------

def test_build_nonce_cache_in_memory(monkeypatch):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "nonce_cache_backend", "memory")
    monkeypatch.setattr(settings, "request_nonce_cache_size", 5000)

    cache = build_nonce_cache()
    assert isinstance(cache, NonceReplayCache)
    assert cache.max_entries == 5000
