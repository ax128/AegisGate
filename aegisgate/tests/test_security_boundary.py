from aegisgate.core.security_boundary import (
    NonceReplayCache,
    build_signature_payload,
    compute_hmac_sha256,
    verify_hmac_signature,
)


def test_hmac_signature_roundtrip():
    secret = "unit-test-secret"
    payload = build_signature_payload("1735689600", "nonce-1", b'{"input":"hello"}')
    sig = compute_hmac_sha256(secret=secret, payload=payload)
    assert verify_hmac_signature(secret=secret, payload=payload, presented=sig) is True
    assert verify_hmac_signature(secret=secret, payload=payload, presented=f"sha256={sig}") is True


def test_hmac_signature_rejects_tampering():
    secret = "unit-test-secret"
    payload = build_signature_payload("1735689600", "nonce-1", b'{"input":"hello"}')
    sig = compute_hmac_sha256(secret=secret, payload=payload)
    tampered = build_signature_payload("1735689600", "nonce-1", b'{"input":"evil"}')
    assert verify_hmac_signature(secret=secret, payload=tampered, presented=sig) is False


def test_nonce_replay_cache_detects_replay():
    cache = NonceReplayCache(max_entries=100)
    now = 1735689600
    assert cache.check_and_store("nonce-1", now_ts=now, window_seconds=300) is False
    assert cache.check_and_store("nonce-1", now_ts=now + 10, window_seconds=300) is True


def test_nonce_replay_cache_allows_expired_nonce():
    cache = NonceReplayCache(max_entries=100)
    now = 1735689600
    assert cache.check_and_store("nonce-1", now_ts=now, window_seconds=5) is False
    assert cache.check_and_store("nonce-1", now_ts=now + 10, window_seconds=5) is False
