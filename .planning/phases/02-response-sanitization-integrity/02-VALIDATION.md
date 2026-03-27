---
phase: 2
slug: response-sanitization-integrity
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-27
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `pytest 8.3.5` |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k "benign or structure or fragment or metadata" -x` |
| **Full suite command** | `pytest -q` |
| **Estimated runtime** | ~25 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k "benign or structure or fragment or metadata" -x`
- **After every plan wave:** Run `pytest -q aegisgate/tests/test_response_sanitization_routes.py aegisgate/tests/test_streaming_router.py -x`
- **Before `$gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 2-01-01 | 01 | 1 | RESP-01 | route integration | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k "benign" -x` | ❌ W0 | ⬜ pending |
| 2-01-02 | 01 | 1 | RESP-04 | route + unit | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k "metadata" -x` | ❌ W0 | ⬜ pending |
| 2-02-01 | 02 | 2 | RESP-02 | route + helper | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k "structure" -x` | ❌ W0 | ⬜ pending |
| 2-02-02 | 02 | 2 | RESP-03 | helper + route | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k "fragment" -x` | ❌ W0 | ⬜ pending |
| 2-03-01 | 03 | 3 | RESP-02 | stream route | `pytest -q aegisgate/tests/test_streaming_router.py -k "messages and sanitize" -x` | ❌ W0 | ⬜ pending |
| 2-03-02 | 03 | 3 | RESP-03 | stream route | `pytest -q aegisgate/tests/test_streaming_router.py -k "sanitize and structure" -x` | ❌ W0 | ⬜ pending |
| 2-03-03 | 03 | 3 | RESP-04 | stream route + audit | `pytest -q aegisgate/tests/test_streaming_router.py -k "messages and metadata" -x` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `aegisgate/tests/test_response_sanitization_routes.py` — route-level JSON sanitize regressions for chat/responses/messages
- [ ] `aegisgate/tests/test_response_sanitization_routes.py` — direct `/v1/messages` sanitize-path contract tests
- [ ] `aegisgate/tests/test_response_sanitization_routes.py` — `aegisgate` metadata and audit assertions on sanitized outputs
- [ ] `aegisgate/tests/test_streaming_router.py` — direct `/v1/messages` sanitize-path stream contract tests
- [ ] `aegisgate/tests/test_streaming_router.py` — focused tests monkeypatch `_run_payload_transform()` to avoid existing executor timeout pattern

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Live upstream acceptance of sanitized `/v1` responses for chat, responses, and messages | RESP-01, RESP-02, RESP-03 | Automated route tests validate protocol-native rendering with mocks, but cannot prove every real provider accepts the patched response shape and SSE sequence | Send benign and high-risk responses through real compatible upstreams for `/v1/chat/completions`, `/v1/responses`, and `/v1/messages`; confirm sanitized outputs stay protocol-valid and clients continue parsing successfully |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
