---
phase: 1
slug: request-redaction-precision
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-27
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `pytest` |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `pytest -q aegisgate/tests/test_request_redaction_routes.py -k "chat_request_redaction_preserves_shape or messages_request_redaction_preserves_anthropic_shape or benign_examples_avoid_false_positives" -x` |
| **Full suite command** | `pytest -q` |
| **Estimated runtime** | ~20 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest -q aegisgate/tests/test_request_redaction_routes.py -k "chat_request_redaction_preserves_shape or messages_request_redaction_preserves_anthropic_shape or benign_examples_avoid_false_positives" -x`
- **After every plan wave:** Run `pytest -q aegisgate/tests/test_request_redaction_routes.py aegisgate/tests/test_payload_compat.py aegisgate/tests/test_sanitize_helpers.py -x`
- **Before `$gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 1-01-01 | 01 | 1 | SAFE-01 | integration | `pytest -q aegisgate/tests/test_request_redaction_routes.py::test_chat_request_redaction_preserves_shape -x` | ❌ W0 | ⬜ pending |
| 1-01-02 | 01 | 1 | SAFE-02 | integration | `pytest -q aegisgate/tests/test_request_redaction_routes.py::test_responses_request_redaction_structured_input -x` | ❌ W0 | ⬜ pending |
| 1-02-01 | 02 | 2 | SAFE-03 | integration | `pytest -q aegisgate/tests/test_request_redaction_routes.py::test_messages_request_redaction_preserves_anthropic_shape -x` | ❌ W0 | ⬜ pending |
| 1-03-01 | 03 | 3 | SAFE-04 | unit/integration | `pytest -q aegisgate/tests/test_request_redaction_routes.py::test_benign_examples_avoid_false_positives -x` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `aegisgate/tests/test_request_redaction_routes.py` — route-level request redaction parity for chat/responses/messages
- [ ] `aegisgate/tests/test_openai_request_mapping.py` — mapper and structured-content coverage for `to_internal_chat`, `to_internal_responses`, and `to_internal_messages`
- [ ] `aegisgate/tests/test_sanitize_helpers.py` — recursive responses-input rewrite, skip fields, whitelist preservation, and benign examples
- [ ] `aegisgate/tests/test_passthrough_filter_mode.py` — non-passthrough request redaction assertions for real upstream payload builders

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Cross-provider smoke check for real upstream payload acceptance after redaction | SAFE-01, SAFE-02, SAFE-03 | Automated tests can verify payload shape and forwarding calls, but not every real upstream tolerance edge | Run representative `/v1/chat/completions`, `/v1/responses`, and `/v1/messages` requests against a real compatible upstream and confirm requests succeed with redacted text and unchanged protocol structure |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
