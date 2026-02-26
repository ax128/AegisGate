## Summary

- Added indirect prompt-injection and remote-content instruction signals in `injection_detector`.
- Added `rag_poison_guard` with ingestion/retrieval detection and response-side poison propagation handling.
- Strengthened confirmation with action-binding token (`act-...`) validation (not only `cfm-...`).
- Added `poison_traceback` into response metadata and audit events.

## Scope

- Affected modules:
  - `aegisgate/filters/injection_detector.py`
  - `aegisgate/filters/rag_poison_guard.py`
  - `aegisgate/adapters/openai_compat/router.py`
  - `aegisgate/core/confirmation.py`
  - `aegisgate/core/confirmation_flow.py`
  - `aegisgate/core/context.py`
  - policy/config files under `aegisgate/config` and `aegisgate/policies/rules`
- Affected endpoints:
  - `/v1/chat/completions`
  - `/v1/responses`
- Affected confirmation flow:
  - pending confirmation matching, explicit confirm-id + action-token verification, audit/log visibility.

## Security Impact

- [ ] No security-impacting change
- [x] Security-impacting change (describe below)

### Security details

- New/updated detection signals:
  - `indirect_injection`
  - `remote_content_instruction`
  - `rag_poison_ingestion`
  - `rag_poison_retrieval`
  - `response_rag_poison_propagation`
- New/updated actions:
  - `injection_detector.remote_content_instruction -> review`
  - `injection_detector.indirect_injection -> review`
  - `rag_poison_guard.ingestion_poison -> block`
  - `rag_poison_guard.retrieval_poison -> review`
  - `rag_poison_guard.poison_propagation -> block`
- Policy defaults changed:
  - enabled `rag_poison_guard` in `default/strict/permissive` policy files.
- Potential FP/FN impact:
  - Slightly higher review volume on retrieval/web/document-origin content with instruction-like phrasing.

## Confirmation Flow Changes

- [ ] No confirmation flow change
- [x] Confirmation flow changed

### Details

- Confirmation message now includes action bind token for copy-ready commands.
- Explicit `cfm-id` confirmation now requires matching `act-...` token; otherwise:
  - `action_token_required`
  - `action_token_mismatch`
- Added richer logs for pending match, token validation, and rejection reasons.
- Maintains existing support for implicit yes path when session has exactly one pending item.

## RAG and Poisoning Controls

- [ ] Not related to RAG/poisoning
- [x] RAG/poisoning logic changed

### Details

- Ingestion-stage controls:
  - detect poisoning patterns in `documents/chunks/knowledge` style payload fields.
- Retrieval-stage controls:
  - detect poisoning patterns in retrieval-like message sources and context fields.
- Propagation handling:
  - if poisoned context exists and response propagates malicious patterns, block/sanitize by policy.
- Traceback/audit:
  - added `poison_traceback` structured entries (`phase/source/item_id/signals/excerpt`).

## Config and Compatibility

- New flags/config:
  - `enable_rag_poison_guard` (default: `true`).
- Updated policy/action map:
  - `rag_poison_guard` and new `injection_detector` signals wired in defaults.
- Backward compatibility:
  - clients that send explicit `cfm-id` should include returned `act-...` token.

## Testing

### Targeted tests

- Commands run:
  - `pytest -q aegisgate/tests/test_injection_advanced_rules.py aegisgate/tests/test_rag_poison_guard.py aegisgate/tests/test_confirmation_routing.py aegisgate/tests/test_poison_traceback_audit.py`
  - grouped suites for filters/policies/routing/confirmation.
- Result:
  - targeted and grouped suites passed (except known existing mismatches listed below).

### Full test suite

- Command run:
  - `pytest -q`
- Result:
  - `124 passed, 2 failed`
- Known failures:
  - `test_request_sanitizer_blocks_secret_exfiltration` (policy now uses `review` for `secret_exfiltration`)
  - `test_anomaly_detector_points_based_payload_scoring` (current score under test threshold)

## Observability

- [x] Logs updated for key decisions/errors
- [x] Audit event fields updated
- [ ] Metrics/dashboards/alerts impact reviewed

### New/changed log keys

- confirmation pending match details, action-token required/mismatch logs, rag poison hit logs.

### New/changed audit keys

- `poison_traceback`

## Rollback Plan

- Disable new guard quickly:
  - set `enable_rag_poison_guard=false`
- Revert confirmation strictness:
  - rollback router/confirmation changes related to `act-...` validation.
- Data/state cleanup:
  - clear pending confirmation records if needed; no schema migration required.

## Release Notes (copy-ready)

```text
Security hardening update: added RAG poisoning guard (ingestion/retrieval/propagation), expanded indirect/remote prompt-injection detection, strengthened confirmation with action-binding token, and included poison traceback in metadata/audit for incident traceability.
```

