---
phase: 02-response-sanitization-integrity
plan: 02
subsystem: api
tags: [response-sanitization, anthropic, messages, router, pytest]
requires: [02-01-SUMMARY.md]
provides:
  - "Anthropic-native JSON sanitize rendering for direct `/v1/messages`"
  - "Regression coverage for explicit sanitize and auto-sanitize message JSON paths"
affects: [/v1/messages, anthropic-json, response-sanitization]
tech-stack:
  added: []
  patterns:
    - "Patch the original protocol body instead of wrapping sanitized dict responses in generic envelopes"
    - "Keep operator-visible risk marks in existing aegisgate metadata and audit channels"
key-files:
  created:
    - .planning/phases/02-response-sanitization-integrity/02-02-SUMMARY.md
  modified:
    - aegisgate/adapters/openai_compat/router.py
    - aegisgate/tests/test_response_sanitization_routes.py
    - README.md
    - README_zh.md
key-decisions:
  - "Direct `/v1/messages` dict responses now render through a dedicated Anthropic-native sanitize helper instead of `sanitized_text` fallback."
  - "Only top-level text-bearing message blocks are sanitized; unknown or non-text blocks stay structurally untouched."
  - "Auto-sanitize for dict message bodies logs sanitized text for operators but renders by patching the original upstream payload once, avoiding double sanitization."
patterns-established:
  - "Anthropic JSON sanitize paths mirror chat/responses: attach metadata, patch known text fields, preserve protocol-required fields."
requirements-completed: [RESP-02, RESP-03, RESP-04]
duration: 15min
completed: 2026-03-27
---

# Phase 02 Plan 02: Response Sanitization Integrity Summary

**Direct `/v1/messages` non-stream sanitize responses now preserve Anthropic JSON structure, replace only dangerous fragments in text blocks, and keep risk marking in the existing operator channels**

## Performance

- **Duration:** 15 min
- **Completed:** 2026-03-27
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Added direct `/v1/messages` JSON regressions for both explicit sanitize and auto-sanitize branches.
- Introduced messages-native JSON patch/render helpers in `router.py`.
- Removed the client-visible `{"sanitized_text": ...}` dict fallback for direct messages JSON responses.
- Documented the direct `/v1/messages` non-stream sanitize contract in both README files.

## Task Commits

1. **Task 1: Replace direct `/v1/messages` JSON sanitize fallback with Anthropic-native fragment patching** - `949f951` (feat)
2. **Task 2: Document the `/v1/messages` JSON sanitize contract** - `3a46bdf` (docs)

## Files Created/Modified

- `aegisgate/adapters/openai_compat/router.py` - adds messages-native JSON patch/render helpers and rewires sanitize branches
- `aegisgate/tests/test_response_sanitization_routes.py` - adds direct messages JSON sanitize regressions for explicit and automatic sanitize paths
- `README.md` - documents preserved Anthropic JSON shape for sanitized `/v1/messages`
- `README_zh.md` - documents the same contract in Chinese

## Decisions Made

- Kept the direct messages JSON fix local to `router.py` rather than introducing a broader normalization layer.
- Preserved `usage`, `stop_reason`, `stop_sequence`, IDs, and unknown fields from upstream dict bodies while sanitizing only text-bearing blocks.
- Used the existing `aegisgate` metadata and audit event path as the only risk-marking contract.

## Deviations from Plan

None.

## Issues Encountered

- Auto-sanitize initially double-processed dict bodies because it reused full-response sanitized text and then patched the upstream body again; the final implementation now only patches dict bodies once.

## User Setup Required

None.

## Next Phase Readiness

Wave 3 can now focus only on Anthropic SSE framing for direct `/v1/messages`; the non-stream JSON contract is already pinned and working.

## Self-Check: PASSED

- FOUND: `.planning/phases/02-response-sanitization-integrity/02-02-SUMMARY.md`
- FOUND: `949f951`
- FOUND: `3a46bdf`
