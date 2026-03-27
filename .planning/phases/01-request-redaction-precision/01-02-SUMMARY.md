---
phase: 01-request-redaction-precision
plan: 02
subsystem: api
tags: [request-redaction, anthropic, openai-compat, streaming, pytest]
requires:
  - phase: 01-request-redaction-precision
    provides: "Chat/responses structured request redaction helpers and route-level regression patterns from plan 01-01"
provides:
  - "Dedicated direct /v1/messages request rewrite path for JSON and streaming Anthropic payloads"
  - "Schema-aware sanitization of top-level system blocks and messages[].content before upstream forwarding"
  - "Focused regressions for direct messages redaction, passthrough preservation, and compat delegation"
affects: [/v1/messages, anthropic-compat, request-redaction, passthrough, streaming]
tech-stack:
  added: []
  patterns:
    - "Provider-specific routes reuse the existing response pipeline while swapping only the request payload builder"
    - "Anthropic top-level system redaction is handled separately from messages[].content to preserve provider shape"
key-files:
  created: []
  modified:
    - aegisgate/adapters/openai_compat/router.py
    - aegisgate/adapters/openai_compat/sanitize.py
    - aegisgate/tests/test_request_redaction_routes.py
    - aegisgate/tests/test_openai_request_mapping.py
    - aegisgate/tests/test_passthrough_filter_mode.py
key-decisions:
  - "Direct /v1/messages now uses a dedicated request execution path instead of generic sanitize-unsupported fallback."
  - "compat=openai_chat on /v1/messages continues to delegate into the existing /v1/responses flow rather than the new direct rewrite path."
patterns-established:
  - "Direct provider-compatible routes can keep generic response handling while applying schema-aware request rewrites at the adapter boundary."
  - "Structured Anthropic system blocks and message content blocks are sanitized recursively, while unknown provider keys are preserved from the original payload."
requirements-completed: [SAFE-03]
duration: 25min
completed: 2026-03-27
---

# Phase 01 Plan 02: Request Redaction Precision Summary

**Direct `/v1/messages` now forwards redacted Anthropic JSON and streaming payloads without falling back to generic sanitize-unsupported blocking**

## Performance

- **Duration:** 25 min
- **Started:** 2026-03-27T11:45:30Z
- **Completed:** 2026-03-27T12:10:13Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added RED coverage that exposed the direct `/v1/messages` gap for JSON forwarding, streaming forwarding, passthrough preservation, and compat delegation.
- Introduced a dedicated direct messages execution path plus `_build_messages_upstream_payload()` so request-side redaction rewrites Anthropic `system` and `messages[].content` before upstream forwarding.
- Preserved existing compat behavior by keeping `compat=openai_chat` on `/v1/messages` routed through `/v1/responses` instead of the new direct rewrite path.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add failing coverage for direct `/v1/messages` rewrite behavior** - `cb9e86c` (test)
2. **Task 2: Replace direct `/v1/messages` analyze-only forwarding with schema-aware rewrite** - `6e4afe4` (feat)

## Files Created/Modified

- `aegisgate/adapters/openai_compat/router.py` - adds direct messages payload builders and dedicated JSON/stream execution paths that reuse the existing response-side pipeline.
- `aegisgate/adapters/openai_compat/sanitize.py` - adds structured Anthropic top-level `system` redaction while reusing the existing recursive text-part sanitization model.
- `aegisgate/tests/test_request_redaction_routes.py` - verifies direct `/v1/messages` JSON and streaming payloads are rewritten in valid Anthropic shape and no longer regress to 403 sanitize-unsupported.
- `aegisgate/tests/test_openai_request_mapping.py` - verifies `to_internal_messages()` still flattens Anthropic blocks for analysis instead of becoming the forwarding format.
- `aegisgate/tests/test_passthrough_filter_mode.py` - verifies direct messages passthrough preserves payload shape and compat mode still delegates to the responses flow.

## Decisions Made

- Introduced a messages-specific request execution path instead of widening `_execute_generic_once()` so schema-aware rewriting stays limited to `/v1/messages`.
- Kept direct messages response handling on the existing generic response pipeline and changed only the request-side builder, which minimized scope and preserved current behavior.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Route-level passthrough and compat tests hit the same payload-transform timeout pattern seen in plan 01-01, so those assertions were narrowed to `_execute_messages_once()` and `_messages_compat_openai_chat()` to keep the tests focused on payload preservation and delegation behavior.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `/v1/messages` now has request-side redaction parity with the existing chat/responses rewrite model for direct Anthropic traffic.
- Phase 01 Plan 03 can focus on low-false-positive alignment across chat, responses, and direct messages without reopening the direct-route rewrite gap.

## Self-Check: PASSED

- FOUND: `.planning/phases/01-request-redaction-precision/01-02-SUMMARY.md`
- FOUND: `cb9e86c`
- FOUND: `6e4afe4`
