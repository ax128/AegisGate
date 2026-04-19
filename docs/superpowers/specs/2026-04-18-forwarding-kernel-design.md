# AegisGate Forwarding Kernel Refactor Design

**Status:** Approved for implementation

## Goal

Refactor `aegisgate/adapters/openai_compat/router.py` into a thinner entrypoint while preserving current security, streaming, confirmation, and protocol-compatibility behavior.

## Problem Statement

The current `openai_compat` adapter mixes route classification, confirmation preflight, shared security orchestration, upstream forwarding, stream probing, route-native rendering, and compat bridging in one place. This makes the code hard to evolve safely because some logic is truly shared while other logic must remain route-specific.

## Design Goals

1. Keep `router.py` as an entrypoint and dispatcher rather than a monolithic executor.
2. Extract only the parts that are truly shared across routes.
3. Preserve route-native protocol contracts for chat, responses, and messages.
4. Keep `upstream.py` as the owner of DNS pinning, SSRF protection, Host/SNI handling, and internal header stripping.
5. Preserve current confirmation ownership during the early phases.
6. Support internal rollout gates and route-level rollback without adding public configuration surface.

## Non-Goals

1. Do not replace `InternalRequest` or `InternalResponse`.
2. Do not introduce a new giant canonical model across the codebase.
3. Do not unify chat/responses/messages stream terminal state machines.
4. Do not move confirmation or pending-store ownership in Phase 0.
5. Do not change `upstream.py` ownership.

## Design Principles

### Share security view, not protocol truth

All routes may share the internal request view used by the policy and filter pipeline, but the final HTTP body and stream contract remain route-specific.

### Share transport shell, not stream terminal semantics

Retry-before-first-byte, stream bootstrap, probe wrappers, and transport framing can be shared. Terminal events, `[DONE]`, Anthropic-native events, and route-native finalize behavior cannot be collapsed into one state machine.

### Compat remains a bridge

Compat flow stays a translation and response-bridge layer, not a replacement for native route ownership.

### Guardrails before refactor

No refactor phase starts before invariants, parity coverage, internal rollout gates, and exactly-once tests are in place.

## Current Implementation Snapshot

- Phase 0 guardrails are implemented.
- Phase 1 classifier extraction is implemented as `forwarding_classifier.py`.
- Phase 2 security-view extraction is implemented as `security_view.py`.
- Phase 3 shared once execution is partially implemented through `execution_common.py`.
- Phase 4 shared stream transport shell is partially implemented through `stream_transport.py`.
- Phase 5 non-stream renderer extraction is implemented as `renderers.py`.
- Route-native stream finalize helpers are **not** extracted into a standalone `stream_finalize.py` yet; they remain route-specific logic in `router.py`.
- Phase 6 and later cutover/parity cleanup work remains pending.

## Target Component Boundaries

### Route Behavior Matrix

| Entry Route | Input Shape | Compat | Target Path | Response Contract | Confirmation Ownership |
|---|---|---|---|---|---|
| `/v1/chat/completions` | chat-native (`messages`, no `input`) | none | `/v1/chat/completions` | chat | router |
| `/v1/chat/completions` | responses-native (`input`, no `messages`) | none | `/v1/responses` | chat | router |
| `/v1/chat/completions` | mixed (`messages` + `input`) | none | `/v1/chat/completions` | chat | router |
| `/v1/responses` | responses-native (`input`, no `messages`) | none | `/v1/responses` | responses | router |
| `/v1/responses` | chat-native (`messages`, no `input`) | none | `/v1/chat/completions` | responses | router |
| `/v1/responses` | mixed (`messages` + `input`) | none | `/v1/responses` | responses | router |
| `/v1/messages` | messages-native (`messages` + `max_tokens`, no `input`) | none | `/v1/messages` | messages | router |
| `/v1/messages` | messages-native (`messages` + `max_tokens`, no `input`) | `openai_chat` | `/v1/responses` | messages | router |
| `/v1/messages` | mixed (`messages` + `input` + `max_tokens`) | `openai_chat` | `/v1/messages` | messages | router |

Mixed payloads are fail-closed to the entry route during Phase 0. They are intentionally **not** auto-redirected, and entrypoint handlers must preserve that fail-closed behavior even if classifier output drifts.

### Ownership Map

| Concern | Owner | Explicitly Not Owned By |
|---|---|---|
| HTTP entrypoint, route dispatch, confirmation preflight | `router.py` | `execution_common.py`, `upstream.py` |
| Route classification and redirect intent | `forwarding_classifier.py` / Phase 0 classifier | `compat_bridge.py`, `upstream.py` |
| Internal security view construction | `security_view.py` backed by `mapper.py::to_internal_*` | `renderers.py`, `upstream.py` |
| Request/response pipeline skeleton | `execution_common.py` | `compat_bridge.py`, `stream_finalize.py` |
| Route-native once rendering | `renderers.py` | `compat_bridge.py`, `mapper.py` |
| Stream bootstrap/retry shell | `stream_transport.py` | `stream_finalize.py`, `compat_bridge.py` |
| Route-native stream finalize and terminal semantics | `router.py` today, planned `stream_finalize.py` | `stream_transport.py` |
| Payload parameter compatibility cleanup | `payload_compat.py` | `mapper.py`, `renderers.py` |
| Compat response/stream coercion | `compat_bridge.py` | `renderers.py`, `execution_common.py` |
| Upstream base resolution, DNS pinning, SSRF, Host/SNI, internal header stripping | `upstream.py` | `router.py`, `execution_common.py` |

`upstream.py` ownership remains fixed throughout Phase 0 and Phase 1. Confirmation and pending-store ownership remains in `router.py` until explicitly redesigned in a later phase.

### `router.py`

- Accept endpoint requests
- Run route intent classification
- Run route-specific confirmation preflight
- Select once/stream execution path
- Wire route-specific callbacks and internal rollout gates

### `forwarding_classifier.py`

- Classify entry route and payload shape
- Determine native vs compat redirect target
- Return typed route intent only

### `security_view.py`

- Build route-specific `InternalRequest` security view from payloads
- Normalize preview identity fields (`request_id`, `session_id`, `tenant_id`, `route`, `model`)
- Reuse existing `mapper.py::to_internal_*`

### `execution_common.py`

- Payload limit validation
- Policy resolution
- Request pipeline
- Upstream dispatch callback
- Response pipeline
- Semantic review
- Audit write
- Shared once-path error adaptation

It does **not** own confirmation store transitions or final protocol rendering.

### `stream_transport.py`

- Shared stream bootstrap and retry shell
- First-byte retry boundary handling
- Shared probe wrapper
- Shared transport framing shell

It does **not** own route-native terminal behavior.

### `stream_finalize.py`

- Route-specific finalize helpers for chat, responses, and messages

This remains a planned boundary. Current route-native finalize logic still lives in `router.py`.

### `renderers.py`

- Route-native non-stream renderers for chat, responses, and messages

### Existing ownership retained

- `mapper.py`: external payload to internal security view, plus model mapping
- `payload_compat.py`: parameter compatibility cleanup
- `compat_bridge.py`: compat response and stream coercion
- `upstream.py`: upstream safety and transport ownership

## Core Data Flow

### Once flow

1. Endpoint receives payload.
2. `forwarding_classifier.py` classifies route and redirect intent.
3. Route-specific confirmation preflight runs.
4. `security_view.py` builds preview/internal request.
5. `execution_common.py` runs the shared once skeleton.
6. Route-specific upstream payload builder constructs upstream payload.
7. `upstream.py` forwards the request.
8. Response pipeline runs.
9. Route-native renderer emits the final response.
10. Compat bridge runs only when the response contract differs from the entry contract.

### Stream flow

1. Endpoint receives payload.
2. `forwarding_classifier.py` classifies route intent.
3. Route-specific confirmation preflight runs.
4. `security_view.py` builds preview/internal request.
5. `stream_transport.py` establishes shared stream shell.
6. `upstream.py` opens the stream.
7. Route-specific finalize helpers preserve native terminal behavior.
8. Compat stream bridge runs only when needed.

## Required Invariants

### Lifecycle invariants

- Request pipeline executes exactly once.
- Response pipeline executes exactly once.
- Audit writes exactly once.
- Upstream dispatch executes exactly once.
- Confirmation state transitions execute exactly once.

### Identity invariants

- `request_id` continuity is preserved.
- `session_id` continuity is preserved.
- `tenant_id` continuity is preserved.
- `model` continuity is preserved.
- Token-scoped session isolation remains unchanged.

### Shape invariants

- Chat message shape is preserved.
- Responses input/output shape is preserved.
- Messages `system` / `content` / `provider_meta` / `tool_choice` are preserved.
- Tool-use continuity is preserved across compat paths.
- Sanitized output never leaks the original dangerous fragment.

### Stream invariants

- Retry may happen before first byte only.
- Retry never happens after first byte.
- Missing terminal markers are repaired exactly as today.
- Messages native stream never degrades into chat stream semantics.

## Phase Ordering

### Phase 0: Guardrails

- Write approved design and plan into the repository.
- Add route behavior matrix and ownership map.
- Add exactly-once, parity, and no-drift tests.
- Add internal rollout gates with all switches defaulted off.

### Phase 1: Route intent extraction

- Extract classifier logic only.
- Preserve existing redirect and native route behavior.

### Phase 2: Security view extraction

- Extract route-specific preview/internal-request construction.
- Keep upstream payload builders and confirmation ownership unchanged.

### Phase 3: Shared once skeleton

- Extract truly shared once-path orchestration.
- Keep route-specific builders/renderers via callbacks.

### Phase 4: Shared stream transport shell

- Extract shared stream transport shell only.
- Keep finalize and terminal semantics route-specific.

### Phase 5: Renderer extraction

- Move route-native non-stream rendering out of `router.py`.

### Phase 6: Shadow parity and controlled cutover

- Compare old and new paths under internal gates before route-by-route enablement.

### Phase 7: Real-upstream contract gate

- Validate the stabilized implementation against real upstreams before cleanup.

### Phase 8: Cleanup

- Delete old duplicated logic only after parity and real-upstream validation pass.

## Rollout and Rollback

- Use private internal gates only.
- Roll back at route granularity.
- Roll back stream and non-stream paths independently.
- Messages native path moves last.
- Live contract failures block cleanup.

## Observability Requirements

- Log and/or emit metrics for `request_id`, `route`, `intent`, `path_version`, `fallback_reason`, `stream_terminal_kind`, and `audit_write_count`.
- Track parity mismatches and per-route fallback counters during cutover.

Current baseline: route entrypoints log `intent`, `path_version`, and `fallback_reason` for redirect/fail-closed decisions. Stream-terminal counters and parity counters remain pending.

## Exit Criteria for Phase 0

Phase 1 may not begin until all of the following are true:

1. Approved design and Phase 0 plan are in the repo.
2. Route behavior matrix and ownership map are written down.
3. Minimal classifier guardrail tests exist and pass.
4. Exactly-once and parity invariants are covered and passing.
5. Internal rollout gates exist and default to off.
6. `upstream.py` ownership remains unchanged.
7. Stream terminal state machines remain route-specific.
8. Confirmation ownership remains unchanged.
