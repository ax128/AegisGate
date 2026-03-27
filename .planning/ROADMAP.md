# Roadmap: AegisGate

## Overview

This roadmap treats AegisGate as a brownfield hardening milestone. The existing gateway already covers the main protocol surface, so phases are organized around incremental quality boundaries on real request paths: lower false positives, structure-preserving sanitization, full `/v1` correctness, production-usable `/v2`, and regression-proof performance/coverage without a large rewrite.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Request Redaction Precision** - Harden `/v1` request-side redaction so sensitive input is scrubbed without breaking benign prompts.
- [ ] **Phase 2: Response Sanitization Integrity** - Preserve response structure while replacing only dangerous fragments and surfacing audit/risk marks.
- [ ] **Phase 3: /v1 Compatibility Completion** - Make the main `/v1` protocol shapes behave consistently through the full security pipeline.
- [ ] **Phase 4: Streaming & Passthrough Fidelity** - Keep SSE, passthrough, and gateway-only rewrites correct after sanitization and compatibility handling.
- [ ] **Phase 5: /v2 Proxy Hardening** - Bring `/v2` request/response controls and target restrictions to production-usable behavior.
- [ ] **Phase 6: Hot-Path Reliability & Coverage** - Remove obvious concurrency bottlenecks on primary routes and close focused regression-test gaps.

## Phase Details

### Phase 1: Request Redaction Precision
**Goal**: Users can send prompts through supported `/v1` routes and get consistent request-side redaction with low false positives.
**Depends on**: Nothing (first phase)
**Requirements**: SAFE-01, SAFE-02, SAFE-03, SAFE-04
**Success Criteria** (what must be TRUE):
  1. Agent user can send prompts through `/v1/chat/completions` and have secret or PII fragments redacted before upstream forwarding.
  2. Agent user can send prompts through `/v1/responses` and `/v1/messages` and get the same request-side redaction outcome for equivalent content.
  3. Agent user can send benign prompts through supported `/v1` routes without excessive false-positive redaction making the request unusable.
  4. Redacted `/v1` requests still reach upstream providers in a valid protocol shape.
**Plans**: 3 plans

Plans:
- [ ] `01-01-PLAN.md` - Reuse the `/v1/responses` rewrite pattern for chat structured-content redaction and lock it with focused regressions.
- [ ] `01-02-PLAN.md` - Add a dedicated direct `/v1/messages` request rewrite path that preserves Anthropic shape for JSON and streaming.
- [ ] `01-03-PLAN.md` - Align low-false-positive request redaction behavior across chat, responses, and direct messages.

### Phase 2: Response Sanitization Integrity
**Goal**: Users receive `/v1` responses that stay structurally valid while only dangerous fragments are replaced and risk-marked.
**Depends on**: Phase 1
**Requirements**: RESP-01, RESP-02, RESP-03, RESP-04
**Success Criteria** (what must be TRUE):
  1. Agent user receives benign responses without unnecessary blocking or loss of valid content.
  2. Agent user receives high-risk responses with only the dangerous fragments replaced by a safe notice instead of the entire response being denied.
  3. Response-side processing preserves valid JSON or event structure after sanitization.
  4. Operator can identify sanitized responses through risk marking or equivalent audit signals without changing the client protocol contract.
**Plans**: TBD

### Phase 3: /v1 Compatibility Completion
**Goal**: Users can rely on every supported `/v1` protocol shape working end-to-end through the hardened gateway path.
**Depends on**: Phase 2
**Requirements**: COMP-01, COMP-02, COMP-03, COMP-04, COMP-05
**Success Criteria** (what must be TRUE):
  1. Agent user can call `/v1/chat/completions` with chat-style payloads and receive valid Chat Completions outputs through the full security pipeline.
  2. Agent user can call `/v1/responses` with responses-style payloads and receive valid Responses outputs through the full security pipeline.
  3. Compatibility conversion between chat-style and responses-style payloads produces valid client-facing outputs without dropping gateway protections.
  4. Anthropic-compatible clients can call `/v1/messages` and reach OpenAI-compatible upstreams through conversion without losing gateway protections.
**Plans**: TBD

### Phase 4: Streaming & Passthrough Fidelity
**Goal**: Users can stream or use passthrough mode on `/v1` routes without SSE breakage or response-shape regressions.
**Depends on**: Phase 3
**Requirements**: STRM-01, STRM-02, STRM-03
**Success Criteria** (what must be TRUE):
  1. Agent user can stream `/v1/chat/completions` responses without broken SSE framing after response-side sanitization.
  2. Agent user can stream `/v1/responses` responses without broken SSE framing after response-side sanitization.
  3. Agent user can use passthrough mode without breaking compatibility rewrites, gateway-only field stripping, or expected client response shapes.
**Plans**: TBD

### Phase 5: /v2 Proxy Hardening
**Goal**: Operators can run `/v2` with explicit request/response controls, safe forwarding defaults, and structurally valid sanitized outputs.
**Depends on**: Phase 2
**Requirements**: V2-01, V2-02, V2-03, V2-04
**Success Criteria** (what must be TRUE):
  1. Operator can independently enable or disable `/v2` request-side redaction.
  2. Operator can independently enable or disable `/v2` response-side risk marking and dangerous-fragment replacement.
  3. Agent user receives structurally valid proxied `/v2` responses after dangerous-fragment replacement is applied.
  4. Operator can keep `/v2` on safe default target restrictions and opt into broader forwarding only through explicit configuration.
**Plans**: TBD

### Phase 6: Hot-Path Reliability & Coverage
**Goal**: Operators can run primary gateway paths under concurrent load with focused regression coverage protecting the hardened behavior.
**Depends on**: Phase 5
**Requirements**: PERF-01, PERF-02
**Success Criteria** (what must be TRUE):
  1. Operator can run concurrent agent traffic on primary `/v1` paths without obvious serialized bottlenecks or avoidable hot-path regressions.
  2. Maintainer has focused automated tests covering allow-path, sanitize-path, compatibility conversion, streaming, passthrough, and `/v2` behavior.
  3. Regression checks cover the hardening slices introduced in earlier phases so incremental brownfield changes can ship without silently breaking main gateway flows.
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Request Redaction Precision | 0/3 | Not started | - |
| 2. Response Sanitization Integrity | 0/TBD | Not started | - |
| 3. /v1 Compatibility Completion | 0/TBD | Not started | - |
| 4. Streaming & Passthrough Fidelity | 0/TBD | Not started | - |
| 5. /v2 Proxy Hardening | 0/TBD | Not started | - |
| 6. Hot-Path Reliability & Coverage | 0/TBD | Not started | - |
