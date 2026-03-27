# Requirements: AegisGate

**Defined:** 2026-03-27
**Core Value:** Agents can route all LLM traffic through one gateway that reduces leakage and dangerous outputs without breaking normal prompts, normal responses, or protocol compatibility.

## v1 Requirements

### Request Safety

- [ ] **SAFE-01**: Agent user can send prompts through `/v1/chat/completions` and have request-side secret/PII redaction applied before upstream forwarding
- [ ] **SAFE-02**: Agent user can send prompts through `/v1/responses` and have the same request-side redaction behavior applied before upstream forwarding
- [ ] **SAFE-03**: Agent user can send prompts through `/v1/messages` and have the same request-side redaction behavior applied before upstream forwarding
- [ ] **SAFE-04**: Agent user can send normal benign prompts through supported `/v1` routes without excessive false-positive redaction that makes the request unusable

### Response Safety

- [ ] **RESP-01**: Agent user receives benign responses without unnecessary blocking or loss of valid content
- [ ] **RESP-02**: Agent user receives responses whose JSON/event structure remains valid after response-side processing
- [ ] **RESP-03**: Agent user receives high-risk responses with only dangerous fragments replaced by a safe default notice instead of the entire response being blocked
- [ ] **RESP-04**: Operator can see risk marking or equivalent audit/reporting for sanitized responses without changing the client protocol contract

### Protocol Compatibility

- [ ] **COMP-01**: Agent user can call `/v1/chat/completions` with chat-style payloads and receive valid Chat Completions outputs through the full security pipeline
- [ ] **COMP-02**: Agent user can call `/v1/responses` with responses-style payloads and receive valid Responses outputs through the full security pipeline
- [ ] **COMP-03**: Agent user can send a responses-style payload to `/v1/chat/completions` and receive a valid Chat Completions-shaped response through compatibility conversion
- [ ] **COMP-04**: Agent user can send a chat-style payload to `/v1/responses` and receive a valid Responses-shaped response through compatibility conversion
- [ ] **COMP-05**: Anthropic-compatible clients can call `/v1/messages` and reach OpenAI-compatible upstreams through message-to-response conversion without losing gateway protections

### Streaming and Passthrough

- [ ] **STRM-01**: Agent user can use streaming on `/v1/chat/completions` without broken SSE framing after response-side sanitization
- [ ] **STRM-02**: Agent user can use streaming on `/v1/responses` without broken SSE framing after response-side sanitization
- [ ] **STRM-03**: Agent user can use passthrough mode without breaking compatibility rewrites, gateway-only field stripping, or expected client response shapes

### V2 Proxy

- [ ] **V2-01**: Operator can independently enable or disable request-side redaction for `/v2` traffic
- [ ] **V2-02**: Operator can independently enable or disable response-side risk marking and dangerous-fragment replacement for `/v2` traffic
- [ ] **V2-03**: Agent user receives structurally valid proxied `/v2` responses after response-side replacement is applied
- [ ] **V2-04**: Operator can run `/v2` with safe default target restrictions and explicit configuration for broader forwarding when needed

### Reliability and Performance

- [ ] **PERF-01**: Operator can run the gateway under concurrent agent traffic on primary `/v1` paths without obvious serialized bottlenecks or avoidable hot-path regressions
- [ ] **PERF-02**: Maintainer has focused automated tests covering allow-path, sanitize-path, compatibility conversion, streaming, passthrough, and `/v2` behavior

## v2 Requirements

### Security Tuning

- **TUNE-01**: Operator can tune false-positive sensitivity and replacement behavior through clearer policy presets beyond the initial v1 defaults
- **TUNE-02**: Operator can define more granular per-route or per-client policy behavior without patching application code

### Operations

- **OPER-01**: Operator can inspect richer security telemetry and false-positive diagnostics without reading raw logs manually
- **OPER-02**: Operator can manage more advanced multi-tenant or deployment-specific policy partitioning

## Out of Scope

| Feature | Reason |
|---------|--------|
| Admin UI redesign or major UX work | User explicitly excluded UI work from this milestone |
| Large gateway/router architecture rewrite | Brownfield hardening should stay incremental and avoid destabilizing broad surfaces |
| Billing, packaging, or commercialization features | Not part of the immediate product goal |
| New detection-model R&D program | Current need is correctness, usability, and operational hardening of the existing stack |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SAFE-01 | TBD | Pending |
| SAFE-02 | TBD | Pending |
| SAFE-03 | TBD | Pending |
| SAFE-04 | TBD | Pending |
| RESP-01 | TBD | Pending |
| RESP-02 | TBD | Pending |
| RESP-03 | TBD | Pending |
| RESP-04 | TBD | Pending |
| COMP-01 | TBD | Pending |
| COMP-02 | TBD | Pending |
| COMP-03 | TBD | Pending |
| COMP-04 | TBD | Pending |
| COMP-05 | TBD | Pending |
| STRM-01 | TBD | Pending |
| STRM-02 | TBD | Pending |
| STRM-03 | TBD | Pending |
| V2-01 | TBD | Pending |
| V2-02 | TBD | Pending |
| V2-03 | TBD | Pending |
| V2-04 | TBD | Pending |
| PERF-01 | TBD | Pending |
| PERF-02 | TBD | Pending |

**Coverage:**
- v1 requirements: 22 total
- Mapped to phases: 0
- Unmapped: 22 ⚠️

---
*Requirements defined: 2026-03-27*
*Last updated: 2026-03-27 after initial definition*
