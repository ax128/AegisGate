# AegisGate

## What This Is

AegisGate is a self-hosted security gateway for LLM traffic. It sits between AI agents or security-conscious users and upstream model providers, applies request-side redaction plus response-side risk handling, and forwards traffic through OpenAI-compatible and generic proxy paths without forcing client-side rewrites.

This brownfield project already implements most of the core gateway surface. The current focus is to harden and complete the main request/response paths so they are safe, structurally correct, and usable in real agent workflows without excessive false positives.

## Core Value

Agents can route all LLM traffic through one gateway that reduces leakage and dangerous outputs without breaking normal prompts, normal responses, or protocol compatibility.

## Requirements

### Validated

- ✓ OpenAI-compatible gateway routes already exist for `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, and generic `/v1/*` forwarding — existing
- ✓ Request/response security pipeline, policy loading, token-based routing, and upstream forwarding are already implemented in the current gateway — existing
- ✓ Anthropic Messages compatibility bridging, streaming support, passthrough modes, and generic `/v2` proxy foundations already exist in the codebase — existing
- ✓ Local admin and runtime configuration surfaces already exist for operators to manage keys, tokens, rules, and runtime settings — existing
- ✓ Supported `/v1/chat/completions`, `/v1/responses`, and `/v1/messages` now apply request-side redaction with route parity and protocol-shape preservation — Phase 1
- ✓ Supported `/v1` request routes now use a lower-false-positive request redaction policy for benign infrastructure and security-review prompts while still redacting explicit secrets — Phase 1

### Active

- [ ] Reduce false positives in response-side handling so normal responses pass cleanly
- [ ] Preserve response payload structure while replacing only dangerous fragments instead of blocking entire high-risk responses
- [ ] Make `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, compatibility conversion, streaming, and passthrough behave consistently through the full security path
- [ ] Bring `/v2` request redaction plus response-side risk marking/replacement to a production-usable level with explicit switches
- [ ] Improve concurrency and hot-path performance where needed without a large-scale rewrite
- [ ] Close coverage gaps with focused tests for allow, sanitize, compatibility, streaming, passthrough, and `/v2` paths

### Out of Scope

- UI redesign or new admin-console features — not part of this milestone
- Large architectural rewrite of the gateway/router layout — keep changes incremental and brownfield-friendly
- Commercialization features such as billing, tenancy packaging, or productized pricing flows — not part of v1 hardening
- New detection-model research program or major ML expansion — current focus is behavior quality and operational correctness

## Context

This is a brownfield Python/FastAPI codebase that already ships the core gateway, multiple protocol adapters, request/response filters, file or DB-backed runtime state, and a built-in management UI. The gateway is primarily intended for agent traffic and for users who want all model calls routed through an intermediate inspection layer before reaching upstream LLM providers.

The most important product tension is security vs usability. The gateway should redact and sanitize risky content, but it must avoid overblocking, avoid damaging valid payloads, and avoid breaking upstream or downstream protocol shapes. For high-risk response content, the preferred behavior is safe fragment replacement and risk marking rather than full response denial.

The codebase map already highlights that the main `/v1` and `/v2` paths exist but have quality risks around oversized modules, compatibility-path complexity, semantic-review behavior, and operational bottlenecks. This initialization should therefore treat the current project as a hardening and completion effort, not a greenfield feature build.

## Constraints

- **Tech stack**: Stay within the existing Python/FastAPI architecture and established adapter/filter patterns — avoid disruptive rewrites in a live brownfield codebase
- **Security behavior**: Default toward pass-with-marking and targeted replacement, not blanket blocking — the product must remain usable for normal agent workloads
- **Protocol correctness**: Do not break OpenAI/Anthropic-compatible payload or stream structure — clients must keep working without special-case patches
- **Scope**: Focus on `/v1` and `/v2` request/response behavior, compatibility, streaming, passthrough, and tests — UI and commercial concerns are deferred
- **Performance**: Concurrency and hot-path efficiency improvements are allowed and encouraged when they directly improve gateway reliability under agent traffic

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Optimize for low false-positive security behavior | Overblocking harms trust and makes the gateway unusable for real agent workflows | ✓ Good in Phase 1 for supported `/v1` request routes |
| Replace dangerous response fragments instead of hard-blocking entire high-risk responses | Users still need usable outputs and stable protocol shapes | — Pending |
| Treat response-structure preservation as a hard requirement | Broken JSON/SSE/protocol framing is a functional regression, not an acceptable tradeoff | — Pending |
| Keep this milestone brownfield-friendly and avoid a major rewrite | The repo already has broad coverage of the target surface; the main need is hardening and completion | — Pending |
| Include `/v2` in scope with switchable request and response controls | `/v2` is part of the product promise and cannot remain a second-class path | — Pending |

## Current State

Phase 1 is complete at the code and automated-test level. The gateway now has route-parity request-side redaction across the three supported `/v1` routes, with schema-safe rewriting for structured chat and direct messages payloads and a lower-false-positive policy for benign prompts.

One human smoke-test item remains recorded in `01-HUMAN-UAT.md`: validating live upstream acceptance against real OpenAI/Anthropic-compatible providers. The next implementation focus is Phase 2, which moves from request-side precision to response-side sanitization integrity.

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `$gsd-transition`):
1. Requirements invalidated? -> Move to Out of Scope with reason
2. Requirements validated? -> Move to Validated with phase reference
3. New requirements emerged? -> Add to Active
4. Decisions to log? -> Add to Key Decisions
5. "What This Is" still accurate? -> Update if drifted

**After each milestone** (via `$gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check -> still the right priority?
3. Audit Out of Scope -> reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-03-27 after Phase 1 completion*
