# Phase 2: Response Sanitization Integrity - Research

**Researched:** 2026-03-27
**Domain:** Brownfield `/v1` response sanitization, protocol-shape preservation, and risk marking in a FastAPI gateway
**Confidence:** HIGH

## User Constraints

No phase `CONTEXT.md` exists for Phase 2.

Use these locked constraints from project docs and roadmap:

- Stay within the existing Python/FastAPI architecture and established adapter/filter patterns.
- Keep the phase brownfield-safe and incremental; do not rewrite the gateway/router architecture.
- Default toward pass-with-marking and targeted fragment replacement, not blanket blocking.
- Preserve OpenAI- and Anthropic-compatible JSON/SSE/message contracts.
- Focus on `/v1` response behavior first; `/v2`, broader compatibility cleanup, and streaming fidelity have later dedicated phases.

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RESP-01 | Agent user receives benign responses without unnecessary blocking or loss of valid content | Tighten post-pipeline auto-sanitize entry points; do not escalate every `response_*` tag into whole-response fallback behavior |
| RESP-02 | Agent user receives responses whose JSON/event structure remains valid after response-side processing | Reuse existing route-specific patch helpers for chat/responses; add equivalent message-safe JSON/SSE patching instead of `sanitized_text` fallback |
| RESP-03 | Agent user receives high-risk responses with only dangerous fragments replaced by a safe default notice instead of the entire response being blocked | Keep `OutputSanitizer`/`PostRestoreGuard` fragment replacement, and route all no-confirmation rendering through fragment patchers instead of full-body replacement |
| RESP-04 | Operator can see risk marking or equivalent audit/reporting for sanitized responses without changing the client protocol contract | Preserve existing `aegisgate` metadata and audit/dangerous-response-log paths; do not invent new client-visible top-level protocol fields |

## Project Constraints (from CLAUDE.md)

- Keep changes inside the existing Python/FastAPI codebase and adapter/filter layout.
- Prefer minimal necessary change over architectural cleanup.
- Keep route handlers lean; shared logic belongs in adapter helpers, `core/`, or `filters/`.
- For behavior changes, add or update focused tests.
- For security/routing behavior, cover both allow-path and block/sanitize-path behavior.
- If command behavior or user-facing protocol behavior changes, update implementation and documentation together.
- Treat config, logs, and session data as runtime data; do not leak secrets into docs or tests.
- If new config is needed, use `AEGIS_*` env vars and document defaults in `README.md` and `config/.env.example`.

## Summary

The good news is that the repository already contains most of the primitives Phase 2 needs. The response pipeline is already split into filter-time risk detection and adapter-time protocol rendering. `OutputSanitizer` and `PostRestoreGuard` already do fragment-level replacement on `InternalResponse.output_text`, and `router.py` already contains body patchers for chat/responses JSON and SSE payloads: `_patch_chat_response_body()`, `_patch_responses_body()`, `_patch_chat_stream_payload()`, `_patch_responses_stream_payload()`, and `_sanitize_stream_event_line()`.

The main problem is not missing sanitization logic. The main problem is that several route branches bypass those structure-preserving helpers and fall back to protocol-breaking outputs once a response is marked risky. `/v1/chat/completions` and `/v1/responses` are closest to the desired design already. Direct `/v1/messages` is not: its non-stream sanitize path returns `{"sanitized_text": ...}` or plain text instead of Anthropic `message` shape, and its stream sanitize path emits chat-style SSE chunks rather than Anthropic `message_start` / `content_block_delta` events. That is the highest-confidence structural bug for Phase 2 planning.

**Primary recommendation:** Keep the existing filter pipeline and risk metadata model; make Phase 2 a rendering-layer hardening pass that routes every sanitized `/v1` response through protocol-native patch helpers instead of generic fallback payloads.

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| FastAPI | repo floor `>=0.115.0`; PyPI latest `0.135.2` (released 2026-03-23) | ASGI routing and response objects | Already owns the gateway surface and response classes |
| httpx | repo floor `>=0.27.0`; PyPI latest `0.28.1` (released 2024-12-06) | Upstream JSON/SSE forwarding | Already used by `/v1` and `/v2` forwarding paths |
| pydantic | repo floor `>=2.8.0`; PyPI latest `2.12.5` (released 2025-11-26) | Internal request/response models | Existing transport contract for pipeline filters |
| pydantic-settings | repo floor `>=2.4.0`; PyPI latest `2.13.1` (released 2026-02-19) | Runtime config via `AEGIS_*` | Existing config mechanism; do not add ad hoc config loaders |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pytest | installed `8.3.5`; PyPI latest `9.0.2` (released 2025-12-06) | Unit/integration regression coverage | Route and helper regression tests for sanitize-path and allow-path |
| uvicorn | installed `0.32.1`; PyPI latest `0.42.0` (released 2026-03-16) | Local gateway runtime | Manual smoke validation only |
| PyYAML | repo floor `>=6.0.0`; PyPI latest `6.0.3` (released 2025-09-25) | Security rule loading | Existing policy/rule source of truth |
| cryptography | repo floor `>=42.0.0`; PyPI latest `46.0.6` (released 2026-03-25) | Redaction/restoration storage crypto | Existing runtime dependency; not Phase 2 specific |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Existing route patch helpers in `router.py` | New response-normalization layer | Too large for this phase; high regression risk in a 5k+ router |
| Existing `aegisgate` metadata + audit log | New risk-marking envelope | Would change client contract and duplicate operator telemetry |
| Existing `stream_utils._iter_sse_frames()` | New SSE parser | Unnecessary duplication; existing helper already handles split frames |

**Installation:**

```bash
python -m pip install -e .[dev]
```

**Version verification:** Verified against PyPI pages on 2026-03-27. For implementation, stay on repo-declared floors unless the phase explicitly requires a dependency bump.

## Architecture Patterns

### Recommended Project Structure

```text
aegisgate/
├── adapters/openai_compat/   # Protocol mapping, upstream forwarding, route-native response patching
├── filters/                  # Risk detection and fragment replacement on InternalResponse
├── core/                     # Audit/logging/context/state helpers
└── tests/                    # Route-level and helper-level regressions
```

### Pattern 1: Detect In Pipeline, Patch In Adapter

**What:** Let filters mutate `InternalResponse.output_text`, `ctx.response_disposition`, `ctx.security_tags`, and `ctx.report_items`. Let route renderers patch the original protocol body or SSE payload using route-specific helpers.

**When to use:** Any `/v1/chat/completions`, `/v1/responses`, or `/v1/messages` response-side sanitize path.

**Example:**

```python
final_resp = await _run_response_pipeline(pipeline, internal_resp, ctx)
if _needs_confirmation(ctx):
    _attach_security_metadata(final_resp, ctx, boundary=boundary)
    return _render_non_confirmation_responses_output(upstream_body, final_resp, ctx)
```

Source: existing brownfield pattern in `aegisgate/adapters/openai_compat/router.py`

### Pattern 2: Patch Only Known Text-Bearing Fields

**What:** For JSON payloads, patch `message.content`, `tool_calls[].function.arguments`, `response.output[].content[].text`, and other known text-bearing leaves. Leave unknown item types untouched.

**When to use:** Non-stream sanitized outputs for chat, responses, and direct messages.

**Example:**

```python
if item_type == "message":
    ...
if item_type == "function_call":
    ...
if item_type in {"bash", "computer_call"}:
    ...
if item_type:
    return patched
```

Source: existing brownfield pattern in `_patch_responses_output_item()` in `aegisgate/adapters/openai_compat/router.py`

### Pattern 3: For SSE, Sanitize Only Safe Event Types

**What:** Patch text delta events and finalized text fields, but do not mutate partial JSON/code/tool-argument delta events whose structure would become invalid if edited mid-stream.

**When to use:** Responses/chat streaming sanitization.

**Example:**

```python
if event_type in _RESPONSES_TEXT_DELTA_EVENT_TYPES:
    patched["delta"] = _sanitize_hit_fragments(...)
```

Source: existing brownfield pattern in `_patch_responses_stream_payload()` in `aegisgate/adapters/openai_compat/router.py`

### Pattern 4: Preserve Risk Marking Out Of Band

**What:** Keep operator-visible risk signals in `resp.metadata["aegisgate"]`, audit logs, and dangerous-response sample logs rather than changing protocol-required fields.

**When to use:** All sanitized or blocked outputs.

**Anti-Patterns to Avoid**

- **Returning `{"sanitized_text": ...}` for protocol-native routes:** breaks Anthropic/OpenAI response contracts and bypasses existing compat helpers.
- **Rebuilding an entire response from `output_text` alone:** drops typed items, annotations, tool calls, and stream event structure.
- **Sanitizing unknown SSE event types:** can corrupt partial JSON, code, or tool-call argument streams.
- **Adding new top-level protocol fields for risk marks:** use existing `aegisgate` metadata instead.
- **Mixing Phase 2 with router refactor:** the router is already fragile; keep this phase scoped to response render correctness.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SSE frame reassembly | New chunk parser | `stream_utils._iter_sse_frames()` | Existing helper already handles split frames and normalized newlines |
| Chat/responses compat conversion | New conversion logic | `compat_bridge.py` + `mapper.py` | Existing code already preserves `aegisgate` metadata across compat redirects |
| Dangerous-fragment audit samples | New side log format | `dangerous_response_log.py` | Existing code already redacts raw content by default and stores fragment metadata |
| Route-native risk marks | Custom envelope | `_attach_security_metadata()` + `_write_audit_event()` | Existing operator contract already exists |
| Fragment replacement | New sanitizer engine | `OutputSanitizer`, `PostRestoreGuard`, `_sanitize_hit_fragments()` | Core replacement logic already exists; missing piece is consistent rendering |

**Key insight:** Phase 2 is mostly a “connect existing primitives consistently” phase, not a “design a new sanitization engine” phase.

## Common Pitfalls

### Pitfall 1: `_needs_confirmation()` Is Broader Than “block”

**What goes wrong:** The route can enter sanitize fallback on any `response_*` security tag or `requires_human_review`, not only explicit `ctx.response_disposition == "block"`.

**Why it happens:** `_needs_confirmation()` returns true for any response-side security tag, even review-only ones.

**How to avoid:** Separate “needs fragment patching” from “needs whole-response alternate rendering”. Keep Phase 2 render branches driven by protocol-safe patch helpers, not by generic fallback bodies.

**Warning signs:** Benign or partially risky responses end up in auto-sanitize path even though `OutputSanitizer` itself only replaced a small fragment or only set review metadata.

### Pitfall 2: Risk Score Alone Can Widen Sanitization

**What goes wrong:** Once `ctx.risk_score >= sanitize_threshold`, `OutputSanitizer` replaces every matching command/URI/markup/spam pattern family in `output_text`, even if the elevated score came from another filter.

**Why it happens:** `risk_triggered` gates multiple replacement branches.

**How to avoid:** Preserve filter-time behavior for Phase 2, but be careful not to add more routes into whole-response fallback. If false positives remain after render fixes, that is a later tuning slice.

**Warning signs:** Safe explanatory text around code, URLs, or HTML snippets gets over-redacted when another filter already raised the risk score.

### Pitfall 3: Context Padding Around Dangerous Hits Over-Sanitizes

**What goes wrong:** `_sanitize_hit_fragments()` expands each dangerous region by 20 surrounding characters before obfuscation.

**Why it happens:** `_collect_hit_regions()` uses `_SANITIZE_HIT_CONTEXT_CHARS = 20`.

**How to avoid:** Treat this as existing replacement policy. Do not stack additional whole-response replacement on top of it.

**Warning signs:** Nearby benign prose is obfuscated together with the actual dangerous token.

### Pitfall 4: Direct `/v1/messages` Currently Breaks Protocol On Sanitize

**What goes wrong:** Non-stream direct messages returns `{"sanitized_text": ...}` or plain text, and stream sanitize emits chat-style chunks.

**Why it happens:** Direct messages path does not have Anthropic-native JSON/SSE patch/render helpers equivalent to chat/responses.

**How to avoid:** Add `_render_non_confirmation_messages_output()` and Anthropic SSE sanitize helpers instead of reusing chat chunk helpers.

**Warning signs:** Sanitized `/v1/messages` responses no longer contain `type: "message"` / `content[]`, or stream output contains `chat.completion.chunk`.

### Pitfall 5: Streaming Tests Are Fragile Because Of Dedicated Offload Executors

**What goes wrong:** Targeted async tests can hang until `pytest-timeout` when route code touches the payload-transform executor.

**Why it happens:** `run_payload_transform_offloop()` uses a process-level `ThreadPoolExecutor`; current test suite already records timeouts in streaming/passthrough areas on Python 3.13.

**How to avoid:** In focused unit tests, monkeypatch `_run_payload_transform()` and `_build_streaming_response()` rather than relying on background executors.

**Warning signs:** Test failures show `aegisgate-payload-transform_*` threads and timeout stack traces instead of assertion failures.

## Code Examples

Verified brownfield patterns to reuse:

### Patch Responses JSON Without Changing The Contract

```python
def _render_non_confirmation_responses_output(upstream_body, final_resp, ctx):
    out = _patch_responses_body(upstream_body, ctx)
    if final_resp.metadata.get("aegisgate"):
        out["aegisgate"] = final_resp.metadata["aegisgate"]
    return out
```

Source: `aegisgate/adapters/openai_compat/router.py`

### Patch Only Safe Responses SSE Event Types

```python
if event_type in _RESPONSES_TEXT_DELTA_EVENT_TYPES:
    patched["delta"] = _sanitize_hit_fragments(...)
    patched["text"] = _sanitize_hit_fragments(...)
```

Source: `aegisgate/adapters/openai_compat/router.py`

### Preserve Risk Marks Without Changing Client Fields

```python
resp.metadata["aegisgate"] = {
    "action": action,
    "risk_score": round(ctx.risk_score, 4),
    "response_disposition": ctx.response_disposition,
    "reasons": sorted(set(ctx.disposition_reasons)),
}
```

Source: `aegisgate/adapters/openai_compat/router.py`

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hold dangerous content for yes/no approval | Auto-sanitize because confirmation flow is removed (`_confirmation_approval_enabled()` always false) | Current repo state as of 2026-03-27 | Route renderers, not confirmation records, now decide whether sanitized output stays protocol-valid |
| Replace whole response text after risk detection | Patch typed protocol body or stream payload in place | Partially present now for chat/responses, missing for direct messages | Phase 2 should finish this pattern instead of expanding fallback bodies |
| Treat `output_text` as sufficient response representation | Use `output[]`/typed items as canonical, with `output_text` as convenience | Current OpenAI Responses API docs | Responses sanitization must patch typed items, not only aggregate text |

**Deprecated/outdated:**

- Approval-flow branches guarded by `require_confirmation_on_block`: still present for legacy code paths, but effectively disabled in runtime behavior.
- Direct `/v1/messages` sanitize fallback shape: not safe to preserve; replace with Anthropic-native rendering.

## Open Questions

1. **Should direct `/v1/messages` streaming contract be fully fixed in Phase 2 or explicitly deferred to Phase 4?**
   - What we know: it is already structurally wrong today when sanitize triggers.
   - What's unclear: whether Phase 2 scope should include Anthropic SSE patching or only non-stream JSON integrity.
   - Recommendation: include the minimal direct messages SSE fix if touched by the same helper extraction; do not broaden into full streaming rewrite.

2. **Should `_needs_confirmation()` semantics be narrowed in Phase 2?**
   - What we know: it is broader than explicit block and can drive over-sanitize branches.
   - What's unclear: whether changing decision semantics risks behavior regressions beyond render integrity.
   - Recommendation: Phase 2 should first fix rendering and protocol preservation. Only narrow decision semantics if a focused test proves a benign-response regression.

3. **Should risk marking be emitted on every sanitized stream event or only final objects/chunks?**
   - What we know: current design uses `aegisgate` metadata on final JSON bodies and some generated chunks.
   - What's unclear: per-event consistency across chat/responses/messages.
   - Recommendation: preserve current metadata strategy and standardize only where the route already fabricates replacement chunks.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python | Runtime/tests | ✓ | 3.13.11 | — |
| pytest | Validation architecture | ✓ | 8.3.5 | — |
| uvicorn | Manual gateway smoke tests | ✓ | 0.32.1 | — |
| Docker | Optional local deployment smoke tests | ✓ | 29.3.0 | — |
| Real upstream OpenAI/Anthropic-compatible endpoint | Live interoperability verification | ✗ | — | Mocked route tests only |

**Missing dependencies with no fallback:**

- None for code and test implementation.

**Missing dependencies with fallback:**

- Real upstream providers for human smoke validation; use mocked route tests during implementation and keep live smoke in human UAT.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `pytest 8.3.5` |
| Config file | `pyproject.toml` |
| Quick run command | `pytest -q aegisgate/tests/test_post_restore_guard.py aegisgate/tests/test_tool_call_guard.py aegisgate/tests/test_dangerous_response_log.py -x` |
| Full suite command | `pytest -q` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| RESP-01 | Benign `/v1` responses pass without fallback sanitize/block | route integration | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k benign -x` | ❌ Wave 0 |
| RESP-02 | Chat/responses/messages sanitized outputs remain protocol-valid JSON/SSE | route + helper | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k structure -x` | ❌ Wave 0 |
| RESP-03 | Only dangerous fragments are replaced in text/tool-call-bearing fields | helper + route | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k fragment -x` | ❌ Wave 0 |
| RESP-04 | Sanitized outputs keep `aegisgate` risk metadata and audit signals | route + unit | `pytest -q aegisgate/tests/test_response_sanitization_routes.py -k metadata -x` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `pytest -q aegisgate/tests/test_response_sanitization_routes.py -x`
- **Per wave merge:** `pytest -q aegisgate/tests/test_streaming_router.py -x`
- **Phase gate:** `pytest -q`

### Wave 0 Gaps

- [ ] `aegisgate/tests/test_response_sanitization_routes.py` — route-level JSON sanitize regressions for chat/responses/messages
- [ ] `aegisgate/tests/test_response_sanitization_routes.py` — direct `/v1/messages` sanitize-path contract tests
- [ ] `aegisgate/tests/test_response_sanitization_routes.py` — `aegisgate` metadata + audit assertions on sanitized outputs
- [ ] `aegisgate/tests/test_streaming_router.py` additions — direct `/v1/messages` sanitize-path stream contract tests
- [ ] `aegisgate/tests/test_streaming_router.py` hardening — monkeypatch `_run_payload_transform()` in new focused tests to avoid current executor timeout pattern

## Sources

### Primary (HIGH confidence)

- Local code: `aegisgate/adapters/openai_compat/router.py` — current `/v1` response render branches, patch helpers, metadata/audit wiring
- Local code: `aegisgate/filters/sanitizer.py` — fragment replacement and block/sanitize thresholds
- Local code: `aegisgate/filters/post_restore_guard.py` — restored-secret masking after restoration
- Local code: `aegisgate/adapters/openai_compat/stream_utils.py` — SSE framing and stream block decision logic
- Local code: `aegisgate/adapters/openai_compat/pipeline_runtime.py` — response filter order
- Local tests: `aegisgate/tests/test_streaming_router.py`, `aegisgate/tests/test_passthrough_filter_mode.py`, `aegisgate/tests/test_post_restore_guard.py`, `aegisgate/tests/test_tool_call_guard.py`, `aegisgate/tests/test_dangerous_response_log.py`
- OpenAI Responses API reference: https://platform.openai.com/docs/api-reference/responses
- OpenAI Chat API reference: https://developers.openai.com/api/reference/resources/chat
- Anthropic streaming docs: https://platform.claude.com/docs/en/build-with-claude/streaming
- Anthropic Messages guide: https://platform.claude.com/docs/en/build-with-claude/working-with-messages

### Secondary (MEDIUM confidence)

- PyPI FastAPI: https://pypi.org/project/fastapi/
- PyPI httpx: https://pypi.org/project/httpx/
- PyPI pydantic: https://pypi.org/project/pydantic/
- PyPI pydantic-settings: https://pypi.org/project/pydantic-settings/
- PyPI pytest: https://pypi.org/project/pytest/
- PyPI uvicorn: https://pypi.org/project/uvicorn/
- PyPI cryptography: https://pypi.org/project/cryptography/
- PyPI PyYAML: https://pypi.org/project/PyYAML/

### Tertiary (LOW confidence)

- None

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - repo dependencies are explicit and current package versions were verified against PyPI
- Architecture: HIGH - conclusions come directly from current route/filter code and tests
- Pitfalls: HIGH - structural break points are visible in current branches and partially reproduced by targeted test runs/timeouts

**Research date:** 2026-03-27
**Valid until:** 2026-04-26
