# Phase 1: Request Redaction Precision - Research

**Researched:** 2026-03-27
**Domain:** `/v1` request-side redaction in an existing FastAPI/OpenAI-compatible gateway
**Confidence:** HIGH

## User Constraints

No phase `CONTEXT.md` exists yet. Planning must therefore honor the project docs, roadmap, requirement IDs, and the explicit user focus for this phase.

### Locked Decisions

- Focus only on Phase 1: request-side redaction precision for `/v1/chat/completions`, `/v1/responses`, and `/v1/messages`
- Must address `SAFE-01`, `SAFE-02`, `SAFE-03`, `SAFE-04`
- Keep changes brownfield-safe and incremental; no router or gateway rewrite
- Preserve upstream protocol validity after redaction
- Reduce false positives instead of increasing blanket blocking

### Claude's Discretion

- Choose the smallest existing integration points in `openai_compat/router.py`, request mapping, request filters, and helper modules
- Reuse existing policy, filter, whitelist, and payload-sanitization helpers instead of introducing parallel mechanisms

### Deferred Ideas (OUT OF SCOPE)

- Response-side sanitization integrity
- Streaming-specific fidelity work beyond avoiding request-shape regressions
- `/v2` proxy hardening
- Large architecture refactors
- Admin/UI work

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SAFE-01 | Agent user can send prompts through `/v1/chat/completions` and have request-side secret/PII redaction applied before upstream forwarding | Verified current chat path, upstream payload builder, and structured-content trap; planner should add schema-safe text-part rewrite for chat payloads |
| SAFE-02 | Agent user can send prompts through `/v1/responses` and have the same request-side redaction behavior applied before upstream forwarding | Verified existing `responses` structured-input sanitizer is the closest correct pattern and should be the template for the phase |
| SAFE-03 | Agent user can send prompts through `/v1/messages` and have the same request-side redaction behavior applied before upstream forwarding | Verified direct `/v1/messages` path currently analyzes but does not rewrite the forwarded Anthropic payload; phase must add protocol-aware message rewrite or equivalent dedicated path |
| SAFE-04 | Agent user can send normal benign prompts through supported `/v1` routes without excessive false-positive redaction that makes the request unusable | Verified likely false-positive sources in current redaction rules and route asymmetry; planner should target precision and route parity before broader rule expansion |
</phase_requirements>

## Summary

Phase 1 is not just a rule-tuning phase. The brownfield code already has one good request-redaction pattern, but only on `/v1/responses`: the route extracts text for risk evaluation, then separately rewrites the real upstream payload with `_sanitize_responses_input_for_upstream_with_hits(...)`. That separation is important because it preserves protocol shape while still applying redaction to the actual forwarded request.

The other two `/v1` paths are not equivalent today. `/v1/chat/completions` usually forwards redacted text correctly for simple string messages, but it preserves original structured `content` arrays wholesale, which can bypass redaction for multimodal or content-part payloads. `/v1/messages` is more serious: the direct Anthropic path goes through the generic executor, which runs request filters on extracted analysis text but forwards the original payload unchanged unless the request is blocked. That means direct `/v1/messages` currently does not satisfy `SAFE-03`.

False positives are introduced in two places: overly broad request redaction rules on chat/messages, and request-sanitizer shape/intent rules that can sanitize or block security-discussion examples. The safest plan slice is to keep the existing pipeline and policy engine, add route-specific protocol-aware rewrite helpers where they are missing, and lock the behavior with new focused tests before any wider regex tuning.

**Primary recommendation:** Use the existing `/v1/responses` structured-redaction pattern as the model, then add protocol-aware upstream rewrite helpers for chat and messages instead of changing the pipeline contract.

## User Constraints (from project docs)

- Stay within the current Python/FastAPI architecture and existing adapter/filter patterns.
- Preserve OpenAI/Anthropic-compatible request shapes.
- Make the smallest necessary change; avoid unrelated module churn.
- Add or update focused tests for adapter/request behavior changes.
- Keep route handlers lean; move reusable request-rewrite logic into adapter helpers.
- Do not copy secrets or real runtime data into docs or tests.

## Project Constraints (from CLAUDE.md)

- Use the existing Python/FastAPI stack and adapter/filter architecture; avoid disruptive rewrites.
- Default security behavior toward pass-with-marking and targeted replacement, not blanket blocking.
- Treat protocol correctness as a hard requirement for OpenAI/Anthropic-compatible payloads.
- Keep milestone scope on `/v1` and `/v2` request/response behavior and tests; UI/commercial work is out of scope.
- Only pursue performance changes when they directly improve hot-path reliability.
- Before code changes, check call sites and references; make the smallest necessary change.
- When behavior changes, add or update tests.
- Keep route handlers lean; extract reusable logic into `core/`, `filters/`, or adapter helpers.

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| FastAPI | repo floor `>=0.115.0`; latest verified `0.135.2` (2026-03-23) | ASGI routing, middleware, request/response surfaces | Existing gateway assembly, adapters, and tests are built on FastAPI |
| Pydantic v2 | repo floor `>=2.8.0` | Internal request/response models | `InternalRequest`, `InternalResponse`, and settings already depend on it |
| pydantic-settings | repo floor `>=2.4.0`; latest verified `2.13.1` (2026-02-19) | Typed runtime settings | Existing env/config model uses `BaseSettings` directly |
| httpx | repo floor `>=0.27.0`; latest verified `0.28.1` (2024-12-06) | Upstream forwarding and streaming | Already wired into both `/v1` and `/v2` transports |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| PyYAML | repo floor `>=6.0.0` | Policy and security-rule loading | Existing policy/rule tuning only; no replacement needed |
| pytest | repo floor `>=8.2.0`; local env `8.3.5`; latest verified `9.0.2` (2025-12-06) | Regression coverage | All Phase 1 verification should stay in pytest |
| Existing helper modules | repo-local | Payload rewrite, whitelist parsing, upstream compatibility | Prefer these over new request-redaction subsystems |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Extending route-specific payload builders | Rewriting the whole router into services | Too large for Phase 1; high regression surface in a 5k+ line module |
| Reusing `sanitize.py` structured recursion | Ad-hoc regex replacement inside route handlers | Duplicates logic and risks invalid protocol shapes |
| Keeping the current pipeline contract | Making filters mutate raw protocol payloads directly | Breaks the existing `InternalRequest` abstraction and increases coupling |

**Installation:**
```bash
python -m pip install -e .[dev]
```

**Version verification:** For this phase, do not plan a dependency upgrade. Use the existing project floors in `pyproject.toml`; current latest package versions were verified against PyPI on 2026-03-27 and are recorded above only to confirm ecosystem currency.

## Architecture Patterns

### Recommended Project Structure

```text
aegisgate/adapters/openai_compat/
├── router.py          # keep endpoint control flow and orchestration
├── mapper.py          # protocol <-> internal mapping
├── sanitize.py        # protocol-aware structured text rewrite helpers
├── payload_compat.py  # route-specific field stripping / renaming
└── upstream.py        # forwarding and header shaping

aegisgate/filters/
├── redaction.py       # request redaction rules + mapping persistence
├── exact_value_redaction.py
└── request_sanitizer.py

aegisgate/tests/
├── test_request_redaction_routes.py   # new route-level request rewrite tests
├── test_openai_request_mapping.py     # new mapper / structured-content tests
└── existing helper suites             # extend sanitize/passthrough tests where useful
```

### Pattern 1: Analyze With `InternalRequest`, Rewrite At The Protocol Boundary

**What:** Keep `to_internal_*()` for risk evaluation and filter execution, but write the actual redacted text back only inside route-specific upstream payload builders.

**When to use:** Every supported `/v1` request route that must preserve upstream schema shape.

**Why:** `InternalRequest.messages` is a normalized analysis view, not always a lossless upstream payload.

**Example:**
```python
# Source: local code - aegisgate/adapters/openai_compat/router.py
sanitized_req = await _run_request_pipeline(pipeline, req, ctx)
upstream_payload = await _run_payload_transform(
    _build_responses_upstream_payload,
    payload,
    sanitized_req.messages,
    request_id=ctx.request_id,
    session_id=ctx.session_id,
    route=ctx.route,
    whitelist_keys=ctx.redaction_whitelist_keys,
)
```

### Pattern 2: Structured Recursive Rewrite For Responses-Style Input

**What:** Recurse through `input`, sanitize only text-bearing nodes, preserve non-content fields and encrypted blobs, and log hit metadata separately.

**When to use:** `/v1/responses`, and as the template for any new `/v1/messages` structured rewrite helper.

**Example:**
```python
# Source: local code - aegisgate/adapters/openai_compat/sanitize.py
sanitized, hits = _sanitize_responses_input_for_upstream_with_hits(
    original_input,
    whitelist_keys=whitelist_keys,
)
```

### Pattern 3: Preserve Unknown Provider Fields, But Rewrite Text Parts Only

**What:** Start from the original provider payload so provider-specific keys survive, then patch only redaction-sensitive text fields.

**When to use:** `/v1/chat/completions` and `/v1/messages`, where upstreams accept richer content blocks.

**Example:**
```python
# Source: local code - aegisgate/adapters/openai_compat/router.py
merged = dict(original_messages[idx])
merged["role"] = message.role
```

The important Phase 1 correction is that structured `content` arrays cannot be preserved wholesale when they contain redactable text.

### Anti-Patterns to Avoid

- **Using flattened analysis text as the final upstream payload:** `to_internal_*()` deliberately flattens content. That is useful for filters, but it loses multimodal/text-part structure.
- **Blindly preserving original structured content in chat/messages:** this keeps schema valid but can skip redaction entirely for text blocks inside arrays.
- **Fixing false positives only by lowering thresholds first:** route parity is currently broken; rule tuning alone will not satisfy `SAFE-03`.
- **Solving `/v1/messages` by expanding generic proxy behavior further:** the generic executor is intentionally schema-agnostic and currently blocks sanitize-on-rewrite for safety.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Responses structured request rewrite | New recursive tree walker in `router.py` | `_sanitize_responses_input_for_upstream_with_hits()` | Already handles skip fields, role-sensitive relaxation, internal-history stripping, and hit logging |
| Chat/Responses field cleanup | Manual key deletion in endpoints | `sanitize_for_chat()` / `sanitize_for_responses()` | Existing compatibility layer already strips route-incompatible fields |
| Whitelist parsing | Custom header parsing or regexes | `normalize_whitelist_keys()` + `protected_spans_for_text()` | Current whitelist logic already supports token-scope and request-header flow |
| Policy/filter activation | Route-local flag checks | `PolicyEngine.resolve(ctx, ...)` | Keeps feature flags and policy YAML behavior consistent |
| Request pipeline assembly | Per-route custom filter lists | `_get_pipeline()` from `pipeline_runtime.py` | Existing order is deliberate and already covered by tests |

**Key insight:** The hard part of this phase is not regex matching. It is preserving protocol-valid upstream payloads while only rewriting the text-bearing parts that should actually be redacted.

## Common Pitfalls

### Pitfall 1: Direct `/v1/messages` Currently Does Not Rewrite The Forwarded Payload

**What goes wrong:** `_execute_generic_once()` and `_execute_generic_stream_once()` run request filters against extracted analysis text, but forward the original Anthropic payload unchanged unless the request is blocked.

**Why it happens:** The generic executor treats sanitize-on-rewrite as unsupported because it does not know the provider schema.

**How to avoid:** Add a dedicated `/v1/messages` upstream payload builder or a message-specific structured rewrite helper; do not rely on generic execution for request-side redaction parity.

**Warning signs:** `ctx.report_items` shows redaction hits, but the forwarded Anthropic request still contains the original sensitive text.

### Pitfall 2: Structured Chat `content` Arrays Can Bypass Redaction

**What goes wrong:** `_build_chat_upstream_payload()` preserves original structured `content` when it is a list or dict. That keeps multimodal shape valid, but it also discards the redacted `message.content` computed by the pipeline.

**Why it happens:** The builder assumes structured content must be preserved untouched.

**How to avoid:** Add a helper that rewrites only text-bearing parts inside structured chat content while preserving non-text parts like images/audio/files.

**Warning signs:** String-message tests pass, but content-part payloads still leak original text upstream.

### Pitfall 3: `/v1/responses` Has Two Request Views, And They Must Stay In Sync

**What goes wrong:** `to_internal_responses()` only extracts the latest user text for filtering, while `_sanitize_responses_input_for_upstream_with_hits()` rewrites the full structured history.

**Why it happens:** The analysis model and the upstream payload model are intentionally different.

**How to avoid:** If you tune redaction precision, change both the analysis-side and the upstream-rewrite-side logic only where parity is required. Do not assume one path covers the other.

**Warning signs:** Route-level tests pass for simple string input but fail once `input` is an array of messages or mixed content parts.

### Pitfall 4: Chat/Messages Use Broader Redaction Rules Than Responses

**What goes wrong:** `RedactionFilter` applies the full PII set on chat/messages, including hostnames, IPs, home paths, names, addresses, and bank/account-like fields. `/v1/responses` already uses a relaxed subset for upstream rewrite.

**Why it happens:** Route-specific relaxation exists only for `/v1/responses`.

**How to avoid:** Make relaxation policy explicit by route and keep it consistent across the actual forwarded payloads for all three supported `/v1` routes.

**Warning signs:** Benign prompts about infrastructure, logs, example data, or security testing get redacted on chat/messages but not on responses.

### Pitfall 5: `RequestSanitizer` Can Convert Precision Work Into 403 Regressions

**What goes wrong:** If a route falls into `request_disposition == "sanitize"` without a schema-safe rewrite path, the generic executor returns `generic_request_sanitize_unsupported`.

**Why it happens:** `RequestSanitizer` is allowed to sanitize or block shape anomalies; generic forwarding refuses partial unsafe mutations.

**How to avoid:** For Phase 1, keep request-side precision work focused on redaction parity and schema-safe text rewrites. Do not casually expand request-sanitizer triggers on unsupported routes.

**Warning signs:** A route starts returning 403 for payloads that previously passed, even though no new block rule was intended.

## Code Examples

Verified patterns from existing code:

### Responses Upstream Rewrite Pattern

```python
# Source: /mnt/d/agent_work/AegisGate/aegisgate/adapters/openai_compat/router.py
def _build_responses_upstream_payload(payload, sanitized_req_messages, *, whitelist_keys=None, **meta):
    upstream_payload = sanitize_for_responses(
        {k: v for k, v in payload.items() if k not in _GATEWAY_INTERNAL_KEYS},
    )
    original_input = payload.get("input")
    if isinstance(original_input, (list, dict)):
        sanitized_input, hits = _sanitize_responses_input_for_upstream_with_hits(
            original_input,
            whitelist_keys=whitelist_keys,
        )
        upstream_payload["input"] = sanitized_input
    else:
        upstream_payload["input"] = _strip_system_exec_runtime_lines(
            str(sanitized_req_messages[0].content)
        )
    return upstream_payload
```

### Policy + Filter Mode Entry Pattern

```python
# Source: /mnt/d/agent_work/AegisGate/aegisgate/adapters/openai_compat/router.py
ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
ctx.redaction_whitelist_keys = _extract_redaction_whitelist_keys(request_headers)
policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
filter_mode = _apply_filter_mode(ctx, request_headers)
sanitized_req = await _run_request_pipeline(_get_pipeline(), req, ctx)
```

### Token-Scope Whitelist Injection Pattern

```python
# Source: /mnt/d/agent_work/AegisGate/aegisgate/core/gateway.py
wk = normalize_whitelist_keys(mapping.get("whitelist_key"))
new_scope["aegis_redaction_whitelist_keys"] = wk
new_scope["aegis_filter_mode"] = filter_mode
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Assume chat message content is just a string | OpenAI Chat accepts string or typed content arrays for multiple roles | Current OpenAI API docs as of 2026-03-27 | Request redaction must patch text parts inside arrays, not just scalar strings |
| Assume Responses `input` is only a string | OpenAI Responses accepts string or message objects with typed content arrays and multiple roles | Current OpenAI API docs as of 2026-03-27 | Any request rewrite must recurse through structured input safely |
| Treat Anthropic Messages as a simple chat clone | Anthropic Messages remains stateless full-history input and also supports content blocks | Current Anthropic docs as of 2026-03-27 | Direct `/v1/messages` needs its own protocol-aware request rewrite path |

**Deprecated/outdated:**

- Flattening rich message payloads and then forwarding the original structured payload unchanged is no longer sufficient for request redaction precision.
- Planning a regex-only fix is outdated for this codebase; route-specific protocol rewrite behavior is already the real correctness boundary.

## Open Questions

1. **Should chat/messages use the same relaxed redaction subset that responses already uses?**
   - What we know: `/v1/responses` already limits actual upstream request redaction to credential-like patterns, while chat/messages use the broader rule set.
   - What's unclear: whether Phase 1 should fully align all three routes or preserve stricter chat/messages behavior for some categories.
   - Recommendation: decide explicitly in planning, then encode it as route-level tests before editing rules.

2. **How should direct `/v1/messages` preserve Anthropic content blocks while redacting text?**
   - What we know: generic execution cannot safely rewrite provider payloads; current direct path forwards original payload unchanged.
   - What's unclear: whether to add a dedicated `_build_messages_upstream_payload()` helper or to reuse compat conversion internally even for Anthropic upstreams.
   - Recommendation: prefer a dedicated helper that preserves Anthropic block shape and rewrites only text-bearing fields.

3. **Do we need message-part-aware chat rewrite for all roles or only user content?**
   - What we know: OpenAI chat content arrays can appear in user, developer, system, and tool contexts.
   - What's unclear: whether the gateway should rewrite all text-bearing roles for request-side secrecy or only user-entered fields.
   - Recommendation: match the current filter intent and sanitize all request text actually forwarded upstream, while preserving non-text parts.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python | app/tests | ✓ | 3.13.11 | — |
| pytest | Phase 1 regression tests | ✓ | 8.3.5 | — |

**Missing dependencies with no fallback:**

- None found for this phase

**Missing dependencies with fallback:**

- None found for this phase

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `pytest` (local env `8.3.5`) |
| Config file | `pyproject.toml` |
| Quick run command | `pytest -q aegisgate/tests/test_request_redaction_routes.py -x` |
| Full suite command | `pytest -q` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SAFE-01 | Chat route redacts sensitive text before upstream forwarding while preserving valid chat schema | integration | `pytest -q aegisgate/tests/test_request_redaction_routes.py::test_chat_request_redaction_preserves_shape -x` | ❌ Wave 0 |
| SAFE-02 | Responses route redacts structured input before upstream forwarding while preserving valid responses schema | integration | `pytest -q aegisgate/tests/test_request_redaction_routes.py::test_responses_request_redaction_structured_input -x` | ❌ Wave 0 |
| SAFE-03 | Direct messages route redacts text-bearing content blocks before upstream forwarding | integration | `pytest -q aegisgate/tests/test_request_redaction_routes.py::test_messages_request_redaction_preserves_anthropic_shape -x` | ❌ Wave 0 |
| SAFE-04 | Benign prompts with paths/IPs/hostnames/examples are not excessively redacted across supported routes | unit/integration | `pytest -q aegisgate/tests/test_request_redaction_routes.py::test_benign_examples_avoid_false_positives -x` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `pytest -q aegisgate/tests/test_request_redaction_routes.py -x`
- **Per wave merge:** `pytest -q aegisgate/tests/test_request_redaction_routes.py aegisgate/tests/test_payload_compat.py aegisgate/tests/test_sanitize_helpers.py -x`
- **Phase gate:** `pytest -q`

### Wave 0 Gaps

- [ ] `aegisgate/tests/test_request_redaction_routes.py` — route-level request redaction parity for chat/responses/messages
- [ ] `aegisgate/tests/test_openai_request_mapping.py` — mapper and structured-content coverage for `to_internal_chat`, `to_internal_responses`, and `to_internal_messages`
- [ ] Extend `aegisgate/tests/test_sanitize_helpers.py` — recursive responses-input rewrite, skip fields, whitelist preservation, and benign examples
- [ ] Extend `aegisgate/tests/test_passthrough_filter_mode.py` — non-passthrough request redaction assertions for real upstream payload builders

## Sources

### Primary (HIGH confidence)

- Local code: `aegisgate/adapters/openai_compat/router.py` — request route execution, upstream payload builders, generic executor behavior
- Local code: `aegisgate/adapters/openai_compat/mapper.py` — request flattening and protocol conversion
- Local code: `aegisgate/adapters/openai_compat/sanitize.py` — structured responses-input rewrite helpers
- Local code: `aegisgate/filters/redaction.py` — request redaction pattern application and mapping persistence
- Local code: `aegisgate/filters/request_sanitizer.py` — request-side sanitize/block behavior
- Local code: `aegisgate/adapters/openai_compat/pipeline_runtime.py` — filter ordering and runtime assembly
- Local code: `aegisgate/policies/rules/default.yaml` and `aegisgate/policies/rules/security_filters.yaml` — route-agnostic request rules and likely false-positive sources
- Local code: `pyproject.toml` — dependency floors and pytest configuration
- OpenAI Responses API docs: https://developers.openai.com/api/reference/resources/responses/methods/create
- OpenAI Chat API docs: https://developers.openai.com/api/reference/resources/chat
- Anthropic Messages guide: https://platform.claude.com/docs/en/build-with-claude/working-with-messages

### Secondary (MEDIUM confidence)

- PyPI FastAPI: https://pypi.org/project/fastapi/
- PyPI httpx: https://pypi.org/project/httpx/
- PyPI pydantic-settings: https://pypi.org/project/pydantic-settings/
- PyPI pytest: https://pypi.org/project/pytest/

### Tertiary (LOW confidence)

- None

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - repo dependency floors were verified locally and current package currency was checked on PyPI
- Architecture: HIGH - main claims come directly from current production code paths
- Pitfalls: HIGH - the major traps are code-verified (`/v1/messages` direct forward behavior, chat structured-content preservation, route asymmetry)

**Research date:** 2026-03-27
**Valid until:** 2026-04-26
