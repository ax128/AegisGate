# Forwarding Kernel Phase 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lock down Phase 0 guardrails for the forwarding-kernel refactor before any behavior-moving refactor begins.

**Architecture:** Phase 0 adds documentation, route-classification guardrails, exactly-once/parity invariants, and private rollout gates while explicitly keeping confirmation ownership, stream terminal semantics, and `upstream.py` ownership unchanged. Entrypoint handlers must also fail-close mixed `messages` + `input` payloads to the entry route even if classifier output drifts. The work is test-first and fail-closed.

**Tech Stack:** Python 3.10+, pytest, FastAPI route tests, existing `openai_compat` helpers and mocks

---

### Task 1: Write and keep the approved design in the repo

**Files:**
- Create: `docs/superpowers/plans/2026-04-18-forwarding-kernel-design.md`
- Create: `docs/superpowers/plans/2026-04-18-forwarding-kernel-phase0.md`

- [ ] **Step 1: Verify both docs exist**

Run: `python - <<'PY'
from pathlib import Path
paths = [
    Path('docs/superpowers/plans/2026-04-18-forwarding-kernel-design.md'),
    Path('docs/superpowers/plans/2026-04-18-forwarding-kernel-phase0.md'),
]
for path in paths:
    print(path, path.exists())
PY`

Expected: both paths print `True`

- [ ] **Step 2: Ensure the design doc includes the Phase 0 exit gate**

Run: `python - <<'PY'
from pathlib import Path
text = Path('docs/superpowers/plans/2026-04-18-forwarding-kernel-design.md').read_text()
needed = ['Exit Criteria for Phase 0', 'upstream.py ownership remains unchanged', 'Confirmation ownership remains unchanged']
for item in needed:
    print(item, item in text)
PY`

Expected: every item prints `True`

### Task 2: Add classifier guardrail tests first

**Files:**
- Create: `aegisgate/tests/test_forwarding_kernel_phase0_guardrails.py`
- Modify: `aegisgate/adapters/openai_compat/router.py`
- Create: `aegisgate/adapters/openai_compat/forwarding_classifier.py`

- [ ] **Step 1: Write failing classification tests**

Add tests covering:

```python
def test_chat_endpoint_input_payload_redirects_to_responses(): ...
def test_responses_endpoint_messages_payload_redirects_to_chat(): ...
def test_messages_endpoint_openai_chat_compat_redirects_to_responses(): ...
def test_messages_plus_input_does_not_redirect_implicitly(): ...
def test_native_messages_shape_stays_native_when_only_messages_present(): ...
```

Also assert handler-level mixed-payload fail-closed behavior so entrypoint routing does not trust classifier output blindly.

- [ ] **Step 2: Run the new test file and verify failure**

Run: `pytest -q aegisgate/tests/test_forwarding_kernel_phase0_guardrails.py`

Expected: FAIL because the new classifier module / route hook does not exist yet or does not satisfy the precedence rules.

- [ ] **Step 3: Implement the minimal classifier**

Create a small classifier that returns only the minimum fields needed for Phase 0:

```python
@dataclass(frozen=True)
class ForwardingRouteIntent:
    entry_route: str
    detected_contract: str
    target_path: str
    compat_mode: str
    stream: bool
```

Use it only to centralize the existing redirect rules. Do not add a canonical request bus or move confirmation logic.

- [ ] **Step 4: Re-run the new tests and make them pass**

Run: `pytest -q aegisgate/tests/test_forwarding_kernel_phase0_guardrails.py`

Expected: PASS

### Task 3: Add internal rollout gate tests first

**Files:**
- Modify: `aegisgate/tests/test_forwarding_kernel_phase0_guardrails.py`
- Create: `aegisgate/adapters/openai_compat/forwarding_gate.py`
- Modify: `aegisgate/config/settings.py`
- Modify: `aegisgate/adapters/openai_compat/router.py`

- [ ] **Step 1: Write failing rollout-gate tests**

Add tests covering:

```python
def test_internal_rollout_gate_defaults_to_all_off(): ...
def test_unknown_rollout_tokens_are_ignored_or_fail_closed(): ...
def test_route_specific_gate_only_affects_its_matching_route_and_mode(): ...
```

- [ ] **Step 2: Run the targeted tests and verify failure**

Run: `pytest -q aegisgate/tests/test_forwarding_kernel_phase0_guardrails.py -k rollout`

Expected: FAIL because the private rollout gate does not exist yet.

- [ ] **Step 3: Implement the minimal private gate**

Add a private internal setting such as `AEGIS_INTERNAL_FORWARDING_KERNEL_ROLLOUT`, parse a comma-separated token list, and keep all switches off by default.

- [ ] **Step 4: Re-run rollout tests**

Run: `pytest -q aegisgate/tests/test_forwarding_kernel_phase0_guardrails.py -k rollout`

Expected: PASS

### Task 4: Strengthen exactly-once and parity guardrails in existing route tests

**Files:**
- Modify: `aegisgate/tests/test_passthrough_filter_mode.py`
- Modify: `aegisgate/tests/test_streaming_router.py`
- Modify: `aegisgate/tests/test_request_redaction_routes.py`
- Modify: `aegisgate/tests/test_response_sanitization_routes.py`
- Modify: `aegisgate/tests/test_session_isolation.py`

- [ ] **Step 1: Write failing assertions before changing production code**

Add assertions for:
- passthrough routes never entering normal request/response pipeline
- compat delegation happening exactly once
- stream terminal handling not duplicating audit/failure paths
- session identity continuity across route families
- parity of allow/sanitize envelopes across native and compat route families

- [ ] **Step 2: Run only the targeted suites and verify at least one failure if new behavior is not already locked**

Run:

```bash
pytest -q aegisgate/tests/test_passthrough_filter_mode.py
pytest -q aegisgate/tests/test_streaming_router.py
pytest -q aegisgate/tests/test_request_redaction_routes.py
pytest -q aegisgate/tests/test_response_sanitization_routes.py
pytest -q aegisgate/tests/test_session_isolation.py
```

Expected: any missing guardrail should fail for the expected reason before production adjustments.

- [ ] **Step 3: Make only the minimal supporting code changes**

Adjust thin wrappers or helper boundaries only as needed to satisfy the tests. Do not move confirmation ownership, do not change `upstream.py`, and do not unify stream finalize logic.

- [ ] **Step 4: Re-run the targeted suites**

Run the same commands again.

Expected: PASS

### Task 5: Full Phase 0 verification

**Files:**
- No additional files

- [ ] **Step 1: Run the complete Phase 0 verification matrix**

Run:

```bash
pytest -q aegisgate/tests/test_forwarding_kernel_phase0_guardrails.py
pytest -q aegisgate/tests/test_openai_request_mapping.py
pytest -q aegisgate/tests/test_request_redaction_routes.py
pytest -q aegisgate/tests/test_response_sanitization_routes.py
pytest -q aegisgate/tests/test_passthrough_filter_mode.py
pytest -q aegisgate/tests/test_streaming_router.py
pytest -q aegisgate/tests/test_upstream_routing.py
pytest -q aegisgate/tests/test_gateway_boundary_access.py
pytest -q aegisgate/tests/test_v2_proxy_router.py
pytest -q aegisgate/tests/test_relay_router.py
pytest -q
```

Expected: all commands exit 0.

- [ ] **Step 2: Confirm Phase 0 exit criteria**

Checklist:
- approved spec and Phase 0 plan are in the repo
- classifier guardrails exist and pass
- exactly-once/parity invariants are covered and passing
- private rollout gates exist and default off
- `upstream.py` ownership unchanged
- stream terminal logic not unified
- confirmation ownership unchanged

- [ ] **Step 3: Do not commit unless explicitly requested by the user**

This repository session must not create a git commit without explicit user instruction.
