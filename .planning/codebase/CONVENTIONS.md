# Coding Conventions

**Analysis Date:** 2026-03-27

## Naming Patterns

**Files:**
- Use `snake_case.py` for modules. Representative paths: `aegisgate/core/gateway.py`, `aegisgate/config/settings.py`, `aegisgate/filters/injection_detector.py`, `aegisgate/tests/test_v2_proxy_router.py`.
- Prefix tests with `test_` and mirror the production concern rather than the package tree. Examples: `aegisgate/tests/test_gateway_boundary_access.py`, `aegisgate/tests/test_openai_pipeline_runtime.py`.

**Functions:**
- Use `snake_case` for functions and helpers, including internal helpers prefixed with `_`. Examples: `_initialize_observability()` in `aegisgate/core/gateway.py`, `_normalize_upstream_base()` in `aegisgate/adapters/openai_compat/upstream.py`, `_build_request()` in `aegisgate/tests/test_gateway_register.py`.
- Route handlers are also `snake_case` functions nested inside `register_ui_routes()` in `aegisgate/core/gateway_ui_routes.py`.

**Variables:**
- Use `snake_case` for locals and module globals. Examples: `_GW_TOKEN_PATH_RE` in `aegisgate/core/gateway.py`, `_SLOW_FILTER_WARN_S` in `aegisgate/core/pipeline.py`, `trace_request_id` in `aegisgate/adapters/openai_compat/upstream.py`.
- Use leading underscore for module-private globals and caches. Examples: `_hot_reloader` in `aegisgate/core/gateway.py`, `_upstream_async_client` in `aegisgate/adapters/openai_compat/upstream.py`.

**Types:**
- Use `PascalCase` for classes and Pydantic models. Examples: `Settings` in `aegisgate/config/settings.py`, `InternalRequest` in `aegisgate/core/models.py`, `PromptInjectionDetector` in `aegisgate/filters/injection_detector.py`.
- Use `UPPER_SNAKE_CASE` for constants and header names. Examples: `LOG_BASE_DIR` in `aegisgate/util/logger.py`, `_REDACTION_WHITELIST_HEADER` in `aegisgate/adapters/openai_compat/upstream.py`.

## Code Style

**Formatting:**
- No formatter config is detected in `pyproject.toml`, `.ruff.toml`, `ruff.toml`, `.editorconfig`, or `.pre-commit-config.yaml`.
- Follow Python 3.10+ style with 4-space indentation and pervasive type hints, matching `pyproject.toml` and files such as `aegisgate/core/models.py` and `aegisgate/core/pipeline.py`.
- Add `from __future__ import annotations` at the top of new Python modules to match most source and test files, including `aegisgate/core/gateway.py`, `aegisgate/core/pipeline.py`, and `aegisgate/tests/test_streaming_router.py`.

**Linting:**
- Dedicated lint tooling is not configured. `pyproject.toml` contains `mypy` settings and `coverage` settings, but no Ruff/Flake8/Black section.
- Keep style self-enforced: short helper functions, explicit conditionals, and readable multiline literals, as seen in `aegisgate/config/settings.py` and `aegisgate/core/gateway_ui_routes.py`.

## Import Organization

**Order:**
1. `from __future__ import annotations`
2. Standard library imports
3. Third-party imports
4. Local `aegisgate.*` imports

**Observed pattern:**
```python
from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator, Mapping

import httpx
from fastapi import Request

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger
```
- This pattern is visible in `aegisgate/adapters/openai_compat/upstream.py` and similar modules.

**Path Aliases:**
- No path aliases are used.
- Use absolute package imports from `aegisgate`, for example `from aegisgate.core.context import RequestContext` in `aegisgate/core/pipeline.py`.

## Error Handling

**Patterns:**
- Validate external input early and return structured `JSONResponse` errors at HTTP boundaries. See `aegisgate/core/gateway_ui_routes.py` for `invalid_json`, `invalid_values`, and `invalid_field_value` responses.
- Raise `ValueError` for invalid internal parameters and `RuntimeError` for operational failures that need escalation. Examples: `_normalize_upstream_base()` in `aegisgate/adapters/openai_compat/upstream.py`, `_write_env_updates()` in `aegisgate/core/gateway_ui_config.py`, and storage constructors in `aegisgate/storage/redis_store.py`.
- Catch narrow exception classes when parsing untrusted data. Representative files: `aegisgate/adapters/v2_proxy/router.py`, `aegisgate/core/gateway_network.py`, `aegisgate/filters/tool_call_guard.py`.
- In the filter pipeline, do not let one plugin abort the entire chain unless the boundary code explicitly decides to block. `aegisgate/core/pipeline.py` logs the exception, records a report entry, and continues.

**Response shape conventions:**
- Boundary and proxy errors usually return nested error objects such as `{"error": {"code": "...", "message": "..."}}`. See tests in `aegisgate/tests/test_gateway_boundary_access.py` and `aegisgate/tests/test_v2_proxy_router.py`.
- UI CRUD endpoints often return flatter payloads like `{"error": "invalid_json"}` or `{"ok": True}`. See `aegisgate/core/gateway_ui_routes.py`.

## Logging

**Framework:** `logging` via a project-level `aegisgate` logger in `aegisgate/util/logger.py`

**Patterns:**
- Use the shared logger from `aegisgate.util.logger`. Avoid ad hoc `print()` or standalone logger instances.
- Log in structured key-value style embedded in the message string. Typical fields include `request_id`, `route`, `status`, `reason`, `path`, and `elapsed_s`. Examples:
```python
logger.warning(
    "upstream http error request_id=%s status=%s detail=%s",
    ctx.request_id,
    status_code,
    detail,
)
```
from `aegisgate/adapters/openai_compat/router.py`.
- Use `logger.exception(...)` when stack traces are required for unexpected failures. Examples: `aegisgate/core/pipeline.py`, `aegisgate/core/hot_reload.py`, `aegisgate/core/gateway.py`.
- Keep logger naming centralized: `aegisgate/util/logger.py` builds the logger, configures stderr plus a daily rotating file handler under `logs/aegisgate/YY/MM/DD.log`, and exposes `apply_log_level()` for hot reload.
- Observability glue in `aegisgate/observability/logging.py` can switch root handlers to JSON formatting and inject trace IDs when OpenTelemetry is available.

## Comments

**When to Comment:**
- Use module docstrings to describe responsibility. Examples: `aegisgate/core/gateway.py`, `aegisgate/filters/base.py`, `aegisgate/observability/logging.py`.
- Use inline comments to explain operational reasons, compatibility behavior, or safety constraints, not obvious code flow. Examples: thread-offload comments in `aegisgate/config/settings.py`, route-rewrite comments in `aegisgate/core/gateway.py`.
- Comments may be English or Chinese; keep new comments aligned with the surrounding file language.

**JSDoc/TSDoc:**
- Not applicable.
- Python docstrings are used selectively on public classes, helper functions, and test modules. Examples: `aegisgate/core/models.py`, `aegisgate/tests/test_crypto_extended.py`.

## Function Design

**Size:**
- Keep functions small when possible, especially helpers and filters. Files may still contain large route modules, but those large modules are broken into many focused private helpers, for example `aegisgate/adapters/openai_compat/router.py` and `aegisgate/core/gateway.py`.

**Parameters:**
- Prefer typed parameters and keyword-only arguments for helper functions with multiple operational flags. Examples: `_record_request_observability()` in `aegisgate/core/gateway.py`, `_run_phase()` in `aegisgate/core/pipeline.py`.
- Prefer `dict[str, str]`, `list[str]`, and union syntax like `str | None` instead of `Optional[...]`, matching `aegisgate/config/settings.py` and tests such as `aegisgate/tests/test_gateway_boundary_access.py`.

**Return Values:**
- Return domain objects or concrete FastAPI responses rather than ambiguous tuples where possible. Examples: `InternalRequest` and `InternalResponse` in `aegisgate/core/pipeline.py`, `JSONResponse` in `aegisgate/core/gateway_ui_routes.py`.
- Tuple returns are used for tightly coupled internal results, such as status/payload pairs in `aegisgate/adapters/openai_compat/upstream.py`.

## Module Design

**Exports:**
- Most modules expose concrete functions/classes directly. There is little use of package-level indirection.
- One explicit compatibility exception exists: `aegisgate/core/gateway.py` re-exports helpers from `gateway_keys`, `gateway_network`, `gateway_auth`, `gateway_ui_config`, and `gateway_ui_routes` so older imports and tests continue to work.

**Barrel Files:**
- Not a general pattern.
- `aegisgate/core/gateway.py` acts as an assembly module and backward-compatibility surface, but package `__init__.py` barrel exports are not a common convention.

## Configuration Conventions

- Centralize runtime config in `aegisgate/config/settings.py` using `pydantic-settings.BaseSettings`.
- Add new settings as typed `Settings` fields with the `AEGIS_` prefix; do not read raw environment variables throughout the codebase.
- Runtime `.env` is expected at `config/.env`; tests that exercise config loading write temporary `config/.env` files and ignore root `.env`, as verified in `aegisgate/tests/test_config_source_convergence.py`.
- Put security and policy data in explicit config files such as `aegisgate/policies/rules/*.yaml` and `config/gw_tokens.json`, then hot-reload via `aegisgate/core/hot_reload.py`.

## Code Organization

- Keep HTTP boundary logic in adapters or gateway modules and pure transformation logic in `core`, `filters`, `storage`, and `util`.
- Model filter behavior through the `BaseFilter` contract in `aegisgate/filters/base.py`, with `process_request()`, `process_response()`, `enabled()`, and `report()`.
- Use Pydantic models for internal transport objects in `aegisgate/core/models.py`; pass these models through the pipeline instead of raw dicts when possible.

## Observed Gaps

- No repository-enforced formatter or linter configuration is present, so style consistency depends on review discipline.
- Error payload shapes are not fully uniform across `aegisgate/core/gateway_ui_routes.py`, `aegisgate/core/gateway.py`, and `aegisgate/adapters/v2_proxy/router.py`; new code should follow the local module pattern unless a repo-wide normalization pass is planned.
- Very large modules such as `aegisgate/adapters/openai_compat/router.py` and `aegisgate/core/gateway.py` rely on private helpers and re-exports for manageability; when changing them, prefer extracting one more helper over adding another long inline branch.

---

*Convention analysis: 2026-03-27*
