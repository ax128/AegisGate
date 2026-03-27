<!-- GSD:project-start source:PROJECT.md -->
## Project

**AegisGate**

AegisGate is a self-hosted security gateway for LLM traffic. It sits between AI agents or security-conscious users and upstream model providers, applies request-side redaction plus response-side risk handling, and forwards traffic through OpenAI-compatible and generic proxy paths without forcing client-side rewrites.

This brownfield project already implements most of the core gateway surface. The current focus is to harden and complete the main request/response paths so they are safe, structurally correct, and usable in real agent workflows without excessive false positives.

**Core Value:** Agents can route all LLM traffic through one gateway that reduces leakage and dangerous outputs without breaking normal prompts, normal responses, or protocol compatibility.

### Constraints

- **Tech stack**: Stay within the existing Python/FastAPI architecture and established adapter/filter patterns — avoid disruptive rewrites in a live brownfield codebase
- **Security behavior**: Default toward pass-with-marking and targeted replacement, not blanket blocking — the product must remain usable for normal agent workloads
- **Protocol correctness**: Do not break OpenAI/Anthropic-compatible payload or stream structure — clients must keep working without special-case patches
- **Scope**: Focus on `/v1` and `/v2` request/response behavior, compatibility, streaming, passthrough, and tests — UI and commercial concerns are deferred
- **Performance**: Concurrency and hot-path efficiency improvements are allowed and encouraged when they directly improve gateway reliability under agent traffic
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- Python 3.10+ - main application code, adapters, filters, storage backends, and scripts under `aegisgate/` and `scripts/`
- YAML - policy and security rule sources under `aegisgate/policies/rules/` and runtime-mounted config under `config/security_filters.yaml`
- JSON - token/model mapping and persisted stats in `config/gw_tokens.json`, `config/model_map.json`, and `config/stats.json`
- HTML/CSS/JS - built-in local admin UI assets under `www/`
- Shell - deployment helpers such as `scripts/caddy-entrypoint.sh` and container startup in `Dockerfile`
## Runtime
- CPython 3.10+ required by `pyproject.toml`
- Docker image uses Python 3.11 slim in `Dockerfile`
- CI validates Python 3.10, 3.12, and 3.13 in `.github/workflows/ci.yml`
- `pip` + setuptools build backend from `pyproject.toml`
- Editable installs are the primary workflow: `python -m pip install -e .`, `python -m pip install -e .[dev]`, `python -m pip install -e .[dev,semantic]`
- Lockfile: missing; no `uv.lock`, `poetry.lock`, or `requirements.txt` detected at repo root
## Frameworks
- FastAPI - HTTP gateway app and route composition in `aegisgate/core/gateway.py`
- Pydantic v2 + `pydantic-settings` - typed runtime settings and internal models in `aegisgate/config/settings.py` and `aegisgate/core/models.py`
- httpx - async upstream HTTP client for `/v1` and `/v2` forwarding in `aegisgate/adapters/openai_compat/upstream.py` and `aegisgate/adapters/v2_proxy/router.py`
- `pytest` - test runner configured in `pyproject.toml`
- `pytest-asyncio`, `pytest-timeout`, `pytest-cov` - async tests, timeouts, and coverage from `pyproject.toml`
- Uvicorn - ASGI server entrypoint used in `Dockerfile`, `README.md`, and `scripts/local_launcher.py`
- Docker Compose - default local/prod-ish deployment path in `docker-compose.yml`
- GitHub Actions - CI test matrix in `.github/workflows/ci.yml`
## Key Dependencies
- `fastapi>=0.115.0` - public gateway API, admin UI routes, and middleware wiring in `aegisgate/core/gateway.py`
- `httpx>=0.27.0` - upstream request forwarding, SSE streaming, and semantic service calls in `aegisgate/adapters/openai_compat/upstream.py`, `aegisgate/adapters/v2_proxy/router.py`, and `aegisgate/core/semantic.py`
- `pydantic>=2.8.0` and `pydantic-settings>=2.4.0` - typed config and request/response models in `aegisgate/config/settings.py` and `aegisgate/core/models.py`
- `pyyaml>=6.0.0` - policy/rule loading in `aegisgate/config/security_rules.py` and `aegisgate/policies/policy_engine.py`
- `cryptography>=42.0.0` - Fernet-based encrypted mapping storage in `aegisgate/storage/crypto.py`
- `redis>=5.0.0` optional extra - Redis KV store and nonce replay cache in `aegisgate/storage/redis_store.py` and `aegisgate/core/security_boundary.py`
- `psycopg[binary]>=3.1.0` optional extra - PostgreSQL KV store in `aegisgate/storage/postgres_store.py`
- `scikit-learn>=1.3.0`, `jieba>=0.42.0`, `joblib>=1.3.0` optional `semantic` extra - built-in TF-IDF semantic classifier and training flow in `aegisgate/core/semantic.py`, `aegisgate/core/tfidf_model.py`, and `scripts/train_tfidf.py`
- `prometheus-client>=0.20.0` optional `observability` extra - `/metrics` endpoint in `aegisgate/observability/metrics.py`
- `opentelemetry-*>=1.24.0` optional `observability` extra - tracing bootstrap in `aegisgate/observability/tracing.py`
## Configuration
- Use `AEGIS_*` env vars defined by `aegisgate/config/settings.py`
- File-based runtime config is `config/.env`; `Settings` reads it directly via `env_file="config/.env"` in `aegisgate/config/settings.py`
- Treat `config/.env` as the only file-based runtime config entrypoint; `config/README.md` explicitly says repo-root `.env` is not used
- Required runtime-writable secret/key files are generated on first boot in `config/aegis_gateway.key`, `config/aegis_proxy_token.key`, and `config/aegis_fernet.key`; these are runtime data, not source-controlled configuration
- Security policies bootstrap from `aegisgate/policies/rules/` and are copied into `config/` by `aegisgate/init_config.py`
- Python package/build metadata lives in `pyproject.toml`
- Container image build and app bootstrap are defined in `Dockerfile`
- Default deployment topology is defined in `docker-compose.yml`
- CI install/test behavior is defined in `.github/workflows/ci.yml`
## Platform Requirements
- Python 3.10+ with `venv` support for `scripts/local_launcher.py`
- Writable `config/` and `logs/` directories; `aegisgate/init_config.py` falls back to `/tmp/aegisgate` for some runtime paths when needed
- For semantic mode, install the `semantic` extra so bundled TF-IDF assets in `aegisgate/models/tfidf/` can be used
- For Redis/Postgres storage, install the matching extras and provide `AEGIS_REDIS_URL` or `AEGIS_POSTGRES_DSN`
- Self-hosted ASGI service served by Uvicorn from `aegisgate.core.gateway:app`
- Default containerized deployment uses `docker-compose.yml`, binds `127.0.0.1:18080`, mounts `./config` and `./logs`, and joins external Docker networks `cliproxy_net` and `sub2api_net`
- Production edge TLS/reverse proxy is expected outside the app; `README.md` recommends Caddy or nginx, and `scripts/caddy-entrypoint.sh` supports a Caddy sidecar using `config/aegis_proxy_token.key`
## Protocol and Adapter Surface
- Main API surface lives in `aegisgate/adapters/openai_compat/router.py`
- Implemented routes include `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, and generic `/v1/{subpath}` via `aegisgate/core/gateway.py`
- Independent proxy/filter chain lives in `aegisgate/adapters/v2_proxy/router.py`
- `/v2` and `/v2/{proxy_path}` are mounted when `enable_v2_proxy` is true in `aegisgate/core/gateway.py`
- Optional relay adapter in `aegisgate/adapters/relay_compat/router.py`
- `/relay/generate` is mounted only when `AEGIS_ENABLE_RELAY_ENDPOINT=true`
- Anthropic Messages to OpenAI Responses conversion is implemented in `aegisgate/adapters/openai_compat/compat_bridge.py`, `aegisgate/adapters/openai_compat/mapper.py`, and token compat data in `config/gw_tokens.json`
- Global model remapping for compat mode comes from `config/model_map.json`
## Runtime Entry Points
- `aegisgate/core/gateway.py` - FastAPI assembly module and main import target
- `python -m aegisgate.init_config` - bootstrap config, writable paths, and policy files from `aegisgate/init_config.py`
- `scripts/local_launcher.py` - create `.venv`, install extras, run bootstrap, and start Uvicorn in foreground/background
- `Dockerfile` command runs `python -m aegisgate.init_config && uvicorn aegisgate.core.gateway:app --host 0.0.0.0 --port 18080`
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Naming Patterns
- Use `snake_case.py` for modules. Representative paths: `aegisgate/core/gateway.py`, `aegisgate/config/settings.py`, `aegisgate/filters/injection_detector.py`, `aegisgate/tests/test_v2_proxy_router.py`.
- Prefix tests with `test_` and mirror the production concern rather than the package tree. Examples: `aegisgate/tests/test_gateway_boundary_access.py`, `aegisgate/tests/test_openai_pipeline_runtime.py`.
- Use `snake_case` for functions and helpers, including internal helpers prefixed with `_`. Examples: `_initialize_observability()` in `aegisgate/core/gateway.py`, `_normalize_upstream_base()` in `aegisgate/adapters/openai_compat/upstream.py`, `_build_request()` in `aegisgate/tests/test_gateway_register.py`.
- Route handlers are also `snake_case` functions nested inside `register_ui_routes()` in `aegisgate/core/gateway_ui_routes.py`.
- Use `snake_case` for locals and module globals. Examples: `_GW_TOKEN_PATH_RE` in `aegisgate/core/gateway.py`, `_SLOW_FILTER_WARN_S` in `aegisgate/core/pipeline.py`, `trace_request_id` in `aegisgate/adapters/openai_compat/upstream.py`.
- Use leading underscore for module-private globals and caches. Examples: `_hot_reloader` in `aegisgate/core/gateway.py`, `_upstream_async_client` in `aegisgate/adapters/openai_compat/upstream.py`.
- Use `PascalCase` for classes and Pydantic models. Examples: `Settings` in `aegisgate/config/settings.py`, `InternalRequest` in `aegisgate/core/models.py`, `PromptInjectionDetector` in `aegisgate/filters/injection_detector.py`.
- Use `UPPER_SNAKE_CASE` for constants and header names. Examples: `LOG_BASE_DIR` in `aegisgate/util/logger.py`, `_REDACTION_WHITELIST_HEADER` in `aegisgate/adapters/openai_compat/upstream.py`.
## Code Style
- No formatter config is detected in `pyproject.toml`, `.ruff.toml`, `ruff.toml`, `.editorconfig`, or `.pre-commit-config.yaml`.
- Follow Python 3.10+ style with 4-space indentation and pervasive type hints, matching `pyproject.toml` and files such as `aegisgate/core/models.py` and `aegisgate/core/pipeline.py`.
- Add `from __future__ import annotations` at the top of new Python modules to match most source and test files, including `aegisgate/core/gateway.py`, `aegisgate/core/pipeline.py`, and `aegisgate/tests/test_streaming_router.py`.
- Dedicated lint tooling is not configured. `pyproject.toml` contains `mypy` settings and `coverage` settings, but no Ruff/Flake8/Black section.
- Keep style self-enforced: short helper functions, explicit conditionals, and readable multiline literals, as seen in `aegisgate/config/settings.py` and `aegisgate/core/gateway_ui_routes.py`.
## Import Organization
- This pattern is visible in `aegisgate/adapters/openai_compat/upstream.py` and similar modules.
- No path aliases are used.
- Use absolute package imports from `aegisgate`, for example `from aegisgate.core.context import RequestContext` in `aegisgate/core/pipeline.py`.
## Error Handling
- Validate external input early and return structured `JSONResponse` errors at HTTP boundaries. See `aegisgate/core/gateway_ui_routes.py` for `invalid_json`, `invalid_values`, and `invalid_field_value` responses.
- Raise `ValueError` for invalid internal parameters and `RuntimeError` for operational failures that need escalation. Examples: `_normalize_upstream_base()` in `aegisgate/adapters/openai_compat/upstream.py`, `_write_env_updates()` in `aegisgate/core/gateway_ui_config.py`, and storage constructors in `aegisgate/storage/redis_store.py`.
- Catch narrow exception classes when parsing untrusted data. Representative files: `aegisgate/adapters/v2_proxy/router.py`, `aegisgate/core/gateway_network.py`, `aegisgate/filters/tool_call_guard.py`.
- In the filter pipeline, do not let one plugin abort the entire chain unless the boundary code explicitly decides to block. `aegisgate/core/pipeline.py` logs the exception, records a report entry, and continues.
- Boundary and proxy errors usually return nested error objects such as `{"error": {"code": "...", "message": "..."}}`. See tests in `aegisgate/tests/test_gateway_boundary_access.py` and `aegisgate/tests/test_v2_proxy_router.py`.
- UI CRUD endpoints often return flatter payloads like `{"error": "invalid_json"}` or `{"ok": True}`. See `aegisgate/core/gateway_ui_routes.py`.
## Logging
- Use the shared logger from `aegisgate.util.logger`. Avoid ad hoc `print()` or standalone logger instances.
- Log in structured key-value style embedded in the message string. Typical fields include `request_id`, `route`, `status`, `reason`, `path`, and `elapsed_s`. Examples:
- Use `logger.exception(...)` when stack traces are required for unexpected failures. Examples: `aegisgate/core/pipeline.py`, `aegisgate/core/hot_reload.py`, `aegisgate/core/gateway.py`.
- Keep logger naming centralized: `aegisgate/util/logger.py` builds the logger, configures stderr plus a daily rotating file handler under `logs/aegisgate/YY/MM/DD.log`, and exposes `apply_log_level()` for hot reload.
- Observability glue in `aegisgate/observability/logging.py` can switch root handlers to JSON formatting and inject trace IDs when OpenTelemetry is available.
## Comments
- Use module docstrings to describe responsibility. Examples: `aegisgate/core/gateway.py`, `aegisgate/filters/base.py`, `aegisgate/observability/logging.py`.
- Use inline comments to explain operational reasons, compatibility behavior, or safety constraints, not obvious code flow. Examples: thread-offload comments in `aegisgate/config/settings.py`, route-rewrite comments in `aegisgate/core/gateway.py`.
- Comments may be English or Chinese; keep new comments aligned with the surrounding file language.
- Not applicable.
- Python docstrings are used selectively on public classes, helper functions, and test modules. Examples: `aegisgate/core/models.py`, `aegisgate/tests/test_crypto_extended.py`.
## Function Design
- Keep functions small when possible, especially helpers and filters. Files may still contain large route modules, but those large modules are broken into many focused private helpers, for example `aegisgate/adapters/openai_compat/router.py` and `aegisgate/core/gateway.py`.
- Prefer typed parameters and keyword-only arguments for helper functions with multiple operational flags. Examples: `_record_request_observability()` in `aegisgate/core/gateway.py`, `_run_phase()` in `aegisgate/core/pipeline.py`.
- Prefer `dict[str, str]`, `list[str]`, and union syntax like `str | None` instead of `Optional[...]`, matching `aegisgate/config/settings.py` and tests such as `aegisgate/tests/test_gateway_boundary_access.py`.
- Return domain objects or concrete FastAPI responses rather than ambiguous tuples where possible. Examples: `InternalRequest` and `InternalResponse` in `aegisgate/core/pipeline.py`, `JSONResponse` in `aegisgate/core/gateway_ui_routes.py`.
- Tuple returns are used for tightly coupled internal results, such as status/payload pairs in `aegisgate/adapters/openai_compat/upstream.py`.
## Module Design
- Most modules expose concrete functions/classes directly. There is little use of package-level indirection.
- One explicit compatibility exception exists: `aegisgate/core/gateway.py` re-exports helpers from `gateway_keys`, `gateway_network`, `gateway_auth`, `gateway_ui_config`, and `gateway_ui_routes` so older imports and tests continue to work.
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
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- `aegisgate/core/gateway.py` is the composition root: it creates the `FastAPI` app, mounts metrics and static UI assets, starts runtime services, and wires protocol routers.
- `aegisgate/adapters/*` owns protocol-facing behavior. `aegisgate/adapters/openai_compat/router.py` is the main execution surface; `aegisgate/adapters/v2_proxy/router.py` and `aegisgate/adapters/relay_compat/router.py` are parallel ingress paths with their own request handling rules.
- Security enforcement is pipeline-driven. `aegisgate/adapters/openai_compat/pipeline_runtime.py` constructs a `Pipeline` from concrete filters under `aegisgate/filters/`, while `aegisgate/policies/policy_engine.py` decides which filters are active per request.
## Layers
- Purpose: Build the ASGI app, enforce outer boundary checks, start and stop runtime workers, and register non-business endpoints.
- Location: `aegisgate/core/gateway.py`
- Contains: FastAPI app creation, lifespan startup/shutdown, token path rewrite middleware, security boundary middleware, admin token management endpoints, root/health endpoints, and UI registration.
- Depends on: `aegisgate/adapters/*`, `aegisgate/core/*`, `aegisgate/config/settings.py`, `aegisgate/observability/*`, `aegisgate/storage/*`, `aegisgate/init_config.py`.
- Used by: `uvicorn aegisgate.core.gateway:app`, tests under `aegisgate/tests/test_gateway_*`.
- Purpose: Convert inbound protocol payloads into internal request models, apply policy and pipeline logic, forward to upstreams, then map results back to client-facing protocol shapes.
- Location: `aegisgate/adapters/openai_compat/`, `aegisgate/adapters/v2_proxy/`, `aegisgate/adapters/relay_compat/`
- Contains: Route handlers, protocol mappers, compatibility bridges, SSE helpers, upstream HTTP forwarding helpers.
- Depends on: `aegisgate/core/context.py`, `aegisgate/core/models.py`, `aegisgate/core/confirmation*.py`, `aegisgate/core/semantic.py`, `aegisgate/policies/policy_engine.py`, `aegisgate/storage/offload.py`, `aegisgate/config/*`, `aegisgate/util/*`.
- Used by: `aegisgate/core/gateway.py`
- Purpose: Hold the shared store proxy and build thread-local `Pipeline` instances used by OpenAI-compatible routes.
- Location: `aegisgate/adapters/openai_compat/pipeline_runtime.py`, `aegisgate/core/pipeline.py`, `aegisgate/core/registry.py`
- Contains: `RuntimeStoreProxy`, thread-local pipeline cache, filter list assembly, sequential request/response execution, hot-reload invalidation.
- Depends on: `aegisgate/storage/__init__.py`, `aegisgate/filters/*`, `aegisgate/core/context.py`, `aegisgate/core/models.py`.
- Used by: `aegisgate/adapters/openai_compat/router.py`, `aegisgate/core/hot_reload.py`
- Purpose: Perform request redaction, request-side validation, response-side risk scoring, restoration, and output sanitization.
- Location: `aegisgate/filters/`
- Contains: `RedactionFilter`, `ExactValueRedactionFilter`, `RequestSanitizer`, `RagPoisonGuard`, `AnomalyDetector`, `PromptInjectionDetector`, `PrivilegeGuard`, `ToolCallGuard`, `RestorationFilter`, `PostRestoreGuard`, `OutputSanitizer`, plus `BaseFilter`.
- Depends on: `aegisgate/core/context.py`, `aegisgate/core/models.py`, `aegisgate/config/security_rules.py`, `aegisgate/storage/kv.py`, `aegisgate/util/*`.
- Used by: `aegisgate/adapters/openai_compat/pipeline_runtime.py`
- Purpose: Persist redaction mappings, pending confirmations, token registrations, audit data, and request stats.
- Location: `aegisgate/storage/`, `aegisgate/core/gw_tokens.py`, `aegisgate/core/audit.py`, `aegisgate/core/stats.py`
- Contains: `KVStore` abstraction and concrete backends, token-map file persistence, queued audit writer, stats collector with file persistence.
- Depends on: `aegisgate/config/settings.py`, `aegisgate/storage/crypto.py`, `aegisgate/util/logger.py`
- Used by: adapters, filters, `aegisgate/core/gateway.py`, UI routes.
- Purpose: Load runtime settings, policy YAML, redaction rules, feature flags, and watch selected files for reload.
- Location: `aegisgate/config/`, `aegisgate/core/hot_reload.py`, `aegisgate/init_config.py`
- Contains: global `settings`, security rule loaders, feature flags, runtime bootstrap copying of config files, file polling watcher, cache invalidation hooks.
- Depends on: filesystem, `aegisgate/adapters/openai_compat/router.py`, `aegisgate/adapters/openai_compat/pipeline_runtime.py`, `aegisgate/adapters/v2_proxy/router.py`.
- Used by: `aegisgate/core/gateway.py`, UI config endpoints, filter modules.
- Purpose: Expose local-only admin pages and APIs for config editing, token management, key rotation, rule CRUD, stats, and restart actions.
- Location: `aegisgate/core/gateway_ui_routes.py`, `aegisgate/core/gateway_auth.py`, `aegisgate/core/gateway_ui_config.py`, static assets in `www/`
- Contains: login/logout, bootstrap/config/docs APIs, token CRUD, rules APIs, compose-file editing, restart endpoint, UI session and CSRF helpers.
- Depends on: `aegisgate/core/gateway.py`, `aegisgate/core/gw_tokens.py`, `aegisgate/config/settings.py`, `aegisgate/core/hot_reload.py`.
- Used by: `aegisgate/core/gateway.py`
## Data Flow
- Request-scoped mutable state lives in `RequestContext` from `aegisgate/core/context.py`.
- Route-scoped gateway metadata lives in `request.state.security_boundary` and `request.scope`.
- Cross-request runtime state is either in memory with locking (`aegisgate/core/gw_tokens.py`, `aegisgate/core/stats.py`) or persisted through `KVStore` backends under `aegisgate/storage/`.
## Key Abstractions
- Purpose: Per-request execution state shared by all filters and adapter logic.
- Examples: `aegisgate/core/context.py`, created throughout `aegisgate/adapters/openai_compat/router.py`
- Pattern: Mutable dataclass carrying enabled filters, risk score, dispositions, report items, redaction mappings, and tenant metadata.
- Purpose: Internal transport model independent from any one upstream or client protocol.
- Examples: `aegisgate/core/models.py`, mapper functions in `aegisgate/adapters/openai_compat/mapper.py`, relay conversion in `aegisgate/adapters/relay_compat/mapper.py`
- Pattern: Pydantic models used as the contract between adapter code and filters.
- Purpose: Contract for pipeline plugins.
- Examples: `aegisgate/filters/base.py`, implementations in `aegisgate/filters/*.py`
- Pattern: Name-based activation plus separate `process_request` and `process_response` hooks and lightweight reporting.
- Purpose: Deterministic ordered executor for request and response filters.
- Examples: `aegisgate/core/pipeline.py`, construction in `aegisgate/adapters/openai_compat/pipeline_runtime.py`
- Pattern: Sequential plugin chain with per-filter exception isolation and latency logging.
- Purpose: Stable storage handle across hot reload and backend swaps.
- Examples: `aegisgate/storage/kv.py`, `aegisgate/adapters/openai_compat/pipeline_runtime.py`, backend implementations in `aegisgate/storage/sqlite_store.py`, `aegisgate/storage/redis_store.py`, `aegisgate/storage/postgres_store.py`
- Pattern: Port-and-adapter storage abstraction with hot-swappable backend delegation.
- Purpose: Resolve active filters and risk thresholds from YAML policy plus feature flags and security level.
- Examples: `aegisgate/policies/policy_engine.py`, singleton usage in `aegisgate/adapters/openai_compat/router.py`
- Pattern: Cached file-backed policy resolution mutating `RequestContext`.
- Purpose: Bind public gateway tokens to upstream base URLs and compatibility metadata.
- Examples: `aegisgate/core/gw_tokens.py`, token rewrite logic in `aegisgate/core/gateway.py`
- Pattern: File-backed in-memory registry with atomic writes and optional synthesized local-port routes.
## Entry Points
- Location: `aegisgate/core/gateway.py`
- Triggers: `uvicorn aegisgate.core.gateway:app`, test client startup, Docker runtime.
- Responsibilities: Compose the app, attach middleware, register routers, initialize runtime services, and expose admin endpoints.
- Location: `aegisgate-local.py`, `scripts/local_launcher.py`
- Triggers: Direct CLI execution for local development.
- Responsibilities: Start the gateway with repository-local defaults.
- Location: `aegisgate/adapters/openai_compat/router.py`
- Triggers: `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, `/v1/{subpath}`
- Responsibilities: Protocol normalization, policy resolution, pipeline orchestration, upstream forwarding, confirmation handling, and response conversion.
- Location: `aegisgate/adapters/v2_proxy/router.py`
- Triggers: `/v2`, `/v2/{proxy_path}`
- Responsibilities: Target URL validation, generic HTTP proxying, request/response safety checks.
- Location: `aegisgate/adapters/relay_compat/router.py`
- Triggers: `/relay/generate`
- Responsibilities: Map relay payloads into chat-style requests and delegate into the main OpenAI-compatible execution path.
- Location: `aegisgate/core/gateway_ui_routes.py`
- Triggers: `register_ui_routes(app)` inside `aegisgate/core/gateway.py`
- Responsibilities: Add management HTML/API routes onto the shared FastAPI app.
## Error Handling
- Boundary-level rejections use `_blocked_response` from `aegisgate/core/gateway_auth.py` and return structured error payloads with `aegisgate` metadata.
- `aegisgate/core/pipeline.py` catches exceptions per filter, logs them, records an error report item, and continues to the next filter.
- Adapter-level upstream failures in `aegisgate/adapters/openai_compat/router.py` and `aegisgate/adapters/v2_proxy/router.py` are translated into JSON/SSE error responses rather than raw stack traces.
- Hot-reload callbacks in `aegisgate/core/hot_reload.py` mark the watcher as degraded instead of crashing the app.
## Cross-Cutting Concerns
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd:quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd:debug` for investigation and bug fixing
- `/gsd:execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd:profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
