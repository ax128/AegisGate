# Architecture

**Analysis Date:** 2026-03-27

## Pattern Overview

**Overall:** Assembly-centric FastAPI monolith with protocol adapters, shared security pipeline, and file-backed runtime control.

**Key Characteristics:**
- `aegisgate/core/gateway.py` is the composition root: it creates the `FastAPI` app, mounts metrics and static UI assets, starts runtime services, and wires protocol routers.
- `aegisgate/adapters/*` owns protocol-facing behavior. `aegisgate/adapters/openai_compat/router.py` is the main execution surface; `aegisgate/adapters/v2_proxy/router.py` and `aegisgate/adapters/relay_compat/router.py` are parallel ingress paths with their own request handling rules.
- Security enforcement is pipeline-driven. `aegisgate/adapters/openai_compat/pipeline_runtime.py` constructs a `Pipeline` from concrete filters under `aegisgate/filters/`, while `aegisgate/policies/policy_engine.py` decides which filters are active per request.

## Layers

**Application Assembly Layer:**
- Purpose: Build the ASGI app, enforce outer boundary checks, start and stop runtime workers, and register non-business endpoints.
- Location: `aegisgate/core/gateway.py`
- Contains: FastAPI app creation, lifespan startup/shutdown, token path rewrite middleware, security boundary middleware, admin token management endpoints, root/health endpoints, and UI registration.
- Depends on: `aegisgate/adapters/*`, `aegisgate/core/*`, `aegisgate/config/settings.py`, `aegisgate/observability/*`, `aegisgate/storage/*`, `aegisgate/init_config.py`.
- Used by: `uvicorn aegisgate.core.gateway:app`, tests under `aegisgate/tests/test_gateway_*`.

**Protocol Adapter Layer:**
- Purpose: Convert inbound protocol payloads into internal request models, apply policy and pipeline logic, forward to upstreams, then map results back to client-facing protocol shapes.
- Location: `aegisgate/adapters/openai_compat/`, `aegisgate/adapters/v2_proxy/`, `aegisgate/adapters/relay_compat/`
- Contains: Route handlers, protocol mappers, compatibility bridges, SSE helpers, upstream HTTP forwarding helpers.
- Depends on: `aegisgate/core/context.py`, `aegisgate/core/models.py`, `aegisgate/core/confirmation*.py`, `aegisgate/core/semantic.py`, `aegisgate/policies/policy_engine.py`, `aegisgate/storage/offload.py`, `aegisgate/config/*`, `aegisgate/util/*`.
- Used by: `aegisgate/core/gateway.py`

**Pipeline Runtime Layer:**
- Purpose: Hold the shared store proxy and build thread-local `Pipeline` instances used by OpenAI-compatible routes.
- Location: `aegisgate/adapters/openai_compat/pipeline_runtime.py`, `aegisgate/core/pipeline.py`, `aegisgate/core/registry.py`
- Contains: `RuntimeStoreProxy`, thread-local pipeline cache, filter list assembly, sequential request/response execution, hot-reload invalidation.
- Depends on: `aegisgate/storage/__init__.py`, `aegisgate/filters/*`, `aegisgate/core/context.py`, `aegisgate/core/models.py`.
- Used by: `aegisgate/adapters/openai_compat/router.py`, `aegisgate/core/hot_reload.py`

**Security Filter Layer:**
- Purpose: Perform request redaction, request-side validation, response-side risk scoring, restoration, and output sanitization.
- Location: `aegisgate/filters/`
- Contains: `RedactionFilter`, `ExactValueRedactionFilter`, `RequestSanitizer`, `RagPoisonGuard`, `AnomalyDetector`, `PromptInjectionDetector`, `PrivilegeGuard`, `ToolCallGuard`, `RestorationFilter`, `PostRestoreGuard`, `OutputSanitizer`, plus `BaseFilter`.
- Depends on: `aegisgate/core/context.py`, `aegisgate/core/models.py`, `aegisgate/config/security_rules.py`, `aegisgate/storage/kv.py`, `aegisgate/util/*`.
- Used by: `aegisgate/adapters/openai_compat/pipeline_runtime.py`

**Runtime State and Storage Layer:**
- Purpose: Persist redaction mappings, pending confirmations, token registrations, audit data, and request stats.
- Location: `aegisgate/storage/`, `aegisgate/core/gw_tokens.py`, `aegisgate/core/audit.py`, `aegisgate/core/stats.py`
- Contains: `KVStore` abstraction and concrete backends, token-map file persistence, queued audit writer, stats collector with file persistence.
- Depends on: `aegisgate/config/settings.py`, `aegisgate/storage/crypto.py`, `aegisgate/util/logger.py`
- Used by: adapters, filters, `aegisgate/core/gateway.py`, UI routes.

**Configuration and Hot Reload Layer:**
- Purpose: Load runtime settings, policy YAML, redaction rules, feature flags, and watch selected files for reload.
- Location: `aegisgate/config/`, `aegisgate/core/hot_reload.py`, `aegisgate/init_config.py`
- Contains: global `settings`, security rule loaders, feature flags, runtime bootstrap copying of config files, file polling watcher, cache invalidation hooks.
- Depends on: filesystem, `aegisgate/adapters/openai_compat/router.py`, `aegisgate/adapters/openai_compat/pipeline_runtime.py`, `aegisgate/adapters/v2_proxy/router.py`.
- Used by: `aegisgate/core/gateway.py`, UI config endpoints, filter modules.

**Management UI Layer:**
- Purpose: Expose local-only admin pages and APIs for config editing, token management, key rotation, rule CRUD, stats, and restart actions.
- Location: `aegisgate/core/gateway_ui_routes.py`, `aegisgate/core/gateway_auth.py`, `aegisgate/core/gateway_ui_config.py`, static assets in `www/`
- Contains: login/logout, bootstrap/config/docs APIs, token CRUD, rules APIs, compose-file editing, restart endpoint, UI session and CSRF helpers.
- Depends on: `aegisgate/core/gateway.py`, `aegisgate/core/gw_tokens.py`, `aegisgate/config/settings.py`, `aegisgate/core/hot_reload.py`.
- Used by: `aegisgate/core/gateway.py`

## Data Flow

**OpenAI-Compatible Request Flow:**

1. Client enters `aegisgate/core/gateway.py` through `/v1/*`.
2. `GWTokenRewriteMiddleware` rewrites `/v1/__gw__/t/{token}...` into normal `/v1/...` paths and injects token-derived scope metadata such as upstream base, compatibility mode, and filter mode.
3. `security_boundary_middleware` enforces loopback/internal-network restrictions, admin endpoint limits, body-size checks, and optional HMAC replay protection before the route handler runs.
4. `aegisgate/adapters/openai_compat/router.py` validates payload size and shape, converts the payload into `InternalRequest` via `mapper.py`, creates `RequestContext`, resolves active filters through `PolicyEngine`, and applies filter-mode overrides.
5. `aegisgate/core/pipeline.py` executes request filters built by `aegisgate/adapters/openai_compat/pipeline_runtime.py`.
6. The adapter forwards the sanitized payload using `aegisgate/adapters/openai_compat/upstream.py`.
7. The adapter converts the upstream result into `InternalResponse`, runs response filters, attaches audit/security metadata, and maps the output back to Chat/Responses/Messages JSON or SSE.

**Token-Routed Request Flow:**

1. Token metadata is loaded from `config/gw_tokens.json` by `aegisgate/core/gw_tokens.py` during lifespan startup or hot reload.
2. `GWTokenRewriteMiddleware` resolves the token, or synthesizes one when local-port routing is enabled.
3. The middleware injects `request.scope["aegis_upstream_base"]`, `request.scope["aegis_token_authenticated"]`, and optional `compat`/`model_map` metadata.
4. All downstream route handlers consume the normalized scope instead of parsing token paths themselves.

**Anthropic Messages Compatibility Flow:**

1. `/v1/messages` enters `aegisgate/adapters/openai_compat/router.py`.
2. If `request.scope["aegis_compat"] == "openai_chat"`, `_messages_compat_openai_chat` converts the Messages payload into a Responses payload using `aegisgate/adapters/openai_compat/mapper.py`.
3. The code reuses the existing `/v1/responses` execution path.
4. The final output is converted back into Anthropic Messages format by `mapper.py` and `compat_bridge.py`.

**v2 Generic Proxy Flow:**

1. `/v2` or `/v2/{proxy_path}` enters `aegisgate/adapters/v2_proxy/router.py`.
2. The router validates `x-target-url`, applies SSRF/allowlist checks, and optionally redacts request content.
3. The router forwards the raw HTTP request with `httpx`.
4. Response content is scanned for obvious dangerous patterns before being streamed or returned.

**Management/UI Flow:**

1. `/__ui__/*` enters `security_boundary_middleware` first, where local-network restrictions, session checks, and CSRF validation are enforced.
2. `aegisgate/core/gateway_ui_routes.py` serves HTML from `www/` and exposes config/token/rules APIs.
3. Config updates write runtime files and invoke `aegisgate/core/hot_reload.py` reload functions to refresh in-memory state without process restart.

**State Management:**
- Request-scoped mutable state lives in `RequestContext` from `aegisgate/core/context.py`.
- Route-scoped gateway metadata lives in `request.state.security_boundary` and `request.scope`.
- Cross-request runtime state is either in memory with locking (`aegisgate/core/gw_tokens.py`, `aegisgate/core/stats.py`) or persisted through `KVStore` backends under `aegisgate/storage/`.

## Key Abstractions

**`RequestContext`:**
- Purpose: Per-request execution state shared by all filters and adapter logic.
- Examples: `aegisgate/core/context.py`, created throughout `aegisgate/adapters/openai_compat/router.py`
- Pattern: Mutable dataclass carrying enabled filters, risk score, dispositions, report items, redaction mappings, and tenant metadata.

**`InternalRequest` / `InternalResponse` / `InternalMessage`:**
- Purpose: Internal transport model independent from any one upstream or client protocol.
- Examples: `aegisgate/core/models.py`, mapper functions in `aegisgate/adapters/openai_compat/mapper.py`, relay conversion in `aegisgate/adapters/relay_compat/mapper.py`
- Pattern: Pydantic models used as the contract between adapter code and filters.

**`BaseFilter`:**
- Purpose: Contract for pipeline plugins.
- Examples: `aegisgate/filters/base.py`, implementations in `aegisgate/filters/*.py`
- Pattern: Name-based activation plus separate `process_request` and `process_response` hooks and lightweight reporting.

**`Pipeline`:**
- Purpose: Deterministic ordered executor for request and response filters.
- Examples: `aegisgate/core/pipeline.py`, construction in `aegisgate/adapters/openai_compat/pipeline_runtime.py`
- Pattern: Sequential plugin chain with per-filter exception isolation and latency logging.

**`RuntimeStoreProxy` / `KVStore`:**
- Purpose: Stable storage handle across hot reload and backend swaps.
- Examples: `aegisgate/storage/kv.py`, `aegisgate/adapters/openai_compat/pipeline_runtime.py`, backend implementations in `aegisgate/storage/sqlite_store.py`, `aegisgate/storage/redis_store.py`, `aegisgate/storage/postgres_store.py`
- Pattern: Port-and-adapter storage abstraction with hot-swappable backend delegation.

**`PolicyEngine`:**
- Purpose: Resolve active filters and risk thresholds from YAML policy plus feature flags and security level.
- Examples: `aegisgate/policies/policy_engine.py`, singleton usage in `aegisgate/adapters/openai_compat/router.py`
- Pattern: Cached file-backed policy resolution mutating `RequestContext`.

**Gateway Token Mapping:**
- Purpose: Bind public gateway tokens to upstream base URLs and compatibility metadata.
- Examples: `aegisgate/core/gw_tokens.py`, token rewrite logic in `aegisgate/core/gateway.py`
- Pattern: File-backed in-memory registry with atomic writes and optional synthesized local-port routes.

## Entry Points

**Main ASGI app:**
- Location: `aegisgate/core/gateway.py`
- Triggers: `uvicorn aegisgate.core.gateway:app`, test client startup, Docker runtime.
- Responsibilities: Compose the app, attach middleware, register routers, initialize runtime services, and expose admin endpoints.

**Local launcher:**
- Location: `aegisgate-local.py`, `scripts/local_launcher.py`
- Triggers: Direct CLI execution for local development.
- Responsibilities: Start the gateway with repository-local defaults.

**OpenAI-compatible ingress:**
- Location: `aegisgate/adapters/openai_compat/router.py`
- Triggers: `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, `/v1/{subpath}`
- Responsibilities: Protocol normalization, policy resolution, pipeline orchestration, upstream forwarding, confirmation handling, and response conversion.

**Generic HTTP ingress:**
- Location: `aegisgate/adapters/v2_proxy/router.py`
- Triggers: `/v2`, `/v2/{proxy_path}`
- Responsibilities: Target URL validation, generic HTTP proxying, request/response safety checks.

**Relay ingress:**
- Location: `aegisgate/adapters/relay_compat/router.py`
- Triggers: `/relay/generate`
- Responsibilities: Map relay payloads into chat-style requests and delegate into the main OpenAI-compatible execution path.

**UI registration point:**
- Location: `aegisgate/core/gateway_ui_routes.py`
- Triggers: `register_ui_routes(app)` inside `aegisgate/core/gateway.py`
- Responsibilities: Add management HTML/API routes onto the shared FastAPI app.

## Error Handling

**Strategy:** Fail closed at the outer boundary, but isolate filter and hot-reload failures so one bad filter or one bad callback does not crash the whole process.

**Patterns:**
- Boundary-level rejections use `_blocked_response` from `aegisgate/core/gateway_auth.py` and return structured error payloads with `aegisgate` metadata.
- `aegisgate/core/pipeline.py` catches exceptions per filter, logs them, records an error report item, and continues to the next filter.
- Adapter-level upstream failures in `aegisgate/adapters/openai_compat/router.py` and `aegisgate/adapters/v2_proxy/router.py` are translated into JSON/SSE error responses rather than raw stack traces.
- Hot-reload callbacks in `aegisgate/core/hot_reload.py` mark the watcher as degraded instead of crashing the app.

## Cross-Cutting Concerns

**Logging:** Structured logging is used across modules through `aegisgate/util/logger.py` and observability setup in `aegisgate/observability/logging.py`.

**Validation:** Input validation is split across several layers: request/body/network limits in `aegisgate/core/gateway.py`, payload shape and route-specific limits in `aegisgate/adapters/openai_compat/router.py`, policy/rule validation in `aegisgate/policies/policy_engine.py`, and security-rule matching in `aegisgate/filters/*`.

**Authentication:** Outer request authentication is handled in `aegisgate/core/gateway.py` through token-path auth, optional proxy-token auth, and optional HMAC replay defense. UI authentication and CSRF protection live in `aegisgate/core/gateway_auth.py`.

**Observability:** Metrics and tracing are initialized in `aegisgate/core/gateway.py` using `aegisgate/observability/metrics.py` and `aegisgate/observability/tracing.py`. Request outcomes are also persisted into `aegisgate/core/stats.py` and `aegisgate/core/audit.py`.

**Runtime Reloadability:** Mutable config and policy files are watched by `aegisgate/core/hot_reload.py`; adapters and pipeline caches expose explicit reload hooks so settings changes propagate without process restart.

**Dependency Reality:** The current package is not a clean onion architecture. `aegisgate/core/gateway.py` and `aegisgate/core/hot_reload.py` intentionally import adapter modules to orchestrate them, while adapters import many `core/*` modules. Preserve that pattern for orchestration code, but keep new protocol-specific behavior inside `aegisgate/adapters/*` and new reusable security/business logic inside `aegisgate/core/*`, `aegisgate/filters/*`, or `aegisgate/storage/*`.

---

*Architecture analysis: 2026-03-27*
