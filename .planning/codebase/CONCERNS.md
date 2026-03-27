# Codebase Concerns

**Analysis Date:** 2026-03-27

## Tech Debt

**OpenAI-compatible request path is concentrated in a single router module:**
- Issue: `aegisgate/adapters/openai_compat/router.py` mixes request parsing, protocol mapping, filter orchestration, semantic review, confirmation replay, upstream forwarding, streaming transforms, and audit/report assembly in one 5k+ line module.
- Files: `aegisgate/adapters/openai_compat/router.py`, `aegisgate/adapters/openai_compat/compat_bridge.py`, `aegisgate/adapters/openai_compat/upstream.py`
- Impact: Small behavior changes have a wide regression surface, local reasoning is expensive, and exception handling is duplicated across many branches.
- Fix approach: Split by lifecycle boundary: request normalization, pipeline execution, confirmation persistence/replay, upstream transport, and streaming/event adaptation. Keep route handlers thin and move branch-heavy helpers behind focused modules with direct tests.

**Gateway assembly still carries multiple operational roles:**
- Issue: `aegisgate/core/gateway.py` remains a large assembly point for startup/shutdown, middleware enforcement, token-path rewriting, request observability, admin endpoints, and UI route registration.
- Files: `aegisgate/core/gateway.py`, `aegisgate/core/gateway_ui_routes.py`, `aegisgate/core/gateway_auth.py`
- Impact: Middleware, admin API, and UI security changes interact indirectly, increasing the chance of boundary regressions.
- Fix approach: Separate middleware/auth concerns from admin route registration and lifecycle wiring. Keep `aegisgate/core/gateway.py` as composition only.

**Runtime dependency reload keeps retired backends alive until shutdown:**
- Issue: `RuntimeStoreProxy.swap()` appends old stores to `_retired_backends`, and `reload_settings()` triggers `reload_runtime_dependencies()` even for broad config edits. Retired stores are only closed in `RuntimeStoreProxy.close()`.
- Files: `aegisgate/adapters/openai_compat/pipeline_runtime.py`, `aegisgate/core/hot_reload.py`, `aegisgate/core/gateway_ui_routes.py`
- Impact: Repeated hot-reload or UI config edits can accumulate old SQLite/Redis/Postgres clients and increase memory/socket usage until process restart.
- Fix approach: Close superseded backends after a bounded grace window, or only rebuild the store when storage-related settings actually change.

## Known Bugs

**Built-in semantic analyzer is not wired into the runtime path:**
- Symptoms: `AEGIS_ENABLE_SEMANTIC_MODULE` defaults to enabled, but gray-zone review uses `SemanticServiceClient` with `AEGIS_SEMANTIC_SERVICE_URL` defaulting to empty. The local `SemanticAnalyzer` class exists but is not instantiated by runtime code.
- Files: `aegisgate/config/settings.py`, `aegisgate/core/semantic.py`, `aegisgate/adapters/openai_compat/router.py`
- Trigger: Default deployment with semantic module enabled and no external semantic service configured.
- Workaround: Set `AEGIS_SEMANTIC_SERVICE_URL` to a working service, or explicitly disable semantic review until the local analyzer is connected to runtime flow.

**Semantic service failures degrade to fail-open behavior inside gray-zone review:**
- Symptoms: Timeout, circuit-open, unavailable, or unconfigured semantic states only append degraded tags/actions and return without increasing `ctx.risk_score`.
- Files: `aegisgate/adapters/openai_compat/router.py`, `aegisgate/core/semantic.py`
- Trigger: External semantic service outage, timeout, misconfiguration, or breaker-open state while a request sits in the gray zone.
- Workaround: Rely on regex/filter pipeline only, or run a healthy semantic service. There is no stricter fallback mode in the current request path.

## Security Considerations

**UI key endpoints return raw secret material over HTTP responses:**
- Risk: `local_ui_key_get()` returns the full gateway/proxy/Fernet key, and `local_ui_key_rotate()` returns the new key in the JSON body.
- Files: `aegisgate/core/gateway_ui_routes.py`, `aegisgate/core/gateway_auth.py`
- Current mitigation: UI access is restricted to loopback/internal network, authenticated by session cookie, and protected by CSRF for state-changing API calls.
- Recommendations: Treat key display as one-time reveal only, avoid returning the Fernet key at all, mask existing values by default, and add explicit audit entries for key read/rotate operations.

**v2 proxy defaults allow outbound access to any public host once a token route is obtained:**
- Risk: `_is_v2_target_allowlisted()` returns `True` when `AEGIS_V2_TARGET_ALLOWLIST` is empty, so the generic proxy can reach any non-internal host reachable from the gateway.
- Files: `aegisgate/config/settings.py`, `aegisgate/adapters/v2_proxy/router.py`, `aegisgate/core/gateway.py`
- Current mitigation: v2 requires a token-authenticated route and blocks internal/private targets when `AEGIS_V2_BLOCK_INTERNAL_TARGETS=true`.
- Recommendations: Default `AEGIS_V2_TARGET_ALLOWLIST` to explicit domains in production, document empty-allowlist risk in operator docs, and add a startup warning when v2 is enabled with no allowlist.

**Config and compose editing from the UI changes live runtime state with broad privileges:**
- Risk: `local_ui_update_config()` writes `.env`, `local_ui_compose_put()` writes compose YAML, and `local_ui_restart()` can terminate the current process.
- Files: `aegisgate/core/gateway_ui_routes.py`, `aegisgate/core/gateway_ui_config.py`, `aegisgate/core/hot_reload.py`
- Current mitigation: Local-only UI boundary plus session/CSRF checks.
- Recommendations: Add per-operation audit logging, split read-only vs privileged UI roles, and require a second confirmation step for restart and config mutations.

## Performance Bottlenecks

**Redis pending-confirmation queries rely on scan-style iteration:**
- Problem: `get_latest_pending_confirmation()`, `get_single_pending_confirmation()`, and the stale `executing` recovery path iterate sorted sets or `SCAN` through broad key patterns instead of using precise secondary indexes.
- Files: `aegisgate/storage/redis_store.py`
- Cause: Session lookups are implemented as repeated `zrevrange`/`scan` passes, and stale execution recovery scans `aegisgate:pending:*`, which also matches non-hash keys and depends on exception-based skipping.
- Improvement path: Maintain explicit per-status indexes, narrow SCAN patterns, and move stale-executing recovery into a dedicated sorted set keyed by `updated_at`.

**Postgres and SQLite stores open a fresh connection for nearly every operation:**
- Problem: `_connect()` is called per request path for CRUD operations, and there is no connection pool or async driver.
- Files: `aegisgate/storage/postgres_store.py`, `aegisgate/storage/sqlite_store.py`, `aegisgate/storage/offload.py`
- Cause: Storage methods wrap each operation in a new connection context and rely on a small offload thread pool (`max_workers=4`).
- Improvement path: Introduce a bounded connection pool for Postgres, reuse SQLite connections where safe, and size offload workers based on backend latency and expected concurrency.

**Audit/sample logging can fall back into synchronous request-path writes under backpressure:**
- Problem: When in-memory queues fill, `write_audit()` and `write_dangerous_response_sample()` write directly to disk on the caller path.
- Files: `aegisgate/core/audit.py`, `aegisgate/core/dangerous_response_log.py`, `aegisgate/core/background_worker.py`
- Cause: Queue size is fixed at 10,000, and overflow handling chooses sync append instead of shedding or batching load.
- Improvement path: Emit drop counters or bounded sampling under pressure, and keep disk I/O off the request path even when queues saturate.

## Fragile Areas

**Hot-reload crosses config, pipeline, semantic client, and storage boundaries at once:**
- Files: `aegisgate/core/hot_reload.py`, `aegisgate/adapters/openai_compat/pipeline_runtime.py`, `aegisgate/adapters/openai_compat/router.py`
- Why fragile: `reload_settings()` mutates the global settings object in place, refreshes feature flags, rebuilds runtime dependencies, and reconfigures semantic behavior in one broad path with many broad `except Exception` fallbacks.
- Safe modification: Change one reload target at a time, preserve current reload ordering, and verify startup reload, UI config reload, and watcher-triggered reload separately.
- Test coverage: `aegisgate/tests/test_hot_reload.py`, `aegisgate/tests/test_hot_reload_unit.py`, and `aegisgate/tests/test_gateway_observability_startup.py` cover baseline flows, but not repeated reload resource accumulation or store backend swaps.

**UI management layer has high privilege and mixed responsibilities:**
- Files: `aegisgate/core/gateway_ui_routes.py`, `aegisgate/core/gateway_auth.py`
- Why fragile: The same module exposes token CRUD, config writes, rules editing, secret rotation, compose writes, and process restart, with many closure-scoped helpers and repeated JSON parsing/error handling.
- Safe modification: Isolate secret management, file-editing, and restart endpoints into separate modules with dedicated auth/audit helpers.
- Test coverage: `aegisgate/tests/test_gateway_ui_routes.py` covers config updates, rule CRUD, and part of key rotation, but does not directly exercise raw key retrieval, restart side effects, or negative paths for compose/rules privilege boundaries.

**Security boundary logic depends on request path classification and scope mutation:**
- Files: `aegisgate/core/gateway.py`, `aegisgate/core/gateway_network.py`, `aegisgate/core/security_boundary.py`
- Why fragile: Token rewrite, loopback restrictions, proxy-token auth, HMAC verification, UI restrictions, and route-specific exemptions all live in a single middleware path.
- Safe modification: When editing boundary behavior, check v1 token routes, direct `/v1` default-upstream access, v2 token routes, admin endpoints, and UI paths as separate cases.
- Test coverage: `aegisgate/tests/test_gateway_boundary_access.py`, `aegisgate/tests/test_gateway_boundary_security.py`, and `aegisgate/tests/test_security_boundary*.py` cover major allow/block paths, but not every middleware interaction with hot-reload or UI secret operations.

## Scaling Limits

**Store offload concurrency is capped at four worker threads:**
- Current capacity: `aegisgate/storage/offload.py` uses `ThreadPoolExecutor(max_workers=4)` for all blocking store work.
- Limit: Slow Redis/Postgres/SQLite operations can serialize confirmation persistence, replay lookups, and prune work behind four workers, increasing response latency under burst traffic.
- Scaling path: Use backend-specific pools and separate latency-sensitive reads from background pruning/maintenance work.

**Admin and UI rate limiting is in-memory and single-process:**
- Current capacity: `_AdminRateLimiter` tracks up to 50,000 buckets in-process and applies per-process decisions only.
- Limit: Multi-instance deployments do not share rate-limit state, and flood traffic can exhaust the bucket cap and reject new clients indiscriminately.
- Scaling path: Move admin/UI rate limits to Redis or another shared store with explicit eviction metrics.

## Dependencies at Risk

**Optional storage backends carry operational risk because they are lightly exercised in tests:**
- Risk: `redis` and `psycopg` backends are selected in production code, but test coverage is centered on the default path and mocks rather than backend-specific integration behavior.
- Impact: Runtime-only issues in Redis/Postgres persistence, stale confirmation recovery, or backend swapping can escape CI.
- Migration plan: Add backend-specific integration suites for `RedisKVStore`, `PostgresKVStore`, and `create_store()` selection, then decide whether all three backends remain worth supporting.

## Missing Critical Features

**No strict fallback policy for semantic degradation:**
- Problem: Semantic timeout/unavailable/circuit-open states only annotate the request context and continue with the existing risk score.
- Blocks: Operators cannot choose fail-closed behavior for gray-zone requests when the semantic dependency is degraded.

**No bounded lifecycle management for hot-reload-retired backends:**
- Problem: Runtime store swaps intentionally retain old backends until process shutdown, but there is no pruning or health metric for retained resources.
- Blocks: Long-running processes cannot safely absorb frequent config edits without gradual resource growth.

## Test Coverage Gaps

**Storage backend behavior is largely untested outside the default path:**
- What's not tested: Direct CRUD semantics, stale confirmation recovery, pruning, and conflict/update behavior of `SqliteKVStore`, `RedisKVStore`, `PostgresKVStore`, and `create_store()`.
- Files: `aegisgate/storage/sqlite_store.py`, `aegisgate/storage/redis_store.py`, `aegisgate/storage/postgres_store.py`, `aegisgate/storage/__init__.py`
- Risk: Data-loss, duplicate-confirmation, or backend-specific performance regressions can land unnoticed.
- Priority: High

**UI secret-management endpoints lack focused tests:**
- What's not tested: Raw key retrieval from `GET /__ui__/api/keys/{key_type}`, non-gateway key rotation responses, and restart endpoint side effects.
- Files: `aegisgate/core/gateway_ui_routes.py`, `aegisgate/tests/test_gateway_ui_routes.py`
- Risk: Secret exposure and high-impact admin actions can change behavior without CI catching it.
- Priority: High

**Runtime reload/resource-retention behavior is not verified:**
- What's not tested: Repeated `reload_settings()` cycles, `RuntimeStoreProxy._retired_backends` growth, and backend closure timing across hot-reload.
- Files: `aegisgate/core/hot_reload.py`, `aegisgate/adapters/openai_compat/pipeline_runtime.py`
- Risk: Memory/socket leaks emerge only in long-lived environments.
- Priority: High

**Overall enforced coverage remains low for a security-sensitive gateway:**
- What's not tested: The repository enforces `fail_under = 50`, leaving wide room for unexecuted branches in high-risk modules.
- Files: `pyproject.toml`, `aegisgate/adapters/openai_compat/router.py`, `aegisgate/core/gateway.py`
- Risk: Security boundary and streaming regressions can pass CI with substantial uncovered code.
- Priority: Medium

---

*Concerns audit: 2026-03-27*
