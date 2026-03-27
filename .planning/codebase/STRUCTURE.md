# Codebase Structure

**Analysis Date:** 2026-03-27

## Directory Layout

```text
[project-root]/
├── aegisgate/                 # Python package: gateway, adapters, filters, config, storage, tests
├── config/                    # Runtime data and operator-managed config files
├── scripts/                   # Local launcher, deploy helpers, training scripts
├── www/                       # Static admin UI assets served by FastAPI
├── .github/workflows/         # CI pipeline
├── docker-compose.yml         # Local/container orchestration
├── Dockerfile                 # Image build
├── pyproject.toml             # Package metadata, dependencies, pytest/coverage config
└── README.md                  # Operator-facing usage and architecture overview
```

## Directory Purposes

**`aegisgate/`:**
- Purpose: All shipped Python source code.
- Contains: adapters, app assembly, filters, config loaders, observability, storage, utilities, and tests.
- Key files: `aegisgate/core/gateway.py`, `aegisgate/config/settings.py`, `aegisgate/adapters/openai_compat/router.py`, `aegisgate/tests/`

**`aegisgate/adapters/`:**
- Purpose: Protocol-facing entry logic and upstream transport helpers.
- Contains: `openai_compat`, `v2_proxy`, `relay_compat`.
- Key files: `aegisgate/adapters/openai_compat/router.py`, `aegisgate/adapters/openai_compat/upstream.py`, `aegisgate/adapters/v2_proxy/router.py`, `aegisgate/adapters/relay_compat/router.py`

**`aegisgate/adapters/openai_compat/`:**
- Purpose: Main request execution path for `/v1/*`.
- Contains: route handlers, protocol mappers, payload compatibility helpers, stream handling, upstream HTTP helpers, sanitizer helpers, runtime pipeline/store binding.
- Key files: `aegisgate/adapters/openai_compat/router.py`, `aegisgate/adapters/openai_compat/pipeline_runtime.py`, `aegisgate/adapters/openai_compat/mapper.py`, `aegisgate/adapters/openai_compat/compat_bridge.py`, `aegisgate/adapters/openai_compat/stream_utils.py`

**`aegisgate/adapters/v2_proxy/`:**
- Purpose: Generic HTTP proxy path separate from the OpenAI-compatible pipeline.
- Contains: one large route module with request validation, SSRF defense, redaction helpers, and response filtering.
- Key files: `aegisgate/adapters/v2_proxy/router.py`

**`aegisgate/adapters/relay_compat/`:**
- Purpose: Relay protocol shim that reuses chat execution logic.
- Contains: relay payload mapping and a thin router.
- Key files: `aegisgate/adapters/relay_compat/router.py`, `aegisgate/adapters/relay_compat/mapper.py`

**`aegisgate/config/`:**
- Purpose: Runtime settings and file-backed rule/config loaders.
- Contains: `Settings`, feature flags, security level helpers, redaction config, rule loading logic.
- Key files: `aegisgate/config/settings.py`, `aegisgate/config/security_rules.py`, `aegisgate/config/feature_flags.py`, `aegisgate/config/redact_values.py`

**`aegisgate/core/`:**
- Purpose: Shared application logic and composition code that is not tied to one external protocol.
- Contains: FastAPI assembly, middleware, confirmation flow, gateway auth/network helpers, token registry, models, pipeline, semantic analysis, stats, audit, hot reload.
- Key files: `aegisgate/core/gateway.py`, `aegisgate/core/context.py`, `aegisgate/core/models.py`, `aegisgate/core/pipeline.py`, `aegisgate/core/gw_tokens.py`, `aegisgate/core/hot_reload.py`

**`aegisgate/filters/`:**
- Purpose: Security plugins used by the OpenAI-compatible request/response pipeline.
- Contains: one filter per file plus `BaseFilter`.
- Key files: `aegisgate/filters/base.py`, `aegisgate/filters/redaction.py`, `aegisgate/filters/request_sanitizer.py`, `aegisgate/filters/injection_detector.py`, `aegisgate/filters/sanitizer.py`

**`aegisgate/models/`:**
- Purpose: Packaged model artifacts used by runtime code.
- Contains: TF-IDF vectorizer and classifier data files.
- Key files: `aegisgate/models/tfidf/vectorizer.joblib`, `aegisgate/models/tfidf/classifier.joblib`

**`aegisgate/observability/`:**
- Purpose: Logging, metrics, and tracing setup.
- Contains: logger wiring, Prometheus endpoint factory, trace initialization.
- Key files: `aegisgate/observability/logging.py`, `aegisgate/observability/metrics.py`, `aegisgate/observability/tracing.py`

**`aegisgate/policies/`:**
- Purpose: Policy engine and packaged YAML policies.
- Contains: policy resolution code and rule files.
- Key files: `aegisgate/policies/policy_engine.py`, `aegisgate/policies/rules/default.yaml`, `aegisgate/policies/rules/strict.yaml`, `aegisgate/policies/rules/permissive.yaml`, `aegisgate/policies/rules/security_filters.yaml`

**`aegisgate/storage/`:**
- Purpose: Persistence ports and backend implementations.
- Contains: `KVStore` abstraction, backend selector, SQLite/Redis/Postgres implementations, encryption helpers, async offload helpers.
- Key files: `aegisgate/storage/kv.py`, `aegisgate/storage/__init__.py`, `aegisgate/storage/sqlite_store.py`, `aegisgate/storage/redis_store.py`, `aegisgate/storage/postgres_store.py`

**`aegisgate/tests/`:**
- Purpose: Pytest suite organized mostly by module or feature surface.
- Contains: gateway boundary tests, router tests, filter tests, storage tests, config tests, hot-reload tests.
- Key files: `aegisgate/tests/test_gateway_boundary_access.py`, `aegisgate/tests/test_openai_pipeline_runtime.py`, `aegisgate/tests/test_v2_proxy_router.py`, `aegisgate/tests/test_relay_router.py`

**`aegisgate/util/`:**
- Purpose: Reusable helpers with low-level, cross-module responsibilities.
- Contains: logging wrapper, masking, whitelist normalization, risk scoring, base64 detection, debug excerpt helpers.
- Key files: `aegisgate/util/logger.py`, `aegisgate/util/masking.py`, `aegisgate/util/redaction_whitelist.py`, `aegisgate/util/risk_scoring.py`

**`config/`:**
- Purpose: Runtime configuration and generated secrets/state, not application source.
- Contains: `.env`, key files, `gw_tokens.json`, `model_map.json`, runtime marker files, example config.
- Key files: `config/.env.example`, `config/gw_tokens.json`, `config/gw_tokens.json.example`, `config/model_map.json`, `config/security_filters.yaml`

**`scripts/`:**
- Purpose: Development and deployment utilities outside the package runtime path.
- Contains: local launcher, caddy entrypoint, redeploy helper, TF-IDF training script.
- Key files: `scripts/local_launcher.py`, `scripts/caddy-entrypoint.sh`, `scripts/redeploy.sh`, `scripts/train_tfidf.py`

**`www/`:**
- Purpose: Static HTML/JS/CSS for the built-in admin console.
- Contains: entry HTML and bundled frontend assets.
- Key files: `www/index.html`, `www/login.html`, `www/assets/app.js`, `www/assets/app.css`, `www/assets/login.js`

## Key File Locations

**Entry Points:**
- `aegisgate/core/gateway.py`: Main FastAPI application assembly and middleware chain.
- `aegisgate-local.py`: Local CLI launcher entrypoint.
- `aegisgate/adapters/openai_compat/router.py`: `/v1/*` protocol ingress.
- `aegisgate/adapters/v2_proxy/router.py`: `/v2/*` generic proxy ingress.
- `aegisgate/adapters/relay_compat/router.py`: `/relay/generate` ingress.

**Configuration:**
- `pyproject.toml`: Package metadata, dependency sets, pytest config, coverage config.
- `aegisgate/config/settings.py`: Typed environment-backed settings singleton.
- `aegisgate/policies/rules/*.yaml`: Packaged policy and security rule sources.
- `aegisgate/init_config.py`: Bootstrap logic for copying defaults and validating runtime paths.
- `.github/workflows/ci.yml`: CI test matrix.

**Core Logic:**
- `aegisgate/core/context.py`: Request execution context.
- `aegisgate/core/models.py`: Internal request/response/message models.
- `aegisgate/core/pipeline.py`: Sequential filter executor.
- `aegisgate/adapters/openai_compat/pipeline_runtime.py`: Shared store and pipeline factory.
- `aegisgate/policies/policy_engine.py`: Policy-to-filter activation resolution.
- `aegisgate/core/gw_tokens.py`: Token registry and file persistence.

**Testing:**
- `aegisgate/tests/`: All tracked pytest suites.
- `aegisgate/tests/test_gateway_boundary_access.py`: Outer security boundary behavior.
- `aegisgate/tests/test_openai_pipeline_runtime.py`: Pipeline assembly and cache lifecycle.
- `aegisgate/tests/test_v2_proxy_router.py`: Generic proxy routing and SSRF checks.
- `aegisgate/tests/test_relay_router.py`: Relay adapter delegation.

## Naming Conventions

**Files:**
- `snake_case.py` for Python modules: `aegisgate/core/security_boundary.py`, `aegisgate/filters/request_sanitizer.py`
- `test_*.py` for tests: `aegisgate/tests/test_pipeline.py`
- Uppercase markdown docs at repo root for operator-facing guides: `README.md`, `WEBUI-QUICKSTART.md`

**Directories:**
- Package directories are lowercase and responsibility-based: `aegisgate/core`, `aegisgate/storage`, `aegisgate/observability`
- Protocol variants live as subpackages under `aegisgate/adapters/`: `openai_compat`, `relay_compat`, `v2_proxy`

## Where to Add New Code

**New OpenAI-compatible behavior:**
- Primary code: `aegisgate/adapters/openai_compat/`
- Tests: `aegisgate/tests/test_streaming_router.py`, `aegisgate/tests/test_upstream_routing.py`, or a new focused `aegisgate/tests/test_*.py` near the affected behavior.

**New protocol adapter:**
- Implementation: `aegisgate/adapters/<protocol_name>/`
- Integration point: register its router in `aegisgate/core/gateway.py`
- Shared protocol-neutral helpers: put them in `aegisgate/core/` or `aegisgate/util/`, not inside another adapter package.

**New security filter:**
- Implementation: `aegisgate/filters/<filter_name>.py`
- Pipeline registration: `aegisgate/adapters/openai_compat/pipeline_runtime.py`
- Policy activation: add the filter name to the relevant YAML under `aegisgate/policies/rules/` and ensure feature-flag support in `aegisgate/config/feature_flags.py` if needed.

**New runtime config or rule loader:**
- Typed setting: `aegisgate/config/settings.py`
- Reload hook: `aegisgate/core/hot_reload.py`
- UI exposure, if operator-editable: `aegisgate/core/gateway_ui_config.py` and `aegisgate/core/gateway_ui_routes.py`

**New shared business/security logic:**
- Request-scoped execution logic: `aegisgate/core/`
- Persistence logic: `aegisgate/storage/`
- Low-level helper without external side effects: `aegisgate/util/`

**New UI management endpoint:**
- HTTP route: `aegisgate/core/gateway_ui_routes.py`
- Auth/session helpers, if reused: `aegisgate/core/gateway_auth.py`
- Static assets: `www/`

**New runtime-persisted data file:**
- Operator config or state: `config/`
- Do not place mutable runtime files under `aegisgate/` unless they are packaged artifacts like `aegisgate/models/tfidf/*.joblib`.

## Module Boundaries

**Composition root boundary:**
- `aegisgate/core/gateway.py` may import adapters, observability, storage, and gateway helper modules.
- Other `aegisgate/core/*` modules should stay reusable and avoid becoming second composition roots.

**Adapter boundary:**
- Modules under `aegisgate/adapters/*` may import `aegisgate/core/*`, `aegisgate/config/*`, `aegisgate/storage/*`, and `aegisgate/util/*`.
- Keep protocol-specific payload mapping, HTTP forwarding details, and stream-shape conversion inside the adapter package that owns that protocol.

**Filter boundary:**
- Modules under `aegisgate/filters/*` should depend on `RequestContext`, internal models, config loaders, and storage ports.
- Do not import FastAPI request objects into filter code; FastAPI stays at the adapter/core boundary.

**Storage boundary:**
- Depend on the abstract port in `aegisgate/storage/kv.py` from filters and adapter runtime code.
- Backend-specific code belongs in `aegisgate/storage/sqlite_store.py`, `aegisgate/storage/redis_store.py`, or `aegisgate/storage/postgres_store.py`.

**Runtime-data boundary:**
- `config/`, `logs/`, `.cache/`, and generated key files are operational data, not source modules.
- Future refactors should avoid importing from `config/` directly; use `aegisgate/config/settings.py` or dedicated loaders instead.

## Special Directories

**`config/`:**
- Purpose: Operator-managed config and generated runtime secrets/state.
- Generated: Partly yes. Files such as `config/.env`, `config/aegis_gateway.key`, `config/aegis_proxy_token.key`, and `config/.admin_initialized` are runtime-generated or mutated.
- Committed: Mixed. Examples and docs are committed; live secrets/state must not be treated as source of truth in code changes.

**`www/`:**
- Purpose: Static admin console bundle served by the FastAPI app.
- Generated: No evidence of a separate frontend build pipeline in this repository snapshot; committed as checked-in assets.
- Committed: Yes.

**`aegisgate/models/tfidf/`:**
- Purpose: Packaged ML artifacts for local semantic classification.
- Generated: Yes, by training workflow such as `scripts/train_tfidf.py`.
- Committed: Yes.

**`build/`, `dist/`, `aegisgate.egg-info/`:**
- Purpose: Packaging artifacts.
- Generated: Yes.
- Committed: Present in the workspace snapshot, but treat them as derived artifacts rather than authoritative source.

**`.planning/codebase/`:**
- Purpose: Generated repository maps used by later planning/execution commands.
- Generated: Yes.
- Committed: Intended to be committed as planning artifacts.

**`logs/`:**
- Purpose: Runtime database, audit logs, and dangerous-response samples.
- Generated: Yes.
- Committed: No source code should depend on committed contents here.

---

*Structure analysis: 2026-03-27*
