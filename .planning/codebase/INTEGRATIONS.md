# External Integrations

**Analysis Date:** 2026-03-27

## APIs & External Services

**LLM / AI Upstreams:**
- Generic OpenAI-compatible upstreams - primary forwarding target for `/v1/chat/completions`, `/v1/responses`, and generic `/v1/*`
  - SDK/Client: `httpx` via `aegisgate/adapters/openai_compat/upstream.py`
  - Auth: client `Authorization` header is forwarded; gateway routing/auth uses `AEGIS_GATEWAY_KEY` or `config/aegis_gateway.key`
- Anthropic-compatible clients - supported on the inbound side through `/v1/messages` and compat bridge conversion
  - SDK/Client: protocol bridge code in `aegisgate/adapters/openai_compat/compat_bridge.py` and `aegisgate/adapters/openai_compat/mapper.py`
  - Auth: inbound client auth still uses gateway routing and forwarded upstream auth headers
- Arbitrary HTTP/HTTPS targets for v2 proxy - generic passthrough with response/request filtering
  - SDK/Client: `httpx` via `aegisgate/adapters/v2_proxy/router.py`
  - Auth: target URL comes from `x-target-url`; request auth headers are proxied except hop-by-hop and internal `x-aegis-*` headers
- Optional external semantic scoring service - used only when `AEGIS_SEMANTIC_SERVICE_URL` is configured
  - SDK/Client: `httpx` via `aegisgate/core/semantic.py`
  - Auth: no dedicated auth layer detected in code; rely on URL/network-level protection

**Container / reverse-proxy integration:**
- Caddy reverse proxy sidecar - internal trust bootstrap using generated proxy token
  - SDK/Client: shell bootstrap in `scripts/caddy-entrypoint.sh`
  - Auth: token file `config/aegis_proxy_token.key` injected into `X-Aegis-Proxy-Token`
- Docker-host routing - token-to-service or token-to-port forwarding for co-located upstream containers
  - SDK/Client: dynamic token injection in `aegisgate/core/gw_tokens.py`
  - Auth: routing configured with `AEGIS_DOCKER_UPSTREAMS`, `AEGIS_ENABLE_LOCAL_PORT_ROUTING`, and `AEGIS_LOCAL_PORT_ROUTING_HOST`

## Data Storage

**Databases:**
- SQLite (default)
  - Connection: `AEGIS_SQLITE_DB_PATH`
  - Client: stdlib `sqlite3` in `aegisgate/storage/sqlite_store.py`
- Redis (optional)
  - Connection: `AEGIS_REDIS_URL`, `AEGIS_REDIS_KEY_PREFIX`
  - Client: `redis` package in `aegisgate/storage/redis_store.py`
- PostgreSQL (optional)
  - Connection: `AEGIS_POSTGRES_DSN`, `AEGIS_POSTGRES_SCHEMA`
  - Client: `psycopg` in `aegisgate/storage/postgres_store.py`

**File Storage:**
- Local filesystem is a first-class runtime dependency
  - Config and policies: `config/.env`, `config/security_filters.yaml`, `config/gw_tokens.json`, `config/model_map.json`
  - Generated secrets: `config/aegis_gateway.key`, `config/aegis_proxy_token.key`, `config/aegis_fernet.key`
  - Logs: `logs/audit.jsonl`, `logs/dangerous_response_samples*.jsonl`
  - UI/runtime stats: `config/stats.json` with fallback to `.cache/aegisgate/stats.json`

**Caching:**
- In-process caches are used heavily
  - Nonce replay cache defaults to memory in `aegisgate/core/security_boundary.py`
  - Semantic results use in-memory LRU+TTL in `aegisgate/core/semantic.py`
  - Policy and rule reload caches exist in `aegisgate/policies/policy_engine.py` and `aegisgate/config/security_rules.py`
- Redis can also back nonce replay defense when `AEGIS_NONCE_CACHE_BACKEND=redis`

## Authentication & Identity

**Auth Provider:**
- Custom gateway auth
  - Implementation: `gateway-key` header/body verification, generated gateway secret file, and HMAC replay protection in `aegisgate/core/gateway_auth.py`, `aegisgate/core/gateway_keys.py`, and `aegisgate/core/security_boundary.py`

**Identity / Session:**
- Local admin UI session is cookie-based
  - Implementation: HMAC-signed session cookie `aegis_ui_session` with CSRF token in `aegisgate/core/gateway_auth.py`
- Tenant segregation is lightweight
  - Implementation: `x-tenant-id` setting and `tenant_id` fields in pending-confirmation storage in `aegisgate/config/settings.py` and all store backends under `aegisgate/storage/`

## Monitoring & Observability

**Error Tracking:**
- None detected as a dedicated SaaS integration

**Logs:**
- Application logs use the project logger and optional JSON formatting in `aegisgate/observability/logging.py`
- Audit events are written asynchronously to `AEGIS_AUDIT_LOG_PATH` by `aegisgate/core/audit.py`
- Dangerous response samples are optionally written asynchronously by `aegisgate/core/dangerous_response_log.py`

**Metrics:**
- Prometheus metrics are exposed at `/metrics` when `prometheus-client` is installed
  - Implementation: `aegisgate/observability/metrics.py` and mounting in `aegisgate/core/gateway.py`

**Tracing:**
- OpenTelemetry initialization is optional and auto-degrades when extras are missing
  - Implementation: `aegisgate/observability/tracing.py`
  - Export: OTLP gRPC exporter when installed; console exporter only when `AEGIS_OTEL_CONSOLE_EXPORTER=true`

## CI/CD & Deployment

**Hosting:**
- Primary supported deployment is self-hosted Docker Compose from `docker-compose.yml`
- Bare-metal/dev workflow is supported via `scripts/local_launcher.py` and direct Uvicorn startup

**CI Pipeline:**
- GitHub Actions CI in `.github/workflows/ci.yml`
  - Installs `.[dev,semantic]`
  - Runs pytest on Python 3.10 and 3.13
  - Runs pytest with coverage upload on Python 3.12

## Environment Configuration

**Required env vars:**
- `AEGIS_HOST`, `AEGIS_PORT` - listener binding from `aegisgate/config/settings.py`
- `AEGIS_UPSTREAM_BASE_URL` or token-based routing config - required to reach upstreams
- `AEGIS_STORAGE_BACKEND` plus one of `AEGIS_SQLITE_DB_PATH`, `AEGIS_REDIS_URL`, or `AEGIS_POSTGRES_DSN`
- `AEGIS_SECURITY_RULES_PATH` and policy files under `config/` or `aegisgate/policies/rules/`
- `AEGIS_ENABLE_REQUEST_HMAC_AUTH`, `AEGIS_REQUEST_HMAC_SECRET`, `AEGIS_TRUSTED_PROXY_IPS` - required only when enabling HMAC/reverse-proxy trust features
- `AEGIS_ENABLE_LOCAL_PORT_ROUTING`, `AEGIS_LOCAL_PORT_ROUTING_HOST`, `AEGIS_DOCKER_UPSTREAMS` - required for zero-registration local/container upstream routing
- `AEGIS_ENABLE_V2_PROXY`, `AEGIS_V2_TARGET_ALLOWLIST`, `AEGIS_V2_BLOCK_INTERNAL_TARGETS` - control generic proxy exposure
- `AEGIS_SEMANTIC_SERVICE_URL` - only required for external semantic service mode

**Secrets location:**
- File-based secrets are generated under `config/`: `config/aegis_gateway.key`, `config/aegis_proxy_token.key`, `config/aegis_fernet.key`
- Runtime env config is expected in `config/.env` (present in the repo workspace, contents not inspected)
- Docker Compose also supports injecting env vars via `docker-compose.yml`

## Webhooks & Callbacks

**Incoming:**
- None detected as webhook-style callbacks
- Exposed HTTP control/admin endpoints include:
  - `POST /__gw__/register`, `POST /__gw__/lookup`, `POST /__gw__/add`, `POST /__gw__/remove`, `POST /__gw__/unregister` through `aegisgate/core/gateway.py`
  - Local UI API under `/__ui__/api/*` through `aegisgate/core/gateway_ui_routes.py`

**Outgoing:**
- Upstream POST requests to configured LLM/provider endpoints via `aegisgate/adapters/openai_compat/upstream.py`
- Generic v2 proxy forwarding to `x-target-url` destinations via `aegisgate/adapters/v2_proxy/router.py`
- Optional OTLP span export from `aegisgate/observability/tracing.py`

## Protocol Adaptation

**Inbound protocols:**
- OpenAI Chat Completions and Responses APIs in `aegisgate/adapters/openai_compat/router.py`
- Anthropic Messages-compatible API in `aegisgate/adapters/openai_compat/router.py`
- Relay-style `/relay/generate` requests in `aegisgate/adapters/relay_compat/router.py`
- Generic HTTP proxy requests in `aegisgate/adapters/v2_proxy/router.py`

**Transformation rules:**
- Token path rewrite `/v1/__gw__/t/{token}/...` and `/v2/__gw__/t/{token}/...` is handled before routing in `aegisgate/core/gateway.py`
- Compat mode `openai_chat` converts Anthropic Messages to OpenAI Responses and back using `aegisgate/adapters/openai_compat/compat_bridge.py`
- Global and token-level model mapping is loaded from `config/model_map.json` and token entries in `config/gw_tokens.json`
- Filter modes `__redact` and `__passthrough` are injected from tokenized paths and applied in `aegisgate/adapters/openai_compat/router.py`

## Deployment Topology Notes

**Default compose wiring:**
- `docker-compose.yml` binds the gateway on `127.0.0.1:18080`
- It mounts `./config` twice, once to `/app/aegisgate/policies/rules` and once to `/app/config`, so runtime-edited config and policy files persist on the host
- It joins external networks `cliproxy_net` and `sub2api_net`; these are not created by the app and must already exist in the host Docker environment

**Safe operating guidance:**
- Use `config/.env.example` as the baseline and keep real values only in `config/.env`
- Persist `config/gw_tokens.json` and generated key files when deploying containers, or token routing and internal proxy trust will reset on restart
- Keep `/metrics` behind network controls; `README.md` and `config/README.md` note that it has no separate auth layer

---

*Integration audit: 2026-03-27*
