# AegisGate

> **English** | **[中文](README_zh.md)**

**Open-source security gateway for LLM API calls** — sits between your AI agents/apps and upstream LLM providers, enforcing security policies on both request and response sides.

## What is AegisGate?

AegisGate is a self-hosted, pipeline-based security proxy designed to protect LLM API traffic. Point your application's `baseUrl` at the gateway, and it automatically applies PII redaction, prompt injection detection, dangerous command blocking, and output sanitization before forwarding to the real upstream model.

### Key Features

- **Prompt Injection Protection** — Multi-layer detection: regex patterns, optional semantic review (gray-zone gated: `AEGIS_ENABLE_SEMANTIC_MODULE` + `AEGIS_SEMANTIC_SERVICE_URL` + `AEGIS_SEMANTIC_GRAY_LOW/HIGH`), Unicode/encoding attack detection, typoglycemia defense
- **PII / Secret Redaction** — 50+ pattern categories covering API keys, tokens, credit cards, SSNs, crypto wallet addresses/seed phrases, medical records, and infrastructure identifiers
- **Dangerous Response Sanitization** — Automatic obfuscation of high-risk LLM outputs (shell commands, SQL injection payloads, HTTP smuggling) with configurable security levels (low/medium/high)
- **OpenAI-Compatible + Anthropic Messages API** — Drop-in routes for `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, and the generic proxy; works with OpenAI-compatible providers and Anthropic-compatible Messages upstreams
- **Anthropic ↔ OpenAI Protocol Conversion** — Token-based `compat` mode converts Anthropic `/v1/messages` requests to OpenAI `/v1/responses` on the fly, enabling Claude Code / Anthropic SDK to talk to OpenAI-compatible upstreams (GPT-5.4, etc.) without code changes
- **MCP & Agent SKILL Support** — Integrates with Cursor, Claude Code, Codex, Windsurf and other AI coding agents via Model Context Protocol
- **Token-Based Routing** — Route requests to multiple upstream providers through a single gateway with per-token upstream mapping and whitelist controls
- **Web Management Console** — Built-in admin UI for configuration, token management, security rules CRUD, key rotation, and real-time request statistics
- **Flexible Deployment** — Docker Compose one-click deploy, supports SQLite/Redis/PostgreSQL backends, Caddy TLS termination

### Use Cases

- **Protect sensitive data** from leaking to LLM providers (PII, API keys, internal URLs)
- **Detect and block prompt injection attacks** in real-time across your AI agent fleet
- **Centralize security policy** instead of implementing protections in every AI application
- **Audit LLM interactions** with structured logging, risk scoring, and dangerous content tracking
- **Secure MCP tool calls** — guard against malicious tool invocations and privilege escalation

### How It Compares

| Feature | AegisGate | LLM Guard | Rebuff | Prompt Armor |
|---------|-----------|-----------|--------|--------------|
| Self-hosted gateway proxy | Yes | Library only | API service | API service |
| Request + Response filtering | Both sides | Both sides | Request only | Request only |
| OpenAI-compatible drop-in | Yes | No | No | No |
| Built-in PII redaction | 50+ patterns | Yes | No | No |
| Web management UI | Yes | No | No | Dashboard |
| MCP / Agent SKILL support | Yes | No | No | No |
| Token-based multi-upstream routing | Yes | N/A | N/A | N/A |
| No external API dependency | Yes (core filters local; semantic service optional) | Yes | No (OpenAI) | No |
| Bilingual (EN/ZH) | Yes | English | English | English |

> **Quick start:** create `cliproxyapi_default` and `sub2api-deploy_sub2api-network` first, then run `docker compose up -d --build` — gateway runs on port 18080, admin UI login at `http://localhost:18080/__ui__/login`

### Architecture

```mermaid
flowchart LR
    subgraph Clients
        A1[AI Agent / Cursor / Claude Code]
        A2[Web App / API Client]
    end

    subgraph AegisGate["AegisGate Security Gateway"]
        direction TB
        MW[Token Router & Middleware]

        subgraph ReqPipeline["Request Pipeline"]
            R1[PII Redaction<br/>50+ patterns]
            R2[Exact-Value Redaction<br/>API keys, secrets]
            R3[Request Sanitizer<br/>injection & leak detection]
            R4[RAG Poison Guard]
        end

        subgraph RespPipeline["Response Pipeline"]
            S1[Injection Detector<br/>regex patterns]
            S2[Anomaly Detector<br/>encoding & command patterns]
            S3[Privilege Guard]
            S4[Tool Call Guard]
            S5[Restoration &<br/>Post-Restore Guard]
            S6[Output Sanitizer<br/>block / sanitize / pass]
        end
        SR[Semantic Review (Gray Zone)<br/>optional service call]

        MW --> ReqPipeline
    end

    subgraph Upstream["Upstream LLM Providers"]
        U1[OpenAI / Claude / Gemini]
        U2[Self-hosted LLM]
        U3[Any OpenAI-compatible API]
    end

    A1 & A2 -->|"baseUrl → gateway"| MW
    ReqPipeline -->|filtered request| U1 & U2 & U3
    U1 & U2 & U3 -->|raw response| RespPipeline
    RespPipeline -->|optional gray-zone review| SR
    SR -->|sanitized response| A1 & A2
```

### Frequently Asked Questions

**What is AegisGate?**
AegisGate is an open-source, self-hosted security gateway that sits between your AI applications and LLM API providers. It inspects and filters both requests and responses in real-time, protecting against prompt injection, PII leakage, and dangerous LLM outputs.

**How does AegisGate detect prompt injection?**
AegisGate uses a multi-layer approach: (1) bilingual regex patterns for known injection techniques (direct injection, system prompt exfiltration, typoglycemia obfuscation), (2) an optional semantic-review stage that is gray-zone gated by `AEGIS_SEMANTIC_GRAY_LOW/HIGH` (enabled by `AEGIS_ENABLE_SEMANTIC_MODULE`, service-backed via `AEGIS_SEMANTIC_SERVICE_URL`), and (3) Unicode/encoding attack detection for invisible characters, bidirectional control abuse, and multi-stage encoded payloads.

**Does AegisGate work with OpenAI, Claude, and other LLM providers?**
Yes. AegisGate provides an OpenAI-compatible API (`/v1/chat/completions`, `/v1/responses`) and a token-based generic HTTP proxy (`/v2/__gw__/t/<token>/...`, with `x-target-url` + `AEGIS_V2_TARGET_ALLOWLIST`). Applications that support a custom `baseUrl` can use the OpenAI-compatible routes as a drop-in proxy, and HTTP tooling can use the v2 token route when a generic proxy is needed. It has been verified with OpenAI, Claude (via compatible proxies), Gemini, and any OpenAI-compatible API.

**What data does AegisGate redact?**
Over 50 PII pattern categories including: API keys and tokens (OpenAI, AWS, GitHub, Slack), credit card numbers, SSNs, email addresses, phone numbers, crypto wallet addresses and seed phrases, medical record numbers, IP addresses, internal URLs, and infrastructure identifiers. Custom exact-value redaction is also supported for arbitrary secrets.

**Can I use AegisGate with AI coding agents like Cursor, Claude Code, or Codex?**
Yes. AegisGate supports MCP (Model Context Protocol) and Agent SKILL integration. Point your agent's `baseUrl` to the gateway and it will transparently filter all LLM traffic. See [SKILL.md](SKILL.md) for agent-specific setup instructions.

**How does AegisGate handle dangerous LLM responses?**
Responses are scored by multiple filters (injection detector, anomaly detector, privilege guard, tool call guard). Based on the cumulative risk score and configurable security level (low/medium/high), the gateway either passes the response through, sanitizes dangerous fragments (replacing them with safe markers), or blocks the entire response. Streaming responses are checked incrementally and can be terminated mid-stream.

**Does AegisGate require an external AI service for detection?**
Not for baseline protection. Regex-based detection, redaction, response sanitization, and routing safeguards run locally. The optional semantic-review stage is gray-zone gated (by `AEGIS_SEMANTIC_GRAY_LOW/HIGH`); when enabled, the gateway queries `AEGIS_SEMANTIC_SERVICE_URL` only for gray-zone cases. If the URL is empty, those gray-zone cases record `semantic_service_unconfigured` and continue without semantic escalation. The repository still ships local TF-IDF assets and training scripts for offline experiments (not wired into the default gateway path).

**How do I deploy AegisGate?**
The recommended method is Docker Compose. With the stock `docker-compose.yml`, create the referenced external networks first (`cliproxyapi_default` and `sub2api-deploy_sub2api-network`), then run `docker compose up -d --build`. The gateway runs on port 18080 with a built-in web management console at `/__ui__/login`. It supports SQLite (default), Redis, or PostgreSQL as storage backends. For production, place Caddy or nginx in front for TLS termination.


## Getting Started

### Docker Compose (Recommended)

```bash
git clone https://github.com/ax128/AegisGate.git
cd AegisGate
# The stock compose file references these external Docker networks by default.
# Create them first, or override/remove those network attachments for your setup.
docker network create cliproxyapi_default || true
docker network create sub2api-deploy_sub2api-network || true
docker compose up -d --build
```

Health check: `curl http://127.0.0.1:18080/health`

Readiness check: `curl http://127.0.0.1:18080/ready`

Admin UI login: `http://localhost:18080/__ui__/login`

Notes:

- The stock `docker-compose.yml` is not a fully standalone "single container only" compose file: it joins external Docker networks for CLIProxyAPI and Sub2API by default.
- The same compose file also sets `AEGIS_DOCKER_UPSTREAMS=8317:cli-proxy-api,8080:sub2api,3000:aiclient2api`. These startup-injected Docker service mappings take precedence over numeric host-port fallback for the same token.

### Local Development (No Docker)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,semantic]"
uvicorn aegisgate.core.gateway:app --host 127.0.0.1 --port 18080
```

## Upstream Integration

AegisGate is a standalone security proxy layer — it does **not** manage upstream services. Upstreams run independently per their own documentation; client requests pass through the gateway.

### Verified Upstreams

| Upstream | Description | Default Port |
|----------|-------------|-------------|
| [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) | OAuth multi-account LLM proxy (Claude/Gemini/OpenAI) | 8317 |
| [Sub2API](https://github.com/Wei-Shaw/sub2api) | AI API subscription platform (Claude/Gemini/Antigravity) | 8080 |
| [AIClient-2-API](https://github.com/justlovemaki/AIClient-2-API) | Multi-source AI client proxy (Gemini CLI/Codex/Kiro/Grok) | 3000 |
| Any OpenAI-compatible API | — | — |

### Scenario 1: Co-located Deployment (gateway and upstream on same server)

AegisGate supports two same-host patterns:

- **Host port routing**: numeric token routes such as `/v1/__gw__/t/8317/...` resolve to `http://<local-port-host>:8317/v1` when `AEGIS_ENABLE_LOCAL_PORT_ROUTING=true`. The stock Docker compose enables this by default; bare-metal deployments must enable it explicitly.
- **Docker service mapping**: when `AEGIS_DOCKER_UPSTREAMS` is set, startup injects token -> service-name mappings such as `8317 -> http://cli-proxy-api:8317/v1`. These mappings override numeric host-port fallback for the same token.

Host-port routing shape:

```
Client → http://<gateway-ip>:18080/v1/__gw__/t/{port}/... → localhost:{port}/v1/...
```

| Upstream | Client Base URL |
|----------|----------------|
| CLIProxyAPI | `http://<gateway-ip>:18080/v1/__gw__/t/8317` |
| Sub2API | `http://<gateway-ip>:18080/v1/__gw__/t/8080` |
| AIClient-2-API | `http://<gateway-ip>:18080/v1/__gw__/t/3000` |

- `Authorization: Bearer <key>` is passed through to upstream transparently
- Multiple upstreams can be used simultaneously
- For host-port routing, no token registration is required
- Supports filter mode suffixes: `token__redact` (redaction only) or `token__passthrough` (full passthrough)
  - `token__passthrough` still keeps the OpenAI compatibility layer: gateway-only fields are stripped before forwarding, and Chat/Responses parameter compatibility is preserved
- **Security default:** numeric port tokens (1024–65535, e.g. `/v1/__gw__/t/8317/...`) are treated as internal-only. For public clients, register a random token (recommended) or enable request HMAC auth; override with `AEGIS_ALLOW_PUBLIC_NUMERIC_TOKENS=true`.
- **Security default:** `token__passthrough` is treated as internal-only because it disables all filters; override with `AEGIS_ALLOW_PUBLIC_PASSTHROUGH_MODE=true` (dangerous).

Docker-specific notes:

- The stock compose file already injects `8317:cli-proxy-api`, `8080:sub2api`, and `3000:aiclient2api` via `AEGIS_DOCKER_UPSTREAMS`.
- Those injected mappings only work if the AegisGate container can resolve and reach the upstream service name on a shared Docker network.
- The stock compose file ships external network attachments for CLIProxyAPI and Sub2API only. If you want `3000:aiclient2api` to work as a Docker service mapping, add the appropriate network wiring yourself or override/remove that mapping and use host-port routing instead.

### Scenario 2: Remote Upstream

For remote upstreams, register a token binding via API:

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://remote-upstream.example.com/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

Use the returned token: `http://<gateway-ip>:18080/v1/__gw__/t/<token>`

### Scenario 3: Caddy + TLS for Public Access

```
Client → https://api.example.com/v1/__gw__/t/<token>/... → Caddy → AegisGate:18080 → localhost:8317
```

For public access, prefer a random registered token. Numeric port tokens and `__passthrough` are blocked for public/non-internal clients by default.

See [Caddyfile.example](Caddyfile.example) for the complete configuration.

## Core Capabilities

### API Endpoints

- **OpenAI-compatible** (full security pipeline): `POST /v1/chat/completions`, `POST /v1/responses`
- **Anthropic Messages**: `POST /v1/messages` — full security pipeline; supports native pass-through to Anthropic-compatible upstreams, or protocol conversion to OpenAI Responses via token `compat` mode
- **v2 Generic HTTP Proxy**: `ANY /v2/__gw__/t/<token>/...` — requires `x-target-url`, and the target host must also be present in `AEGIS_V2_TARGET_ALLOWLIST` because empty allowlist is fail-closed
- **Generic pass-through**: `POST /v1/{subpath}` — forwards any other `/v1/` path to upstream; by default it still runs the v1 request/response safety pipeline, and only `__passthrough` or upstream whitelist bypass skips filtering
- **Relay-compatible endpoint**: `POST /relay/generate` — disabled by default; enable with `AEGIS_ENABLE_RELAY_ENDPOINT=true`. This endpoint maps relay-style payloads to `/v1/chat/completions` and requires internal `x-upstream-base` and `gateway-key` headers

Compatibility notes:

- If a client accidentally sends a Responses-style payload (`input`) to `/v1/chat/completions`, AegisGate forwards it upstream as `/v1/responses` but converts the result back to Chat Completions JSON/SSE for the client.
- If a client accidentally sends a Chat-style payload (`messages`) to `/v1/responses`, AegisGate applies the inverse compatibility mapping and returns Responses-shaped output.
- benign or low-risk /v1/chat/completions and /v1/responses outputs should stay in their native client schema. When response-side sanitization is needed, AegisGate keeps operator-visible risk marking in existing `aegisgate` metadata and audit paths instead of switching to a whole-response fallback envelope.
- For direct `/v1/messages`, sanitized non-stream JSON responses preserve Anthropic-native `type/message/content[]` structure and keep risk marks in the existing aegisgate metadata and audit paths instead of returning a `sanitized_text` wrapper.
- For direct `/v1/messages` streaming, sanitized responses keep Anthropic-native SSE events, replace only dangerous text fragments, and continue surfacing operator-visible risk marks through the existing aegisgate metadata and audit paths instead of emitting chat chunks or `[DONE]` fallbacks.
- For `/v2` textual responses, high-risk HTTP attack fragments detected inside the current non-stream path or streaming probe window are replaced in-place and surfaced via response headers instead of forcing a whole-response `403` for every hit. The response-side toggle remains `AEGIS_V2_ENABLE_RESPONSE_COMMAND_FILTER`.

### Protocol Conversion (Anthropic → OpenAI)

When a token is configured with `"compat": "openai_chat"` in `config/gw_tokens.json`, the gateway automatically converts Anthropic `/v1/messages` requests to OpenAI `/v1/responses` format and converts responses back. This enables Claude Code and the Anthropic SDK to use OpenAI-compatible upstreams transparently.

**Setup:**

1. Register a compat token in `config/gw_tokens.json`:
   ```json
   {
     "tokens": {
       "claude-to-gpt": {
         "compat": "openai_chat"
       }
     }
   }
   ```

2. Configure global model mapping in `config/model_map.json`:
   ```json
   {
     "map": {
       "claude-opus-4-20250514": "gpt-5.4",
       "claude-sonnet-4-20250514": "gpt-5.4",
       "claude-haiku-4-5-20251001": "gpt-5.4-mini"
     }
   }
   ```

3. Point your client at the compat token with a local port:
   ```bash
   # Allow compat port routing (fail-closed by default)
   export AEGIS_COMPAT_ALLOWED_PORTS=8317

   # Claude Code / Anthropic SDK
   export ANTHROPIC_BASE_URL=http://gateway:18080/v1/__gw__/t/claude-to-gpt/8317
   ```

**URL patterns:**

| URL | Behavior |
|-----|----------|
| `/v1/__gw__/t/claude-to-gpt/8317/messages` | Messages → Responses → `:8317` → response converted back |
| `/v1/__gw__/t/claude-to-gpt/8317__redact/messages` | Same + PII redaction only |
| `/v1/__gw__/t/claude-to-gpt/8317__passthrough/messages` | Same + skip all filters |
| `/v1/__gw__/t/8317/messages` | Native pass-through (no conversion) |

**Model mapping priority:** token-level `model_map` > global `config/model_map.json` > token-level `default_model` > `gpt-5.4` (default)

**Allowed target models:** `gpt-5`, `gpt-5.2`, `gpt-5.4`, `gpt-5.4-mini`, `gpt-5.2-codex`, `gpt-5.3-codex`

### Security Pipeline

**Request side:** PII redaction → exact-value redaction → untrusted content guard → request sanitizer → RAG poison guard

**Response side:** anomaly detector → injection detector → RAG poison guard → privilege guard → tool call guard → restoration → post-restore guard → output sanitizer

### Error Response Format

AegisGate does not use one single JSON error envelope for every route. Current behavior falls into three families:

```json
{
  "error": "token_not_found",
  "detail": "token invalid or expired"
}
```

```json
{
  "error": {
    "message": "<human-readable reason>",
    "type": "aegisgate_error",
    "code": "<error_code>"
  },
  "error_code": "<error_code>",
  "detail": "<human-readable reason>",
  "request_id": "<request_id>",
  "aegisgate": { "...": "..." }
}
```

Use HTTP status plus the stable error code fields (`error`, `error.code`, `error_code`) rather than assuming every endpoint returns the same JSON shape.

Common current error codes:

| Code | Meaning |
|------|---------|
| `token_not_found` | Token route is missing, deleted, or not persisted |
| `token_route_required` | Non-token `/v1` or `/v2` access rejected by the security boundary |
| `invalid_filter_mode` | Unrecognized filter-mode token suffix such as `__foo` |
| `gateway_key_invalid` | Admin request supplied the wrong `gateway_key` |
| `missing_params` | Required JSON fields are missing on admin endpoints |
| `request_body_too_large` | Request body exceeds `AEGIS_MAX_REQUEST_BODY_BYTES` |
| `missing_target_url_header` | Current v2 code reused for missing `x-target-url`, malformed target URL, or target host not allowlisted |
| `upstream_unreachable` | Gateway could not connect to the upstream |
| `upstream_http_error` | Upstream returned 4xx/5xx and the gateway forwarded the failure |

Filter pipeline results may also include an `aegisgate` metadata object in successful responses, containing risk scores and disposition information.

### Custom HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `x-target-url` | Client -> Gateway | Required on v2 token routes. Must be a complete `http://` or `https://` URL, and the hostname must be allowed by `AEGIS_V2_TARGET_ALLOWLIST`. |
| `x-aegis-request-id` | Gateway -> Upstream | Injected by the gateway into upstream-bound requests for tracing correlation. Not set by clients — appears in upstream headers and gateway logs. |
| `x-aegis-filter-mode` | Gateway internal | Derived from the token URL suffix (`__redact` / `__passthrough`) and re-injected by the gateway. Client-supplied values are stripped before inner handlers run. |
| `x-aegis-redaction-whitelist` | Gateway internal | Derived from token `whitelist_key` bindings and injected by the gateway. Client-supplied values are stripped or ignored. |

### Filter Modes (Passthrough / Redact-Only)

AegisGate supports three filter modes on token routes. Select them with the token URL suffix. Client-supplied `x-aegis-filter-mode` headers are stripped, and direct `/v1/...` mode always uses full protection.

| Mode | Token URL Suffix | Behavior |
|------|-----------------|----------|
| **Full protection** (default) | `/v1/__gw__/t/<token>/...` | All enabled policy filters run on both request and response |
| **Redact-only** | `/v1/__gw__/t/<token>__redact/...` | Only redaction filters run (`exact_value_redaction`, `redaction`, `restoration`); security detection is skipped |
| **Passthrough** | `/v1/__gw__/t/<token>__passthrough/...` | All filters skipped; request/response forwarded as-is to upstream |

**Examples with local port routing:**

```bash
# Full protection (default)
curl http://gateway:18080/v1/__gw__/t/8317/chat/completions ...

# Redact-only — PII/secrets replaced, no injection detection or response blocking
curl http://gateway:18080/v1/__gw__/t/8317__redact/chat/completions ...

# Passthrough — zero filtering, direct upstream forwarding
curl http://gateway:18080/v1/__gw__/t/8317__passthrough/chat/completions ...
```

**Notes:**

1. Filter mode applies per-request only; it does not change the token's registration.
2. Works with both registered tokens and local port routing.
3. Invalid suffixes (e.g., `__foo`) return `400 invalid_filter_mode`.
4. Audit logs record the active filter mode (`filter_mode:redact` or `filter_mode:passthrough` security tag).
5. Direct `/v1/...` mode does not expose a client-settable filter-mode header; use token routes if you need `redact-only` or `passthrough`.
6. **Passthrough** still preserves the minimal protocol compatibility layer: gateway-internal fields are stripped, and Chat/Responses parameter conversion is maintained so upstream does not receive unknown fields.
7. **Security warning:** Passthrough mode skips all security checks. Use only in trusted environments or for debugging.
8. **Public surface:** by default, numeric port tokens (1024–65535) and `__passthrough` mode are blocked for public/non-internal clients. For public use, register a random token (recommended), or enable HMAC / explicit allow flags.

### Dangerous Content Handling

| Risk Level | Action | Examples |
|------------|--------|----------|
| **Safe** | Pass through | Normal conversation |
| **Low risk** | Chunked-hyphen obfuscation (insert `-` every 3 chars) | `dev-elo-per mes-sag-e` |
| **High risk / dangerous commands** | Replace with safety marker | SQL injection, reverse shell, `rm -rf` |
| **Spam noise** | Replace with `[AegisGate:spam-content-removed]` | Gambling/porn spam + fake tool calls |

### PII Redaction Coverage (50+ categories)

- **Credentials**: API keys, JWT, cookies, private keys (PEM), AWS access/secret, GitHub/Slack tokens
- **Financial**: credit cards, IBAN, SWIFT/BIC, routing numbers, bank accounts
- **Network & Devices**: IPv4/IPv6, MAC, IMEI/IMSI, device serial numbers
- **Identity & Compliance**: SSN, tax IDs, passport/driver's license, medical records
- **Crypto**: BTC/ETH/SOL/TRON addresses, WIF/xprv/xpub, seed phrases, exchange API keys
- **Infrastructure** (relaxed mode): hostnames, OS versions, container IDs, K8s resources, internal URLs

## Configuration

Key environment variables (set in `config/.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_HOST` | `127.0.0.1` | Listen address |
| `AEGIS_PORT` | `18080` | Listen port |
| `AEGIS_UPSTREAM_BASE_URL` | _(empty)_ | Direct upstream URL for `/v1/...` from localhost/internal clients only |
| `AEGIS_SECURITY_LEVEL` | `medium` | Security strictness: `low` / `medium` / `high` |
| `AEGIS_RISK_SCORE_THRESHOLD` | `0.7` | Risk score threshold (0–1); lower = stricter. Overridden per-policy by `risk_threshold` in policy YAML (default policy uses `0.85`) |
| `AEGIS_ENABLE_SEMANTIC_MODULE` | `true` | Enable semantic review (gray-zone gated; see `AEGIS_SEMANTIC_GRAY_LOW/HIGH`) |
| `AEGIS_SEMANTIC_SERVICE_URL` | _(empty)_ | Semantic service endpoint. When empty, gray-zone cases record `semantic_service_unconfigured` and skip semantic escalation |
| `AEGIS_SEMANTIC_GRAY_LOW` | `0.25` | Lower bound for triggering semantic review (only when `risk_score` is between low/high) |
| `AEGIS_SEMANTIC_GRAY_HIGH` | `0.75` | Upper bound for triggering semantic review (only when `risk_score` is between low/high) |
| `AEGIS_STORAGE_BACKEND` | `sqlite` | Storage: `sqlite` / `redis` / `postgres` |
| `AEGIS_ENFORCE_LOOPBACK_ONLY` | `true` | Restrict access to loopback; set `false` for Docker |
| `AEGIS_ENABLE_LOCAL_PORT_ROUTING` | `false` | Enable numeric token host-port fallback such as `/v1/__gw__/t/8317/...` |
| `AEGIS_ALLOW_PUBLIC_NUMERIC_TOKENS` | `false` | Allow numeric tokens (1024–65535) from public/non-internal clients (default: internal-only) |
| `AEGIS_ALLOW_PUBLIC_PASSTHROUGH_MODE` | `false` | Allow `__passthrough` mode from public/non-internal clients (dangerous; default: internal-only) |
| `AEGIS_DOCKER_UPSTREAMS` | _(empty)_ | Startup token -> Docker service mappings; same-name mappings override host-port fallback |
| `AEGIS_ENABLE_V2_PROXY` | `true` | Enable v2 generic HTTP proxy |
| `AEGIS_V2_TARGET_ALLOWLIST` | _(empty)_ | Required hostname allowlist for v2 targets; empty = deny all target hosts |
| `AEGIS_ENABLE_REDACTION` | `true` | Enable PII redaction |
| `AEGIS_ENABLE_INJECTION_DETECTOR` | `true` | Enable prompt injection detection |
| `AEGIS_STRICT_COMMAND_BLOCK_ENABLED` | `false` | Force-block on dangerous command match |
| `AEGIS_MAX_REQUEST_BODY_BYTES` | `12000000` | Maximum request body size in bytes |
| `AEGIS_MAX_MESSAGES_COUNT` | `500` | Maximum number of messages allowed in `/v1/chat/completions` |
| `AEGIS_FILTER_PIPELINE_TIMEOUT_S` | `90` | Filter pipeline timeout in seconds |
| `AEGIS_REQUEST_PIPELINE_TIMEOUT_ACTION` | `block` | Action on request pipeline timeout: `block` or `pass` |
| `AEGIS_UPSTREAM_TIMEOUT_SECONDS` | `600` | Upstream request timeout in seconds |
| `AEGIS_STREAM_BOOTSTRAP_RETRIES` | `0` | Streaming retries before first byte is sent to client (retryable upstream errors only); enabling may cause duplicate upstream execution |
| `AEGIS_ENABLE_BUILTIN_COMPAT_TOKENS` | `false` | Auto-inject built-in compat token(s) such as `claude-to-gpt` |
| `AEGIS_COMPAT_ALLOWED_PORTS` | _(empty)_ | Required allowlist for compat token port routing; empty = deny all compat port routing |
| `AEGIS_ENABLE_RELAY_ENDPOINT` | `false` | Enable optional `POST /relay/generate` relay-compatible endpoint |
| `AEGIS_ENABLE_REQUEST_HMAC_AUTH` | `false` | Enable HMAC signature verification for requests |
| `AEGIS_TRUSTED_PROXY_IPS` | _(empty)_ | Comma-separated trusted reverse-proxy IPs/CIDRs for X-Forwarded-For |

Full configuration reference: [`aegisgate/config/settings.py`](aegisgate/config/settings.py) and [`config/.env.example`](config/.env.example).

### Semantic Service Protocol (Optional)

If `AEGIS_ENABLE_SEMANTIC_MODULE=true` and a request falls into the gray-zone gate, the gateway may call `AEGIS_SEMANTIC_SERVICE_URL` with:

```json
{"text":"..."}
```

The semantic service should return a JSON object:

```json
{"risk_score":0.0,"tags":[],"reasons":[]}
```

## Agent Skill

Agent-executable installation and integration guide: [SKILL.md](SKILL.md)

## Development

```bash
pip install -e ".[dev,semantic]"
pytest -q
```

Optional observability support:

```bash
pip install -e ".[observability]"
```

With the observability extra installed, AegisGate exposes `/metrics` for Prometheus scraping and initializes the OpenTelemetry provider/exporter during startup.
Gateway request handling creates `gateway.request` spans. Whether those spans are exported depends on your OpenTelemetry exporter setup; without an OTLP exporter, spans are discarded unless `AEGIS_OTEL_CONSOLE_EXPORTER=true` is set.
`/metrics` does not have a dedicated auth layer; it inherits the gateway's normal network and auth controls, so disabling loopback/HMAC protections may expose it more broadly.

## Troubleshooting

### `sqlite3.OperationalError: unable to open database file`
Check that `AEGIS_SQLITE_DB_PATH` points to a writable path and volume mount permissions are correct.

### Token path returns `token_not_found`
Token not registered, deleted, or `AEGIS_GW_TOKENS_PATH` not persisted across restarts.

### Upstream returns 4xx/5xx
Gateway transparently forwards upstream errors. Verify upstream availability independently first.

### Streaming logs show `upstream_eof_no_done` or `terminal_event_no_done_recovered:*`
Two different cases are logged separately:

- `upstream_eof_no_done`: upstream closed the stream without sending `data: [DONE]`; the gateway auto-recovers by synthesizing a completion event.
- `terminal_event_no_done_recovered:response.completed|response.failed|error`: the gateway already received an explicit terminal event from upstream, but upstream closed before sending `[DONE]`. This is no longer logged as a generic EOF recovery.

For `/v1/responses`, forwarded upstream calls now carry `x-aegis-request-id`, and upstream forwarding logs include the same `request_id`. If gateway logs show repeated `incoming request` entries but only one or two `forward_stream start/connected` entries for matching request IDs, the extra traffic is coming into the gateway as new HTTP requests rather than SSE chunks being split into multiple upstream calls.

Optimization note (2026-03): Responses SSE frames that include explicit `event:` headers are now buffered and forwarded as full event frames instead of line-by-line. This prevents `event:` and `data:` lines from being reordered across `response.output_text.delta`, `response.output_text.done`, and `response.completed`.

### v2 returns `missing_target_url_header`
Current v2 code reuses `missing_target_url_header` for three target-resolution failures:

- the `x-target-url` header is missing or empty
- the header value is not a complete `http://` or `https://` URL
- the target hostname is not present in `AEGIS_V2_TARGET_ALLOWLIST`

Include the full target URL with query string, and make sure the hostname is allowlisted first.

## License

[MIT](LICENSE)
