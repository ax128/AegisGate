# Terminal Clients Wiki (AegisGate)

This page is the **Wiki-style navigation hub** for connecting terminal/desktop IDE clients to AegisGate.

## Start Here

1. Use **Token mode** first.
2. For Claude, use `POST /v1/messages` (supports streaming).
3. OAuth-hosted login mode is **not supported**.

---

## Wiki Navigation

- [Quick Start (Token Mode)](#quick-start-token-mode)
- [Claude API Support](#claude-api-support)
- [Platform Notes (Windows/macOS/Linux/WSL2)](#platform-notes-windowsmacoslinuxwsl2)
- [Client Matrix](#client-matrix)
- [Client Profiles](#client-profiles)
- [Config Templates](#config-templates)
- [Troubleshooting](#troubleshooting)
- [Security Baseline](#security-baseline)

---

## Quick Start (Token Mode)

Register once:

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"agent"}'
```

Use returned `baseUrl`:

```text
http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>
```

Client config baseline:
- `baseUrl = token baseUrl`
- `apiKey = upstream real API key`

---

## Claude API Support

Supported via generic proxy:
- `POST /v1/messages`
- `POST /v1/messages/count_tokens`
- `stream=true` streaming passthrough
- query passthrough, e.g. `?anthropic-version=2023-06-01`

Example:

```bash
curl -X POST 'http://127.0.0.1:18080/v1/messages?anthropic-version=2023-06-01' \
  -H 'Content-Type: application/json' \
  -H 'X-Upstream-Base: https://your-upstream.example.com/v1' \
  -H 'gateway-key: agent' \
  -d '{"model":"claude-3-5-sonnet-latest","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}'
```

---

## Platform Notes (Windows/macOS/Linux/WSL2)

- Windows (PowerShell): use `Invoke-RestMethod` for token registration.
- macOS/Linux: use `curl` registration.
- WSL2: prefer `127.0.0.1:18080`; if unreachable, try Windows host IP.

---

## Client Matrix

| Client | Base URL + API Key | Header Injection | Claude `messages` | OAuth Hosted Login |
|---|---|---|---|---|
| Codex CLI | Yes | Version-dependent | Yes | No |
| OpenCodeX | Yes | Version-dependent | Yes | No |
| OpenClaw | Yes | Usually yes | Yes | No |
| Cherry Studio | Yes | Yes | Yes | No |
| VS Code extensions | Extension-dependent | Extension-dependent | Yes (if base URL configurable) | No |
| Cursor | Yes | Usually not needed (Token mode) | Yes | No |

---

## Client Profiles

### Codex CLI
- Recommended: Token mode.
- Requirement: customizable `baseUrl` + API key mode.

### OpenCodeX
- Use OpenAI-compatible provider mode.
- Recommended: Token mode.

### OpenClaw
- Use OpenAI-compatible endpoint.
- Token mode first; Header mode if needed.

### Cherry Studio
- Provider: OpenAI-compatible.
- Use Token `baseUrl` + upstream API key.

### VS Code
- Must use an extension that supports custom OpenAI-compatible endpoint.
- OAuth-only extension mode is not supported.

### Cursor
- Use custom OpenAI-compatible endpoint mode.
- Recommended: Token mode.

---

## Config Templates

### Token Mode (Recommended)

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1/__gw__/t/<YOUR_TOKEN>
api_key: <UPSTREAM_API_KEY>
model: claude-3-5-sonnet-latest
```

### Header Mode

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1
api_key: <UPSTREAM_API_KEY>
model: claude-3-5-sonnet-latest
headers:
  X-Upstream-Base: https://your-upstream.example.com/v1
  gateway-key: agent
```

---

## Troubleshooting

### `invalid_parameters`
- Header mode request did not actually include required headers.
- Switch to Token mode.

### `token_not_found`
- Token not registered, removed, or token file not persisted.
- Check `AEGIS_GW_TOKENS_PATH` and volume mapping.

### No Claude streaming output
- Confirm upstream supports `stream=true`.
- Confirm client reads SSE stream.
- Verify with `curl -N` first.

---

## Security Baseline

- Restrict access to:
  - `POST /__gw__/register`
  - `POST /__gw__/lookup`
  - `POST /__gw__/unregister`
- Use strong `AEGIS_GATEWAY_KEY`.
- Prefer Token mode for all new clients.
- Do not use OAuth-hosted-only mode for AegisGate routing.

---

## Related Docs

- `README.md`
- `docs/other-terminal-clients-usage.md` (longer draft)
