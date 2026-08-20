# Terminal Clients Wiki (AegisGate)

How to point terminal and desktop IDE clients at AegisGate.

## Start Here

1. Multi-upstream / multi-tenant: use **Token mode** first.
2. Single-upstream fast path: use `AEGIS_UPSTREAM_BASE_URL` only for localhost/internal clients calling `/v1/...` directly.
3. For Claude, use `POST /v1/messages` (supports streaming).
4. OAuth-hosted login mode is **not supported**.

---

## Quick Start (Token Mode)

Register once:

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://remote-upstream.example.com/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

Use returned `baseUrl`:

```text
http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>
```

Client config baseline:
- `baseUrl = token baseUrl`
- `apiKey = upstream real API key`

> If you use Caddy to expose the gateway publicly, `/__gw__/*` admin endpoints should be blocked in Caddyfile.
> Run registration against `http://127.0.0.1:18080` (localhost) or an internal admin ingress.

---

## Quick Start (Direct v1 Mode, Internal Only)

For single-upstream deployments, configure:

```text
AEGIS_UPSTREAM_BASE_URL=<YOUR_UPSTREAM_V1_BASE>
```

Then let localhost/internal clients call:

```text
http://127.0.0.1:18080/v1/...
```

Example:

```bash
curl -X POST 'http://127.0.0.1:18080/v1/messages?anthropic-version=2023-06-01' \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-3-5-sonnet-latest","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}'
```

Notes:
- Use an upstream base that includes provider API prefix (e.g. `.../v1`).
- This mode is internal-only. Public or reverse-proxied callers should use token mode instead of direct `/v1/...`.
- Exception: a front reverse proxy may present `x-aegis-proxy-token` (value = `config/aegis_proxy_token.key`) to lift the internal-only check on `/v1/...` and `/v2/...`. Treat that key as equivalent to opening direct `/v1` access — never hand it to clients. See README "Custom HTTP Headers".
- `v2` should still use token path: `/v2/__gw__/t/<TOKEN>/...` + `x-target-url`, and target hosts must be allowed by `AEGIS_V2_TARGET_ALLOWLIST`.

---

## Claude API Support

Supported via the v1 OpenAI-compatible adapter (`/v1/messages` is handled natively with the full safety pipeline; other subpaths such as `count_tokens` go through the v1 generic pass-through):
- `POST /v1/messages`
- `POST /v1/messages/count_tokens`
- `stream=true` streaming passthrough
- query passthrough, e.g. `?anthropic-version=2023-06-01`

Example:

```bash
curl -X POST 'http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>/messages?anthropic-version=2023-06-01' \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-3-5-sonnet-latest","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}'
```

---

## Platform Notes (Windows/macOS/Linux/WSL2)

- Windows (PowerShell): use `Invoke-RestMethod` for token registration.
- macOS/Linux: use `curl` registration.
- WSL2: prefer `127.0.0.1:18080`; if unreachable, try Windows host IP.

---

## Client Matrix

| Client | Base URL + API Key | Claude `messages` | OAuth Hosted Login |
|---|---|---|---|
| Codex CLI | Yes | Yes | No |
| OpenCodeX | Yes | Yes | No |
| Cherry Studio | Yes | Yes | No |
| VS Code extensions | Extension-dependent | Yes (if base URL configurable) | No |
| Cursor | Yes | Yes | No |

Every client in the table is configured the same way: pick the provider's
"OpenAI-compatible / custom endpoint" mode, set `base_url` to the gateway, and use the **upstream's**
API key. No client needs a gateway-specific setting.

---

## Config Templates

### Token Mode (Recommended)

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1/__gw__/t/<YOUR_TOKEN>
api_key: <UPSTREAM_API_KEY>
model: claude-3-5-sonnet-latest
```

### Direct v1 Mode (Internal Only)

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1
api_key: <UPSTREAM_API_KEY>
model: claude-3-5-sonnet-latest
```

## Troubleshooting

### `token_route_required`
- A non-token `/v1` or `/v2` request was rejected by the security boundary.
- Either switch the client to a token `base_url`, or — for direct v1 mode — make sure the caller is
  on localhost/internal and `AEGIS_UPSTREAM_BASE_URL` is set.

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
  - `POST /__gw__/add`
  - `POST /__gw__/remove`
- In public ingress, block `/__gw__/*` externally and keep it localhost/internal only.
- Keep `v2` on token path (`/v2/__gw__/t/<TOKEN>/...`), avoid exposing non-token generic proxy, and set `AEGIS_V2_TARGET_ALLOWLIST` explicitly.
- Gateway key is stored in `config/aegis_gateway.key` (auto-generated on first run, chmod 600). Read it with `cat config/aegis_gateway.key`.
- Prefer Token mode for all new clients.
- Do not use OAuth-hosted-only mode for AegisGate routing.

---

## Related Docs

- [README.md](README.md) / [README_zh.md](README_zh.md) — full reference
- [UPSTREAM-QUICKSTART.md](UPSTREAM-QUICKSTART.md) — connecting the upstream itself
- [WEBUI-QUICKSTART.md](WEBUI-QUICKSTART.md) — registering tokens from the admin console
