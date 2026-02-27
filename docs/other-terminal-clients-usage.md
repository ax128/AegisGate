# AegisGate 多客户端接入指南（Claude 优先版）

> 参考：esapi 文档（`https://esapi.top/docs/`）与 AegisGate 当前实现。  
> 本文重点：让 Codex CLI / OpenCodeX / OpenClaw / Cherry / VS Code / Cursor 在 Windows/macOS/Linux/WSL2 下稳定走网关，且优先支持 Claude 系列 API。

---

## 1. 先看结论

1. 新客户端统一优先用 **Token 模式**。  
2. Claude 系列建议走 `POST /v1/messages`（非流式和流式都支持）。  
3. 已支持 `POST /v1/messages/count_tokens`（通用代理路径）。  
4. 已支持 **query 透传**（例如 `?anthropic-version=2023-06-01`）。  
5. **OAuth 托管登录模式不支持**（不能稳定控制 Base URL/Header）。

---

## 2. 网关现有 Claude 相关能力

AegisGate 当前可支持 Claude 常见调用形态：

- 非流式：`POST /v1/messages`
- 流式：`POST /v1/messages` + `"stream": true`
- 计数：`POST /v1/messages/count_tokens`
- 透传 query：`/v1/messages?anthropic-version=2023-06-01`

说明：
- 网关只做安全检查与转发，不替代上游 API 协议本身。
- Claude 请求体（`messages/content/system/tools` 等）按通用代理转发。

---

## 3. 接入模式

## 3.1 Token 模式（推荐）

先注册一次：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"agent"}'
```

返回：

```json
{
  "token": "Ab3k9Qx7",
  "baseUrl": "http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7"
}
```

客户端统一配置：
- `baseUrl = http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7`
- `apiKey = 上游真实 API Key`

---

## 4. Claude API 示例

## 4.1 非流式 messages

```bash
curl -X POST 'http://127.0.0.1:18080/v1/__gw__/t/<YOUR_TOKEN>/messages' \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"claude-3-5-sonnet-latest",
    "max_tokens":256,
    "messages":[{"role":"user","content":"hello"}]
  }'
```

## 4.2 流式 messages

```bash
curl -N -X POST 'http://127.0.0.1:18080/v1/__gw__/t/<YOUR_TOKEN>/messages' \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"claude-3-5-sonnet-latest",
    "stream":true,
    "max_tokens":256,
    "messages":[{"role":"user","content":"write haiku"}]
  }'
```

## 4.3 count_tokens

```bash
curl -X POST 'http://127.0.0.1:18080/v1/__gw__/t/<YOUR_TOKEN>/messages/count_tokens' \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"claude-3-5-sonnet-latest",
    "messages":[{"role":"user","content":"token count please"}]
  }'
```

## 4.4 带 query 的版本参数（已透传）

```bash
curl -X POST 'http://127.0.0.1:18080/v1/__gw__/t/<YOUR_TOKEN>/messages?anthropic-version=2023-06-01' \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"claude-3-5-sonnet-latest",
    "max_tokens":128,
    "messages":[{"role":"user","content":"hi"}]
  }'
```

---

## 5. 客户端支持矩阵

| 客户端 | Base URL + API Key | Claude messages | OAuth 托管登录 |
|---|---|---|---|
| Codex CLI | 支持 | 支持（建议 Token 模式） | 不支持 |
| OpenCodeX | 支持 | 支持 | 不支持 |
| OpenClaw | 支持 | 支持 | 不支持 |
| Cherry Studio | 支持 | 支持 | 不支持 |
| VS Code（扩展） | 视扩展 | 支持（能配 Base URL 即可） | 不支持 |
| Cursor | 支持 | 支持 | 不支持 |

---

## 6. 平台场景

## 6.1 Windows（PowerShell）注册 token

```powershell
$body = @{
  upstream_base = "https://your-upstream.example.com/v1"
  gateway_key   = "agent"
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:18080/__gw__/register" `
  -ContentType "application/json" `
  -Body $body
```

## 6.2 macOS / Linux

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"agent"}'
```

## 6.3 WSL2

优先：
- `http://127.0.0.1:18080`
- `http://localhost:18080`

若不可达，再用 Windows 主机 IP。

---

## 7. 通用配置模板

## 7.1 Token 模式模板（推荐）

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1/__gw__/t/<YOUR_TOKEN>
api_key: <UPSTREAM_API_KEY>
model: claude-3-5-sonnet-latest
```

## 8. OAuth 为什么不支持

AegisGate 接入至少需要：
1. 可配置 `Base URL`（Token 路由）
2. 可配置 API Key（上游密钥）

纯 OAuth 托管链路一般无法满足上述要求，因此不支持。

---

## 9. 常见问题

## 9.1 `invalid_parameters`

- 路径不是 token 路由，或请求参数不符合上游接口要求
- 检查 `base_url` 是否为 `/v1/__gw__/t/<TOKEN>` 前缀

## 9.2 `token_not_found`

- token 未注册 / 已删除
- `AEGIS_GW_TOKENS_PATH` 未持久化

## 9.3 Claude 流式无输出

- 检查上游是否支持 `stream=true`
- 检查客户端是否按 SSE 读取
- 先用 `curl -N` 验证网关到上游链路

---

## 10. 建议默认策略

1. 所有新终端接入先走 Token 模式。  
2. 对外暴露时限制 `POST /__gw__/register|lookup|unregister` 访问源。  
3. 能走 API Key + Base URL 就不要走 OAuth 托管。  
