# AIClient-2-API 经网关中转 — 3 步接入

让 [AIClient-2-API](https://github.com/justlovemaki/AIClient-2-API) 请求先经 AegisGate 安检再转发，**不改 AIClient-2-API 代码**，**客户端零改动**。

## 请求链路

```
客户端 → https://api.example.com/v1/... → Caddy → AegisGate(安检) → aiclient2api:3000
```

## 两种部署模式

| 模式 | 命令 | 说明 |
|------|------|------|
| **基础模式** | `docker compose up -d --build` | 仅 AegisGate，不启用 AIClient-2-API / Caddy |
| **AIClient-2-API 模式** | `docker compose -f docker-compose.yml -f docker-compose.aiclient2api.yml up -d --build` | AegisGate + AIClient-2-API + Caddy 完整栈 |

## 1. 准备配置

无需克隆仓库，compose 直接使用官方镜像 `justlikemaki/aiclient-2-api:latest`。

创建配置目录：

```bash
cd ~/AegisGate
mkdir -p aiclient2api/configs
```

目录结构：

```
AegisGate/
  aiclient2api/
    configs/              # AIClient-2-API 配置（启动后通过 Web UI 管理）
      config.json         # 自动生成
      provider_pools.json # 账号池配置
  Caddyfile               # Caddy 反代配置（在 AegisGate 根目录）
  docker-compose.yml      # 基础模式
  docker-compose.aiclient2api.yml  # AIClient-2-API 叠加栈
```

## 2. 修改 Caddyfile

将 `Caddyfile` 中管理后台的 `reverse_proxy` 指向 AIClient-2-API：

```caddy
# 管理后台：直连 AIClient-2-API Web UI，不经过网关
panel.example.com {
    # ... header 配置 ...
    reverse_proxy aiclient2api:3000 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        flush_interval -1
        transport http {
            response_header_timeout 660s
            read_timeout 660s
            write_timeout 660s
        }
    }
}
```

## 3. 启动

```bash
docker compose -f docker-compose.yml -f docker-compose.aiclient2api.yml up -d --build
```

compose 已把网关上游设为 `http://aiclient2api:3000/v1`，API 请求会默认走网关再转 AIClient-2-API。

首次启动后：
- 访问 `http://127.0.0.1:3000` 进入 Web UI 配置账号池（默认密码见 `aiclient2api/configs/pwd`）
- 网关自动生成 `gateway_key`（保存在 `config/aegis_gateway.key`）

```bash
cat config/aegis_gateway.key
```

## 4. 客户端

**无需改任何配置**。继续使用：

- **Base URL**：`https://api.example.com/v1`（或你的域名）
- **API Key**：AIClient-2-API Web UI 中配置的 API Key

管理后台：`https://panel.example.com`（不经网关，直连 AIClient-2-API Web UI）。

## 5. 更新 AIClient-2-API

```bash
docker compose -f docker-compose.yml -f docker-compose.aiclient2api.yml pull aiclient2api
docker compose -f docker-compose.yml -f docker-compose.aiclient2api.yml up -d
```

## 6. AIClient-2-API 支持的上游

| 上游 | 说明 |
|------|------|
| Gemini CLI | Google Gemini 模型（OAuth 授权） |
| Antigravity | Claude / Gemini 中转 |
| Qwen Code | 通义千问编程模型 |
| Kiro | Claude 扩展思考模式 |
| Grok | xAI Grok 模型 |
| Codex | OpenAI Codex |
| 自定义 OpenAI/Claude | 任意兼容端点 |

所有端点均经 AegisGate 安检过滤后转发，统一暴露为 OpenAI 兼容接口（`/v1/chat/completions`）和 Claude 兼容接口（`/v1/messages`）。

## 7. OAuth 回调端口

AIClient-2-API 需要以下端口接收 OAuth 回调，compose 已配置：

| 端口 | 用途 |
|------|------|
| 8085-8087 | Gemini / Antigravity OAuth |
| 1455 | Codex OAuth |
| 19876-19880 | Kiro OAuth |

如服务器有防火墙，需对这些端口放行。

## 8. 流式与长上下文（已内置）

compose 已预置以下能力：
- 流式传输：Caddy `flush_interval -1`，SSE 不缓冲，网关保留断流 `[DONE]` 恢复。
- 长上下文：提高请求体/消息条数/单条消息/响应长度上限。
- 高负载稳定性：开启 `AEGIS_ENABLE_THREAD_OFFLOAD=true`，避免过滤管道阻塞 event loop。
- 上游超时 600s（10 分钟），适配长时间推理请求。

如需更高阈值，可在 `docker-compose.aiclient2api.yml`（`aegisgate.environment`）继续上调这些环境变量：
`AEGIS_MAX_REQUEST_BODY_BYTES`、`AEGIS_MAX_MESSAGES_COUNT`、`AEGIS_MAX_CONTENT_LENGTH_PER_MESSAGE`、`AEGIS_MAX_RESPONSE_LENGTH`、`AEGIS_FILTER_PIPELINE_TIMEOUT_S`。

---

## 可选：Token 模式（不对外开放）

不需要 Caddy 对公网暴露服务时，推荐使用 Token 内网模式：

```bash
# 仅启动基础栈（不含 Caddy）
docker compose up -d --build

# 单独启动 AIClient-2-API
docker run -d -p 127.0.0.1:3000:3000 -p 8085-8087:8085-8087 -p 1455:1455 \
  -p 19876-19880:19876-19880 --restart=always \
  -v ./aiclient2api/configs:/app/configs --name aiclient2api \
  justlikemaki/aiclient-2-api

# 注册 token 绑定上游
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base": "http://aiclient2api:3000/v1", "gateway_key": "<your_gateway_key>"}'

# 客户端使用返回的 token 路径
# Base URL: http://127.0.0.1:18080/v1/__gw__/t/<token>
```

注意：
- Token 模式下 `/__gw__/*` 管理端点仅允许内网访问。
- `v2` 通用代理始终建议走 token 路径：`/v2/__gw__/t/{token}/...`，并在 Header 里携带 `x-target-url`。
