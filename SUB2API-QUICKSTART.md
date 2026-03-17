# Sub2API 经网关中转 — 3 步接入

> **前置条件**：请先阅读 [Sub2API 官方文档](https://github.com/Wei-Shaw/sub2api) 了解其配置与使用方式，再按以下步骤接入 AegisGate。

让 [Sub2API](https://github.com/Wei-Shaw/sub2api) 请求先经 AegisGate 安检再转发，**不改 Sub2API 代码**，**客户端零改动**（仍用原 base URL 和 API Key）。

## 请求链路

```
客户端 → https://api.example.com/v1/... → Caddy → AegisGate(安检) → sub2api:8080
```

## 两种部署模式

| 模式 | 命令 | 说明 |
|------|------|------|
| **基础模式** | `docker compose up -d --build` | 仅 AegisGate，不启用 Sub2API / Caddy |
| **Sub2API 模式** | `docker compose -f docker-compose.yml -f docker-compose.sub2api.yml up -d --build` | AegisGate + Sub2API + PostgreSQL + Redis + Caddy 完整栈 |

## 1. 准备配置

无需克隆 Sub2API 仓库，compose 直接使用官方镜像 `weishaw/sub2api:latest`。

在 AegisGate 根目录创建 `.env`（或在 `config/.env` 中追加），配置 Sub2API 所需的密钥：

```bash
cd ~/AegisGate

cat >> config/.env << 'EOF'
# ---- Sub2API ----
POSTGRES_PASSWORD=your_secure_password_here
JWT_SECRET=your_jwt_secret_here
TOTP_ENCRYPTION_KEY=your_totp_key_here
# ADMIN_EMAIL=admin@sub2api.local
# ADMIN_PASSWORD=your_admin_password
EOF
```

> 生成安全密钥：`openssl rand -hex 32`

目录结构：

```
AegisGate/
  config/.env               # Sub2API 密钥配置（POSTGRES_PASSWORD / JWT_SECRET 等）
  Caddyfile                 # Caddy 反代配置（在 AegisGate 根目录）
  docker-compose.yml        # 基础模式
  docker-compose.sub2api.yml  # Sub2API 叠加栈
```

## 2. 修改 Caddyfile

将 `Caddyfile` 中管理后台的 `reverse_proxy` 指向 Sub2API：

```caddy
# 管理后台：直连 Sub2API，不经过网关
panel.example.com {
    # ... header 配置 ...
    reverse_proxy sub2api:8080 {
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
docker compose -f docker-compose.yml -f docker-compose.sub2api.yml up -d --build
```

compose 已把网关上游设为 `http://sub2api:8080/v1`，API 请求会默认走网关再转 Sub2API。

首次启动后：
- Sub2API 自动初始化数据库、创建管理员账号
- 网关密钥保存在 `config/aegis_gateway.key`（首次启动自动生成，chmod 600）

```bash
# 查看网关密钥（注册 Token 和 UI 登录均需此值）
cat config/aegis_gateway.key
```

## 4. 客户端

**无需改任何配置**。继续使用：

- **Base URL**：`https://api.example.com/v1`（或你的域名）
- **API Key**：Sub2API 管理后台分配的 API Key

管理后台：`https://panel.example.com`（不经网关，直连 Sub2API）。

## 5. 更新 Sub2API

```bash
docker compose -f docker-compose.yml -f docker-compose.sub2api.yml pull sub2api
docker compose -f docker-compose.yml -f docker-compose.sub2api.yml up -d
```

## 6. Sub2API 支持的上游

| 上游 | 端点路径 | 说明 |
|------|---------|------|
| Claude (Anthropic) | `/v1/messages` | Anthropic 原生格式 |
| Gemini (Google) | `/v1beta/...` | Google AI 格式 |
| Antigravity Claude | `/antigravity/v1/messages` | 经 Antigravity 中转 |
| Antigravity Gemini | `/antigravity/v1beta/...` | 经 Antigravity 中转 |
| OpenAI 兼容 | `/v1/chat/completions` | 通过订阅配置 |

所有端点均经 AegisGate 安检过滤后转发。

## 7. 流式与长上下文（已内置）

compose 已预置以下能力：
- 流式传输：Caddy `flush_interval -1`，SSE 不缓冲，网关保留断流 `[DONE]` 恢复。
- 长上下文：提高请求体/消息条数/单条消息/响应长度上限。
- 高负载稳定性：开启 `AEGIS_ENABLE_THREAD_OFFLOAD=true`，避免过滤管道阻塞 event loop。
- 上游超时 600s（10 分钟），适配长时间推理请求。

如需更高阈值，可在 `docker-compose.sub2api.yml`（`aegisgate.environment`）继续上调这些环境变量：
`AEGIS_MAX_REQUEST_BODY_BYTES`、`AEGIS_MAX_MESSAGES_COUNT`、`AEGIS_MAX_CONTENT_LENGTH_PER_MESSAGE`、`AEGIS_MAX_RESPONSE_LENGTH`、`AEGIS_FILTER_PIPELINE_TIMEOUT_S`。

---

## 可选：多上游 / Token 模式

需要多套上游或按 token 区分时，仍可使用 `/__gw__/register` 与 `/v1/__gw__/t/{token}/...`；未配置默认上游时，`/v1` 与 `/v2` 都会要求走 token 路径。

注意：
- Sub2API 叠加栈使用的 `Caddyfile` 默认会对公网域名阻断 `/__gw__/*`。请通过 `http://127.0.0.1:18080`（本机）或内网管理入口调用注册接口。
- `v2` 通用代理始终建议走 token 路径：`/v2/__gw__/t/{token}/...`，并在 Header 里携带 `x-target-url`。
