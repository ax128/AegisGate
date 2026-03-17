# Sub2API 经网关中转 — 接入指南

> **前置条件**：请先阅读 [Sub2API 官方文档](https://github.com/Wei-Shaw/sub2api) 了解其配置与使用方式，再按以下步骤接入 AegisGate。

让 [Sub2API](https://github.com/Wei-Shaw/sub2api) 请求先经 AegisGate 安检再转发，**不改 Sub2API 代码**。

---

## 部署模式选择

### 模式 A：Sub2API 作为唯一上游（直连模式）

```
客户端 → Caddy → AegisGate(安检) → sub2api:8080
```

```bash
# .env 中设置
AEGIS_UPSTREAM_BASE_URL=http://sub2api:8080/v1

# 启动
docker compose -f docker-compose.yml -f docker-compose.sub2api.yml up -d --build
```

### 模式 B：与 CLIProxyAPI 等其他上游共存（Token 路由模式）✨推荐

```
客户端 → AegisGate /v1/__gw__/t/<TOKEN>/... → sub2api:8080
                                             → cli-proxy-api:8317（直连上游）
```

```bash
# 启动（叠加到 cliproxy 栈）
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml -f docker-compose.sub2api.yml up -d --build
```

CLIProxyAPI 保持直连上游，Sub2API 通过 Token 路由接入，互不冲突。

---

## 1. 准备配置

无需克隆 Sub2API 仓库，compose 直接使用官方镜像 `weishaw/sub2api:latest`。

在 `config/.env` 中追加 Sub2API 所需的密钥：

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

## 2. 启动

```bash
# 模式 A（唯一上游）
docker compose -f docker-compose.yml -f docker-compose.sub2api.yml up -d --build

# 模式 B（与 CLIProxyAPI 共存）
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml -f docker-compose.sub2api.yml up -d --build
```

首次启动后 Sub2API 自动初始化数据库、创建管理员账号。

## 3. 配置 Token（模式 B 必须）

与其他上游共存时，在 `config/gw_tokens.json` 中添加 Sub2API 的 token（无需 curl，编辑文件即可）：

```json
{
  "tokens": {
    "sub2api": {
      "upstream_base": "http://sub2api:8080/v1",
      "gateway_key": "<sub2api管理后台分配的API Key>",
      "whitelist_key": []
    }
  }
}
```

> 如果文件中已有其他 token，在 `tokens` 对象中追加即可。参考 `config/gw_tokens.json.example`。

重启网关后生效：

```bash
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml -f docker-compose.sub2api.yml restart aegisgate
```

客户端使用方式：
- **Base URL**：`http://<host>:18080/v1/__gw__/t/sub2api`
- **API Key**：Sub2API 管理后台分配的 API Key

## 4. 客户端配置

### 模式 A（直连）

无需改配置，继续使用：
- **Base URL**：`https://api.example.com/v1`（或你的域名）
- **API Key**：Sub2API 管理后台分配的 API Key

### 模式 B（Token 路由）

- **Base URL**：`http://<host>:18080/v1/__gw__/t/<TOKEN>`
- **API Key**：Sub2API 管理后台分配的 API Key

### 管理后台

如需通过 Caddy 暴露管理后台（不经网关），在 `Caddyfile` 中添加：

```caddy
panel.example.com {
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
