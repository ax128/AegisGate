# CLIProxyAPI 经网关中转 — 3 步接入

让现有 CLIProxyAPI 请求先经 AegisGate 安检再转发，**不改 CLIProxyAPI 代码**，**客户端零改动**（仍用原 base URL 和 API Key）。

## 请求链路

```
客户端 → https://api.example.com/v1/... → Caddy → AegisGate(安检) → cli-proxy-api:8317
```

## 两种部署模式

| 模式 | 命令 | 说明 |
|------|------|------|
| **基础模式** | `docker compose up -d --build` | 仅 AegisGate，不启用 CLIProxyAPI / Caddy |
| **ProxyAPI 模式** | `docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml up -d --build` | AegisGate + CLIProxyAPI + Caddy 完整栈 |

## 1. 克隆 CLIProxyAPI 到 AegisGate 目录下

```bash
cd ~/AegisGate
git clone https://github.com/router-for-me/CLIProxyAPI.git
```

目录结构：

```
AegisGate/
  CLIProxyAPI/          # git clone 的 API 项目（内容由 CLIProxyAPI 自身管理）
    config.yaml         # CLIProxyAPI 配置（首次需从 config.example.yaml 复制）
    config.example.yaml
    auths/              # OAuth 认证文件（CLIProxyAPI 登录后自动生成）
    logs/               # CLIProxyAPI 日志
    Dockerfile          # 用于 docker build
    ...
  Caddyfile             # Caddy 反代配置（在 AegisGate 根目录）
  docker-compose.yml    # 基础模式
  docker-compose.cliproxy.yml  # ProxyAPI 叠加栈
```

初始化配置：

```bash
cp CLIProxyAPI/config.example.yaml CLIProxyAPI/config.yaml
# 编辑 CLIProxyAPI/config.yaml 配置你的 API Keys 等参数
```

## 2. 启动

```bash
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml up -d --build
```

compose 已把网关上游设为 `http://cli-proxy-api:8317/v1`，API 请求会默认走网关再转 CLIProxyAPI。

CLIProxyAPI 从本地源码构建 Docker 镜像，无需拉取远程镜像。

首次启动后，网关会自动生成 `gateway_key`（保存在 `config/aegis_gateway.key`）：

```bash
cat config/aegis_gateway.key
```

## 3. 客户端

**无需改任何配置**。继续使用：

- **Base URL**：`https://api.example.com/v1`（或你的域名）
- **API Key**：CLIProxyAPI 的 `config.yaml` 里配置的 `api-keys` 之一

管理后台仍直连：`https://panel.example.com/management.html`（不经网关）。

## 4. 更新 CLIProxyAPI

```bash
git -C ./CLIProxyAPI pull
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml up -d --build
```

## 5. CLIProxyAPI 登录认证

```bash
# Claude 登录
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml exec cli-proxy-api /CLIProxyAPI/CLIProxyAPI -no-browser --claude-login

# Gemini 登录
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml exec cli-proxy-api /CLIProxyAPI/CLIProxyAPI -no-browser --login
```

## 6. 流式与长上下文（已内置）

compose 已预置以下能力：
- 流式传输：Caddy `flush_interval -1`，SSE 不缓冲，网关保留断流 `[DONE]` 恢复。
- 长上下文：提高请求体/消息条数/单条消息/响应长度上限。
- 高负载稳定性：开启 `AEGIS_ENABLE_THREAD_OFFLOAD=true`，避免过滤管道阻塞 event loop。

如需更高阈值，可在 `docker-compose.cliproxy.yml`（`aegisgate.environment`）继续上调这些环境变量：
`AEGIS_MAX_REQUEST_BODY_BYTES`、`AEGIS_MAX_MESSAGES_COUNT`、`AEGIS_MAX_CONTENT_LENGTH_PER_MESSAGE`、`AEGIS_MAX_RESPONSE_LENGTH`、`AEGIS_FILTER_PIPELINE_TIMEOUT_S`。

---

## 可选：多上游 / Token 模式

需要多套上游或按 token 区分时，仍可使用 `/__gw__/register` 与 `/v1/__gw__/t/{token}/...`；未配置默认上游时，`/v1` 与 `/v2` 都会要求走 token 路径。

注意：
- CLIProxy 叠加栈使用的 `Caddyfile` 默认会对公网域名阻断 `/__gw__/*`。请通过 `http://127.0.0.1:18080`（本机）或内网管理入口调用注册接口。
- `v2` 通用代理始终建议走 token 路径：`/v2/__gw__/t/{token}/...`，并在 Header 里携带 `x-target-url`。
