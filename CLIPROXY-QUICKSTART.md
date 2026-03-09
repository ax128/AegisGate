# CLIProxyAPI 经网关中转 — 3 步接入

让现有 CLIProxyAPI 请求先经 AegisGate 安检再转发，**不改 CLIProxyAPI 代码**，**客户端零改动**（仍用原 base URL 和 API Key）。

## 请求链路

```
客户端 → https://api.example.com/v1/... → Caddy → AegisGate(安检) → cli-proxy-api:8317
```

## 1. 准备配置目录

在 AegisGate 项目下建一个目录，把 CLIProxyAPI 的配置放进去：

```bash
mkdir -p cli-proxy/auths cli-proxy/logs
cp /path/to/CLIProxyAPI/config.yaml cli-proxy/
# 若已有 OAuth 等认证文件，复制到 cli-proxy/auths/
```

目录结构：

```
AegisGate/
  cli-proxy/
    config.yaml   # 从 CLIProxyAPI 项目复制
    auths/        # 可选，认证文件
    logs/         # 可选，日志会写在这里
```

## 2. 启动

```bash
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml up -d --build
```

compose 已把网关上游设为 `http://cli-proxy-api:8317/v1`，API 请求会默认走网关再转 CLIProxyAPI。

首次启动后，网关会自动生成 `gateway_key`（保存在 `config/aegis_gateway.key`）。如需手动注册 token 或调用管理接口，需查看此 key：

```bash
cat config/aegis_gateway.key
```

## 3. 客户端

**无需改任何配置**。继续使用：

- **Base URL**：`https://api.example.com/v1`（或你的域名）
- **API Key**：CLIProxyAPI 的 `config.yaml` 里配置的 `api-keys` 之一

管理后台仍直连：`https://panel.example.com/management.html`（不经网关）。

## 4. 流式与长上下文（已内置）

compose 已预置以下能力：
- 流式传输：Caddy `flush_interval -1`，SSE 不缓冲，网关保留断流 `[DONE]` 恢复。
- 长上下文：提高请求体/消息条数/单条消息/响应长度上限。
- 高负载稳定性：开启 `AEGIS_ENABLE_THREAD_OFFLOAD=true`，避免过滤管道阻塞 event loop。

如需更高阈值，可在 `docker-compose.cliproxy.yml`（`aegisgate.environment`）继续上调这些环境变量：
`AEGIS_MAX_REQUEST_BODY_BYTES`、`AEGIS_MAX_MESSAGES_COUNT`、`AEGIS_MAX_CONTENT_LENGTH_PER_MESSAGE`、`AEGIS_MAX_RESPONSE_LENGTH`、`AEGIS_FILTER_PIPELINE_TIMEOUT_S`。

---

## 可选：自定义路径

若不想用 `./cli-proxy/`，可设置环境变量后再启动 CLIProxy 叠加栈：

```bash
export CLI_PROXY_CONFIG_PATH=/your/path/config.yaml
export CLI_PROXY_AUTH_PATH=/your/path/auths
export CLI_PROXY_LOG_PATH=/your/path/logs
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml up -d --build
```

## 可选：多上游 / Token 模式

需要多套上游或按 token 区分时，仍可使用 `/__gw__/register` 与 `/v1/__gw__/t/{token}/...`；未配置默认上游时，`/v1` 与 `/v2` 都会要求走 token 路径。

注意：
- CLIProxy 叠加栈使用的 `Caddyfile` 默认会对公网域名阻断 `/__gw__/*`。请通过 `http://127.0.0.1:18080`（本机）或内网管理入口调用注册接口。
- `v2` 通用代理始终建议走 token 路径：`/v2/__gw__/t/{token}/...`，并在 Header 里携带 `x-target-url`。
