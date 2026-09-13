# 上游接入 AegisGate（CLIProxyAPI / Sub2API / AIClient-2-API）

> **前置条件**：请先按上游的官方文档完成安装和配置，确认上游本身可用，再接入网关。AegisGate 是独立的安全代理层，不管理也不约束上游服务。

## 已验证的上游

| 上游 | 官方文档 | 默认端口 | Docker 服务名 |
|------|----------|:--------:|---------------|
| CLIProxyAPI | https://github.com/router-for-me/CLIProxyAPI | 8317 | `cli-proxy-api` |
| Sub2API | https://github.com/Wei-Shaw/sub2api | 8080 | `sub2api` |
| AIClient-2-API | https://github.com/justlovemaki/AIClient-2-API | 3000 | `aiclient2api` |
| 任意 OpenAI 兼容 API | — | 自定 | — |

下文用 `<PORT>` 表示上表中的默认端口，用 `<SERVICE>` 表示 Docker 服务名。

## 同机部署（网关与上游在同一台服务器）

客户端 Base URL 改为：

```
http://<网关IP>:18080/v1/__gw__/t/<PORT>
```

完成。客户端 `Authorization` 头直接透传到上游，无需注册 token、无需编辑配置、无需重启网关。

对应到三个上游：

| 上游 | 客户端 Base URL |
|------|-----------------|
| CLIProxyAPI | `http://<网关IP>:18080/v1/__gw__/t/8317` |
| Sub2API | `http://<网关IP>:18080/v1/__gw__/t/8080` |
| AIClient-2-API | `http://<网关IP>:18080/v1/__gw__/t/3000` |

说明：

- **安全默认**：纯数字端口 token（1024–65535，如 `8317`）默认按**仅内网**处理。对公网暴露请改用 `/__gw__/register` 注册随机 token（推荐），或启用请求 HMAC，或显式放开 `AEGIS_ALLOW_PUBLIC_NUMERIC_TOKENS=true`。
- 端口路由需要 `AEGIS_ENABLE_LOCAL_PORT_ROUTING=true`。仓库自带 Docker Compose 默认开启；裸机部署需显式开启，并把 `AEGIS_LOCAL_PORT_ROUTING_HOST` 改为 `127.0.0.1`。
- 端口路由通过 `host.docker.internal:<PORT>` 访问宿主机，因此**上游端口必须映射到宿主机**。

### Docker 服务映射（优先级高于端口回退）

仓库自带 Compose 默认注入：

```
AEGIS_DOCKER_UPSTREAMS=8317:cli-proxy-api,8080:sub2api,3000:aiclient2api
```

这些映射会生成 `<PORT> -> http://<SERVICE>:<PORT>/v1` 的 token 绑定，**优先级高于同名数字端口回退**。它们只有在 AegisGate 容器与上游共享 Docker 网络、且能解析对应服务名时才生效。

仓库自带 Compose 默认只附加 CLIProxyAPI 与 Sub2API 的外部网络。因此：

- `8317:cli-proxy-api`、`8080:sub2api` 在补齐外部网络后可直接工作。
- `3000:aiclient2api` **默认不可用**——需要你自行补齐网络连通性，否则应移除该映射并改用主机端口路由。
- 如果容器无法解析或访问服务名，请优先把上游端口映射到宿主机并使用端口路由。

## 远程部署（网关与上游不在同一台服务器）

端口路由不可用，需注册 token 绑定远程地址：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"http://远程IP:<PORT>/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

其中 `gateway_key` 的值为 `cat config/aegis_gateway.key` 的输出内容。

客户端使用返回的 token：`http://<网关IP>:18080/v1/__gw__/t/<token>`

也可以直接编辑 `config/gw_tokens.json`（参考 `config/gw_tokens.json.example`）：

```json
{
  "tokens": {
    "remote-claude": {
      "upstream_base": "https://远程上游地址/v1",
      "whitelist_key": []
    }
  }
}
```

该文件在热重载 watcher 的监听范围内，保存后即时生效，**无需重启网关**。命名 token 的优先级高于数字端口回退。

## 整域名转发（baseUrl = 网关域名）

前面两节都把路由键放在 URL 路径里（`/v1/__gw__/t/...`）。如果客户端只允许改域名，可以用**按域名（Host）路由**：客户端 baseUrl 直接用网关域名，形状与上游原始地址一致。

```
客户端 → https://api.ag.example.com/v1/chat/completions → AegisGate:18080 → http://127.0.0.1:8317/v1/chat/completions
```

### 1. 启动态开关

```bash
# config/.env
AEGIS_ENABLE_GATEWAY_FORWARD=true
# 前面有 Caddy/Nginx 时必填，否则任何 X-Forwarded-For 都会被当成公网客户端
AEGIS_TRUSTED_PROXY_IPS=127.0.0.1
# 可选：允许 public 规则关闭基线脱敏（默认 false）
AEGIS_FORWARD_ALLOW_PUBLIC_BASELINE_OFF=false
```

`AEGIS_ENABLE_GATEWAY_FORWARD` 与 `AEGIS_FORWARD_ALLOW_PUBLIC_BASELINE_OFF` 在启动时固定，改完需重启。

### 2. 规则文件（或控制台面板）

`config/gw_forwards.json`（模板：`config/gw_forwards.json.example`），或直接使用控制台「网关转发」面板。`upstream_base` 填上游**根地址，不带 `/v1`**；整个域名的路径原样透传。

```json
{
  "version": 1,
  "forwards": {
    "api.ag.example.com": {
      "enabled": true,
      "upstream_base": "http://127.0.0.1:8317",
      "note": "CLIProxyAPI 同机",
      "expose": "internal",
      "filters": { "mode": "policy" }
    }
  }
}
```

该文件也在热重载监听范围内，保存即生效（无需重启）；启动开关除外。

### 3. 客户端

Base URL 改为 `https://api.ag.example.com`（前缀 `http://` 则为 `http://api.ag.example.com:18080`）。`Authorization` 仍由客户端自带并透传给上游。

### 4. 分流规则

| 请求 | 落点 |
|------|------|
| `POST /v1/chat/completions`、`/v1/responses`、`/v1/messages` | 网关 V1 管线，按规则的过滤开关处理 |
| 其余全部路径与方法（含其它 `/v1` POST、`/v2/*`、`/relay/*`、上游管理台、OAuth 回调、静态资源） | 原样转发到 `upstream_base`，不过滤 |
| `/__ui__`、`/__gw__`、`/metrics`、`/health`、`/ready`、`/`、`/robots.txt`、`/favicon.ico` | 网关自身，永不转发（上游同名路径会被遮蔽） |

每条规则可单独开关 13 个过滤器（`filters.mode: "custom"`），能打开全局关掉的、也能关掉全局开着的。基线是 `redaction` 与 `exact_value_redaction`。

### 5. 安全前提（必读）

- **本层不鉴权，只选目的地。** 网关只是把请求送到规则指定的上游；真实凭据是客户端的 `Authorization`。`expose` 默认 `internal`（仅内网客户端）；要开放公网必须显式写 `public`。
- **`AEGIS_ENABLE_REQUEST_HMAC_AUTH=true` 与转发互斥**：HMAC 会强制所有非 passthrough 请求带签名，浏览器无法提供；两者同开时转发表拒绝加载并在日志打 ERROR。
- `public` 规则关闭基线脱敏需要启动态 `AEGIS_FORWARD_ALLOW_PUBLIC_BASELINE_OFF=true`，否则该条目直接判为非法（`_denied`，请求 403），并在日志打 ERROR。
- 配置文件解析失败 / `version` 不是 `1` / 顶层结构非法时，**上一份有效规则的全部 host 一律 403**（`forward_config_invalid`），不会静默回落到默认上游；单条非法只影响该 host。
- 无 `Content-Length` 的上传会被 boundary 缓冲到 `AEGIS_FORWARD_MAX_REQUEST_BODY_BYTES`（默认 64MB）；大文件上游需客户端带 `Content-Length`。
- 转发域名上的 `/v2/*`、`/relay/*` 一律透传，**不**进入网关自己的 v2/relay 路由，也不受本面板开关控制。

### 6. Caddy 示例（泛域名）

```caddyfile
*.gw.example.com {
    # 管理面永不出网
    @gw_admin path /__gw__ /__gw__/* /__ui__ /__ui__/*
    respond @gw_admin "forbidden" 403

    reverse_proxy 127.0.0.1:18080 {
        header_up Host {host}
        header_up X-Forwarded-Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote_host}
        flush_interval -1
        transport http {
            response_header_timeout 660s
            read_timeout 660s
            write_timeout 660s
        }
    }
}
```

注意这里是**整域名转发**，所以不能像 [Caddyfile.example](Caddyfile.example) 的 token 场景那样只放行 `/v1/*` 与 `/v2/*`——上游管理台、OAuth 回调、静态资源都要能到达网关。完整的两种形态对照见 [Caddyfile.example](Caddyfile.example)。

## Caddy 对外暴露

形态：

```
客户端 → https://api.example.com/v1/__gw__/t/<token>/... → Caddy → AegisGate:18080 → localhost:<PORT>
```

参见 [Caddyfile.example](Caddyfile.example)。要点：

- `/__gw__/*` 返回 403，管理接口不暴露到公网；示例里 `/v1/*`、`/v2/*` 之外的路径一律 404，因此 `__ui__` 也不会被暴露。
- `flush_interval -1` 必须设置，否则 SSE 流式会被缓冲。
- `response_header_timeout 660s`：长时间推理不超时。
- 同时在网关侧设 `AEGIS_TRUSTED_PROXY_IPS=127.0.0.1`（或你的 Caddy 地址）。默认 `AEGIS_XFF_STRICT_INTERNAL=true` 下，可信代理列表为空时任何 `X-Forwarded-For` 都会让请求被当成公网客户端。
- 对公网暴露时使用随机注册 token；纯数字端口 token 与 `__passthrough` 默认会被公网/非内网客户端拒绝。
- Caddy 只做 TLS + 转发，路由逻辑全在网关内部。
- 上游自己的管理后台建议用单独域名直连上游（CLIProxyAPI 8317 / Sub2API 8080 / AIClient-2-API 3000），不经网关。

## 更多

- 过滤模式（`__redact` / `__passthrough`）、协议转换、完整环境变量：[README_zh.md](README_zh.md)
- 终端与 IDE 客户端接入：[OTHER_TERMINAL_CLIENTS_USAGE.md](OTHER_TERMINAL_CLIENTS_USAGE.md)
- 本地 Web 控制台：[WEBUI-QUICKSTART.md](WEBUI-QUICKSTART.md)
