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
