# AIClient-2-API 接入 AegisGate

> **前置条件**：请先按 [AIClient-2-API 官方文档](https://github.com/justlovemaki/AIClient-2-API) 完成安装和配置，确认可用（默认端口 3000）。

## 同机部署（网关与 AIClient-2-API 在同一台服务器）

客户端 Base URL 改为：

```
http://<网关IP>:18080/v1/__gw__/t/3000
```

完成。客户端 `Authorization` 头直接透传到 AIClient-2-API。

说明：

- 安全默认：纯数字端口 token（如 `3000`）仅内网可用；对公网暴露请改用 `/__gw__/register` 注册随机 token（推荐），或启用请求 HMAC / 显式放开 `AEGIS_ALLOW_PUBLIC_NUMERIC_TOKENS=true`。
- 仓库自带 Docker Compose 默认也会注入 `AEGIS_DOCKER_UPSTREAMS=3000:aiclient2api`，但默认**不会**同时附加 AIClient-2-API 的共享网络。
- 如果 AegisGate 容器无法解析或访问 `aiclient2api`，这个服务映射不会生效；此时应优先把 AIClient-2-API 的 `3000` 端口映射到宿主机，并使用本地端口路由。
- 如果你自行补齐了共享网络，也可以保留 `3000:aiclient2api` 这种 Docker 服务映射。

## 远程部署（不在同一台服务器）

注册 token 绑定远程地址：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"http://远程IP:3000/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

其中 `gateway_key` 的值为 `cat config/aegis_gateway.key` 输出内容。

客户端使用返回的 token：`http://<网关IP>:18080/v1/__gw__/t/<token>`

## Caddy 对外暴露

参见 [Caddyfile.example](Caddyfile.example)。

管理后台建议单独域名直连 AIClient-2-API（端口 3000），不经网关。
