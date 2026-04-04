# CLIProxyAPI 接入 AegisGate

> **前置条件**：请先按 [CLIProxyAPI 官方文档](https://github.com/router-for-me/CLIProxyAPI) 完成安装和配置，确认可用（默认端口 8317）。

## 同机部署（网关与 CLIProxyAPI 在同一台服务器）

客户端 Base URL 改为：

```
http://<网关IP>:18080/v1/__gw__/t/8317
```

完成。客户端 `Authorization` 头直接透传到 CLIProxyAPI。

说明：

- 若你使用仓库自带 Docker Compose，`8317` 可能优先命中启动时注入的 `AEGIS_DOCKER_UPSTREAMS=8317:cli-proxy-api`，而不是主机端口回退。
- 这个 Docker 服务映射只有在 AegisGate 容器与 CLIProxyAPI 共享网络、且能解析 `cli-proxy-api` 服务名时才生效。
- 若没有共享网络，请把 CLIProxyAPI 端口映射到宿主机，并启用/保留本地端口路由。

## 远程部署（不在同一台服务器）

注册 token 绑定远程地址：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"http://远程IP:8317/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

其中 `gateway_key` 的值为 `cat config/aegis_gateway.key` 输出内容。

客户端使用返回的 token：`http://<网关IP>:18080/v1/__gw__/t/<token>`

## Caddy 对外暴露

参见 [README.md — Caddy + 网关对公网暴露](README.md#场景三caddy--网关对公网暴露)。

管理后台建议单独域名直连 CLIProxyAPI，不经网关。
