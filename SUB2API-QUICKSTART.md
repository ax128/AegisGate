# Sub2API 接入 AegisGate

> **前置条件**：请先按 [Sub2API 官方文档](https://github.com/Wei-Shaw/sub2api) 完成安装和配置，确认可用（默认端口 8080）。

## 同机部署（网关与 Sub2API 在同一台服务器）

客户端 Base URL 改为：

```
http://<网关IP>:18080/v1/__gw__/t/8080
```

完成。客户端 `Authorization` 头直接透传到 Sub2API。

说明：

- 安全默认：纯数字端口 token（如 `8080`）仅内网可用；对公网暴露请改用 `/__gw__/register` 注册随机 token（推荐），或启用请求 HMAC / 显式放开 `AEGIS_ALLOW_PUBLIC_NUMERIC_TOKENS=true`。
- 若你使用仓库自带 Docker Compose，`8080` 可能优先命中启动时注入的 `AEGIS_DOCKER_UPSTREAMS=8080:sub2api`，而不是主机端口回退。
- 这个 Docker 服务映射只有在 AegisGate 容器与 Sub2API 共享网络、且能解析 `sub2api` 服务名时才生效。
- 若没有共享网络，请把 Sub2API 端口映射到宿主机，并启用/保留本地端口路由。

## 远程部署（不在同一台服务器）

注册 token 绑定远程地址：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"http://远程IP:8080/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

其中 `gateway_key` 的值为 `cat config/aegis_gateway.key` 输出内容。

客户端使用返回的 token：`http://<网关IP>:18080/v1/__gw__/t/<token>`

## Caddy 对外暴露

参见 [Caddyfile.example](Caddyfile.example)。

管理后台建议单独域名直连 Sub2API（端口 8080），不经网关。
