# Sub2API 接入 AegisGate

> **前置条件**：请先按 [Sub2API 官方文档](https://github.com/Wei-Shaw/sub2api) 完成安装和配置，确认可用（默认端口 8080）。

## 同机部署（网关与 Sub2API 在同一台服务器）

客户端 Base URL 改为：

```
http://<网关IP>:18080/v1/__gw__/t/8080
```

完成。客户端 `Authorization` 头直接透传到 Sub2API。

## 远程部署（不在同一台服务器）

注册 token 绑定远程地址：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat config/aegis_gateway.key)" \
  -d '{"upstream_base":"http://远程IP:8080/v1","api_key":"你的API-Key"}'
```

客户端使用返回的 token：`http://<网关IP>:18080/v1/__gw__/t/<token>`

## Caddy 对外暴露

参见 [README.md — Caddy + 网关对公网暴露](README.md#场景三caddy--网关对公网暴露)。

管理后台建议单独域名直连 Sub2API（端口 8080），不经网关。
