# CLIProxyAPI 接入 AegisGate

> **前置条件**：请先按 [CLIProxyAPI 官方文档](https://github.com/router-for-me/CLIProxyAPI) 完成安装和配置，确认 CLIProxyAPI 本身可用（默认端口 8317）。

## 接入方式

CLIProxyAPI 独立运行，AegisGate 独立运行。客户端 Base URL 指向网关即可：

```
客户端 → AegisGate:18080 → CLIProxyAPI:8317
```

### 方式 1：端口路由（推荐，多上游共存）

客户端 Base URL 改为：
```
http://<网关地址>:18080/v1/__gw__/t/8317
```

网关自动转发到 `localhost:8317/v1`，客户端的 `Authorization` 头直接透传。

### 方式 2：直连上游（单上游）

在网关 `config/.env` 中设置：
```
AEGIS_UPSTREAM_BASE_URL=http://localhost:8317/v1
```

客户端 Base URL：`http://<网关地址>:18080/v1`

### 方式 3：Caddy 对外暴露

参见 [README.md 中的 Caddy 反代配置](README.md#caddy-反代配置对公网暴露时)。

管理后台建议单独域名直连 CLIProxyAPI，不经网关。
