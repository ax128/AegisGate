# AegisGate Web UI 使用说明

AegisGate 提供本地 Web UI，适合作为单机或内网环境下的轻量控制面。

## 1. 适用场景

- 本机启动 AegisGate 后，通过浏览器查看状态、配置和 Token
- 不想每次都手动改 `config/.env` 或调用管理接口
- 通过 SSH 隧道远程访问服务器上的本地控制台

## 2. 启动方式

推荐使用仓库根目录的一键启动器：`aegisgate-local.py`

```bash
# 首次安装依赖
python aegisgate-local.py install

# 初始化本地配置
python aegisgate-local.py init

# 后台启动网关
python aegisgate-local.py start
```

默认地址：

```text
API: http://127.0.0.1:18080
UI:  http://127.0.0.1:18080/__ui__/login
```

常用命令：

```bash
python aegisgate-local.py status
python aegisgate-local.py logs --tail 50
python aegisgate-local.py stop
```

如果你使用手动开发方式，也可以直接运行：

```bash
uvicorn aegisgate.core.gateway:app --host 127.0.0.1 --port 18080 --reload
```

## 3. 登录方式

- 登录入口：`http://127.0.0.1:18080/__ui__/login`
- 登录密码：`config/aegis_gateway.key` 文件内容

> **安全提示**：当前版本不再提供默认初始密码。Web UI 登录始终使用真实的网关密钥。

查看网关密钥：

```bash
cat config/aegis_gateway.key
```

### 3.1 UI API 会话与 CSRF

当前 UI 的接口契约如下：

- 登录接口：`POST /__ui__/api/login`
- 登录请求体：`{"password":"<gateway_key>"}`；成功后只会下发 UI session cookie
- 登录后应调用 `GET /__ui__/api/bootstrap`，从返回的 `ui.csrf_token` 读取当前会话的 CSRF token
- 对 `__ui__/api/*` 的非只读请求（除 `POST /__ui__/api/login` 外的 `POST`/`PUT`/`PATCH`/`DELETE` 等），都必须携带请求头 `x-aegis-ui-csrf: <token>`
- 只读接口（`GET` / `HEAD` / `OPTIONS`）不需要这个 Header

如果缺少或使用了错误的 CSRF token，服务端会返回 `403 ui_csrf_invalid`。

示例流程：

```bash
# 1) 登录，保存 cookie
curl -X POST http://127.0.0.1:18080/__ui__/api/login \
  -H "Content-Type: application/json" \
  -c /tmp/aegisgate-ui.cookie \
  -d '{"password":"<YOUR_GATEWAY_KEY>"}'

# 2) 读取 bootstrap，取得 ui.csrf_token
curl http://127.0.0.1:18080/__ui__/api/bootstrap \
  -b /tmp/aegisgate-ui.cookie

# 3) 发起写操作时携带 x-aegis-ui-csrf
curl -X POST http://127.0.0.1:18080/__ui__/api/config \
  -H "Content-Type: application/json" \
  -H "x-aegis-ui-csrf: <BOOTSTRAP_RETURNED_TOKEN>" \
  -b /tmp/aegisgate-ui.cookie \
  -d '{"values":{"enable_local_port_routing":true}}'
```

## 4. UI 能力

- 查看服务状态、监听地址、安全级别、默认上游
- 编辑**主要**运行参数（基础设置、安全设置、v2 代理、功能开关、限流阈值等）
- 安全过滤规则增删改查（PII 规则、工具注入规则、命令规则、动作映射）
- Token 管理：注册/编辑/删除/重命名
- 密钥管理：查看/更换 `aegis_gateway.key`、`aegis_proxy_token.key`、`aegis_fernet.key`
- Docker Compose 配置文件在线编辑
- 一键重启网关（SIGTERM，配合 Docker `restart: unless-stopped` 自动恢复）
- 阅读仓库内嵌 Markdown 文档

## 5. 安全说明

- Web UI 默认只允许本机访问
- 如需允许内网访问，需要显式设置 `AEGIS_LOCAL_UI_ALLOW_INTERNAL_NETWORK=true`
- 不建议把 `__ui__` 直接暴露到公网
- 登录密码与管理接口使用同一份网关密钥，请妥善保管 `config/aegis_gateway.key`

## 6. 远程服务器访问

如果 AegisGate 部署在远程机器上，推荐通过 SSH 隧道访问：

```bash
ssh -N -L 127.0.0.1:18080:127.0.0.1:18080 用户名@服务器IP
```

建立隧道后，在你自己的浏览器打开：

```text
http://127.0.0.1:18080/__ui__/login
```

## 7. 故障排查

- 打不开页面：先检查 `http://127.0.0.1:18080/health`
- 登录失败：确认 `config/aegis_gateway.key` 存在，且输入内容完整无多余空格
- 无法远程访问：确认你访问的是 SSH 转发后的本机地址，而不是服务器公网直接暴露的 `__ui__`
