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
python aegisgate-local.py restart
python aegisgate-local.py stop
python aegisgate-local.py open-ui      # 在浏览器中打开本地 UI
```

常用参数：

- `start --foreground`：前台运行，便于直接看日志
- `start --skip-install`：跳过 venv 安装步骤
- `install --extras semantic,redis`：安装可选依赖组
- `install --python /usr/bin/python3.12`：指定解释器
- `stop --graceful-seconds 8`：强杀前的等待时间

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

> 注意：`AEGIS_LOCAL_UI_SECURE_COOKIE=true`（默认）会下发 `Secure` cookie。`curl -c/-b` 在 `http://127.0.0.1` 下通常不会回传该 cookie，导致后续 UI API 调用返回 401。用 `curl` 调试 UI API 时建议临时设置 `AEGIS_LOCAL_UI_SECURE_COOKIE=false` 后重启网关，或在 HTTPS 下访问。

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
- 编辑**主要**运行参数（基础设置、安全设置、v2 代理、功能开关、限流阈值等，共 59 项）
- 安全过滤规则增删改查（PII 规则、工具注入规则、命令规则、动作映射）
- 精确值脱敏列表（exact-value redaction）增删改查
- 请求统计仪表盘：总请求、脱敏替换、危险内容替换、拦截、穿透五个维度，按小时/按天查看
- Token 管理：注册/编辑/删除/重命名
- 密钥管理：查看/更换 `aegis_gateway.key`、`aegis_proxy_token.key`、`aegis_fernet.key`
- Docker Compose 配置文件在线编辑
- 一键重启网关（SIGTERM，配合 Docker `restart: unless-stopped` 自动恢复）
- 阅读仓库内嵌 Markdown 文档

### 4.1 哪些配置改完需要重启

保存配置会写入 `config/.env` 并触发热更新，但少数安全关键项在启动时固定，热更新不会生效。UI 上可编辑、却**需要重启才生效**的有三项：

- `AEGIS_SECURITY_LEVEL`（安全级别）
- `AEGIS_ENFORCE_LOOPBACK_ONLY`（仅本机访问）
- `AEGIS_TRUSTED_PROXY_IPS`（可信反向代理 IP）

改完这三项，请用本页的「重启网关」按钮，或执行 `docker compose restart aegisgate` / `python aegisgate-local.py restart`。完整的不可热更新清单见 [config/README.md](config/README.md) 的「热更新说明」。

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
