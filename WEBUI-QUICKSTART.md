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

查看网关密钥（登录页的「怎么拿到网关密钥？」里也有这两条命令，可直接复制）：

```bash
# 裸机 / 本机部署
cat config/aegis_gateway.key

# Docker 部署：这个路径在容器内，宿主机上直接 cat 是拿不到的
docker compose exec aegisgate cat config/aegis_gateway.key
```

### 3.0 登录成功却弹回登录页？

`AEGIS_LOCAL_UI_SECURE_COOKIE` 默认为 `true`，会下发 `Secure` cookie。浏览器只在 HTTPS 或 `localhost` 下保存这类 cookie，所以用 `http://<内网 IP>` 或 HTTP 反向代理访问时，登录本身成功、cookie 却被丢弃，跳转会立刻退回登录页。

登录页会先验证会话再跳转，遇到这种情况直接把原因写在错误区。两种处理方式：改用 HTTPS 访问，或把 `AEGIS_LOCAL_UI_SECURE_COOKIE=false` 后重启网关（仅建议在受信网络里这么做）。

### 3.1 UI API 会话与 CSRF

当前 UI 的接口契约如下：

- 登录接口：`POST /__ui__/api/login`
- 登录请求体：`{"password":"<gateway_key>"}`；成功后只会下发 UI session cookie
- 登录后应调用 `GET /__ui__/api/bootstrap`，从返回的 `ui.csrf_token` 读取当前会话的 CSRF token
- 对 `__ui__/api/*` 的非只读请求（除 `POST /__ui__/api/login` 外的 `POST`/`PUT`/`PATCH`/`DELETE` 等），都必须携带请求头 `x-aegis-ui-csrf: <token>`
- 只读接口（`GET` / `HEAD` / `OPTIONS`）不需要这个 Header

如果缺少或使用了错误的 CSRF token，服务端会返回 `403 ui_csrf_invalid`。

### 3.2 乐观并发（If-Match / ETag）

以下六类资源都是整文件读改写，`GET` 都会返回 `ETag`：配置、安全规则、动作映射、compose 文件、精确值脱敏、请求侧脱敏设置（`/__ui__/api/request_redaction/settings`）。

```bash
curl -sD - -o /dev/null http://127.0.0.1:18080/__ui__/api/rules/pii_patterns -b cookie.txt | grep -i etag
# etag: "997c45e1092faae6d9432a6e4e9f70d7"
```

写请求带上 `If-Match: <etag>` 后，若期间该资源已被其他会话改动，服务端返回 `409 etag_mismatch` 并附带 `current_etag`，从而避免覆盖对方的改动：

```bash
curl -X POST http://127.0.0.1:18080/__ui__/api/rules/pii_patterns \
  -H "Content-Type: application/json" \
  -H "x-aegis-ui-csrf: <TOKEN>" \
  -H 'If-Match: "997c45e1092faae6d9432a6e4e9f70d7"' \
  -b cookie.txt -d '{"id":"MY_RULE","regex":"..."}'
```

`If-Match` 的要求**分两层**，Web UI 两层都始终携带：

| 端点 | `If-Match` | 不带该头时 |
| --- | --- | --- |
| `/__ui__/api/config`、`/__ui__/api/rules/*`、`/__ui__/api/rules_action_map`、`/__ui__/api/compose/*`、`/__ui__/api/redact_values` | **有则校验、无则放行** | 行为与加该头之前完全一致，既有脚本无需改动 |
| `PATCH /__ui__/api/request_redaction/settings` | **强制**，必须是具体的 ETag 值 | 直接拒绝 |

这条端点强制要求是有意为之：它是新增端点，不存在早于该头的客户端；而它的每个操作都在重写调用方当时正看着的那份列表（relaxed 集成员、自定义规则物化、清理失效引用），"没带头就按当前内容写"在这里等同于盲写。

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

- **首次上手引导**：概览页给出「登录 → 注册上游 Token → 复制 Base URL」三步清单，未完成的那一步直接带动作按钮；已有 Token 或已配置 `AEGIS_UPSTREAM_BASE_URL` 时自动折叠
- 查看服务状态、监听地址、安全级别、默认上游
- 编辑运行参数，共 100 项，按 8 个分区呈现：基础设置、存储与保留、限额与超时、安全策略、访问控制、协议转换与路由、v2 代理、控制台
  - 侧栏顶部有**全局搜索**，一次过滤全部 8 个分区，无命中的分区连同导航项一起折叠；快捷键 `/` 聚焦当前可见分区的搜索框
  - 每个分区带搜索框；字段按用途分组，并标注对应的环境变量名与默认值
  - 当前值与默认值不同的字段带 **已改** 徽章，旁边有「恢复默认」（只回填表单，仍需点保存）
  - 有未保存改动时保存按钮显示「（N 项待保存）」，离开页面前会提示
  - 未开放编辑的 4 项：`app_name`、`gateway_key`（走密钥管理页）、`require_confirmation_on_block`（已废弃）、`internal_forwarding_kernel_rollout`（内部灰度开关）
- **请求侧脱敏**（独立面板，见 §4.3）：PII、字段级与精确值三类规则的总控、生效面与管理入口
- 安全过滤规则增删改查：规则工作台列出 `security_filters.yaml` 中的 **31 个规则组**（193 条规则）
  - 该文件实际有 32 组 / 249 条。差额是 `redaction.pii_patterns`（56 条 PII 规则），已由「请求侧脱敏」面板接管，工作台不再列出它，以免同一条规则有两个写入口
  - `tool_call_guard.parameter_rules` 按 `tool`+`param` 而非 `id` 寻址，因此**只读**：可查看、不可增删改
  - 其余规则组由 YAML 结构自动发现，往文件里新增一组规则即可在控制台看到，无需改代码
  - 左侧按过滤器分组的规则树带条数；规则组与规则各有独立搜索框
  - 编辑框内置**正则试验场**：粘一段文本，实时高亮这条正则命中的位置
  - 动作映射（block / review / sanitize / pass）
- 请求统计仪表盘：总请求、脱敏替换、危险内容替换、拦截、穿透五个维度，按小时/按天查看
- **审计日志检索**：查询网关逐请求写下的结构化审计记录
  - 筛选：时间区间、路由、处置（allow / block / sanitize / review / pass）、最低风险分、安全标签、全文关键词
  - 概览卡片：样本数、拦截数、风险分分布、最活跃路由、最常见安全标签
  - 点击任意行展开完整 JSON；支持按当前筛选导出 JSONL / CSV
  - 反向分块读取并设有单次扫描字节上限，日志涨到几百 MB 也不会拖垮网关
  - 同页可浏览危险响应样本（按日期切分，默认只含 sha256 与长度，不含原文）
- Token 管理：注册/编辑/删除/重命名
  - 列表直接给出**客户端 Base URL**（`<origin>/v1/__gw__/t/<token>`）并支持一键复制
  - 上游地址即时校验：缺 `http(s)://`、缺主机名、带查询参数或 `#` 片段会当场拦下，填成 `/chat/completions` 这类具体端点会提示改回 base URL
  - 「测试连通性」按钮，见 §4.2
- 密钥管理：查看/更换 `aegis_gateway.key`、`aegis_proxy_token.key`、`aegis_fernet.key`
  - 读写位置与运行时加载密钥的位置是同一个：设了 `AEGIS_CONFIG_DIR` 就用它，否则用 `<工作目录>/config`。轮换 `aegis_fernet.key` 时旧密钥会存到 `aegis_fernet_prev.key`，旧密文在过渡窗口内仍可解
- Docker Compose 配置文件在线编辑
- 一键重启网关（SIGTERM，配合 Docker `restart: unless-stopped` 自动恢复）
- 阅读仓库内嵌 Markdown 文档（支持表格与链接渲染；默认打开本篇）

### 4.1 哪些配置改完需要重启

保存配置会写入 `config/.env` 并触发热更新，但安全关键项在启动时固定（`hot_reload._IMMUTABLE_FIELDS`），热更新不会生效。这类字段在配置页上带 **需重启** 徽章，保存后页面会给出提示条和「重启网关」按钮，不再报告一次并未发生的热重载。

配置页上可编辑、需要重启才生效的字段（即 `_IMMUTABLE_FIELDS` 的 12 项减去不在配置页开放的 `gateway_key`）：

- `AEGIS_SECURITY_LEVEL`（安全级别）
- `AEGIS_ENFORCE_LOOPBACK_ONLY`（仅本机访问）
- `AEGIS_TRUSTED_PROXY_IPS`（可信反向代理 IP）
- `AEGIS_XFF_STRICT_INTERNAL`（默认 `true`：带 `X-Forwarded-For` 且直连不在可信代理列表时，admin / 默认 `/v1` / UI 按公网处理）
- `AEGIS_V2_BLOCK_INTERNAL_TARGETS`（v2 SSRF 防护）
- `AEGIS_ALLOW_PUBLIC_NUMERIC_TOKENS`、`AEGIS_ALLOW_PUBLIC_PASSTHROUGH_MODE`、`AEGIS_ALLOW_PUBLIC_UPSTREAM_WHITELIST`（公网闸门）
- `AEGIS_ENABLE_REQUEST_HMAC_AUTH`、`AEGIS_REQUEST_HMAC_SECRET`（请求签名）
- `AEGIS_LOCAL_UI_ALLOW_INTERNAL_NETWORK`（控制台内网访问）

已写入 `.env` 但当前进程尚未采用的字段，会额外带 **待生效** 徽章，并显示 `.env` 中的新值而不是进程里的旧值。

改完这些项，请用本页的「重启网关」按钮，或执行 `docker compose restart aegisgate` / `python aegisgate-local.py restart`。**注意**：设了 `AEGIS_TRUSTED_PROXY_IPS` 之后，仅把 `AEGIS_XFF_STRICT_INTERNAL=false` **回滚不了** client IP 与限流键的变化；配置侧回退是清空该变量并重启。完整的不可热更新清单见 [config/README.md](config/README.md) 的「热更新说明」。

### 4.2 上游连通性测试

Token 表单里的「测试连通性」按钮对应 `POST /__ui__/api/tokens/probe`，由**网关**向你填的上游发一次请求，把结果直接显示在表单里。上游返回 `401` / `403` 会被标为正常——说明地址通了，只是要带上客户端自己的 API key。

这是控制台里唯一一个主动对外发起请求的接口，因此边界是收紧的：

- 目标先过注册用的同一套校验（`http(s)://`、有主机名、无查询参数与 `#` 片段、无内嵌凭据）
- 云元数据地址（`169.254.169.254`、`169.254.170.2`、`metadata.google.internal`、`metadata.goog`）直接拒绝，返回 `400 probe_target_forbidden`
- 单次请求：先 `HEAD`，仅当上游回 `405` / `501` 时退回 `GET`
- 不带任何凭据、不跟随重定向、3 秒硬超时
- 只返回 `{reachable, status_code, elapsed_ms}` 或失败原因，**不回传响应体**
- 与管理接口共用限流（`AEGIS_ADMIN_RATE_LIMIT_PER_MINUTE`），并需要有效会话与 `x-aegis-ui-csrf`
- 每次探测写审计事件 `ui_upstream_probe`（只记录主机名）

私网目标（`127.0.0.1`、`host.docker.internal`、局域网地址）**保持允许**：本地 Ollama / vLLM / LM Studio 正是这个页面最常配置的上游，而能进控制台的人本来就能注册这个地址并让网关向它转发。

```bash
curl -X POST http://127.0.0.1:18080/__ui__/api/tokens/probe \
  -H "Content-Type: application/json" \
  -H "x-aegis-ui-csrf: <TOKEN>" \
  -b /tmp/aegisgate-ui.cookie \
  -d '{"upstream_base":"https://api.openai.com/v1"}'
# {"ok":true,"reachable":true,"status_code":401,"elapsed_ms":214}
```

### 4.3 请求侧脱敏面板

请求侧脱敏散落在多个执行层，"这条规则到底在哪些请求上生效"过去只能靠读代码回答。这个面板把答案集中呈现，**且全部由服务端计算后下发**——浏览器不自行推导任何生效面，否则就会出现第二份判定逻辑，和请求路径用的那份各自漂移。

面板分六块：

| 区块 | 内容 |
| --- | --- |
| 总控与状态 | 四个总控开关各自真正控制哪一层执行面；规则文件路径解析结果与热重载状态 |
| 生效面 | 六个执行面各自使用哪套 PII 集合（见下表） |
| PII 规则 | 增删改查，外加两个正交控件：**启用**、**在 relaxed 集内** |
| Field 规则 | 按实际行为**只读**展示；本期不提供逐条启停或范围控制 |
| 豁免与绕过 | 字段级白名单（`whitelist_key`）与上游白名单各自的前置条件，按路由分别说明 |
| 精确值 | 精确值脱敏列表的增删改查（原独立入口已并入此处，`#redact-values` 书签仍可用） |

六个执行面与各自使用的规则集：

| 执行面 | 范围 | 使用的 PII 集合 |
| --- | --- | --- |
| E1 管道层 · 对话路由 | `/v1/chat/completions`、`/v1/responses`、`/v1/messages` | relaxed（可配） |
| E2 管道层 · 其他路由 | 含 multipart、通用 JSON | 全量 |
| E3 转发层 · 对话消息 / `system` / `instructions` / 工具定义 | 同 E1 三条路由 | relaxed（可配） |
| E4 转发层 · multipart 表单字段 | `/v1/files`、`/v1/images/*` | 全量 |
| E5 转发层 · 通用 `/v1/<子路径>` JSON | embeddings、rerank 等 | 全量 |
| E6 v2 请求体 | `/v2/__gw__/t/<token>/...` | relaxed（可配，与 E1/E3/E4 同一套） |

六个执行面都**按路由**取集合，打分与改写用同一条判据。此前转发层按消息**角色**推导，而所有真实角色都在 relaxed 角色集里——等价于"永远 relaxed"，于是 multipart（非低误报路由）出现了"用全量集打分、用 relaxed 集改写"的分歧。

`field_value_patterns` 是独立于 relaxed 集的一层：只要该执行面跑脱敏，field 规则就跑，不受 `relaxed_pii_ids` 增删影响。

写接口是 `PATCH /__ui__/api/request_redaction/settings`，只接受具名的领域操作（`set_mode`、`set_membership`、`materialize_custom`、`remove_unresolved`）加三个标量值，不接受任意 key path；每个操作都在写事务内、对着锁下读到的那份文档重新校验。该端点**强制** `If-Match`，见 §3.2。

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
