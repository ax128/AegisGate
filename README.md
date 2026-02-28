# AegisGate

AegisGate 是一个面向 LLM 调用链的安全网关。业务方把 `baseUrl` 指向网关，网关在请求/响应两侧执行安全策略，再转发到真实上游模型。

核心目标：
- 统一入口：把安全策略集中在网关层，而不是散落在各个 Agent/应用里。
- 降低泄露面：请求侧脱敏与输入清洗、响应侧风险检测与阻断。
- 可追踪：统一审计、风险标签、确认放行流程（yes/no）。

## Agent Skill

给 Agent 直接执行的安装与接入手册：  
- [SKILL.md](SKILL.md)

## 1. 主要能力

- OpenAI 兼容接口：
  - `POST /v1/chat/completions`
  - `POST /v1/responses`
  - `POST /v1/{subpath}` 通用代理
- v2 通用 HTTP 代理（独立安全链路）：
  - `ANY /v2` / `ANY /v2/{subpath}`
  - 必须携带原始目标头（兼容 `x-target-url` / `x-original-url`，优先读取 `AEGIS_V2_ORIGINAL_URL_HEADER`）
  - 请求侧仅做脱敏（可开关，默认开）
  - 响应侧仅做 HTTP 注入攻击识别拦截（可开关，默认开）
    - 例如：SQLi / XSS / 路径穿越 / XXE / SSTI / Log4Shell / SSRF / CRLF 注入
    - 命中后直接返回非 200（默认 `403`）格式化错误，不走确认放行链路
- Claude 系列 API（通用代理）：
  - `POST /v1/messages`
  - `POST /v1/messages/count_tokens`
  - `stream=true` 流式透传
  - 支持 query 透传（例如 `?anthropic-version=2023-06-01`）
- 请求侧：redaction、request_sanitizer、rag_poison_guard
- 响应侧：anomaly/injection/privilege/tool-call/restoration/post-restore/output-sanitizer
- 扩展脱敏：覆盖 `P0/P1` 常见敏感字段 + `Crypto` 专项字段（地址/私钥/助记词/交易所密钥）
- `responses` 结构化 `input` 预转发脱敏：覆盖 `user/developer/system/assistant` 与 `function_call_output/tool_output` 等节点
- 高风险确认：命中高风险可返回确认模板，确认指令在 request 入口按三态处理
- 流式韧性：上游未发送 `[DONE]` 提前断流时，网关会合成恢复完成事件并补齐 `[DONE]`
- 可选能力：
  - 语义灰区复核（超时、熔断、缓存）
  - HMAC + nonce 防重放
  - loopback-only 边界限制
- 存储后端：`sqlite` / `redis` / `postgres`

### 1.1 确认放行三态（当前行为）

当会话中存在 pending 确认时，新消息在请求入口按以下规则处理：

1. `yes` 放行：仅当消息中命中绑定码 `cfm-<id>--act-<token>`，且绑定码前缀可提取到 `yes`，才放行并回放/释放对应 pending 缓存内容。
2. `no` 取消：仅当消息中命中绑定码 `cfm-<id>--act-<token>`，且绑定码前缀可提取到 `no`，才取消并销毁对应 pending 缓存数据。
3. 其他输入：包括未命中绑定码、命中但格式不符合放行规则、或命中系统模板前缀（如 `放行（复制这一行）` / `Approve (copy this line):`），都视为普通新消息继续转发上游，不会被网关直接丢弃。

推荐发送完整单行指令：`yes cfm-<id>--act-<token>` 或 `no cfm-<id>--act-<token>`。  
当前实现不再支持仅 `yes` / `no` 的简化确认。

确认文案中的“命中片段（安全变形）”可通过开关控制：
- `AEGIS_CONFIRMATION_SHOW_HIT_PREVIEW=true|false`（默认 `true`）
- 展示规则：默认按“命中片段前后 40 字”分段变形展示；无可匹配上下文时回退到命中片段本身。
- `AEGIS_STRICT_COMMAND_BLOCK_ENABLED=true|false`（默认 `false`）：开启后命中强制命令会进入高风险确认拦截（返回 `yes/no cfm...`），不依赖 `security_level` 阈值。默认覆盖高危 `SSH/sshd` 改写与密钥外传、`iptables/nft/ufw/pfctl/netsh` 关键放开动作、`docker --privileged/挂载宿主根目录/docker.sock` 等。

### 1.2 脱敏覆盖范围（当前）

请求侧 `redaction` + `request_sanitizer` + `responses` 结构化 `input` 预转发脱敏 + 响应侧 `post_restore_guard` 已覆盖以下类别：

- 凭据/密钥：`API Key`、`Bearer`、`JWT`、`Cookie/Session`、`Private Key PEM`、`AWS Access/Secret`、`GitHub/Slack token`
- 金融标识：`银行卡`、`IBAN`、`SWIFT/BIC`、`Routing/ABA`、银行账号字段
- 网络与设备：`IPv4/IPv6`、`MAC`、`IMEI/IMSI`、设备序列号
- 证件与合规：`SSN`、`税号`、`护照/驾照`、证书/执照编号、医疗记录号、医保受益人编号
- 人员与地理：姓名字段、地址/经纬度/邮编字段、精确日期（生日/入院/出院/死亡）、传真字段
- 车辆与生物：`VIN`、车牌字段、生物特征模板字段（文本形态）
- Crypto 专项：`BTC/ETH/SOL/TRON` 地址、`WIF/xprv/xpub`、助记词/seed phrase、交易所 API key/secret/passphrase

`responses` 结构化输入补充说明（当前）：
- 全节点文本扫描：`role=user/developer/system/assistant` + `type=function_call_output/tool_result/tool_output/computer_call_output`
- 角色分级：`system/developer` 使用放宽规则（优先脱敏 token/key/secret/private key/IP 等高风险项）；`user` 保持严格
- 命中位置记录：日志记录 `path/field/role/pattern/count` 摘要（不含命中原文）
- 幂等：已包含 `[REDACTED:*]` 的文本不会重复脱敏

### 1.3 v1 / v2 实现链路与逻辑

统一入口（v1/v2 共用）：
1. 客户端必须走 token 路径：`/v1/__gw__/t/<token>/...` 或 `/v2/__gw__/t/<token>/...`
2. 中间件重写 token 路径到真实路由，并把 token 绑定信息注入请求上下文
3. 安全边界中间件执行基础限制：token 路径强制、请求体大小限制、可选 loopback-only、可选 HMAC/nonce 防重放

`v1` 链路（OpenAI 兼容）：
1. 请求侧过滤：`redaction -> request_sanitizer -> rag_poison_guard`
2. 转发到上游 LLM（chat/responses/generic 子路径）
3. 响应侧过滤：`anomaly_detector -> injection_detector -> rag_poison_guard -> privilege_guard -> tool_call_guard -> restoration -> post_restore_guard -> output_sanitizer`
4. 按风险处置：`allow / sanitize / block / confirmation(yes/no)`
5. 记录审计事件（含风险标签、处置原因、确认状态）

`v2` 链路（通用 HTTP 代理）：
1. 读取原始目标 URL 头（支持 `x-target-url`、`x-original-url`，优先 `AEGIS_V2_ORIGINAL_URL_HEADER`）
2. 请求侧按配置进行脱敏（默认开启）
3. 转发到目标 HTTP(S) 地址
4. 响应侧按配置进行 HTTP 注入检测（默认开启，文本类响应）
5. 命中即返回 `403` 格式化错误（不走确认放行）

### 1.4 过滤范围、安全检查、审计能力

| 维度 | v1 | v2 |
|---|---|---|
| 请求体过滤 | 脱敏 + 请求清洗 + RAG 投毒检测 | 脱敏（文本/JSON） |
| 响应过滤 | 异常评分、注入检测、权限防护、恢复后防护、输出清洗 | HTTP 注入攻击检测 |
| 可识别攻击/风险 | 系统提示词泄露、规则绕过、越权、编码混淆、异常命令/高危输出、投毒传播等 | SQLi / XSS / 路径穿越 / XXE / SSTI / Log4Shell / SSRF / CRLF 注入 |
| 处置动作 | `allow`、`sanitize`、`block`、`confirmation` | `allow`、`block(403)` |
| 流式处理 | 支持（含流式窗口检测、提前断流恢复） | 按普通 HTTP 响应处理 |
| 审计 | 完整安全审计链路（`audit.jsonl` + 安全标签/处置记录） | 运行日志与阻断元信息（不走确认缓存链路） |

### 1.5 命中后的处理方式（怎么处理）

1. `allow`：直接透传结果。
2. `sanitize`：替换敏感片段或可疑片段后返回。
3. `block`：立即拒绝并返回统一错误结构（v2 默认为 `403`）。
4. `confirmation`（仅 v1）：返回确认模板，用户需发送绑定确认指令 `yes/no cfm-...--act-...` 再继续。

建议：
1. LLM 主链路用 `v1`（具备确认放行与完整审计）。
2. 通用 HTTP 安检用 `v2`（命中即阻断，响应更直接）。

## 2. 接入模型

当前支持 token 路由模式：
- `v1`：`/v1/__gw__/t/<token>/...`
- `v2`：`/v2/__gw__/t/<token>/...`（复用同一 token，无需单独注册）

### 2.1 Token 注册（必选）

先注册一次，之后客户端只配置 token baseUrl，不再每次传网关头。

注册：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"agent"}'
```

返回：

```json
{
  "token": "Ab3k9Qx7Yp",
  "baseUrl": "http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7Yp"
}
```

说明：token 长度为 10 位（沿用原有生成方式，长度调整为 10）。

然后请求：

```bash
curl -X POST http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7Yp/responses \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

v2 请求示例（原始目标放请求头）：

```bash
curl -X POST http://127.0.0.1:18080/v2/__gw__/t/Ab3k9Qx7Yp/proxy \
  -H "Content-Type: application/json" \
  -H "x-target-url: https://httpbin.org/post" \
  -d '{"api_key":"sk-test-1234567890","message":"hello"}'
```

说明：`v2` 同时兼容 `x-target-url` 和 `x-original-url`；如果你有自定义头名，可通过 `AEGIS_V2_ORIGINAL_URL_HEADER` 配置。

辅助接口：
- 查询：`POST /__gw__/lookup`
- 删除：`POST /__gw__/unregister`

### 2.2 Claude 接入快速示例

```bash
# 非流式
curl -X POST 'http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>/messages' \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-3-5-sonnet-latest","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}'

# 流式
curl -N -X POST 'http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>/messages' \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-3-5-sonnet-latest","stream":true,"max_tokens":128,"messages":[{"role":"user","content":"hi"}]}'
```

更多终端/客户端（Codex CLI、OpenClaw、Cherry、VS Code、Cursor、WSL2）接入见：  
- [OTHER_TERMINAL_CLIENTS_USAGE.md](OTHER_TERMINAL_CLIENTS_USAGE.md)
- OpenClaw 自动注入代理脚本说明见：
  - [OPENCLAW_INJECT_PROXY_FETCH.md](OPENCLAW_INJECT_PROXY_FETCH.md)

OpenClaw 自动注入脚本位置：
- `scripts/openclaw-inject-proxy-fetch.py`
- 示例：
  - `python scripts/openclaw-inject-proxy-fetch.py D:\agent_work\openclaw`
- 行为：
  - 不自动检索目录；必须通过参数或 `OPENCLAW_ROOT` 显式指定 OpenClaw 根目录
  - 注入成功后自动执行 `build`（`pnpm/yarn/npm` 自动检测）
  - 设置环境变量示例：`export OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2/__gw__/t/XapJ3D0x`
  - 修改环境变量后需重启 OpenClaw 进程才生效

## 3. 本地开发

安装：

```bash
python -m pip install -e .
# 可选
python -m pip install -e .[redis]
python -m pip install -e .[postgres]
```

启动：

```bash
uvicorn aegisgate.core.gateway:app --host 127.0.0.1 --port 18080 --reload
```

健康检查：

```bash
curl http://127.0.0.1:18080/health
```

## 4. Docker 部署（配置/日志/token 持久化到宿主机）

本仓库的 `docker-compose.yml` 默认把关键数据挂到宿主机：

- `./config`：策略、`.env`、`gw_tokens.json`
- `./logs`：`aegisgate.db`、`audit.jsonl`、`aegisgate.log`

启动：

```bash
docker compose up -d --build
```

默认端口策略：
- `127.0.0.1:18080:18080`：仅宿主机本机可访问，不对公网直接暴露。
- `expose: 18080`：同 Docker 网络内其它容器可通过服务名 `aegisgate:18080` 访问。
- `extra_hosts: host.docker.internal:host-gateway`：容器内可访问宿主机服务（Linux/WSL2 也可用）。

查看日志：

```bash
docker compose logs -f aegisgate
```

连通性快速自检（注册 + 响应）：

```bash
# 1) 宿主机 -> 容器：健康检查
curl -sS http://127.0.0.1:18080/health

# 2) 宿主机 -> 容器：注册 token（检查 baseUrl）
curl -sS -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-real-upstream.example.com/v1","gateway_key":"agent"}'

# 3) 同网络容器 -> aegisgate（需要在同一 compose network）
docker run --rm --network $(basename "$PWD")_default curlimages/curl:8.10.1 \
  -sS http://aegisgate:18080/health
```

校验 token 是否持久化：
1. 调 `POST /__gw__/register` 注册 token。
2. 确认宿主机出现 `./config/gw_tokens.json`。
3. 执行 `docker compose restart aegisgate`。
4. 用原 token 继续请求，应可正常使用（除非手动 `unregister` 或未注册）。

## 5. 关键环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `AEGIS_GATEWAY_KEY` | 网关校验 key | `agent` |
| `AEGIS_LOG_LEVEL` | 日志等级 | `info` |
| `AEGIS_LOG_FULL_REQUEST_BODY` | DEBUG 下是否打印完整请求体 | `false` |
| `AEGIS_ENFORCE_LOOPBACK_ONLY` | 仅允许本机访问 | `true` |
| `AEGIS_ENABLE_REQUEST_HMAC_AUTH` | 开启 HMAC 验签 | `false` |
| `AEGIS_UPSTREAM_BASE_URL` | 默认上游地址 | `https://your-upstream.example.com/v1` |
| `AEGIS_UPSTREAM_WHITELIST_URL_LIST` | 白名单上游（逗号分隔） | 空 |
| `AEGIS_STORAGE_BACKEND` | `sqlite`/`redis`/`postgres` | `sqlite` |
| `AEGIS_SQLITE_DB_PATH` | sqlite 文件路径 | `logs/aegisgate.db` |
| `AEGIS_AUDIT_LOG_PATH` | 审计日志路径 | `logs/audit.jsonl` |
| `AEGIS_GW_TOKENS_PATH` | token 映射文件路径 | `config/gw_tokens.json` |
| `AEGIS_MAX_REQUEST_BODY_BYTES` | 请求体上限 | `2000000` |
| `AEGIS_MAX_MESSAGES_COUNT` | messages 条数上限 | `100` |
| `AEGIS_MAX_CONTENT_LENGTH_PER_MESSAGE` | 单条消息长度上限 | `50000` |
| `AEGIS_MAX_PENDING_PAYLOAD_BYTES` | pending 存储体积上限 | `100000` |
| `AEGIS_MAX_RESPONSE_LENGTH` | 响应长度上限 | `500000` |
| `AEGIS_SECURITY_LEVEL` | `low`/`medium`/`high` | `medium` |
| `AEGIS_STRICT_COMMAND_BLOCK_ENABLED` | 强制命令拦截开关（命中即进入确认拦截） | `false` |
| `AEGIS_ENABLE_V2_PROXY` | 启用 v2 通用代理 | `true` |
| `AEGIS_V2_ORIGINAL_URL_HEADER` | v2 原始目标 URL 请求头名（默认；仍兼容 `x-target-url`） | `x-original-url` |
| `AEGIS_V2_ENABLE_REQUEST_REDACTION` | v2 请求体脱敏开关 | `true` |
| `AEGIS_V2_ENABLE_RESPONSE_COMMAND_FILTER` | v2 响应 HTTP 注入攻击过滤开关 | `true` |
| `AEGIS_V2_RESPONSE_FILTER_MAX_CHARS` | v2 响应注入检测最大字符数 | `200000` |

完整可调项见：
- [config/.env.example](config/.env.example)
- [aegisgate/config/settings.py](aegisgate/config/settings.py)

## 6. 安全与边界说明

- 网关是安全中间层，不负责上游模型参数（如 model/api-key/超时）语义正确性。
- 默认会写日志和审计文件到本地；是否包含正文取决于日志级别与策略配置。
- 当 `AEGIS_LOG_LEVEL=debug` 且 `AEGIS_LOG_FULL_REQUEST_BODY=true` 时，请求体会完整打印（含 function/tool 输出原文），仅建议在受控环境短时开启。
- 若对外网开放，建议至少做到：
  - 使用高强度 `AEGIS_GATEWAY_KEY`（不要用默认值）
  - 启用 `AEGIS_ENABLE_REQUEST_HMAC_AUTH=true`
  - 在入口网关（Nginx/Caddy/WAF）上加 IP 白名单、限流与访问控制
  - 管理端点 `POST /__gw__/register|lookup|unregister` 仅允许内网来源访问（网关入口已强制）
- OAuth 托管登录模式通常无法配置 Base URL/Header，不适合接入 AegisGate；建议统一使用 API Key + Base URL 模式。

## 7. 测试

运行全部测试：

```bash
pytest -q
```

## 8. 常见问题

### 8.1 `sqlite3.OperationalError: unable to open database file`

典型原因是容器内路径不可写。优先检查：
- `AEGIS_SQLITE_DB_PATH` 指向的路径是否可写
- 宿主机挂载目录权限是否正确

### 8.2 Token 路径请求返回 `token_not_found`

- token 未注册
- token 已被删除
- `AEGIS_GW_TOKENS_PATH` 未持久化导致重启后丢失

### 8.3 上游返回 4xx/5xx

网关会透传上游错误摘要。请先独立验证上游接口可用，再检查网关策略拦截。

### 8.4 流式日志出现 `upstream_eof_no_done`

含义：上游流式连接提前关闭，未按协议发送 `data: [DONE]`。

- 网关会自动执行恢复并补发 `[DONE]`：
  - `chat/completions`：合成包含恢复提示的可见文本 chunk。
  - `responses`：合成 `response.completed` 终止事件（不保证回放已输出文本）。
- 这通常是上游或其中间代理链路（CDN/反代）问题，不是网关确认匹配失败。
- 建议同时排查上游超时、代理 `read timeout`、连接重置日志。

## 9. 许可证

[MIT](LICENSE)
