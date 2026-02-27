# AegisGate

AegisGate 是一个面向 LLM 调用链的安全网关。业务方把 `baseUrl` 指向网关，网关在请求/响应两侧执行安全策略，再转发到真实上游模型。

核心目标：
- 统一入口：把安全策略集中在网关层，而不是散落在各个 Agent/应用里。
- 降低泄露面：请求侧脱敏与输入清洗、响应侧风险检测与阻断。
- 可追踪：统一审计、风险标签、确认放行流程（yes/no）。

## 1. 主要能力

- OpenAI 兼容接口：
  - `POST /v1/chat/completions`
  - `POST /v1/responses`
  - `POST /v1/{subpath}` 通用代理
- Claude 系列 API（通用代理）：
  - `POST /v1/messages`
  - `POST /v1/messages/count_tokens`
  - `stream=true` 流式透传
  - 支持 query 透传（例如 `?anthropic-version=2023-06-01`）
- 请求侧：redaction、request_sanitizer、rag_poison_guard
- 响应侧：anomaly/injection/privilege/tool-call/restoration/post-restore/output-sanitizer
- 扩展脱敏：覆盖 `P0/P1` 常见敏感字段 + `Crypto` 专项字段（地址/私钥/助记词/交易所密钥）
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

### 1.2 脱敏覆盖范围（当前）

请求侧 `redaction` + `request_sanitizer` + 响应侧 `post_restore_guard` 已覆盖以下类别：

- 凭据/密钥：`API Key`、`Bearer`、`JWT`、`Cookie/Session`、`Private Key PEM`、`AWS Access/Secret`、`GitHub/Slack token`
- 金融标识：`银行卡`、`IBAN`、`SWIFT/BIC`、`Routing/ABA`、银行账号字段
- 网络与设备：`IPv4/IPv6`、`MAC`、`IMEI/IMSI`、设备序列号
- 证件与合规：`SSN`、`税号`、`护照/驾照`、证书/执照编号、医疗记录号、医保受益人编号
- 人员与地理：姓名字段、地址/经纬度/邮编字段、精确日期（生日/入院/出院/死亡）、传真字段
- 车辆与生物：`VIN`、车牌字段、生物特征模板字段（文本形态）
- Crypto 专项：`BTC/ETH/SOL/TRON` 地址、`WIF/xprv/xpub`、助记词/seed phrase、交易所 API key/secret/passphrase

## 2. 接入模型

当前仅支持 token 路由模式：`/v1/__gw__/t/<token>/...`。  
Header 直连模式（`X-Upstream-Base` + `gateway-key`）已禁用。

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

完整可调项见：
- [config/.env.example](config/.env.example)
- [aegisgate/config/settings.py](aegisgate/config/settings.py)

## 6. 安全与边界说明

- 网关是安全中间层，不负责上游模型参数（如 model/api-key/超时）语义正确性。
- 默认会写日志和审计文件到本地；是否包含正文取决于日志级别与策略配置。
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

- 网关会自动执行恢复：合成可见完成事件（含已缓存文本和提示）并补发 `[DONE]`，避免客户端“无反馈/卡住”。
- 这通常是上游或其中间代理链路（CDN/反代）问题，不是网关确认匹配失败。
- 建议同时排查上游超时、代理 `read timeout`、连接重置日志。

## 9. 许可证

[MIT](LICENSE)
