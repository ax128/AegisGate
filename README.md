# AegisGate

AegisGate 是一个面向 LLM 调用链的安全网关。业务方把 `baseUrl` 指向网关，网关负责做请求/响应安全检查，再转发到真实上游模型。

核心目标：
- 统一入口：把安全策略集中在网关层，而不是散落在各个 Agent/应用里。
- 降低泄露面：请求侧脱敏、越权/注入检测、响应侧清洗与阻断。
- 可追踪：统一审计、风险标签、确认放行流程（yes/no）。

## 1. 主要能力

- OpenAI 兼容接口：
  - `POST /v1/chat/completions`
  - `POST /v1/responses`
  - `POST /v1/{subpath}` 通用代理
- 请求侧：redaction、request_sanitizer、注入/异常/越权检测
- 响应侧：anomaly/injection/privilege/tool-call/restoration/post-restore/output-sanitizer
- 高风险确认：命中高风险可返回确认模板，用户 `yes/no` 后一次性执行或取消
- 可选能力：
  - 语义灰区复核（超时、熔断、缓存）
  - HMAC + nonce 防重放
  - loopback-only 边界限制
- 存储后端：`sqlite` / `redis` / `postgres`

## 2. 接入模型

你有两种接入方式。

### 2.1 方式 A：Header 传上游

请求发给网关，同时带：
- `X-Upstream-Base: https://your-upstream/v1`
- `gateway-key: <your-gateway-key>`

示例：

```bash
curl -X POST http://127.0.0.1:18080/v1/responses \
  -H "Content-Type: application/json" \
  -H "X-Upstream-Base: https://your-upstream.example.com/v1" \
  -H "gateway-key: agent" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

### 2.2 方式 B：Token 注册（推荐）

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
  "token": "Ab3k9Qx7",
  "baseUrl": "http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7"
}
```

然后请求：

```bash
curl -X POST http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7/responses \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

辅助接口：
- 查询：`POST /__gw__/lookup`
- 删除：`POST /__gw__/unregister`

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

查看日志：

```bash
docker compose logs -f aegisgate
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
  - 限制管理端点 `POST /__gw__/register|lookup|unregister` 的访问来源

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

## 9. 许可证

[MIT](LICENSE)
