# AegisGate

AegisGate 是面向 LLM 调用的**安全网关**：Agent 与业务只对接网关，不直连上游模型，在网关层统一做**请求脱敏与拦截、响应检测与阻断、高风险确认放行**，实现「单点防御、可追溯」。

**隐私与数据**：本网关**不记录任何业务数据**，仅作为本地中间层做过滤与转发；请求与响应内容不落盘、不上报，从机制上避免经第三方转发导致隐私数据泄露。

**防御思路**：请求进入前做最小充分检查（脱敏 + 泄露/越权/注入检测），转发前不暴露上游地址与密钥；响应返回前做强检查（异常与投毒检测、必要时清洗或阻断）；流式响应支持分段检查与中途阻断；命中高风险时要求用户确认后再放行一次，避免自动执行危险指令。

**项目定位**：
- Agent 侧 `baseUrl` 固定指向网关，不持有真实上游地址
- 真实上游由请求头 `X-Upstream-Base` 动态指定，由网关校验与转发
- 所有请求必须携带 `gateway-key`（默认值：`agent`），缺一即拒

## 1. 核心能力

**接口与协议**
- OpenAI 兼容：`POST /v1/chat/completions`、`POST /v1/responses`，以及 `/v1/*` 通用代理
- 流式：SSE 透传，支持流式增量检查与中途阻断

**请求侧防御**
- 可逆脱敏（redaction）：敏感内容在网关侧脱敏后转发，降低泄露面
- 泄露检查：防止 prompt/密钥/内部信息随请求流出
- 越权与注入拦截：高置信命中时直接拒绝，不转发上游

**响应侧防御**
- 异常与投毒检测：对模型输出做规则与策略检查
- 恢复后再检查：解码/还原后再次校验，必要时对内容清洗或整段阻断
- 流式分段检查：边收边检，发现问题可立即断流

**风险可控**
- 高风险确认放行：命中高风险时返回确认模板，用户 `yes/no` 决定是否执行一次，避免自动执行危险操作

**审计与扩展**
- 存储后端：`sqlite` / `redis` / `postgres`，用于审计与状态落盘
- 语义模块（可选）：独立异步语义服务，超时 + 熔断 + 缓存，用于灰区语义风险判断
- 边界加固（可选）：loopback 限制、HMAC 验签、nonce 防重放

## 2. 请求转发模型

### 2.1 Agent 配置示例

```json
{
  "baseUrl": "http://127.0.0.1:18080/v1",
  "headers": {
    "X-Upstream-Base": "https://your-upstream.example.com/v1",
    "gateway-key": "agent"
  }
}
```

说明：
- 业务请求发给网关，不直连第三方。
- `X-Upstream-Base` 作为真实上游地址。
- 缺少 `X-Upstream-Base` 或 `gateway-key`，网关直接返回参数错误。
- 命中上游白名单 `AEGIS_UPSTREAM_WHITELIST_URL_LIST` 时，网关可直接透传不做过滤。

### 2.2 网关处理链

1. 校验网关头（`X-Upstream-Base` + `gateway-key`）。
2. 请求侧脱敏与最小充分检查。
3. 转发到上游模型。
4. 响应侧强检查（含流式分段检查）。
5. 命中高风险则进入确认流程；否则直接返回。

## 3. 本地开发运行

### 3.1 安装

```bash
python -m pip install -e .
```

可选依赖：

```bash
# Redis 后端
python -m pip install -e .[redis]

# PostgreSQL 后端
python -m pip install -e .[postgres]
```

### 3.2 启动

```bash
uvicorn aegisgate.core.gateway:app --host 127.0.0.1 --port 18080 --reload
```

### 3.3 健康检查

网关提供健康检查接口，请求后返回 `{"status":"ok"}` 表示运行正常。

- **健康测试链接**（本地启动后可在浏览器打开或用于监控探测）：  
  [http://127.0.0.1:18080/health](http://127.0.0.1:18080/health)
- 命令行校验：

```bash
curl http://127.0.0.1:18080/health
```

## 4. Docker 一键部署

### 4.1 下载

从 GitHub 克隆仓库：

```bash
git clone https://github.com/ax128/AegisGate.git
cd AegisGate
```

### 4.2 启动

```bash
docker compose up -d --build
```

启动后可用同一健康测试链接确认网关已就绪：[http://127.0.0.1:18080/health](http://127.0.0.1:18080/health)（返回 `{"status":"ok"}`）。

### 4.3 查看日志

```bash
docker compose logs -f aegisgate
```

### 4.4 停止

```bash
docker compose down
```

默认端口映射：`127.0.0.1:18080:18080`（仅本机可访问）。

## 5. API 使用示例

### 5.1 Chat Completions

```bash
curl -X POST http://127.0.0.1:18080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Upstream-Base: https://your-upstream.example.com/v1' \
  -H 'gateway-key: agent' \
  -d '{
    "model": "your-chat-model",
    "messages": [{"role": "user", "content": "hello"}]
  }'
```

### 5.2 Responses

```bash
curl -X POST http://127.0.0.1:18080/v1/responses \
  -H 'Content-Type: application/json' \
  -H 'X-Upstream-Base: https://your-upstream.example.com/v1' \
  -H 'gateway-key: agent' \
  -d '{
    "model": "your-response-model",
    "input": "hello"
  }'
```

### 5.3 Relay（可选）

- 路由：`POST /relay/generate`
- 默认关闭，需设置 `AEGIS_ENABLE_RELAY_ENDPOINT=true`
- 开启后复用 `/v1/chat/completions` 同一安全链

### 5.4 通用接口兼容

网关支持 `/v1/*` 通用代理入口，可直接承接非 OpenAI schema 的 JSON 接口。

示例（通用 messages）：

```bash
curl -X POST http://127.0.0.1:18080/v1/messages \
  -H 'Content-Type: application/json' \
  -H 'X-Upstream-Base: https://your-upstream.example.com/v1' \
  -H 'gateway-key: agent' \
  -d '{
    "model": "your-generic-model",
    "messages": [{"role":"user","content":"hello"}]
  }'
```

示例（通用模型路由）：

```bash
curl -X POST http://127.0.0.1:18080/v1/models/your-model:generateContent \
  -H 'Content-Type: application/json' \
  -H 'X-Upstream-Base: https://your-upstream.example.com/v1' \
  -H 'gateway-key: agent' \
  -d '{
    "contents":[{"parts":[{"text":"hello"}]}]
  }'
```

说明：多模态（图片/音频/视频）结构会保持原样透传上游，网关仅提取文本副本用于安全分析。

## 6. 高风险确认机制

当响应命中高风险时，网关返回确认模板与 `CONFIRM_ID`，并缓存 pending 请求。

- 允许执行（一次）：
  - 英文：`yes`, `y`, `ok`, `okay`, `confirm`, `proceed`, `continue`
  - 中文：`是`, `是的`, `确认`, `同意`, `继续`, `执行`, `好的`
- 拒绝执行：
  - 英文：`no`, `n`, `cancel`, `stop`, `reject`
  - 中文：`否`, `不是`, `取消`, `拒绝`, `不要`, `停止`

pending 记录包含：`confirm_id / payload_hash / status / expires_at / retained_until`。

## 7. 语义服务接入（异步）

网关语义模块调用外部 HTTP 服务（灰区触发）：

- 请求：`POST $AEGIS_SEMANTIC_SERVICE_URL`
- Body：

```json
{"text": "待分析文本"}
```

- 响应：

```json
{
  "risk_score": 0.87,
  "tags": ["semantic_leak"],
  "reasons": ["semantic_secret_or_prompt_leak"]
}
```

策略：
- 超时：按 `AEGIS_SEMANTIC_TIMEOUT_MS` 降级
- 熔断：失败阈值 `AEGIS_SEMANTIC_CIRCUIT_FAILURE_THRESHOLD`，打开时长 `AEGIS_SEMANTIC_CIRCUIT_OPEN_SECONDS`
- 缓存：`AEGIS_SEMANTIC_CACHE_TTL_SECONDS` + `AEGIS_SEMANTIC_CACHE_MAX_ENTRIES`

## 8. 关键环境变量

- 基础
  - `AEGIS_LOG_LEVEL`：日志等级（大小写不敏感：`debug|info|warning|error|critical`，默认 `info`）
  - `AEGIS_HOST`（默认 `127.0.0.1`）
  - `AEGIS_PORT`（默认 `18080`）
  - `AEGIS_GATEWAY_KEY`（默认 `agent`）
  - `AEGIS_GATEWAY_KEY_HEADER`（默认 `gateway-key`）
- 上游
  - `AEGIS_UPSTREAM_BASE_HEADER`（默认 `x-upstream-base`）
  - `AEGIS_UPSTREAM_TIMEOUT_SECONDS`
  - `AEGIS_UPSTREAM_MAX_CONNECTIONS`
  - `AEGIS_UPSTREAM_MAX_KEEPALIVE_CONNECTIONS`
  - `AEGIS_UPSTREAM_WHITELIST_URL_LIST`（逗号分隔）
- 安全策略
  - `AEGIS_SECURITY_LEVEL`：`high|medium|low`（默认 `medium`）
  - `AEGIS_CONFIRMATION_TTL_SECONDS`
  - `AEGIS_PENDING_DATA_TTL_SECONDS`（默认 24h）
- 存储
  - `AEGIS_STORAGE_BACKEND`：`sqlite|redis|postgres`
  - `AEGIS_REDIS_URL`
  - `AEGIS_REDIS_KEY_PREFIX`
  - `AEGIS_POSTGRES_DSN`
  - `AEGIS_POSTGRES_SCHEMA`
- 语义
  - `AEGIS_ENABLE_SEMANTIC_MODULE`
  - `AEGIS_SEMANTIC_SERVICE_URL`
  - `AEGIS_SEMANTIC_GRAY_LOW`
  - `AEGIS_SEMANTIC_GRAY_HIGH`
  - `AEGIS_SEMANTIC_TIMEOUT_MS`
  - `AEGIS_SEMANTIC_CACHE_TTL_SECONDS`
  - `AEGIS_SEMANTIC_CACHE_MAX_ENTRIES`
  - `AEGIS_SEMANTIC_CIRCUIT_FAILURE_THRESHOLD`
  - `AEGIS_SEMANTIC_CIRCUIT_OPEN_SECONDS`
- 网关边界（可选）
  - `AEGIS_ENFORCE_LOOPBACK_ONLY`
  - `AEGIS_ENABLE_REQUEST_HMAC_AUTH`
  - `AEGIS_REQUEST_HMAC_SECRET`
  - `AEGIS_REQUEST_SIGNATURE_HEADER`
  - `AEGIS_REQUEST_TIMESTAMP_HEADER`
  - `AEGIS_REQUEST_NONCE_HEADER`
  - `AEGIS_REQUEST_REPLAY_WINDOW_SECONDS`
  - `AEGIS_NONCE_CACHE_BACKEND`：`memory|redis`

## 9. 项目结构

```text
aegisgate/
  adapters/        # OpenAI/Relay 兼容入口
  core/            # 网关核心、上下文、审计、边界
  filters/         # 各类安全过滤器
  policies/        # 策略与规则
  storage/         # sqlite/redis/postgres
  tests/           # 测试
Dockerfile
docker-compose.yml
README.md
```
