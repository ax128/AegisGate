# AegisGate

AegisGate 是一个面向 LLM 调用链的安全网关。业务方把 `baseUrl` 指向网关，网关在请求/响应两侧执行安全策略，再转发到真实上游模型。支持 **MCP**（Model Context Protocol）与 **Agent SKILL** 接入，可与 Cursor/Codex 等 Agent 环境配合使用。

核心目标：
- 统一入口：把安全策略集中在网关层，而不是散落在各个 Agent/应用里。
- 降低泄露面：请求侧脱敏与输入清洗、响应侧风险检测与阻断。
- 可追踪：统一审计、风险标签、自动遮挡/分割危险内容。

## 上游接入

本地 Web 控制台使用说明见 [WEBUI-QUICKSTART.md](WEBUI-QUICKSTART.md)。

AegisGate 是独立的安全代理层，**不管理也不约束上游服务**。上游按各自官方文档独立安装运行，客户端请求时经网关即可。

### 已验证的上游

| 上游 | 官方文档 | 默认端口 |
|------|---------|---------|
| [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) | OAuth 多账号 LLM 代理（Claude/Gemini/OpenAI） | 8317 |
| [Sub2API](https://github.com/Wei-Shaw/sub2api) | AI API 订阅管理平台（Claude/Gemini/Antigravity） | 8080 |
| [AIClient-2-API](https://github.com/justlovemaki/AIClient-2-API) | 多源 AI 客户端代理（Gemini CLI/Codex/Kiro/Grok） | 3000 |
| 任意 OpenAI 兼容 API | — | — |

> 请先按上游官方文档完成安装和配置，确认上游本身可用后再接入网关。

### 场景一：同机部署（网关与上游在同一台服务器）

网关默认开启**本地端口自动路由**，客户端 Base URL 带上端口号即可，零配置：

```
客户端 → http://<网关IP>:18080/v1/__gw__/t/{端口号}/... → localhost:{端口号}/v1/...
```

| 上游 | 客户端 Base URL |
|------|----------------|
| CLIProxyAPI | `http://<网关IP>:18080/v1/__gw__/t/8317` |
| Sub2API | `http://<网关IP>:18080/v1/__gw__/t/8080` |
| AIClient-2-API | `http://<网关IP>:18080/v1/__gw__/t/3000` |
| 自建 OpenAI 兼容 | `http://<网关IP>:18080/v1/__gw__/t/{你的端口}` |

- 客户端的 `Authorization: Bearer <key>` 直接透传到上游
- 多个上游可同时使用，互不冲突
- **无需注册 token、无需编辑配置、无需重启网关**

> Docker 环境默认通过 `host.docker.internal` 访问宿主机端口（compose 已配置）。
> 裸机部署改 host：`AEGIS_LOCAL_PORT_ROUTING_HOST=127.0.0.1`

### 场景二：远程上游（网关与上游不在同一台服务器）

上游在远程时，端口路由不可用，需通过 `/__gw__/register` 注册 token 绑定远程地址：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat config/aegis_gateway.key)" \
  -d '{"upstream_base":"https://远程上游地址/v1","api_key":"上游API-Key"}'
```

返回 token 后，客户端使用：`http://<网关IP>:18080/v1/__gw__/t/<返回的token>`

也可以直接编辑 `config/gw_tokens.json`（参考 `config/gw_tokens.json.example`）：

```json
{
  "tokens": {
    "remote-claude": {
      "upstream_base": "https://远程上游地址/v1",
      "gateway_key": "上游API-Key",
      "whitelist_key": []
    }
  }
}
```

重启网关后生效。命名 token 优先级高于端口自动路由。

### 场景三：Caddy + 网关对公网暴露

通过域名 + TLS 对外提供服务时，Caddy 在网关前面做 TLS 终结，请求仍走网关端口路由到上游：

```
客户端 → https://api.example.com/v1/__gw__/t/8317/... → Caddy → AegisGate:18080 → localhost:8317
```

**Caddyfile 示例**：

```caddy
api.example.com {
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        -Server
    }

    # 管理端点不对公网暴露
    @gw_admin path /__gw__ /__gw__/*
    respond @gw_admin "forbidden" 403

    # 拦截扫描器探测路径
    @scanner_probe {
        path /assets/* /static/* /js/* /css/* /images/* /fonts/*
        path /robots.txt /favicon.ico /.env /wp-login.php /wp-admin/*
        path /.git/* /.svn/* /phpmyadmin/* /admin/* /cgi-bin/*
    }
    respond @scanner_probe 404

    # 仅放行 API 路径
    @not_api not path /v1/* /v2/*
    respond @not_api 404

    # 转发到网关（端口路由由网关处理）
    reverse_proxy aegisgate:18080 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Real-IP {remote_host}
        flush_interval -1
        transport http {
            response_header_timeout 660s
            read_timeout 660s
            write_timeout 660s
        }
    }
}

# 上游管理后台（可选）：直连上游，不经网关
# panel.example.com {
#     reverse_proxy localhost:8080 {
#         flush_interval -1
#         transport http { response_header_timeout 660s }
#     }
# }
```

要点：
- `flush_interval -1`：SSE 流式不缓冲，**必须设置**
- `response_header_timeout 660s`：长时间推理不超时
- `/__gw__/*` 返回 403：管理接口不暴露到公网
- 管理后台建议单独域名直连上游，不经网关
- Caddy 只做 TLS + 转发，路由逻辑全在网关内部

## Agent Skill

给 Agent 直接执行的安装与接入手册：
- [SKILL.md](SKILL.md)

## 1. 主要能力

- **MCP 与 SKILL 支持**：支持 MCP（Model Context Protocol）与 Agent SKILL 接入，可与 Cursor/Codex 等 Agent 环境配合使用；Agent 安装与接入手册见 [SKILL.md](SKILL.md)。
- OpenAI 兼容接口：
  - `POST /v1/chat/completions`
  - `POST /v1/responses`
  - `POST /v1/{subpath}` 通用代理
- v2 通用 HTTP 代理（独立安全链路）：
  - `ANY /v2` / `ANY /v2/{subpath}`
  - 生产建议使用 token 路径：`/v2/__gw__/t/<token>/...`
  - 必须携带 `x-target-url` 请求头指定原始目标地址
  - 请求侧：请求体脱敏（可开关，默认开）
  - 响应侧仅做 HTTP 注入攻击识别拦截（可开关，默认开）
    - 默认最小误拦模式：协议层高危特征（HTTP request smuggling / response splitting，如 CL.TE / TE.CL / TE.TE）
    - 可通过规则配置扩展检测模式
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
- 高风险自动处理：命中高风险时自动遮挡/分割危险片段后返回，无需人工确认
- 流式韧性：上游未发送 `[DONE]` 提前断流时，网关会合成恢复完成事件并补齐 `[DONE]`
- **语义检测（TF-IDF）**：内置轻量 TF-IDF + LogisticRegression 分类器，中英文双语 prompt injection 检测，无需 GPU，启动时自动加载（约 166KB 模型文件）。高置信度安全文本直接放行（跳过正则），高置信度注入文本提前标记，灰区交由正则细分。
- 可选能力：
  - 外部语义服务（超时、熔断、缓存）
  - HMAC + nonce 防重放
  - loopback-only 边界限制
- 存储后端：`sqlite` / `redis` / `postgres`

### 1.1 危险内容处理策略（当前行为）

> **重要变更**：yes/no 确认放行流程已移除。所有危险内容统一走自动处理，不再支持手动放行。

网关对 LLM 响应中的危险内容按以下分级自动处理：

| 风险等级 | 处理方式 | 示例 |
|---------|---------|------|
| **无风险** | 直接透传 | 正常对话内容 |
| **轻度危险** | 每 3 字符插入 `-` 分割变形（chunked-hyphen） | `dev-elo-per mes-sag-e` |
| **重度危险/危险指令** | 危险片段替换为 `【AegisGate已处理危险疑似片段】` | SQL 注入、反弹 shell、`rm -rf` 等 |
| **垃圾内容噪声** | 替换为 `[AegisGate:spam-content-removed]` | 赌博/色情推广 + 伪造工具调用组合 |

处理后的内容会以 INFO 级别记录到网关日志（遮挡/分割后的安全摘要），便于审计追踪。

说明：
- `AEGIS_STRICT_COMMAND_BLOCK_ENABLED=true|false`（默认 `false`）：开启后命中强制命令规则即直接拦截并遮挡，不依赖 `security_level` 阈值。
- `AEGIS_CONFIRMATION_SHOW_HIT_PREVIEW=true|false`（默认 `true`）：拦截通知中是否展示命中片段（安全变形后）的预览。

### 1.2 脱敏覆盖范围（当前）

请求侧 `redaction` + `request_sanitizer` + `responses` 结构化 `input` 预转发脱敏 + 响应侧 `post_restore_guard` 已覆盖以下类别：

- 凭据/密钥：`API Key`、`Bearer`、`JWT`、`Cookie/Session`、`Private Key PEM`、`AWS Access/Secret`、`GitHub/Slack token`
- 金融标识：`银行卡`、`IBAN`、`SWIFT/BIC`、`Routing/ABA`、银行账号字段
- 网络与设备：`IPv4/IPv6`、`MAC`、`IMEI/IMSI`、设备序列号
- 证件与合规：`SSN`、`税号`、`护照/驾照`、证书/执照编号、医疗记录号、医保受益人编号
- 人员与地理：姓名字段、地址/经纬度/邮编字段、精确日期（生日/入院/出院/死亡）、传真字段
- 车辆与生物：`VIN`、车牌字段、生物特征模板字段（文本形态）
- Crypto 专项：`BTC/ETH/SOL/TRON` 地址、`WIF/xprv/xpub`、助记词/seed phrase、交易所 API key/secret/passphrase
- 电脑/基础设施（宽松模式，仅 `field: value` 格式）：主机名、系统用户名、OS 版本、内核信息、用户目录路径（`/home/`、`/Users/`、`C:\Users\`）、环境变量、容器 ID、K8s 资源名、内部服务 URL（`*.internal`、`*.local`、`*.svc.cluster.local`）

`responses` 结构化输入补充说明（当前）：
- 全节点文本扫描：`role=user/developer/system/assistant` + `type=function_call_output/tool_result/tool_output/computer_call_output`
- 角色分级：`user/developer/system/assistant/tool` 统一使用放宽规则（优先脱敏 token/key/secret/private key 等高风险项）
- 命中位置记录：日志记录 `path/field/role/pattern/count` 摘要（不含命中原文）
- 幂等：已包含 `[REDACTED:*]` 的文本不会重复脱敏

### 1.3 v1 / v2 实现链路与逻辑

统一入口（v1/v2 共用）：
1. `v1` 支持两种方式：默认上游直连（配置 `AEGIS_UPSTREAM_BASE_URL`）或 token 路径 `/v1/__gw__/t/<token>/...`
2. `v2` 必须走 token 路径：`/v2/__gw__/t/<token>/...`（避免非 token 的通用代理暴露）
3. token 路径会先被中间件重写到真实路由，并把 token 绑定信息注入请求上下文
4. 安全边界中间件执行基础限制：请求体大小限制、可选 loopback-only、可选 HMAC/nonce 防重放

`v1` 链路（OpenAI 兼容）：
1. 请求侧过滤：`redaction -> untrusted_content_guard -> request_sanitizer -> rag_poison_guard`
2. 转发到上游 LLM（chat/responses/generic 子路径）
3. 响应侧过滤：`anomaly_detector -> injection_detector -> rag_poison_guard -> privilege_guard -> tool_call_guard -> restoration -> post_restore_guard -> output_sanitizer`
4. 按风险处置：`allow / sanitize / block`（危险片段自动遮挡/分割，不走确认流程）
5. 记录审计事件（含风险标签、处置原因、确认状态）

说明：
- 上述顺序表示默认流水线构造顺序；实际是否执行仍取决于策略 `enabled_filters` 与全局开关。
- 当前默认策略已启用 `untrusted_content_guard` 与 `tool_call_guard`，但默认采取低误拦策略：
  - `untrusted_content_guard` 默认只做不可信来源包裹与风险抬升，不直接阻断。
  - `tool_call_guard` 默认重点阻断危险参数；工具名白名单默认留空，避免误伤不同上游的自定义工具。若显式配置白名单，未命中的工具名默认按 `review` 处理。

`v2` 链路（通用 HTTP 代理）：
1. 读取 `x-target-url` 请求头获取原始目标 URL（必须是 `http://` 或 `https://` 完整 URL，含 query string）
2. 请求侧：仅做请求体脱敏（可选，默认开启），不做其他拦截
3. 转发到目标 HTTP(S) 地址（`follow_redirects=false`：不自动跟随 3xx 重定向，直接透传给客户端）
4. 响应侧：仅对响应正文做高危代码检测（HTTP 走私、响应拆分等嵌入式攻击特征），命中返回 `403`
5. 正常响应（含 CDN/Nginx 的 CL+TE 并存头）直接透传，不做干预

> **安全边界提示**：v2 代理默认启用 SSRF 防护（`AEGIS_V2_BLOCK_INTERNAL_TARGETS=true`），会阻止请求到内网 IP（RFC1918/loopback/link-local）和云元数据端点（169.254.169.254 等）。如需访问内网服务，可设为 `false` 并在网络层（防火墙、出口 ACL）做补偿控制。`AEGIS_V2_RESPONSE_FILTER_BYPASS_HOSTS` 仅用于跳过响应拦截，不是目标主机访问白名单。

### 1.4 过滤范围、安全检查、审计能力

| 维度 | v1 | v2 |
|---|---|---|
| 请求体过滤 | 脱敏 + 非可信来源隔离 + 请求清洗 + RAG 投毒检测 | 仅脱敏（文本/JSON，可选） |
| 响应过滤 | 异常评分、注入检测、权限防护、恢复后防护、输出清洗 | 仅正文高危代码检测（HTTP smuggling/splitting 嵌入正文） |
| 可识别攻击/风险 | 系统提示词泄露、规则绕过、越权、编码混淆、危险 tool call 参数、投毒传播等 | 响应正文中嵌入的 HTTP smuggling/splitting 特征（CL.TE/TE.CL/TE.TE）；可扩展更多规则 |
| 处置动作 | `allow`、`sanitize`、`block`（自动遮挡/分割，无确认流程） | `allow`、`block(403)` |
| 流式处理 | 支持（含流式窗口检测、提前断流恢复） | 支持 SSE 透传（自动检测 `Accept: text/event-stream` 或 `"stream":true`；断流时补齐 `[DONE]`） |
| 审计 | 完整安全审计链路（`audit.jsonl` + 安全标签/处置记录 + 处理后内容 INFO 日志） | 运行日志与阻断元信息 |

### 1.5 命中后的处理方式（怎么处理）

1. `allow`：直接透传结果。
2. `sanitize`：过滤器就地替换敏感/可疑片段（如危险标签/URI/命令/垃圾内容）后直接返回。
3. `block`：高风险拦截，危险片段±20 字符上下文自动变形（轻度：chunked-hyphen 分割；重度：完全替换为网关提示）后返回。

> **注意**：yes/no 确认放行流程已永久移除。`AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK` 设置已废弃，无论值为何均等同 `false`。

补充：
- `privilege_guard` 与 `request_sanitizer` 对研究/教学/引用类上下文有降权处理，避免安全分析类内容被过度拦截。
- `tool_call_guard` 若要切换到严格白名单模式，可在 `security_filters.yaml` 中显式配置 `tool_whitelist` 与 `action_map.tool_call_guard.disallowed_tool=block`。

**分级变形策略**：
- **极度危险指令**（`rm -rf`、SQL 注入、反弹 shell、fork bomb、`curl|bash`、`dd if=of=`、`mkfs`、`powershell -enc` 等约 45 条模式）：片段被完全替换为 `【AegisGate已处理危险疑似片段】`，**原文不会出现在返回中**。
- **一般危险片段**（系统提示词泄露、可疑权限操作等）：使用 chunked-hyphen 分词变形（如 `dev-elo-per mes-sag-e`）。

建议：
1. LLM 主链路用 `v1`（具备完整安全过滤与审计）。
2. 通用 HTTP 安检用 `v2`（命中即阻断，响应更直接）。
3. 外部 MCP / Skill（涉及外部网站访问）同样支持走 `v1` 或 `v2` 网关路径；默认建议优先走 `v1`，安全检查更全面、使用方式与普通模型请求一致。

## 2. 接入模型

当前支持两种接入模式：
- `v1` 默认上游直连模式：配置 `AEGIS_UPSTREAM_BASE_URL` 后，客户端可直接请求 `/v1/...`（适合单上游、零注册）。
- token 路由模式：
  - `v1`：`/v1/__gw__/t/<token>/...`（**一个 token 绑定一个 upstream_base URL**）
  - `v2`：`/v2/__gw__/t/<token>/...`（可复用 v1 的 token；实际转发目标由 `x-target-url` 指定，不绑定 `upstream_base`）

### 2.0 v1 默认上游直连（单上游最简模式）

当 `AEGIS_UPSTREAM_BASE_URL` 已配置时，可直接请求：

```bash
curl -X POST http://127.0.0.1:18080/v1/responses \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

建议：
1. 上游使用 v1 基路径，例如 `AEGIS_UPSTREAM_BASE_URL=http://localhost:8317/v1`。
2. 该模式仅适用于 `v1`；`v2` 仍建议使用 token 路径。
3. 多上游场景建议使用端口路由（`/v1/__gw__/t/{端口号}/...`）而非此模式。

### 2.1 Token 注册（多上游/多租户推荐）

先注册一次，之后客户端只配置 token baseUrl，不再每次传网关头。

注册：

```bash
# gateway_key 的值即 config/aegis_gateway.key 文件内容（cat config/aegis_gateway.key 查看）
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"<YOUR_GATEWAY_KEY>","whitelist_key":["bn_key","okx_key"]}'
```

返回：

```json
{
  "token": "rQ5VZva-ssZsqAy1gAyondtS",
  "baseUrl": "http://127.0.0.1:18080/v1/__gw__/t/rQ5VZva-ssZsqAy1gAyondtS",
  "whitelist_key": ["bn_key", "okx_key"]
}
```

说明：
1. token 长度为 24 位（`secrets.token_urlsafe` 生成，约 144 位熵）。
2. `v1` 必须是一对一：一个 token 对应一个 `upstream_base` URL（不支持 `upstream_base` 传 list）。
3. `v2` 可复用该 token，因为 v2 转发目标由 `x-target-url` 决定，不绑定 `upstream_base`。
4. `whitelist_key` 可选，支持字符串/数组（集合语义去重）。命中这些字段名的键值片段会跳过请求体脱敏，例如 `bn_key=...`、`"bn_key": {...}`、URL 参数 `?bn_key=...`。
5. 所有管理端点（register/lookup/add/remove/unregister）都需要在请求体中提供 `gateway_key`，其值即 `config/aegis_gateway.key` 文件内容（`cat config/aegis_gateway.key` 查看）。

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

说明：`v2` 仅识别 `x-target-url` 请求头，头值必须是完整的 `http://` 或 `https://` URL。

辅助接口：
- 查询：`POST /__gw__/lookup`
- 删除：`POST /__gw__/unregister`
- 追加白名单：`POST /__gw__/add`（必填：`token`、`gateway_key`、`whitelist_key`(list)；可选：`upstream_base`，传入则替换该 token 绑定上游）
- 减少白名单：`POST /__gw__/remove`（必填：`token`、`gateway_key`、`whitelist_key`(list)）

> 若使用 Caddy 对外暴露，建议在 Caddyfile 中阻断 `/__gw__/*` 管理端点（参见 Caddy 配置示例）。注册/查询/变更请通过 `127.0.0.1:18080` 或内网入口执行。

追加示例（在原 whitelist 基础上增加；可选替换 upstream_base）：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/add \
  -H "Content-Type: application/json" \
  -d '{"token":"Ab3k9Qx7Yp","gateway_key":"<YOUR_GATEWAY_KEY>","whitelist_key":["bn_key","okx_key"],"upstream_base":"https://your-upstream-new.example.com/v1"}'
```

减少示例（从原 whitelist 中删除）：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/remove \
  -H "Content-Type: application/json" \
  -d '{"token":"Ab3k9Qx7Yp","gateway_key":"<YOUR_GATEWAY_KEY>","whitelist_key":["okx_key"]}'
```

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

外部 MCP / Skill 对外网站访问接入建议：
1. 可走 `v1`：`/v1/__gw__/t/<TOKEN>/...`（推荐，检查链路更完整）。
2. 可走 `v2`：`/v2/__gw__/t/<TOKEN>/...`（通用 HTTP 代理模式，需 `x-target-url`）。

OpenClaw 自动注入脚本位置：
- `scripts/openclaw-inject-proxy-fetch.py`
- 推荐命令（注入 + 构建 + 自动写入服务环境并重启网关）：
  - `python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2/__gw__/t/XapJ3D0x`
  - 如需强制服务运行本地注入构建：在命令后追加 `--pin-local-build`
- 关键行为：
  - 不自动检索目录；必须通过参数或 `OPENCLAW_ROOT` 显式指定 OpenClaw 根目录
  - 检测到已注入时，先恢复备份再重注入，避免重复注入错位
  - 自动备份到 `.aegisgate-backups/openclaw-inject-proxy-fetch/`
  - 自动维护 OpenClaw 仓库 `.gitignore`：忽略 `.aegisgate-backups/` 与 `src/infra/proxy-fetch.ts`（避免上传 git）
  - 注入成功后自动执行 `build`（`pnpm/yarn/npm` 自动检测）
  - 命令携带 `OPENCLAW_PROXY_GATEWAY_URL=...` 时，脚本自动生成/更新：
    - `~/.config/systemd/user/openclaw-gateway.service.d/90-openclaw-proxy-fetch.conf`
    - 写入 `OPENCLAW_PROXY_GATEWAY_URL`
    - 自动补充默认 `OPENCLAW_PROXY_DIRECT_HOSTS`（未显式传入时）
    - 执行 `systemctl --user daemon-reload && systemctl --user restart openclaw-gateway.service`
  - 追加 `--pin-local-build` 时，脚本会额外写入 `91-openclaw-local-build.conf`，把 systemd `ExecStart` 固定到 `/path/to/openclaw/dist/index.js`
  - 若未携带网关变量，脚本只做注入 + build，不改服务环境
  - `--remove` 会恢复备份、删除注入文件与备份目录、删除相关 systemd drop-in，并自动 `daemon-reload + restart`

## 3. 本地开发与本地 UI

本节保留本地开发启动命令；Web UI 的单独说明见 `WEBUI-QUICKSTART.md`。

### 3.1 直接用 launcher 启动（推荐）

仓库根目录提供了一键启动入口：`aegisgate-local.py`。

常用命令：

```bash
# 首次安装依赖
python aegisgate-local.py install

# 初始化 config/.env 和默认策略文件
python aegisgate-local.py init

# 后台启动网关
python aegisgate-local.py start

# 查看状态
python aegisgate-local.py status

# 查看日志路径，或输出 stdout 最后 50 行
python aegisgate-local.py logs --tail 50

# 停止网关
python aegisgate-local.py stop
```

启动成功后默认访问：

```text
API: http://127.0.0.1:18080
UI:  http://127.0.0.1:18080/__ui__/login
```

> **首次登录**：密码为 `admin123`（一次性默认密码，仅全新部署第一次登录有效）。登录成功后系统写入初始化标记，之后需用 `config/aegis_gateway.key` 的内容登录。

说明：

- `start` 会在需要时自动创建 `.venv`、安装项目依赖、执行 `aegisgate.init_config`，并以后台方式启动网关
- launcher 会把自身状态与输出写入 `logs/launcher/`
- 若当前环境下项目默认 sqlite 路径不可用，launcher 会自动切换到用户本地状态目录中的 sqlite 文件，避免启动失败

### 3.2 手动开发启动

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

UI 检查：

```bash
curl -I http://127.0.0.1:18080/__ui__/login
```

## 4. Docker 部署（配置/日志/token 持久化到宿主机）

本仓库默认基础部署（`docker-compose.yml`）仅启动 AegisGate，并把关键数据挂到宿主机：

- `./config`：策略、`.env`、`gw_tokens.json`
- `./logs`：`aegisgate.db`、`audit.jsonl`、`aegisgate.log`

基础模式启动：

```bash
docker compose up -d --build
```

默认端口策略：
- `127.0.0.1:18080:18080`：仅宿主机本机可访问，不对公网直接暴露。
- `expose: 18080`：同 Docker 网络内其它容器可通过服务名 `aegisgate:18080` 访问。
- `extra_hosts: host.docker.internal:host-gateway`：容器内可访问宿主机服务（Linux/WSL2 也可用）。
- 对公网暴露时，在网关前加 Caddy 做 TLS（参见上方 Caddy 配置示例）。

查看日志：

```bash
docker compose logs -f aegisgate
```

连通性快速自检（注册 + 响应）：

```bash
# 0) 查看网关密钥（保存在 config/aegis_gateway.key，首次启动自动生成）
cat config/aegis_gateway.key

# 1) 宿主机 -> 容器：健康检查
curl -sS http://127.0.0.1:18080/health

# 2) 宿主机 -> 容器：注册 token（gateway_key 用上面查到的值）
curl -sS -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-real-upstream.example.com/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'

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
| `AEGIS_GATEWAY_KEY` | 网关密钥（可选，Docker/CI 覆盖用）；默认从 `config/aegis_gateway.key` 自动加载，首次启动自动生成 | 文件加载 |
| `AEGIS_ENCRYPTION_KEY` | 脱敏映射加密密钥（Fernet AES-128-CBC+HMAC，留空自动生成到 `config/aegis_fernet.key`） | 空（自动生成） |
| `AEGIS_LOG_LEVEL` | 日志等级 | `info` |
| `AEGIS_LOG_FULL_REQUEST_BODY` | DEBUG 下是否打印完整请求体 | `false` |
| `AEGIS_ENFORCE_LOOPBACK_ONLY` | 仅允许本机访问 | `true` |
| `AEGIS_TRUSTED_PROXY_IPS` | 可信反向代理 IP（逗号分隔，支持 CIDR 如 `172.16.0.0/12`）；仅这些 IP 的 XFF 会被信任 | 空 |
| `AEGIS_ENABLE_REQUEST_HMAC_AUTH` | 开启 HMAC 验签 | `false` |
| `AEGIS_UPSTREAM_BASE_URL` | v1 默认上游（启用后可直连 `/v1/...`） | 空 |
| `AEGIS_UPSTREAM_WHITELIST_URL_LIST` | 白名单上游（逗号分隔） | 空 |
| `AEGIS_ENABLE_THREAD_OFFLOAD` | Store/过滤管道线程池执行开关（避免阻塞 event loop） | `true` |
| `AEGIS_FILTER_PIPELINE_TIMEOUT_S` | 过滤管道超时（秒） | `30.0` |
| `AEGIS_REQUEST_PIPELINE_TIMEOUT_ACTION` | 请求过滤超时动作：`block`（安全默认）或 `pass`（兼容旧行为） | `block` |
| `AEGIS_ADMIN_RATE_LIMIT_PER_MINUTE` | 管理端点每 IP 每分钟最大请求数 | `30` |
| `AEGIS_STORAGE_BACKEND` | `sqlite`/`redis`/`postgres` | `sqlite` |
| `AEGIS_SQLITE_DB_PATH` | sqlite 文件路径 | `logs/aegisgate.db` |
| `AEGIS_AUDIT_LOG_PATH` | 审计日志路径 | `logs/audit.jsonl` |
| `AEGIS_GW_TOKENS_PATH` | token 映射文件路径 | `config/gw_tokens.json` |
| `AEGIS_MAX_REQUEST_BODY_BYTES` | 请求体上限 | `2000000` |
| `AEGIS_MAX_MESSAGES_COUNT` | messages 条数上限 | `100` |
| `AEGIS_MAX_CONTENT_LENGTH_PER_MESSAGE` | 单条消息长度上限 | `50000` |
| `AEGIS_MAX_PENDING_PAYLOAD_BYTES` | pending 存储体积上限 | `100000` |
| `AEGIS_MAX_RESPONSE_LENGTH` | 响应长度上限 | `500000` |
| `AEGIS_SECURITY_LEVEL` | `low`/`medium`/`high`（见下方安全级别说明） | `medium` |
| `AEGIS_ENABLE_SEMANTIC_MODULE` | 启用内置 TF-IDF 语义分类器（无需 GPU） | `true` |
| `AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK` | **[已废弃]** 放行确认流程已移除，该值无论设为何均等同 `false`：拦截时自动遮挡/分割后返回 | `false` |
| `AEGIS_STRICT_COMMAND_BLOCK_ENABLED` | 强制命令拦截开关（命中即进入确认拦截） | `false` |
| `AEGIS_ENABLE_V2_PROXY` | 启用 v2 通用代理 | `true` |
| `AEGIS_V2_ENABLE_REQUEST_REDACTION` | v2 请求体脱敏开关 | `true` |
| `AEGIS_V2_ENABLE_RESPONSE_COMMAND_FILTER` | v2 响应 HTTP 注入攻击过滤开关 | `true` |
| `AEGIS_V2_RESPONSE_FILTER_OBVIOUS_ONLY` | v2 最小误拦模式（仅拦截协议层高危签名：走私/响应拆分/报文混淆） | `true` |
| `AEGIS_V2_RESPONSE_FILTER_BYPASS_HOSTS` | v2 响应拦截跳过域名（逗号分隔；支持 `example.com`/`.example.com`/`*.example.com`） | 空 |
| `AEGIS_V2_RESPONSE_FILTER_MAX_CHARS` | v2 响应注入检测最大字符数 | `200000` |
| `AEGIS_V2_SSE_FILTER_PROBE_MAX_CHARS` | v2 SSE 流式响应检测探针最大字符数 | `4000` |
| `AEGIS_V2_BLOCK_INTERNAL_TARGETS` | v2 阻止请求到内网/私有 IP（SSRF 防护） | `true` |

说明：v1 与 v2 的 HTTP/HTTPS 响应命中库已统一收敛到协议层高危签名（来源于 `sanitizer.command_patterns`）。

### 5.1 安全级别（`AEGIS_SECURITY_LEVEL`）

三档定位，控制所有阈值/地板的缩放系数：

| 级别 | 定位 | 行为 |
|------|------|------|
| `high` | 全量检测，宁可误拦不放过 | 阈值缩小（×0.90），地板抬高（×1.05），更容易触发拦截 |
| **`medium`（默认）** | 宽松，仅高危 + 脱敏 | 阈值放大（×1.30），地板降低（×0.85），大部分"可能危险"指令不拦截 |
| `low` | 极宽松，基本只脱敏 | 阈值放大（×1.60），地板大幅降低（×0.70），几乎不触发 risk-based 拦截 |

**所有级别下，`disposition=block` 的特殊类别始终强制拦截**（不受阈值影响）：
- `system_exfil`（系统提示泄露）
- `obfuscated`（编码混淆攻击，含消息级多脚本噪声注入）
- `unicode_bidi`（bidi 方向控制攻击）
- `tool_call_injection`（伪造工具调用，覆盖 OpenAI/Anthropic/Gemini/Bedrock/ReAct/MCP 等 45+ 模式）
- `spam_noise`（赌博/色情/平台垃圾内容噪声，>=2 类别组合时触发）

### 5.2 语义检测模块

内置 TF-IDF + LogisticRegression 双语分类器（`AEGIS_ENABLE_SEMANTIC_MODULE=true`，默认开启）：

- **模型**：char n-gram (3-5) + sublinear TF-IDF，约 166KB（vectorizer 104KB + classifier 62KB）
- **训练数据**：deepset/prompt-injections + 中英文补充样本（DAN/jailbreak/角色劫持 + Agent 工作指令安全样本）
- **三层检测逻辑**：
  1. TF-IDF 高置信度安全（≥0.88）→ 跳过正则，直接放行
  2. TF-IDF 高置信度注入（≥0.85）→ 标记 + 风险提升，再交正则细分
  3. 灰区 → 正则分类 → TF-IDF 安全中置信度（≥0.70）可抑制正则误报
- **重训练**：`pip install scikit-learn jieba datasets && python scripts/train_tfidf.py`

`AEGIS_V2_RESPONSE_FILTER_BYPASS_HOSTS` 示例：
`moltbook.com,semanticscholar.org,openalex.org,arxiv.org,pubmed.ncbi.nlm.nih.gov,search.crossref.org,core.ac.uk,doaj.org`

完整可调项见：
- [config/.env.example](config/.env.example)
- [aegisgate/config/settings.py](aegisgate/config/settings.py)

## 6. 安全与边界说明

- 网关是安全中间层，不负责上游模型参数（如 model/api-key/超时）语义正确性。
- 默认会写日志和审计文件到本地；是否包含正文取决于日志级别与策略配置。
- 当 `AEGIS_LOG_LEVEL=debug` 且 `AEGIS_LOG_FULL_REQUEST_BODY=true` 时，请求体会完整打印（含 function/tool 输出原文），仅建议在受控环境短时开启。
- 安全自动化：
  - 网关密钥保存在 `config/aegis_gateway.key`（首次启动自动生成，权限 `0600`）。查看：`cat config/aegis_gateway.key`。
  - `AEGIS_ENCRYPTION_KEY` 留空时自动生成 Fernet 加密密钥（持久化到 `config/aegis_fernet.key`，文件权限 `0600`）。脱敏映射使用 AES-128-CBC+HMAC 加密存储，不再使用 base64。
  - 管理端点内置速率限制（默认每 IP 每分钟 30 次）和内网 IP 校验。
  - v2 代理默认启用 SSRF 防护，阻止请求到内网地址和云元数据端点。
- 若对外网开放，建议至少做到：
  - 确认 `config/aegis_gateway.key` 已存在且为高强度值（所有管理端点和 UI 登录都需要此 key 认证）
  - 启用 `AEGIS_ENABLE_REQUEST_HMAC_AUTH=true`
  - 配置 `AEGIS_TRUSTED_PROXY_IPS`（仅信任你的反向代理 IP，支持 CIDR）
  - 在入口网关（Nginx/Caddy/WAF）上加 IP 白名单、限流与访问控制
  - 管理端点 `POST /__gw__/register|lookup|unregister|add|remove` 仅允许内网来源访问
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
  - `v2`（SSE 流）：自动补发 `data: [DONE]\n\n`，保证客户端收到终止信号。
- 这通常是上游或其中间代理链路（CDN/反代）问题，不是网关确认匹配失败。
- 建议同时排查上游超时、代理 `read timeout`、连接重置日志。

### 8.5 v2 请求返回 `missing_target_url_header`

原因：请求未携带 `x-target-url` 请求头，或头值为空。

- `v2` 仅通过 `x-target-url` 请求头获取目标地址，URL 路径中的子路径（`/v2/{subpath}`）不用于路由。
- 确认客户端在 Header 中传递完整 URL，包括 query string，例如：`x-target-url: https://api.example.com/v1/data?page=1`。

### 8.6 v2 上游返回 3xx 重定向，但客户端未跳转

v2 不自动跟随重定向（`follow_redirects=false`），`Location` 头会透传给客户端。
客户端需自行处理重定向，或在 `x-target-url` 直接指定最终地址。

## 9. 许可证

[MIT](LICENSE)
