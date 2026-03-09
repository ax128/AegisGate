# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security

- **安全过滤强度调优（减少误杀 + 防止高危放行）**
  - `privilege_guard`：降低 risk_floor（0.9→0.75 / 0.85→0.70），精确化中英文模式——"读取配置文件"、"show token usage" 不再误杀，"cat /etc/passwd"、"泄露密钥" 仍被拦截。
  - `injection_detector`：降低 `direct` severity（9→7）、`html_markdown` severity（6→4），增大误报降分上限（0.35→0.45）——HTML 代码示例从 risk=0.85 降至 0.197，学术讨论 risk=0.58 放行。
  - `output_sanitizer`：移除 `docker ps/images/logs` 等只读诊断命令的强制拦截，仅保留 `down/stop/restart/exec -it`。
  - `request_sanitizer`：`rule_bypass` 动作从 `block` 改为 `review`（教学讨论提到"绕过"不再直接拦截）。
  - `anomaly_detector`：放宽重复阈值（ratio 0.35→0.45, repeated_line 20→28），减少重复格式内容误触。
  - `rag_poison_guard`：降低 retrieval（0.86→0.78）和 propagation（0.88→0.82）风险分。

- **[Critical] 修复 action=block 在 low 级别下失效的问题**
  - `security_level=low` 时 risk_threshold 被 cap 到 1.0，导致 `injection_detector`（system_exfil/obfuscated/unicode_bidi）和 `privilege_guard` 的 block action 仅提升 risk=0.95 但无法达到阈值——真正的高危指令被放行。
  - **修复**：所有 action=block 的过滤器现在直接设置 `disposition=block`，绕过 risk_threshold 限制，确保高危指令在任何安全级别下都被拦截。
  - 涉及：`injection_detector`（区分 request/response phase）、`privilege_guard`（request + response）。

### Changed

- **默认安全级别改为 `low`**：减少正常对话的误拦截；高危指令（系统提示泄露、编码攻击、凭据泄露）仍通过 disposition=block 强制拦截。
- **`AEGIS_ENABLE_THREAD_OFFLOAD` 默认改为 `true`**：Store 操作在线程池执行，避免 SQLite 读写阻塞 event loop，提升高并发性能。
- **`confirmation_ttl_seconds` 从 300s 增加到 600s**：给用户更充裕的时间做 yes/no 决策。
- **Stale executing 状态自动恢复**：prune 后台任务每 60s 自动将卡在 `executing` 超过 120s 的确认记录恢复为 `pending`，不再依赖下次请求触发。涉及 SQLite/Redis/PostgreSQL 三个存储后端。

### Previous Security

- **[Critical] 真正的加密存储**：脱敏映射改用 Fernet (AES-128-CBC+HMAC) 加密，替代原有的 base64 编码。密钥自动生成并持久化到 `config/aegis_fernet.key`（权限 0600）。支持 `AEGIS_ENCRYPTION_KEY` 环境变量显式指定。向后兼容旧 base64 数据。
- **[Critical] Gateway Key 自动生成**：`AEGIS_GATEWAY_KEY` 留空时首次启动自动生成 32 字符 `secrets.token_urlsafe` 密钥，持久化到 `config/aegis_gateway.key`（权限 0600）。所有管理端点使用 `hmac.compare_digest` 常量时间比较。
- **管理端点全面鉴权**：register/lookup/add/remove/unregister 端点均需要 `gateway_key` 匹配配置值，且仅允许内网 IP 访问。
- **管理端点速率限制**：新增 `AEGIS_ADMIN_RATE_LIMIT_PER_MINUTE`（默认 30），按 IP 限流。
- **可信代理处理**：新增 `AEGIS_TRUSTED_PROXY_IPS`（支持 CIDR），仅从配置的代理 IP 信任 X-Forwarded-For。默认不信任任何 XFF。
- **v2 SSRF 防护**：新增 `AEGIS_V2_BLOCK_INTERNAL_TARGETS`（默认 true），阻止 v2 代理请求到 RFC1918、loopback、link-local、云元数据端点。
- **请求管道超时改为阻断**：新增 `AEGIS_REQUEST_PIPELINE_TIMEOUT_ACTION`（默认 `block`），请求过滤超时时默认阻断而非放行未过滤内容。
- **Token 熵增强**：网关 token 从 10 字符增至 24 字符（约 144 位熵）；确认动作绑定 token 从 40 位增至 64 位熵。
- **错误信息脱敏**：阻断响应不再暴露内部异常堆栈信息。
- **正则规则修复**：修复 `security_rules.py` 中约 30 个双转义正则表达式（PII 检测、注入检测、输出清洗），此前这些规则因 `\\b` 等模式无法正确匹配。
- **依赖补全**：`pyproject.toml` 新增 `cryptography>=41.0.0`。

### Changed

- **文档口径与当前实现同步（CLIProxyAPI 接入与边界说明）**
  - `README.md`：补充 `v1` 默认上游直连模式（`AEGIS_UPSTREAM_BASE_URL`）与 token 模式并行说明；明确 `v2` 需走 token 路径的安全边界。
  - `README.md`：修正 `AEGIS_V2_RESPONSE_FILTER_BYPASS_HOSTS` 含义，仅用于响应过滤跳过，不是目标主机访问白名单。
  - `config/README.md`：更新 `gw_tokens.json` 默认持久化路径与 `config/.env` 可选行为说明。
  - `CLIPROXY-QUICKSTART.md` / `OTHER_TERMINAL_CLIENTS_USAGE.md`：同步 Caddy 对公网 `__gw__` 管理端点阻断策略、流式与长上下文建议参数、直连/Token 双接入方式。

- **部署默认行为调整：默认不启用 Caddy / CLIProxyAPI**
  - `docker-compose.yml` 改为基础栈，仅启动 `aegisgate`。
  - 新增 `docker-compose.cliproxy.yml` 作为按需叠加文件，显式启用 `caddy + cli-proxy-api` 与 CLIProxy 代理优化参数。

### Fixed

- **[Critical] 网关卡死：`_flatten_text` 无法处理 Responses API 的 `function_call` 类型输出**
  - `gpt-5.3-codex` 等模型在 `output` 中返回 `function_call`/`computer_call`/`bash` 类型 item 时，`_flatten_text` 返回空字符串，导致 `_extract_responses_output_text` / `_extract_chat_output_text` 回退到 `json.dumps(upstream_body)`。
  - 上游响应 body 包含完整 `instructions` 字段（Codex CLI 系统提示词，可达 40k+ 字符），被当作"模型输出文本"传给全部响应过滤器，导致过滤器在巨大文本上执行正则、循环等 CPU 密集操作。
  - **修复**：`_flatten_text` 新增对 `function_call`/`computer_call`/`bash` 类型的简短摘要生成，永远不再产生空字符串迫使调用方 fallback。
  - **修复**：`_extract_responses_output_text` 与 `_extract_chat_output_text` 安全回退改为仅提取 `status`/`error` 字段的短字符串，**不再** `json.dumps` 整个 body。

- **[Critical] 网关卡死：过滤管道同步执行阻塞 event loop**
  - `enable_thread_offload=False`（默认值）时，`pipeline.run_request` / `pipeline.run_response` 直接在 asyncio event loop 线程中同步执行。CPU 密集型过滤器（正则扫描、typoglycemia 检测等）处理大文本时会占用 event loop 数秒至数十秒，令网关无法处理任何新请求，表现为"卡死"。
  - **修复**：`_run_request_pipeline` / `_run_response_pipeline` 无论 `enable_thread_offload` 设置如何，现在一律通过 `asyncio.to_thread` 在线程池中执行，保证 event loop 永远不被阻塞。
  - **新增**：通过 `asyncio.wait_for` 对过滤管道强制施加硬超时（默认 30 秒）。超时后请求侧原样放行，响应侧返回超时拦截。
  - **新增** `AEGIS_FILTER_PIPELINE_TIMEOUT_S`（settings: `filter_pipeline_timeout_s`，默认 `30.0`）：控制过滤管道最大执行时间。设为 `0` 表示不限制。

### Added

- **Pipeline 逐过滤器耗时日志**
  - `pipeline.py` 现在对每个过滤器记录执行耗时（`filter_done phase=... filter=... elapsed_s=...`）。
  - 耗时超过 1 秒的过滤器会升级为 **WARNING** 级别（`slow_filter`），方便快速定位性能瓶颈。

- **调试日志：原文摘要长度可配置与诊断**
  - 新增环境变量 `AEGIS_DEBUG_EXCERPT_MAX_LEN`：覆盖默认截断长度（默认 500 字符）。设为 `0` 表示不截断，在 DEBUG 下打印完整 request/response 原文（日志会很长，建议仅在排查问题时临时开启）。
  - `debug_excerpt` 支持 `max_len <= 0` 表示不截断。
  - 每次 `debug_log_original` 调用会多打一条诊断日志：`debug_excerpt label=... AEGIS_DEBUG_EXCERPT_MAX_LEN=... max_len_used=... original_len=... excerpt_len=... truncated=...`，便于排查「为何仍被截断」。
  - 在 `response_before_filters` 调用前增加 `response_before_filters (chat)|(responses) input_len=... request_id=...` 日志，便于确认传入的响应文本长度。

---

## 使用说明

### 修复卡死问题后的配置项

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AEGIS_FILTER_PIPELINE_TIMEOUT_S` | `30.0` | 过滤管道最大执行时间（秒），超时后响应被拦截，请求被放行，`0` 表示不限制 |
| `AEGIS_ENABLE_THREAD_OFFLOAD` | `true` | 控制 Store 操作是否在线程池执行（默认开启，避免 SQLite 阻塞 event loop） |

### 调试日志配置

- **完整打印 request/response 原文**：启动前设置 `AEGIS_DEBUG_EXCERPT_MAX_LEN=0`（Docker 需在 compose 的 `environment` 中配置并重启容器）。
- **仅放宽长度**：例如 `AEGIS_DEBUG_EXCERPT_MAX_LEN=20000`。
- 若设置后仍看到截断，请查看同一次请求的 `debug_excerpt` 诊断行中 `AEGIS_DEBUG_EXCERPT_MAX_LEN` 与 `max_len_used` 的值，以判断是环境变量未生效还是下游日志层截断。
