# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **过滤模式（Filter Mode）**：token 路径支持 `__redact` 和 `__passthrough` 后缀，按需切换过滤行为
  - `token__redact`：仅执行脱敏过滤器（`exact_value_redaction` / `redaction` / `restoration`），跳过安全检测
  - `token__passthrough`：跳过所有过滤器，请求/响应直接转发
  - 无效模式名返回 `400 invalid_filter_mode`
  - 审计日志记录 `filter_mode:redact` / `filter_mode:passthrough` 安全标签
  - 端口路由同样支持：`/v1/__gw__/t/8317__redact/...`

- **请求统计仪表盘**：新增 `GET /__ui__/api/stats` 端点和 UI 统计页面
  - 线程安全的内存统计收集器，按小时分桶，保留 7 天
  - 追踪 5 个维度：总请求、脱敏替换次数、危险内容替换、拦截、穿透
  - UI 页面包含汇总卡片 + 按小时/按天表格，支持刷新

### Changed

- **Token 生成改为纯字母数字**（`a-zA-Z0-9`），不再包含 `-` `_` 符号，避免与 `__` 过滤模式分隔符冲突

### Fixed

- **[Critical] tool_call_guard `review` 动作在流式模式下被当作 `block` 处理**
  - `_stream_block_reason()` 只要检测到 `tool_call_violation` 标签就触发流阻断，不区分 `block`/`review`
  - 导致 `apply_patch`、`write` 等编码工具的正常 tool call 被整体替换为 `【AegisGate已处理危险疑似片段】`
  - 修复：仅在 `tool_call_guard:*:block` 动作存在时才触发流阻断，`review` 动作不再阻断流

- **tool_call_guard 对编码工具参数的误拦截**
  - `apply_patch` 等工具的参数是代码/diff 内容，其中可能包含看起来像危险命令的文本
  - 新增 `_CODE_CONTENT_TOOLS` 白名单（25+ 编码工具），跳过 `dangerous_param_patterns` 扫描
  - `dangerous_param` action 从 `block` 降为 `review`，避免过度拦截
  - tool_call_guard 各类命中新增 DEBUG 日志，打印匹配的工具名、pattern、具体文本

- **[Critical] SSE 流式 holdback 分隔符泄露导致客户端 JSON 解析失败**
  - content 事件被 hold back 时，SSE 空行分隔符直接 yield 给客户端，导致事件顺序错乱
  - `response.completed` 在剩余 text delta 之前到达，且 flush 的 pending 事件之间缺少分隔符
  - 客户端收到破损 SSE 流 → `Unexpected end of JSON input`
  - 修复：`_suppress_next_separator` 标志位抑制被 hold back 事件的分隔符，释放时补上 `b"\n"`
  - chat completions 和 responses 两条流式路径均已修复

- **[Critical] 被阻断的 tool call `function.arguments` 非法 JSON**
  - `_patch_chat_tool_call` 将 `arguments` 设为裸中文占位符（非 JSON），客户端解析失败
  - 修复：改为 `json.dumps({"_blocked": "【AegisGate已处理危险疑似片段】"})`

- **日志 `info_log_sanitized` 泄露原始危险 tool call 内容**
  - `_extract_chat_output_text` 生成 tool call 摘要时未检测危险性
  - 修复：先检查 `_looks_executable_payload_dangerous`，危险内容用占位符替代

### Changed

- **过滤规则降敏（降低误报率）**
  - `dangerous_param_patterns`：`&&`/`;`/`||`/`` ` `` 裸匹配 → 必须后跟危险命令（curl/wget/bash/sh/nc 等）
  - `python`/`perl`/`ruby`/`php` → 仅在 `-c`/`-e` 内联执行标志时触发
  - `semantic_approval_patterns`：`delete`/`drop` 裸词 → 仅匹配完整短语如 `drop table`
  - `privilege_escalation`：`读取配置`/`read config` 过宽 → 收窄为 `系统配置`/`system file` 等
  - `tool_call_injection`：severity 9→6，action block→review，从 non-reducible 移除
  - `obfuscated`：从 non-reducible 移除（讨论编码原理时可降分）
  - non-reducible 类别：5→3（仅保留 system_exfil, unicode_bidi, spam_noise）

### Added

- **电脑/基础设施信息 PII 脱敏（请求侧，宽松模式）**
  - 新增 9 个 field-labeled 模式：SYS_HOSTNAME、SYS_USERNAME、SYS_OS_VERSION、SYS_KERNEL、SYS_HOME_PATH、SYS_ENV_VAR、SYS_DOCKER_ID、SYS_K8S_RESOURCE、SYS_INTERNAL_URL
  - 仅匹配 `field: value` / `field=value` 格式（如 `hostname: prod-web-01`），避免普通提及误报
  - SYS_HOME_PATH 和 SYS_INTERNAL_URL 无需字段标签，直接匹配路径/URL 格式

---

## [Previous]

### Breaking Changes

- **yes/no 确认放行流程已永久移除**
  - 所有危险内容统一走自动遮挡/分割处理，不再支持手动放行
  - `YES_WORDS` 已清空，`parse_confirmation_decision("yes")` 返回 `"unknown"`
  - `confirmation_template` 改为纯通知模板（拦截原因 + 处理方式 + 事件编号），不含 yes/no 选项
  - `AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK` 已废弃，无论值为何均等同 `false`
  - 发送 `yes cfm-xxx--act-yyy` 将返回 `⚠️ [AegisGate] 放行功能已禁用` 提示
  - 处理策略：无风险→直接透传；轻度危险→每3字符 `-` 分割；重度危险/指令→替换为 `【AegisGate已处理危险疑似片段】`；垃圾内容→替换为 `[AegisGate:spam-content-removed]`

### Added

- **垃圾内容噪声检测（`spam_noise` 信号）**
  - 新增 3 类 spam 模式：赌博（`彩神争霸`/`大发快三`/`北京赛车` 等 18 关键词）、色情（`毛片`/`无码`/`一级特黄` 等 14 关键词）、平台推广（`菲律宾申博`/`娱乐平台注册` 等 8 关键词）
  - 同一消息命中 >=2 个不同类别时触发 `spam_noise` 信号 → action: `block`，不可被讨论上下文缓解
  - 已加入 `non_reducible_categories`，防止误判为"研究讨论"而被降权

- **结构化 tool call 参数安全扫描**
  - 新增 `InternalResponse.tool_call_content` 属性，自动提取 OpenAI `function.arguments` 和 Anthropic `tool_use.input`
  - `injection_detector` 和 `output_sanitizer` 的响应管道同时扫描 `output_text` + `tool_call_content`
  - 对 `choice`/`msg`/`tc`/`func` 等嵌套字段做全链路 `isinstance` 防御，防止上游返回 `null`/非 dict 时崩溃

- **增强 spam + tool injection 组合检测**
  - `tool_call_with_spam` / `spam_with_tool_call` 的 tool call 匹配部分新增 `functions\.` 命名空间（覆盖 `functions.ls` 等变体）
  - 新增独立规则 `to_eq_functions`：检测 `to=functions.xxx` 格式的伪造函数调用
  - 匹配距离从 30 字符扩展到 60 字符

- **消息级多脚本多样性检测**
  - 当同一消息出现 >=3 种非常见 Unicode 脚本（如亚美尼亚文+古吉拉特文+格鲁吉亚文）时触发 `obfuscated` 信号
  - 常见脚本（Latin/CJK/Hiragana/Katakana/Hangul/Fullwidth/Digit）不计入

- **处理后内容 INFO 级别日志**
  - 新增 `info_log_sanitized()` 函数（`debug_excerpt.py`），在 INFO 级别记录遮挡/分割后的内容摘要
  - 覆盖所有 auto-sanitize 路径：chat completions / responses endpoint / chat stream / responses stream / generic proxy / generic stream / request blocked
  - 默认截断 800 字符，可通过 `AEGIS_DEBUG_EXCERPT_MAX_LEN` 环境变量调整

### Fixed

- **[Critical] `tool_call_content` 属性在上游返回 `tool_calls: null` 时崩溃**
  - `msg.get("tool_calls", [])` 在值为 `null` 时返回 `None` 而非 `[]`，导致 `for tc in None` 抛出 `TypeError: 'NoneType' object is not iterable`
  - 已修复：使用 `msg.get("tool_calls") or []` 并对所有嵌套字段添加 `isinstance` 防御

- **[Critical] 过滤器 sanitize 管道未真正修改响应文本**
  - `PostRestoreGuard`：sanitize 模式下计算了 masked 文本，但未回写 `resp.output_text`，导致恢复后的密钥/token 原样泄露。
  - `OutputSanitizer`：sanitize 模式下计算了 cleaned 文本，但未回写 `resp.output_text`，导致危险 markup/URI/命令片段原样返回。
  - 已修复：两个过滤器现在在 sanitize 路径正确回写处理后的文本。

- **[Critical] 确认放行后释放未经任何 sanitize 的原文**
  - 用户确认放行（`yes cfm-xxx`）后，网关重新执行请求但直接恢复上游原文，绕过了所有过滤器的 sanitize 结果。
  - 已修复：确认放行路径现在对 block/sanitize 级响应做 hit-fragment 变形后再返回（纵深防御）。

- **disposition="sanitize" 错误触发确认流程**
  - `_needs_confirmation()` 将 `sanitize` 与 `block` 等同处理，导致已就地清洗完成的响应仍需用户确认。
  - 已修复：仅 `block` 触发确认流程，`sanitize` 直接返回修改后的响应。

- **generic proxy 路径 sanitize 结果丢失**
  - generic proxy 在 `sanitize` disposition 时跳过了过滤器已处理的文本，返回未修改的上游原文。
  - 已修复：新增 `disposition == "sanitize"` 提前返回分支。

### Added

- **可配置拦截行为：`AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK`（现已废弃）**
  - 原本支持 `true` 走确认流程，现已永久禁用，所有路径统一自动遮挡/分割
  - `_sanitize_hit_fragments()` 辅助函数保留，作为自动遮挡的核心实现

- **极度危险指令完全移除（分级变形策略）**
  - 匹配约 45 条高危模式（`rm -rf`、SQL 注入、反弹 shell、fork bomb、`curl|bash`、`dd if=of=`、`mkfs`、`powershell -enc` 等）的片段被替换为 `【AegisGate已处理危险疑似片段】`，原文**不会出现在返回中**
  - 一般危险片段仍使用 chunked-hyphen 分词变形
  - 模式来源：`anomaly_detector.command_patterns` + `sanitizer.force_block_command_patterns` + `privilege_guard.blocked_patterns` + 硬编码高危 shell 命令（13 条）

- **TF-IDF 语义检测模块**（Phase 1）
  - 内置轻量 TF-IDF + LogisticRegression 双语分类器，无需 GPU，约 166KB 模型文件
  - 训练数据：deepset/prompt-injections + 中英文补充样本（DAN/jailbreak/角色劫持 + Agent 工作指令安全样本）
  - 三层检测逻辑：TF-IDF 高置信度安全直接放行 → 高置信度注入标记 → 灰区交正则细分 → TF-IDF 安全中置信度抑制正则误报
  - 新增 `AEGIS_ENABLE_SEMANTIC_MODULE`（默认 `true`）
  - 重训练脚本：`scripts/train_tfidf.py`
  - 新增可选依赖组：`pip install ".[semantic]"`（scikit-learn、jieba、joblib）

### Security

- **安全阈值全面调低（语义化检测 + 减少误杀）**
  - **默认安全级别改为 `medium`**：大部分"可能危险"指令不拦截，仅高危 + 脱敏
  - `injection_detector` 评分模型：`nonlinear_k` 2.2→2.0，`allow` 0.35→0.40，`review` 0.70→0.75
  - `injection_detector` 信号严重度：`direct` 7→5，`html_markdown` 4→3，`remote_content` 7→5，`remote_content_instruction` 8→6，`indirect_injection` 8→6，`typoglycemia` 5→4，`unicode_invisible` 5→4
  - `privilege_guard` 风险地板：request 0.75→0.65，response 0.70→0.60
  - `anomaly_detector` 重复阈值：ratio 0.45→0.55，max_run_length 50→80，repeated_line 28→40
  - `anomaly_detector` 评分模型：`nonlinear_k` 2.2→2.0，`allow` 0.35→0.40，`review` 0.70→0.75
  - `rag_poison_guard` 风险分：ingestion 0.88→0.80，retrieval 0.78→0.70，propagation 0.82→0.75
  - 安全级别乘数：medium（阈值×1.30，地板×0.85），low（阈值×1.60，地板×0.70）
  - **保持 disposition=block 强制拦截**：system_exfil（10）、obfuscated（9）、unicode_bidi（10）在任何安全级别下都被拦截
  - `leak_check` 从 `block` 改为 `review`：Agent 工作指令提到 "system prompt"/"write_file" 不再被拦截

- **此前已修复的安全过滤问题（保留记录）**
  - `privilege_guard`：精确化中英文模式——"读取配置文件"、"show token usage" 不再误杀
  - `output_sanitizer`：移除 `docker ps/images/logs` 等只读诊断命令的强制拦截
  - `request_sanitizer`：`rule_bypass` 动作从 `block` 改为 `review`

- **[Critical] 修复 action=block 在 low 级别下失效的问题**
  - `security_level=low` 时 risk_threshold 被 cap 到 1.0，导致 `injection_detector`（system_exfil/obfuscated/unicode_bidi）和 `privilege_guard` 的 block action 仅提升 risk=0.95 但无法达到阈值——真正的高危指令被放行。
  - **修复**：所有 action=block 的过滤器现在直接设置 `disposition=block`，绕过 risk_threshold 限制，确保高危指令在任何安全级别下都被拦截。
  - 涉及：`injection_detector`（区分 request/response phase）、`privilege_guard`（request + response）。

### Changed

- **默认安全级别改为 `medium`**：宽松模式，大部分"可能危险"指令不拦截，仅高危 + 脱敏；高危指令（系统提示泄露、编码攻击、凭据泄露）仍通过 disposition=block 强制拦截。语义检测模块（TF-IDF）默认开启，进一步降低误报。
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
| `AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK` | `false` | **[已废弃]** 放行确认流程已移除，无论值为何均自动遮挡/分割后返回 |

### 调试日志配置

- **完整打印 request/response 原文**：启动前设置 `AEGIS_DEBUG_EXCERPT_MAX_LEN=0`（Docker 需在 compose 的 `environment` 中配置并重启容器）。
- **仅放宽长度**：例如 `AEGIS_DEBUG_EXCERPT_MAX_LEN=20000`。
- 若设置后仍看到截断，请查看同一次请求的 `debug_excerpt` 诊断行中 `AEGIS_DEBUG_EXCERPT_MAX_LEN` 与 `max_len_used` 的值，以判断是环境变量未生效还是下游日志层截断。
