# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **PII 规则的 `enabled` 开始真正生效，并在同一版本提供对应 UI**。此前 `redaction.pii_patterns`
  条目上的 `enabled` 字段没有任何读取者：写了 `enabled: false` 的规则照常编译、照常脱敏。
  现在 V1 管道层、V1 转发层与 V2 三处编译循环统一读同一个谓词
  （`config/security_rules.rule_enabled()`），控制台面板也读它——**面板显示为停用的规则，
  不可能仍在改写流量**。

  谓词是 fail-safe 的：只有显式的布尔 `false` 才停用规则。`enabled: "false"`（字符串）或
  `enabled: 0` 一律按启用处理——对脱敏规则来说，「继续脱敏」是歧义值的安全读法，而控制台只会写真布尔。
  legacy 的字符串形式条目没有这个字段可读，恒编译。

  **升级前请检查配置里是否已存在 `enabled: false`**：这些规则此前一直在运行，本版本起将真正停用。
  上一版本的面板会列出它们并给出「待启用语义」告警。
  **回滚前同样需要确认**：旧版本忽略该字段，会把这些规则重新启用。

- **新增 `PATCH /__ui__/api/request_redaction/settings`**，只接受强类型领域操作，不接受任意 key path：

  - `relaxed.set_mode`（`default` / `all`）、`relaxed.set_membership`、
    `relaxed.materialize_custom`、`relaxed.remove_unresolved`；
  - `values`：`normalize_nfkc`、`strip_invisible_chars`、`request_prefix_max_len`（有界 1–64）。

  该端点**强制携带具体 `If-Match`**，缺失或 `*` 返回 428。既有 `/__ui__/api/rules/{section}` 与
  `/__ui__/api/rules_action_map` 维持「present 则校验」的历史契约不变——改成强制会让所有不发
  `If-Match` 的既有脚本对**任意**规则组的写入直接失败。

- **控制台面板可管理 PII 规则与 relaxed 集**：逐条启用/停用、逐条 relaxed 归属、增删改、
  正则测试（复用规则工作台的正则实验室，含服务端固定对抗样本探针）、以及三个归一化参数。
  两个控件各写一个维度：**停用不会删除 relaxed 归属**，重新启用后的范围没有隐藏状态。

  relaxed 模式之间的转换不对称，因此都要求明确触发：

  - 自定义 → 代码默认：**删除 YAML key**，而不是写入当前默认集合（写入会把它冻结）；
  - 代码默认 → 自定义：以当前默认集合为基线，需要 `confirm_materialize`；
  - 全部 → 自定义：按当前完整 configured ID 集展开，需要 `confirm`，
    确认框列出两处已知的无害不等价（编译失败的条目会被收进来；legacy 字符串 field 条目按
    `FIELD_SECRET_{idx}` 展开，与真正受 relaxed 过滤的 E3/E4 一致）；
  - 任意模式 → 空列表：`confirm_empty` 二次确认并写审计。

  逐条修改采用**增量语义**：未被操作的 field ID 与悬空成员原样保留。新增未知 ID 一律拒绝；
  删除既有悬空 ID 必须走 `remove_unresolved`。存在归一化 ID 冲突时相关写入返回
  `409 id_normalization_conflict`，不替管理员选择保留哪一条。

- **删除 PII 规则会在同一次写入里处理它的 relaxed 归属**，且**没有** `409 rule_referenced`：
  自定义列表模式下一并移除该成员（或按 `confirm_referenced=true` 保留悬空引用）；
  代码默认模式下直接允许删除，响应附「无害悬空引用」提示并写审计——悬空 ID 只会让集合过滤跳过它
  并记录一次告警，为此强制管理员先做一次 relaxed 模式迁移，等于把代码默认集写死进 YAML。

### Changed

- 精确值脱敏从独立的顶层 `<section>` 迁入「请求侧脱敏」面板，改为 `<div id="redact-values">`：
  `#redact-values` 旧书签仍然定位正确，但滚动到该区域时侧栏高亮的是「请求侧脱敏」。
  嵌套 `<section>` 会与包含它的面板争夺 scroll spy（选择器是 `main section[id]`），故用 `div`；
  `.panel` 是类选择器，样式不变。精确值的旧侧栏入口已移除。
- 规则工作台不再列出 `redaction.pii_patterns`——它现在由请求侧脱敏面板端到端管理。
  CRUD 端点保持开放（面板正是通过它们工作），`/__ui__/api/rules` 为该组返回 `hidden: true`。
  这样一条 PII 规则只有一个编辑入口，删除时的 relaxed 后果也总会被展示。
- `enabled` 通过独立的布尔白名单处理，不再经过 `_RULE_EXTRA_STRING_FIELDS`——
  后者会把值 `str()` 成 `"False"`，而非空字符串在 YAML 里是真值。非布尔值返回 400。
- `adapters/v2_proxy/router.py` 的 `_compile_patterns` 由 `pii_patterns`、`field_value_patterns`
  与 `sanitizer.command_patterns` 共用，因此遵守 `enabled` 的行为改为**由调用方显式开启**
  （`honour_enabled=True`），只有两个 redaction 调用点传它。三个 V1 过滤器
  （`filters/sanitizer.py`、`filters/request_sanitizer.py`、`filters/anomaly_detector.py`）
  完全不读该字段，若 V2 单方面遵守，一条 `enabled: false` 的危险命令规则会在 V2 上被关掉、
  在 V1 上继续运行——对一个阻断类检测控件来说是单侧变松。
- `enabled` 只在**确实有编译循环读取它**的规则组上被接受（`redaction.pii_patterns`、
  `redaction.field_value_patterns`），其余规则组返回 400 `field_not_supported`：
  否则写进去的是一个要么毫无效果、要么只在部分执行层生效的字段。
- **PII 规则 ID 采用去空白、大小写不敏感的唯一性校验**（v4 §2.3）。`relaxed_pii_ids` 按归一化后的
  ID 解析，因此同时存在 `EMAIL` 与 `Email` 时它无法判断成员指向哪一条，面板也会因此进入阻断状态。
  此前 CRUD 只做精确字符串比较，等于允许控制台给自己制造这个状态。现在：新增会与既有 ID 归一化比较，
  冲突返回 409 `id_normalization_conflict`；已存在冲突时，针对该 ID 的**修改**被拒绝，
  **删除仍然放行**——删掉其中一条正是唯一的解法。其他规则组的精确匹配契约不变。
- 存在归一化冲突时，`materialize_custom` 与 `remove_unresolved` 一并拒绝：前者会把两种写法
  静默折叠成一个成员。
- 规则更新的审计除字段名外还记录**新值**（正则与 `patterns` 除外）。此前停用一条规则与重新启用它
  留下的审计记录完全相同，看不出发生了什么。relaxed 写入同时记录 `relaxed_members_after` 与
  `relaxed_emptied`。
- 删除一条会让自定义 relaxed 列表清空的规则时，面板会**再问一次**并说明后果，
  而不是替调用方补上 `confirm_empty=true`——服务端为此设的门不能由发起方自己答掉。

### Added

- **控制台新增「请求侧脱敏」面板（只读）**，侧栏位于「安全规则」之前。此前控制台没有任何一处
  说明四个总控各自控制哪一层、一条 PII 规则到底在哪些执行面上生效，也没有说明两类绕过机制的前置条件。
  面板集中回答这些问题，**全部由服务端计算后下发，前端不做任何推导**
  （新端点 `GET /__ui__/api/request_redaction/settings`）：

  - **六个执行面模型**。请求侧脱敏不是「V1 / V2」两桶：E1 V1 管道层·对话路由、E2 V1 管道层·其他路由、
    E3 V1 转发层·对话消息/system/instructions/tools、E4 V1 转发层·multipart 表单字段、
    E5 V1 转发层·通用 `/v1/<subpath>` JSON、E6 V2 请求体。其中 **E1/E3/E4 三个受 `relaxed_pii_ids` 支配**。
    E4 尤其容易被忽略：multipart 路由不在低误报路由白名单里，所以 **E2 用全量集打分，而 E4 用 relaxed 集
    实际改写外发内容**——把一个 ID 移出 relaxed 集，会同时关掉它在上传表单字段上的转发期脱敏。
  - **总控真实作用层**。`enable_redaction` 只控制 V1 管道层，不控制 V1 转发期的 `[REDACTED:ID]`；
    `enable_restoration` 对 `[REDACTED:ID]` 无效；V1 转发期脱敏显示为**强制安全基线，没有关闭开关**。
  - **豁免与绕过按路由分层**。字段级白名单**只保护指定 key/span，不是整请求绕过**；V1 会把 token 注入的 key
    再过一遍 denylist 而 V2 不会，所以面板对每个 key 分别标注「V1 忽略 / V2 生效」；
    上游白名单显示 `allow_public_upstream_whitelist` 与 client_is_internal 两个前置条件的当前值。
  - **覆盖面表**，含此前三处文档都漏掉的一行：**V1 multipart 的文件内容不脱敏、不扫描**，
    字节原样转发，分析文本里只放一个 `[BINARY_CONTENT]` 占位。`/v1/files` 是最容易夹带凭据的通道。
  - **Field 规则只读展示**三层各自的 fallback ID、`field_value_min_len` 下限差异（V1 两层 `max(8,…)`，
    V2 `max(12,…)`）与是否受 relaxed 过滤。本期不提供逐条启停——那会造出「YAML 已停用但 V2 fallback 仍在跑」的假控制。
  - **规则文件路径自检**与影子文件提示（见上一版本的路径统一修复）。
  - 配置里已存在的 `enabled: false` 会显示「待启用语义」告警：当前代码不读取该字段，这些规则仍在运行，
    生效面按「运行中」计算。

  本阶段**保留全部旧入口与旧 CRUD**，规则增删改仍在「安全规则」中进行。

### Changed

- 精确值脱敏面板的「V1/V2 均适用」文案纠正：V1 只对**对话路由的扁平消息文本**生效，
  结构化内容、`instructions`、工具定义、通用 `/v1/<subpath>` JSON 与 multipart 均不生效；
  V2 需 `enable_exact_value_redaction` 与 `v2_enable_request_redaction` 同时开启。替换不可还原。
- 统计卡口径纠正为「管道层去重后的敏感值替换数（含 PII 与 field 规则，统计期内）」：
  该计数**含 field 规则**，且因为相同原文复用同一占位符，它是**唯一敏感值个数**而非命中次数；
  不含 V1 转发层替换、V2 替换与精确值替换（`ExactValueRedactionFilter.report()` 不提供 `replacements`，
  实际贡献恒为 0）。
- `adapters/openai_compat/router.py` 导出公开常量 `WHITELIST_HEADER_DENYLIST`（保留下划线别名），
  `config/security_rules.py` 导出 `DEFAULT_RELAXED_PII_IDS` 与 `configured_redaction_pattern_ids()`，
  供控制台使用，避免反向依赖私有名。
- `core/rules_write.py` 记录最近一次**通过写入后校验**的规则应用，供面板显示「当前运行的是哪一版」；
  重新从磁盘计算一遍集合回答的是另一个问题。
- 面板下发的 `ETag` 改为在构造响应体**之前**读取，并随响应体一并返回（`rules_etag`）。
  原先的顺序会在并发写入时把一个比响应体更新的校验值交给控制台——那正是 `If-Match` 要拦的覆盖；
  改成先读校验值后，并发写入只会让下一次保存变成 409。
- 执行面徽章在被总控关掉时改为置灰加删除线，不再用警告色——那会让一个已关闭的执行面比生效的还醒目。
- Field 层表更正 V2 一列：V2 与 `pii_patterns` 共用同一个编译循环，因此没有 id 的映射条目缺省为
  `rule` 而不是 `field_secret_{idx}`（后者只用于 legacy 字符串条目），并注明 V2 的两条 fallback
  与显式列表**同时**编译，而 V1 只在列表为空时才用 fallback。
- 「查看安全规则原始配置」链接仅在 `field_value_patterns` 确实写在 YAML 里时才渲染：
  规则工作台只列出文件中存在的规则组，否则该链接会落到一个不相干的组上。

### Fixed

- **控制台可能写入运行时从不读取的规则文件（路径解析统一）**。`config/security_rules.py`、
  `core/gateway_ui_routes.py`、`core/hot_reload.py` 三处各自解析 `AEGIS_SECURITY_RULES_PATH`：
  加载器走 `cwd` → 包根 → `AEGIS_BOOTSTRAP_RULES_DIR`，控制台与热重载监听器只试 `cwd`。
  在 `cwd != 应用根目录` 的部署（Docker 镜像、`AEGIS_CONFIG_DIR` 布局）里，控制台会在 `cwd` 下
  凭空建出一份 `security_filters.yaml` 并对它做 ETag、备份与校验，**所有校验都通过、审计记录成功，
  但规则从未生效**。三处现统一调用 `config/security_rules.py` 的 `resolve_rules_file()`。
  **这是本次唯一的对外行为变化**：升级后控制台写入的就是运行时读取的文件；请检查此前是否留下过
  这类「影子文件」（典型位置：启动目录下与 `AEGIS_SECURITY_RULES_PATH` 同名的相对路径）。
- **一条 legacy 字符串形式的 `redaction.field_value_patterns` 会让每个 V2 请求脱敏抛错**。
  `adapters/v2_proxy/router.py` 的 `_compile_patterns` 直接对每一项调用 `item.get("regex")`，
  没有 `isinstance` 判断；而 `lru_cache` 不缓存抛异常的调用，所以 `AttributeError` 会在**每个**
  V2 请求上重新抛出，不是一次性故障。现按 V1 管道层与转发层已有的双分支语义编译
  （V2 侧 id 小写，`field_secret_{idx}`，对齐 `sanitize.py` 的 `FIELD_SECRET_{idx}`）。
- 规则组的最后一条规则被删除后，YAML 里留下的裸 `key:` 会被解析成 `null` 而不是空列表，
  且此后无法再通过控制台加回规则。删除会写出显式的 `key: []`，新增能识别该形态。

### Security

- **规则文件写入改为串行化事务**（`core/rules_write.py`）。此前 `security_filters.yaml` 有三条
  互不加锁的整档 read-modify-write 路径（PII/规则 CRUD、action_map、以及各 section 共用的保存函数），
  `If-Match` 又是在读取「真正被写入的字节」之前校验的。并发写入下的表现不是丢一次编辑，而是
  一份显示「已保存」、实际仍在执行旧策略的安全策略。现在所有写入共用**同一把规则文件级、
  全 section 共享的进程内写锁**，锁内重新读字节、重算 ETag、校验 `If-Match`，然后：
  保留注释地打补丁 → 重新解析并证明本次目标 section 之外的内容逐字节未变 → 在文件外编译
  V1 管道 / V1 转发 / V2 三层的候选正则产物 → 对**新增或修改**的正则跑服务端固定对抗样本探针
  （子进程 + 2s 超时）→ 毫秒级时间戳备份 → 原子替换 → 结构化热重载 → 校验磁盘字节与各层重编译
  产物 → 失败时 **compare-and-restore** 回滚。
- **回滚不再覆盖并发写入者已提交的改动**。无条件恢复旧字节会把另一位管理员刚落盘的规则静默回退；
  现在只有磁盘当前字节仍等于本次写入的字节时才恢复，否则返回 `409 concurrent_write_detected`
  并在响应与审计中标注「未回滚，磁盘已被其他写入者变更」。
- **保存路径不再接受调用方自选的简单样本**。控制台的正则测试器由调用方提供样本，
  用「hello」测 `(a+)+$` 会顺利通过；保存路径改为额外跑一组服务端维护的固定对抗样本，
  超时即拒绝保存，并强制 `MAX_REGEX_LEN` 上限。
- **规则写入全部落审计**：新增/修改/删除、写入失败、回滚结果，以及「检测到并发写入、未回滚」
  这一分支。审计不记录正则命中的敏感原文。
- 规则备份改为毫秒级时间戳并在同毫秒冲突时追加序号（此前连续写入会互相覆盖），
  权限与原文件一致，保留数量有上限，且命名保证不被 `policies_dir.glob("*.yaml")` 当成策略文件。
  `.gitignore` 现覆盖任意目录下的 `*.yaml.bak-*`。
- `_write_rules_text` 不再 `mkdir(parents=True)`：目标目录不存在说明路径解析出了问题，
  应报错而不是造出一棵目录树。
- **写入后的校验现在问了一个答案可能是「否」的问题**。原先的第 12 步把本次写入的字节重新解析、
  与从同一份字节算出的候选产物比较，恒真；真正会出问题的是写完之后某个**缓存**仍在提供旧文档。
  校验改为：从磁盘重新读回字节并重编译，再确认规则加载器提供的 `redaction` 各键与本次写入一致，
  否则判定为失败并回滚（`loader_stale:<key>`）。
- **`reload_security_rules()` 显式失效规则缓存，不再依赖 mtime 判断**。加载器按 `st_mtime_ns`
  缓存，而两次保存可能落在同一个文件系统时间戳刻度内，第二次就会被旧缓存应答、同时控制台报告
  「已生效」。热重载是按名索取的操作，因此先丢缓存再加载
  （新增 `config/security_rules.invalidate_security_rules_cache()`）。
- **写前编译的候选产物现在逐层还原三个层各自的读法**：id 大小写、`field_value_min_len` 下限、
  legacy 字符串条目的位置化 id，以及「V1 只在显式列表为空时才用代码 fallback，而 V2 两者都编译」
  这条关键差异。此前候选把三层当成同一种读法，V2 层因此少了两条恒生效的 fallback。
- **文件里已存在的非映射 `pii_patterns` 条目不再阻断所有写入**。三层运行时本来就跳过这类条目，
  而它没有 id、删不掉，所以为它拒绝一次无关编辑只会让控制台完全无法编辑该文件。
  现在只有**本次写入引入或改动**了这类条目才拒绝（按值比较，在其上方插入规则不算引入）。

### Changed

- **规则编辑器失败时返回错误，不再退回全量 `yaml.dump`**。此前补丁不适用时会 dump 整个文档并
  返回成功，代价是 `security_filters.yaml` 的全部 80 行注释——那些注释就是安全策略的文档。
  现在无法安全打补丁时返回非 2xx 且**不写文件**。为此补齐了两种此前只能靠 dump 兜底的形态：
  与 key 同缩进的 block list（`yaml.dump` 的默认输出），以及键路径的插入/删除。
- `core/rules_editor.py` 新增 `LeafOp` / `apply_leaf_ops` / `render_leaf_ops`：保留注释地插入、
  替换、删除一个键路径。删除是「恢复代码默认值」的实现方式——把当前默认集合写回文件会把它冻结。
  `apply_scalar_update` 被 `render_leaf_ops` 取代（后者还能创建缺失的键）。
- `reload_security_rules()` 返回结构化的分层结果（YAML 加载、OpenAI LRU、V2 LRU、pipeline、
  错误列表、pipeline generation），不再逐层吞掉异常。任一必需层失败都会让本次写入判定为失败并回滚。
- `adapters/v2_proxy/router.py` 导出公开常量 `V2_RELAXED_PII_IDS`（保留 `_V2_RELAXED_PII_IDS`
  别名），供控制台读取，避免反向依赖适配器内部名。

### Documentation

- **文档与代码全面对齐**（本次为文档 + 死配置清理，不改变任何过滤/拦截行为）

  **纠正的事实性错误**

  - `config/README.md` 称 `medium` 档「使用 YAML 声明的 `risk_threshold`」——实际上三档都会缩放。
    `medium` 系数为 `×1.30`，配 `default` 策略（0.85）时 `0.85 × 1.30 = 1.105` 被 clamp 到 **1.0**，
    `low`（×1.60）同样是 1.0，两档在默认策略下完全等价。三处文档补上系数表与实测有效阈值
    （README.md 新增「Security Levels」、README_zh §5.2、config/README.md §配置交互）
  - `config/README.md` 的不可热更新清单写「11 项」且漏了 `allow_public_upstream_whitelist`，
    实际 `_IMMUTABLE_FIELDS` 是 12 项——设了这个公网闸门却不重启会以为已生效
  - README.md 的 PII 特性行与 FAQ 宣称覆盖信用卡/SSN/邮箱/医疗记录，但没写路由限定：
    `/v1/chat/completions`、`/v1/responses`、`/v1/messages` 默认只跑 `relaxed_pii_ids` 凭据子集
    （56 条里的 12 条）。两篇 README 的特性行都补上限定
  - README.md 声称错误响应有 three families 却只给了两个示例；补上第三种（`gateway_auth`
    的无 `request_id` 信封）
  - `OTHER_TERMINAL_CLIENTS_USAGE.md` 的 `invalid_parameters` 排查条目与该文场景无关——
    这个码只由默认关闭的 `/relay/generate` 在缺 `x-upstream-base` 时返回。改为 `token_route_required`
  - README_zh §5.2 只列了 `injection_detector` 的 5 类强制拦截，遗漏 `rag_poison_guard`；并补充说明
    `restoration` / `sanitizer` 的 `block` **只抬分不设 disposition**，语义与前两者不同
  - README_zh 的 `AEGIS_MAX_MESSAGES_COUNT` 未写明只对 `/v1/chat/completions` 生效
  - `config/.env.example` 头部声称「hot-reloadable items are marked」但全文无任何标记；
    「Filter switches (all default to true)」紧接着就是 `AEGIS_ENABLE_SYSTEM_PROMPT_GUARD=false`
  - `README_zh.md` 章节编号从 2.1 直接跳到 2.3（§2.2 从不存在），已顺移并修正交叉引用
  - `CHANGELOG.md` 的历史配置表仍把 `AEGIS_ENABLE_THREAD_OFFLOAD` 写成「保留字段」，
    与本文件「删除无效配置」条目冲突，已加 `[已删除]` 标记

  **补齐的空白**

  - README.md 从未说明 `<YOUR_GATEWAY_KEY>` 从哪来，也没提控制台登录密码就是网关密钥——
    新增「Gateway Key」小节（`cat config/aegis_gateway.key` / `docker compose exec`）
  - README.md 配置表补 20 个只在 README_zh 里有的变量，其中包括 `AEGIS_V2_BLOCK_INTERNAL_TARGETS`
    （v2 SSRF 防护）与 `AEGIS_LOCAL_PORT_ROUTING_HOST`（裸机端口路由必须改成 `127.0.0.1`）
  - **仅支持单进程部署**：统计、限流窗口、内存 nonce 防重放、规则 LRU 缓存、后台 worker 都是
    进程内单例，多进程会静默破裂。此前 9 篇文档没有任何一处写明，README.md 与 README_zh §6 补上
  - `config/README.md` 补上升级时 `init_config.migrate_http_smuggling_regex()` 会定点改写挂载目录里的
    YAML 并留下 `security_filters.yaml.bak-<UTC>`；以及 v2 内置规则表**无条件编译**、
    从控制台删掉那 5 条 `web_http_*` 并不能让 v2 停止命中
  - README.md / README_zh.md 新增文档导航表。此前 `UPSTREAM-QUICKSTART.md` 与 `ROADMAP.md`
    **零入站链接**，英文读者无法发现控制台、上游、终端客户端三篇指南
  - `SKILL.md` 的本地安装漏了 `.[dev]`（照做后 `pytest` 不可用），并补上相关文档链接
  - `ROADMAP.md` 新增 R6（阈值与 `block` 语义一致性，需先决策）、R7（无消费者的配置项），
    以及上游章节重复、CHANGELOG 结构两条待办

### Changed

- **`AEGIS_RISK_SCORE_THRESHOLD` 接上了消费者**：此前 `policy_engine` 的兜底值是硬编码 `0.85`，
  这个被两篇 README、`.env.example` 和控制台配置页共同宣传的「全局风险阈值」没有任何运行时读取者。
  现改为策略 YAML 未声明 `risk_threshold` 时的兜底值。**仓库自带的三个策略都声明了该键，因此默认
  部署的有效阈值不变**；只有自定义的、省略该键的策略 YAML 行为会变（从固定 0.85 变为读该环境变量）
- `aegisgate/core/gateway_ui_routes.py` 的 `_RULE_SECTION_LABELS` 提升为模块级常量，便于测试直接
  比对控制台规则组与 `security_filters.yaml`（纯搬运，无行为变化）

### Removed

- **`AEGIS_TENANT_ID_HEADER`**：租户 id 实际由 `_trusted_scope_id()` 与 `x-aegis-token-hint` 推导，
  该 setting 从来没有读取者，却在控制台配置页可编辑并提示保存成功。配置页可编辑项 100 → 99。
  `Settings` 为 `extra="ignore"`，旧 `.env` 里的残留键不会导致启动失败
- `observability.log_event()` 与 `observability.trace()`：两者都自带
  "Legacy interface preserved for backward compatibility" 注释，但全仓库（含测试）零调用者

### Added

- `test_doc_alignment.py` 新增 5 条守护，把本次人工发现的问题固化进 CI：
  `_IMMUTABLE_FIELDS` 数量与名单必须与 `config/README.md` 一致、控制台分区数与
  `WEBUI-QUICKSTART.md` 一致、规则组/规则条数与 `WEBUI-QUICKSTART.md` 一致、
  **每个 `Settings` 字段都必须有非 UI 非测试的运行时读取者**（`AEGIS_RISK_SCORE_THRESHOLD`
  与 `AEGIS_TENANT_ID_HEADER` 正是这条能自动抓到的）、策略文件缺失时的兜底策略
  `_BUILTIN_DEFAULT_POLICY` 的 `risk_threshold` 必须与 `default.yaml` 一致（`enabled_filters`
  早有守护，这个数是唯一没被钉住的手工副本）；并把 `log_event` / `trace` 加入
  既有的死代码符号守护

### Added

- **控制台首次上手引导**
  - 概览页新增「先把第一个请求跑通」卡片：登录 → 注册上游 Token → 复制 Base URL 三步，每步带完成状态，未完成的那一步直接给出动作按钮
  - 已有 Token 或已配置 `AEGIS_UPSTREAM_BASE_URL` 时自动折叠为「网关已就绪」，折叠状态记在 localStorage
  - 第三步给出可直接复制的 `base_url` 与 `export OPENAI_BASE_URL=...`，这两个值此前只在注册成功的那一次弹窗里出现过

- **Token 列表新增「客户端 Base URL」列**
  - 值由浏览器当前 origin 拼出（与 `gateway_auth._gateway_token_base_url` 同构），带一键复制
  - 此前列表只显示 token 本身，完整的 `/v1/__gw__/t/<token>` 路径在整个控制台里没有任何地方写着，关掉注册弹窗就再也找不回来

- **上游地址连通性测试**：`POST /__ui__/api/tokens/probe`
  - Token 表单里的「测试连通性」按钮。返回 401 / 403 会明确说明「地址通了，只是需要鉴权，属正常」
  - 边界是收紧的：目标先过注册用的同一套校验；云元数据地址（`169.254.169.254`、`metadata.google.internal` 等）直接拒绝；单次请求、不带任何凭据、不跟随重定向、3 秒硬超时；只返回状态码与耗时，**不回传响应体**；复用管理接口限流；每次探测写审计（`ui_upstream_probe`）
  - 私网目标保持允许：本地 Ollama / vLLM / LM Studio 正是这个页面最常配置的上游，`.internal` 后缀规则只适用于转发路径上客户端可控的目标（否则会误伤 Docker 部署文档里的 `host.docker.internal`）

- **配置中心全局搜索**：侧栏「配置」分组顶部新增搜索框，一次过滤全部 8 个分区，无命中的分区连同其导航项一并折叠；快捷键 `/` 聚焦当前可见分区的搜索框

- **配置项「已改」标识与「恢复默认」**：当前值与默认值不同的字段带徽章，旁边给出恢复默认按钮（只回填表单，仍需点保存，不绕过任何服务端校验与范围检查）

### Changed

- **保存配置不再重置整个控制台**
  - `saveSection` 此前在 `renderConfig` 之后又调 `loadBootstrap()`，后者会再拉一次 `/api/config` 并二次渲染，同时重新加载文档目录
  - 结果是保存一个分区会重建全部 8 个面板两次、清空每个面板的搜索框、把「使用说明」强制切回第一篇。现在只刷新概览所需的 bootstrap 字段，并在重建前后保留搜索内容与滚动位置

- **未保存的改动不再静默丢失**：`dirtyFields` 此前是只写的，唯一反馈是一圈蓝边。现在保存按钮显示「（N 项待保存）」，离开页面前有浏览器提示；动作映射同样有待保存计数，切换规则组前会确认

- **文档面板支持表格与链接**：内置 Markdown 渲染器此前既不认表格也不认链接，而 README.md 有 96 行表格、README_zh.md 有 120 行，全部会被拼成一段管道符文本。链接只放行 `http(s)` 与站内 `.md`（相对链接在面板内切换文档），`javascript:` 等一律保留为原文
  - 默认打开的文档由英文 README 改为《Web UI 快速上手》

- **上游地址校验前移**
  - `gateway_keys.upstream_base_error()` 复用转发路径的 `_normalize_upstream_base` 作为唯一真源，注册 / 编辑 Token 时即时拦下缺 scheme、缺主机名、带查询参数或 `#` 片段的地址
  - 此前这些地址能注册成功，直到第一个真实请求才失败，控制台里看不出任何异常
  - 额外拒绝 URL 内嵌的用户名密码（凭据会进日志，应走请求头）——这是收紧，不是放宽
  - 表单侧同步做即时反馈，并对填成 `/chat/completions`、`/messages` 这类具体端点的情况给出提示

- **错误提示收敛为一处**：409 / 403 CSRF / 429 / 5xx 各有可读中文说明。此前 403 会把后端的英文 `missing or invalid csrf token` 原样弹给用户，同一个 409 在配置页弹两条、在规则页弹一条

- **登录页**
  - 取密钥的提示改为两条可复制命令（裸机 / Docker）。此前只有一个相对路径 `config/aegis_gateway.key`，Docker 部署时它在容器里
  - 429 限流不再显示英文 `too many login attempts`
  - HTTP 访问下 `AEGIS_LOCAL_UI_SECURE_COOKIE=true` 导致 Cookie 被浏览器丢弃时，此前表现为「登录成功 → 弹回登录页 → 页面上什么都没有」。现在跳转前先验一次会话，失败时明确说明是哪个配置项

- **加载态与空态**：表格加载改用骨架行（`prefers-reduced-motion` 下不动画），空态直接带「注册 Token」/「添加值」/「添加规则」按钮

- **窄屏与键盘**
  - ≤720px 时顶栏按钮只留图标（保留 `aria-label`）。此前品牌加五个带文字的按钮撑破手机视口，整页出现横向滚动
  - ≤980px 的横向导航条右侧加渐变遮罩，暗示可横滑
  - 新增「跳到主内容」跳转链接；焦点样式在原有 glow 之外补 `outline` 兜底
  - 动作映射页保留搜索框（此前被整个隐藏），可按类别或威胁名过滤

- **Web 控制台改用 Apple HIG 设计系统**
  - 中性色由 `--text` / `--muted` 两级扩展为 **四级 label + 三级 fill + 独立 separator**：标题、正文、次要说明、占位符不再靠字号硬拉开层次
  - 深色模式补上 **elevation 层级**（页面 `#1C1C1E` / 卡片 `#2C2C2E` / 弹层 `#3A3A3C`）。此前 `--panel: #18181b` 是单层的，模态框与卡片同色，层次全靠边框撑
  - 语义色改用 Apple 系统色，且深浅两套各自取值：`#0071E3` / `#0A84FF`（accent）、`#248A3D` / `#30D158`、`#B25000` / `#FF9F0A`、`#D70015` / `#FF453A`
  - 字体改为 `-apple-system` → `SF Pro` → `PingFang SC` 栈；字号走 HIG 阶梯（largeTitle / title2 / title3 / headline / body / callout / footnote / caption），数字统一 `tabular-nums`
  - 四个控件替换：布尔开关 → **iOS Switch**（51×31 轨道 + 27 滑块 + 弹簧过渡）、视图切换 → **Segmented Control**、表格 → **Inset Grouped List**（整表一张圆角卡片、分隔线左侧内缩）、配置项 → 设置行式布局（标签与控件左右分列）
  - 按钮分三档：filled（主操作）/ tinted（次要）/ plain（第三级），破坏性操作用 tinted red。移除渐变填充、hover 位移与 `brightness()` 滤镜——Apple 的按压反馈是「变淡并回落」而非「浮起」
  - 动效统一到一条缓动曲线 `cubic-bezier(.32,.72,0,1)`；模态在窄屏改为从底部滑入的 sheet；`prefers-reduced-motion` 保护保留
  - 材质分三档（thin / regular / thick），顶栏模糊由 16px 提升到 30px 并加 `saturate(180%)`，模态遮罩改用材质而非纯黑蒙层
  - 圆角与间距成体系：控件 10 / 卡片 12 / 面板 16 / 模态 20；间距走 8pt 阶梯
  - 移除页面背景的靛蓝径向渐变，改为纯粹的 grouped 底色 —— 深度由 elevation 提供
  - 既有 CSS 变量名（`--bg` `--panel` `--line` `--text` `--muted` …）全部保留为新 token 的别名，本文件其余规则无需改动

- **可访问性修复**
  - 布尔开关补 `role="switch"` + `aria-checked`，状态不再只靠颜色（滑块位移同时表达）
  - 侧栏当前项补 `aria-current="page"`
  - 全部表头补 `scope="col"`（含 JS 动态生成的表头）
  - 分段控件补 `role="tablist"` / `role="tab"` / `aria-selected`
  - 所有可聚焦控件统一 `:focus-visible` 焦点环

### Fixed

- **重启失败后顶栏按钮永久停在「重启中…」**
  - `btn.querySelector("svg + span, svg ~ *") || (btn.textContent = "重启中…")` 两个选择器都匹配不到按钮里的纯文本节点，于是走 `textContent` 赋值，把 `<svg>` 一起冲掉；失败分支只恢复 `disabled`，不恢复文案和图标
  - 改为只更新独立的 `#restart-label`，失败时还原

- **Token 列表「豁免字段数」显示 `∞`**：未设置豁免时显示 `∞`，但实际语义是「豁免 0 个字段、全部参与脱敏」，与直觉相反。现在显示 `0`

- **带 `#` 锚点打开控制台会落在错的位置**：浏览器解析锚点时页面几乎还是空的，配置面板、规则工作台、精确值列表都在其后加载且都位于 `#tokens` / `#docs` 之上，锚点因此偏出数千像素。改为在页面稳定前重新应用锚点，用户一滚动即停止

- **连通性测试遇到 httpx 无法编码的主机名会返回 500**：`https://xn--/v1` 这类地址能通过 `urlparse` 校验，但 `idna` 会抛 `IDNAError`，而它不是 `httpx.HTTPError`。探测是诊断动作，现在返回可读的失败原因而不是 500

- **控制台改规则不再清空 `security_filters.yaml` 的注释**
  - `_save_rules_yaml()` 走 `yaml.safe_load` → `yaml.dump`，PyYAML 不保留注释，还会重排缩进与引号风格：从 UI 改一条正则会重写整个文件，**80 行注释全部消失**，并产生约 1250 行的 diff
  - 这些注释是安全策略的说明文档（哪些 pattern 在低误报面上保持启用、个别 pattern 的 ReDoS 注意事项等），静默丢失属于实打实的信息损失
  - 新增 `aegisgate/core/rules_editor.py`：规则的增 / 改 / 删以及 action_map 的动作修改，都以**行级文本补丁**的方式应用，只有目标规则所在的行会变，其余部分逐字节保持不变
  - 文本改 YAML 天然脆弱，因此补丁结果**从不被直接信任**：先重新解析，再与调用方期望的完整文档逐字段比对，只有完全一致才写入；否则退回原来的 dump 路径并打出告警（结果依然正确，只是注释会丢）
  - 删除规则时保留其后的空行与注释，避免顺带吃掉块之间的分隔
  - `regex` 值统一单引号，其余字段沿用文件既有风格

### Added

- **Web 控制台配置中心：全字段覆盖与「需重启」标注**
  - 修复：`security_level` / `enforce_loopback_only` / `trusted_proxy_ips` / `v2_block_internal_targets` 在配置页可编辑，但它们属于 `hot_reload._IMMUTABLE_FIELDS`，保存后运行时并未生效，页面却提示「已保存，配置已热重载」且把输入框回填成进程里的旧值
  - 配置项元数据新增 `requires_restart`（由 `_IMMUTABLE_FIELDS` 推导，不手工维护），`POST /__ui__/api/config` 返回 `restart_required` 列表；页面对这些字段展示「需重启」徽章与提示条，并提供「重启网关」按钮
  - 已写入 `.env` 但进程未采用的字段额外标注「待生效」，且回填 `.env` 中的新值而非内存旧值
  - 可编辑配置项从 58 项扩到 100 项（`Settings` 共 104 项，另 4 项按用途明确排除），新增 PostgreSQL、请求 HMAC 签名、公网闸门、Docker 上游、控制台会话、清理任务等分组
  - 分区从 3 个扩到 8 个（基础设置 / 存储与保留 / 限额与超时 / 安全策略 / 访问控制 / 协议转换与路由 / v2 代理 / 控制台）；分区、分组与面板均由后端元数据生成，新增字段无需改前端
  - 每个分区带搜索框，字段展示对应环境变量名与说明，`depends_on` 支持按依赖字段联动显隐
  - 新增 `float` 字段类型与 `min` / `max` 范围校验；`int` 字段接受 `600.0` 这类往返值但仍拒绝真正的小数
  - 敏感字段（`postgres_dsn` / `request_hmac_secret`）不再回显明文，仅返回掩码；提交空值表示保持不变，审计与响应中一律记为 `***`

- **Web 控制台审计日志检索**
  - 网关逐请求写入 `logs/audit.jsonl`（`risk_score` / `request_disposition` / `response_disposition` / `disposition_reasons` / `security_tags` / `enforcement_actions`），此前控制台自己也在往里写，却没有任何读取入口——「哪条请求被拦了、为什么」只能 SSH 上去 grep
  - 新增 `aegisgate/core/audit_query.py`：从文件尾部**反向分块读取**，最新记录在前，按字节游标翻页
    - 单次请求设有扫描字节上限（默认 8 MB），命中不足即返回 `budget_exhausted` 与游标，绝不整文件读入
    - 跨 chunk 边界的记录会被拼接还原，不会丢行或截断
    - 无匹配的筛选条件下游标仍严格前进，调用方不会空转
  - 新增端点：
    - `GET /__ui__/api/audit`：按时间区间 / 路由 / 处置 / 最低风险分 / 安全标签 / 全文关键词筛选，游标翻页
    - `GET /__ui__/api/audit/summary`：处置分布、风险分桶、Top 路由与安全标签；统计不完整时如实返回 `complete: false`
    - `GET /__ui__/api/audit/record/{request_id}`：按 request_id 精确查单条
    - `GET /__ui__/api/audit/export`：按当前筛选导出 JSONL / CSV，最多 5000 行；CSV 对以 `=` `+` `-` `@` 开头的单元格加前缀，避免表格软件把审计内容当公式执行
    - `GET /__ui__/api/dangerous_samples` 与 `/dates`：浏览按日期切分的危险响应样本；日期参数只能命中枚举出来的文件，不参与路径拼接
  - 控制台新增「审计日志」面板：筛选栏 + 概览卡片 + 行展开完整 JSON + 导出按钮；风险分按高/中/低着色，处置用语义色徽章
  - 前端代码放在独立的 `www/assets/audit.js`，不再往 1300 行的 `app.js` 里堆

- **Web 控制台规则工作台：全部规则组可管理 + 正则试验场**
  - 规则组由 `_RULES_SECTIONS` 硬编码 5 组改为**遍历 `security_filters.yaml` 自动发现**，控制台可管理的规则从 109 条（5 组）扩到 228 条（32 组）
  - 此前完全没有入口的规则组：`request_sanitizer`（33 条）、`sanitizer`（17 条）、`tool_call_guard`（14 条）、`rag_poison_guard`（13 条）、`post_restore_guard`（12 条）、`privilege_guard`（7 条）以及 `injection_detector` 的另外 5 组（19 条）
  - section id 改为点号路径（如 `request_sanitizer.leak_check_patterns`）；旧的 5 个 id 保留为别名，既有 API 调用与书签不受影响
  - 路径不可任意穿越：请求中的 section 只能命中服务端发现出来的枚举，标量节点与非规则列表一律 404
  - `tool_call_guard.parameter_rules` 以 tool+param 为标识而非 id，标记为只读：可查看，写操作返回 403
  - 规则的 `category` / `kind` 等元数据在编辑时不再被丢弃；表格列按规则实际字段动态生成
  - 新增 `POST /__ui__/api/rules_test` 正则试验场：给出每条样本的命中区间，UI 高亮显示
    - 匹配在**可终止的子进程**中执行（`aegisgate/core/regex_probe.py`），灾难性回溯的正则会被超时终止并如实告知作者，而不是拖死网关线程
    - 子进程刻意零加锁：正则在父进程编译好后传入，结果走裸 Pipe 而非带 feeder 线程的 Queue
    - 输入上限：正则 500 字符、样本 5 条、单条 2000 字符
  - 规则组树按过滤器分组并显示条数；规则组与规则各有搜索框

- **Web 控制台并发保护与交互反馈**
  - 规则 YAML、`config/.env`、compose 文件、精确值列表都是「读全量 → 改内存 → 整体写回」，写入本身原子但**没有版本校验**：两个标签页各自打开规则页，A 加规则、B 删规则，后保存的一方会静默覆盖前者，而规则会立即热重载——等于安全策略被无声回滚
  - 新增 `aegisgate/core/ui_etag.py`：上述四类资源的 GET 返回基于文件内容的 `ETag`，写请求携带 `If-Match` 时校验，不匹配返回 `409 etag_mismatch` 并回传当前 `current_etag` 供客户端刷新重放
  - `If-Match` **有则校验、无则放行**：既有 API 调用与脚本行为不变；控制台始终携带，因此始终受保护
  - `rules` 与 `rules_action_map` 共用同一份 YAML 的校验值，一方写入会使另一方的 `If-Match` 失效
  - 精确值脱敏的按序号删除也纳入校验——过期视图里删「第 3 条」原本会删掉此刻恰好排在第 3 位的值
  - 兼容 `*`、无引号、`W/` 弱校验前缀以及逗号分隔的多值 `If-Match`
  - 新增 `www/assets/ui-kit.js`：toast 提示与自绘确认/信息对话框，替换全部 17 处 `window.alert` / `window.confirm`
    - 破坏性操作（删除 Token / 删除规则 / 清除统计 / 重启网关）使用红色危险样式，且默认焦点落在「取消」，回车不会误触发
    - 更换密钥要求手动键入密钥类型名才能提交
    - Token 注册与更新结果改为带「复制」按钮的对话框，不再让人从 `alert` 里手抄 base_url
    - 对话框自带焦点陷阱、Esc 关闭、`aria-modal`
  - 写冲突不再表现为一句失败文案：提示「已被其他会话修改」并自动重新加载受影响的视图

- **关键安全模块的直接测试（P14）**
  - `util/ip_safety.py`：内网/保留地址判定（含 IPv4-mapped IPv6）、DNS rebinding（域名过检但解析指向内网）、多记录应答中混入内网地址、解析失败 fail-closed
  - `core/security_boundary.py`：HMAC 签名验证（`sha256=` 前缀、篡改、错密钥）、nonce 重放窗口、Redis nonce 后端不可用时 fail-closed
  - 请求边界中间件：HMAC 缺头/错签名/时间戳越窗（含未来时间）/时间戳非法/密钥为空，UI 会话过期、会话指纹绑定、CSRF 缺失与错值、跨会话 CSRF、非 loopback 来源拒绝、登录限流的每 IP 配额边界
  - `adapters/v2_proxy`：allowlist 精确与后缀匹配、留空即拒绝、目标 IP pinning 与 SNI/Host 绑定、解析结果指向内网时拒绝
  - `storage/crypto.py` 与 `storage/redis_store.py`：映射加解密往返、非法密文、轮换后旧密钥仍可解、密钥文件 0600 权限、映射存取与一次性消费契约
  - `gateway_ui_routes.py`：登录正负例、规则 CRUD 全生命周期、Fernet 密钥轮换
  - `filters/`：privilege / rag_poison / tool_call / anomaly 四个过滤器的直接单测
  - 测试内固定了 DNS 解析器与 Redis 客户端，安全用例不依赖真实网络或真实 Redis


- **本地 UI 访问范围收紧**：新增 `AEGIS_LOCAL_UI_ALLOW_INTERNAL_NETWORK` 配置项（默认 `false`）
  - 默认仅允许 loopback（127.0.0.1 / ::1）访问 UI，内网 IP 被拒绝
  - 显式设置为 `true` 时恢复此前行为（允许 RFC1918 内网访问）
  - 属于不可变字段（immutable），变更需重启生效

- **v2 SSRF 防护增强：DNS 解析检查**
  - 新增 `_resolve_target_ips()` 异步 DNS 解析，阻止域名解析到内网/私有 IP 的请求
  - DNS 解析失败时采用 fail-closed 策略（阻断请求），防止 DNS rebinding 攻击
  - `_is_ssrf_target()` 和 `_extract_target_url()` 改为 async，避免同步 DNS 阻塞事件循环


- **流式回归缺口补齐（A7 / P14 前置）**
  - 扩展既有 `test_streaming_router.py`，补「独立终止帧 + 末块危险载荷」（chat/responses 标 xfail 留给 B1）以及 generic 五形态基线；messages 终止帧按代码现状写为绿（并不刷空 holdback）
  - 记录 messages / generic 在 EOF 无 `[DONE]` 时没有恢复分支的当前行为，供后续 B9' 立项


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


- **电脑/基础设施信息 PII 脱敏（请求侧，宽松模式）**
  - 新增 9 个 field-labeled 模式：SYS_HOSTNAME、SYS_USERNAME、SYS_OS_VERSION、SYS_KERNEL、SYS_HOME_PATH、SYS_ENV_VAR、SYS_DOCKER_ID、SYS_K8S_RESOURCE、SYS_INTERNAL_URL
  - 仅匹配 `field: value` / `field=value` 格式（如 `hostname: prod-web-01`），避免普通提及误报
  - SYS_HOME_PATH 和 SYS_INTERNAL_URL 无需字段标签，直接匹配路径/URL 格式

---

### Breaking Changes

- **公网上游白名单旁路默认关闭**
  - `AEGIS_UPSTREAM_WHITELIST_URL_LIST` 命中后仍会**整体旁路请求与响应双侧管道（含 PII 脱敏）**；文档此前写「仅跳过响应侧」是错的，现已对齐
  - 新增 `AEGIS_ALLOW_PUBLIC_UPSTREAM_WHITELIST`（默认 `false`，热重载不可变）。公网客户端命中白名单时不再旁路，回落正常过滤管道。内网客户端与未设 `client_is_internal` 的既有调用保持旁路
  - 公网部署若仍需对白名单上游明文转发，须显式设 `AEGIS_ALLOW_PUBLIC_UPSTREAM_WHITELIST=true` 并重启


- **反代 XFF 内网判定收紧（默认开启）**
  - 新增 `AEGIS_XFF_STRICT_INTERNAL`（默认 `true`，热重载不可变，需重启）。存在 `X-Forwarded-For` 且直连 IP 不在 `AEGIS_TRUSTED_PROXY_IPS` 时，admin、默认上游 `/v1`、以及 `/__ui__` 一律按公网处理
  - **只影响同时满足这 4 个前提的部署**：① 设了 `AEGIS_UPSTREAM_BASE_URL` ② 客户端走非 token `/v1/...` ③ 未带 `X-Aegis-Proxy-Token` ④ 未设 `AEGIS_TRUSTED_PROXY_IPS`。参考 Caddy 配置里 admin 本就不经公网；带 proxy token 的 `/v1` 不受影响
  - **代码回滚**：`AEGIS_XFF_STRICT_INTERNAL=false` 并重启，回到旧的 admin / 默认 `/v1` / UI 判定。数字 token 与 `__passthrough` 在 A3 之前就已经有 XFF 降级，开关不会放宽它们
  - **配置回滚**：若已设置 `AEGIS_TRUSTED_PROXY_IPS`，该开关**回滚不了**它对 `_real_client_ip`（7 处）和 `_is_trusted_proxy`（1 处，含 UI 限流键）的影响。回退办法是清空该变量并重启


- **删除无效配置 `AEGIS_ENABLE_THREAD_OFFLOAD`（P11 / B6）**
  - 该字段从未接线，Web UI 可切换但不生效。`Settings` 为 `extra="ignore"`，旧 `.env` 里残留此键不会导致启动失败
  - 历史 CHANGELOG 条目保留，不改


- **HTTP 走私正则会定点改写现网 `config/security_filters.yaml`**
  - Docker 挂载下该文件是 Web UI 规则 CRUD 的目标，`init_config` 从不整文件覆盖。升级后启动时只替换三段 `command_patterns` 里 id 为 `http_smuggling_*` / `web_http_smuggling_*` 的 regex，其余自定义规则原样保留
  - 改写前另存 `security_filters.yaml.bak-<UTC>`。回滚 = 把备份拷回该路径并回退镜像。`config/*.yaml.bak-*` 已加入 `.gitignore`，避免 `git add -A` 带走含用户规则的备份
  - YAML 顶层 `version:` 现为 `3`（仅作标记；迁移按规则 id，不按版本号门控）

- **清理 yes/no 确认流程的最后残留**
  - 删除 `ConfirmationCacheTask`、`clear_pending_confirmations_on_startup()`、三个存储后端的 `prune_pending_confirmations()` / `clear_all_pending_confirmations()`，以及 `pending_confirmation` 建表语句。写入方在更早的版本就已删除，这些只剩清理旧数据的作用
  - 后台任务改名为 `MappingPruneTask`（`aegisgate/core/mapping_prune_task.py`），只负责脱敏映射的保留期清理
  - 删除 `aegisgate/adapters/relay_compat/mapper.py`（无调用方）与 `scripts/redeploy.sh`（内容已随 compose 叠加文件失效）

  **移除的配置项**（`Settings` 为 `extra="ignore"`，旧 `.env` 里的残留键不会导致启动失败）

  | 环境变量 | 说明 |
  |----------|------|
  | `AEGIS_ENABLE_PENDING_PRUNE_TASK` | **改名**为 `AEGIS_ENABLE_MAPPING_PRUNE_TASK`。注意：此前显式设为 `false` 关闭后台清理的部署，升级后该值被忽略，映射清理任务会重新启用 |
  | `AEGIS_PENDING_PRUNE_INTERVAL_SECONDS` | 已无消费者；映射清理周期由 `AEGIS_MAPPING_PRUNE_INTERVAL_SECONDS` 单独控制 |
  | `AEGIS_CLEAR_PENDING_ON_STARTUP` | 启动清理逻辑已删除 |
  | `AEGIS_MAX_PENDING_PAYLOAD_BYTES` | 一并从 Web UI 配置页移除 |
  | `AEGIS_CONFIRMATION_TTL_SECONDS` | 已无消费者 |
  | `AEGIS_CONFIRMATION_EXECUTING_TIMEOUT_SECONDS` | 已无消费者 |
  | `AEGIS_REDIS_PENDING_SCAN_BATCH_SIZE` | 已无消费者 |
  | `AEGIS_REDIS_PENDING_SCAN_MAX_ENTRIES` | 已无消费者 |

  **移除的可观测性接口**

  - Prometheus gauge `aegisgate_pending_confirmations` 与 `aegisgate.observability.set_pending_confirmations()` 一并删除。引用该指标的 Grafana 面板/告警规则会变成无数据，需要自行摘除

  **遗留数据需要手工清理**

  本次没有附带 DROP/迁移脚本。从很早的版本一路升级上来的实例，可能还留有确认记录（含 `pending_request_payload`，即原始请求体）；清理入口已经删除，这些数据不会再被自动回收。确认无用后按存储后端执行：

  ```sql
  -- SQLite / PostgreSQL
  DROP TABLE IF EXISTS pending_confirmation;
  ```

  ```bash
  # Redis（前缀为 AEGIS_REDIS_KEY_PREFIX，默认 aegisgate）
  redis-cli --scan --pattern 'aegisgate:pending:*' | xargs -r redis-cli DEL
  ```

- **移除 Token 映射中的 `gateway_key` 字段**
  - `gw_tokens.json` 不再包含 `gateway_key`，每个 token 仅绑定 `upstream_base` + `whitelist_key`
  - 同一 `upstream_base` 只保留一个 token（此前按 `upstream_base + gateway_key` 组合去重）
  - `/__gw__/register`、`/__gw__/add`、`/__gw__/remove`、`/__gw__/lookup`、`/__gw__/unregister` 等管理端点不再将请求体中的 `gateway_key` 写入映射或用于匹配 token（管理端点仍需要 `gateway_key` 做身份认证）
  - `register()`、`find_token()`、`update()`、`update_and_rename()` 的 `gateway_key` 参数已废弃，传入时忽略
  - UI Token 管理表格和编辑弹窗移除「网关密钥」列

- **移除默认管理密码 `admin123`**
  - 本地 UI 登录不再接受一次性默认密码，始终使用 `config/aegis_gateway.key` 文件内容
  - 删除 `_is_admin_initialized()` / `_mark_admin_initialized()` 和 `.admin_initialized` 标记文件机制

### Changed

- **`AEGIS_STORAGE_FAILURE_ACTION=forward` 默认对未登记的请求侧过滤器 fail-closed（P12 / B6）**
  - 这是预防性加固，不是修复一条现存的 fail-open：今天 6 个请求侧过滤器都已在 critical 名单里，`:111` 的 `continue` 不可达
  - 未登记的新请求侧过滤器在 forward 模式下不再被静默跳过；forward 只豁免映射/审计持久化失败


- **清理未接线的死代码与恒 0 指标（P11）**
  - 删除无调用方的 `SemanticAnalyzer`（保留 `SemanticServiceClient` 与 TF-IDF 离线实验资产，下架需产品决策）
  - 删除 `core/registry.py`、`FilterRejectedError`、无调用方的 `coerce_chat_stream_to_messages_stream`，以及 `storage/_helpers.py` 中未使用的 `json_dumps` / `json_loads` / `to_int`（`LRUMappingCache` 保留）
  - 删除从未在热路径上报的 Prometheus 指标与包装函数：`aegisgate_filter_hits_total`、`aegisgate_pipeline_duration_seconds`、`aegisgate_confirmations_total`、`aegisgate_upstream_errors_total`，以及 `emit_counter` / `traced`
  - `system_prompt_guard` / `untrusted_content_guard` **默认仍关闭**：未写入 `default.yaml` / `strict.yaml`。内置缺省策略与 `default.yaml` 对齐，避免策略文件缺失时悄悄启用 `untrusted_content_guard`。两者仍须同时出现在策略 YAML **并且**对应 feature flag 为 true 才会运行


- **Messages→Responses 隐私默认与参数保真（P10 + P7 H5）**
  - compat 映射显式设 `store: false`，避免 OpenAI 侧默认持久化对话
  - `stop_sequences` 映射为 `stop`；`top_k` 无 Responses 对应参数，显式丢弃而非透传（上游 payload 走黑名单过滤，透传会让原本可用的请求变 400）；`thinking` / `redacted_thinking` 块跳过，不再落成 `[NON_TEXT_PART]`
  - Anthropic `tool_choice` 按表映射到 Responses（`any` → `auto` 并打 tag，**不等于** `required`；`tool`+name → `{type:function,name}`；未知取值 → `auto` + tag）。Responses→Chat 把 flat `{type:function,name}` 转成 Chat 嵌套 `function`
  - Chat→Responses rename 补 `max_completion_tokens→max_output_tokens`；`parallel_tool_calls` 不再当作 Responses-only 从 Chat 方向剥掉
  - **意图确认**：Chat 方向把 `reasoning` 透传给能接受它的上游（如 Azure 变体）；仅当 dict 内全部为 `None` 时仍丢弃空对象


- **统一文本归一化（P8 M-2/M-3）**
  - 新增 `aegisgate/util/text_normalize.py`：NFKC + confusable 折叠 + 不可见/BIDI 剥离 + 小写 + 空白折叠
  - 打分型过滤器（`injection_detector` / `privilege_guard` / `rag_poison_guard` / `anomaly_detector` / `tool_call_guard`）在归一化文本上匹配，同形字与换行拆分不再绕过
  - `rag_poison_guard` 规则编译补 `re.DOTALL`
  - 改写型（`request_sanitizer` / `output_sanitizer`）在归一化后检测；原文能匹配时仍对原文 `sub`，仅归一化命中时整段替换为占位符，**不会**把 NFKC/小写后的文本写回转发载荷


- **热重载原子化与 store swap 条件化（P9）**
  - `reload_settings` 先构造完整 `Settings`，再一次 `__dict__.update` 写入可变字段；后续步骤失败则回滚快照，避免半新旧配置
  - `reload_runtime_dependencies` 仅在存储相关字段变化时 `swap()`；只改日志级别不再 churn 后端
  - `_retired_backends` 上限 8，超限 `close()` 最老后端，并打 INFO 记录当前退役数量（不引入 TTL 回收）
  - SQLite 迁移补 `created_at = 0` 回填；prune 后重置 LRU；三后端共用 `MIN_MAPPING_TTL_SECONDS = 300`
  - 热重载后调度关闭共享 upstream HTTP client，超时/连接数变更无需整进程重启



- **CI 覆盖率 / 版本矩阵 / 测试入库（A6 / P14）**
  - 覆盖率门槛拆成独立的 `coverage report` 步骤：跑测试那步保留 `--cov-fail-under=0`，只对测试失败 gating；门槛检查单独 `continue-on-error`，先拿到真实数字再决定是否把 50 写成硬门槛，不主动下调已声明值。`continue-on-error` 不再盖在测试步骤上，否则 3.12 的测试失败会被吞掉
  - CI Python 矩阵补入 `3.11`，与 `Dockerfile` 的 `python:3.11-slim` 对齐
  - 删除 `.gitignore` 对 `aegisgate/tests/*` 的白名单机制（此前新增测试默认被忽略，零测试仍绿灯）。Detect tests 在找不到 `test_*.py` 时直接失败
  - 把 `OPTIMIZATION_PLAN.md` 列入内部报告忽略段，避免审计方案随 `git add -A` 进入公开仓库


- **Token 生成改为纯字母数字**（`a-zA-Z0-9`），不再包含 `-` `_` 符号，避免与 `__` 过滤模式分隔符冲突


- **过滤规则降敏（降低误报率）**
  - `dangerous_param_patterns`：`&&`/`;`/`||`/`` ` `` 裸匹配 → 必须后跟危险命令（curl/wget/bash/sh/nc 等）
  - `python`/`perl`/`ruby`/`php` → 仅在 `-c`/`-e` 内联执行标志时触发
  - `semantic_approval_patterns`：`delete`/`drop` 裸词 → 仅匹配完整短语如 `drop table`
  - `privilege_escalation`：`读取配置`/`read config` 过宽 → 收窄为 `系统配置`/`system file` 等
  - `tool_call_injection`：severity 9→6，action block→review，从 non-reducible 移除
  - `obfuscated`：从 non-reducible 移除（讨论编码原理时可降分）
  - non-reducible 类别：5→3（仅保留 system_exfil, unicode_bidi, spam_noise）
  - > **已过期**：上面三条对 `tool_call_injection` / `obfuscated` 的降敏，已被后续的 P1 安全审计修复撤销——severity 恢复 `9`、action 恢复 `block`，两者都加回 non-reducible。该修复当时只落到 `config/` 副本，包内副本一直停在降敏后的值，直到本次合并两份 YAML 时才同步过去（见上方 `### Security` 首条）。当前 `non_reducible_categories` 是 5 项：`system_exfil`、`obfuscated`、`unicode_bidi`、`tool_call_injection`、`spam_noise`。本条其余降敏（`dangerous_param_patterns`、`python`/`perl` 等、`semantic_approval_patterns`、`privilege_escalation`）仍然有效。

### Fixed

- **messages 路由扫描并清洗 `tool_use` 危险载荷（P7 H4 / B4'）**
  - `InternalResponse.tool_call_content` 本来就能从 Anthropic `content[].input` 取值，但 sanitizer 只改 `output_text`：命中若只在 tool_use 里，处置仍是 allow，原始 `input` 原样返回
  - sanitizer 在 tool_call_content-only 命中时改为 `sanitize`；`patch_messages_content_block` 清洗 `tool_use.input`
  - 流式 `content_block_delta.partial_json` 进入扫描窗口，并随 probe 的 `tool_calls` metadata 交给 `tool_call_content`


- **EOF 无 `[DONE]` 时不再把已刷出的流式正文再播一遍（P7 H2 / B9）**
  - chat 恢复分支此前会先刷出 holdback，再把整个 `stream_window` 放进合成 chunk，客户端看到重复正文
  - 抽共享 helper `_eof_recovery_replay_text`：已发出或即将刷出内容时只补断开提示；responses 有正文时本就走 finalize-only，空流仍只补提示
  - 不给 messages / generic 新增 EOF 恢复（B9'，本轮不做）


- **流式尾部探测改为按探测边界推进（P4 / B1）**
  - `_needs_final_stream_probe` 不再要求 holdback 仍非空，改为比较 `chunk_count` 与上次探测过的内容块
  - chat / responses 在独立终止帧刷出 holdback **之前**补跑一次响应管道探测，避免末 1–3 块未扫描即外发
  - generic 流式路径补齐与另外三条对齐的 holdback（`_STREAM_BLOCK_HOLDBACK_EVENTS`）和尾部探测
  - messages 路径的 `content_block_*` / `message_*` 本就不会整缓冲刷出，行为保持；共享判据避免再分叉一份实现


- **stats 优雅关闭死锁（A4 / P6）**
  - `_persist_async` 在队列满时 `get_nowait()` 丢弃旧快照却不调用 `task_done()`，`Queue` 的 unfinished 计数永久 +1，`flush()` 里的 `join()` 永不返回，lifespan 关闭挂死
  - 丢弃项出队后立即 `task_done()`；与 worker `finally` 里的 `task_done()` 不重叠（worker 从未拿到被丢弃的项）

- **后台 worker 双启动竞态（A5 / P9）**
  - `ensure_worker_thread` 原先按值接收 `worker`，锁内复查的是过期局部值；并发首启可拉起两个非 daemon 线程，关闭只发一个哨兵，另一个永阻塞在 `queue.get()`
  - 改为在锁内通过 getter/setter 读写当前全局（或实例）持有的线程，赋值发生在 `start()` 之后、放锁之前

- **占位符往返守卫对含数字 PII id 失明（B3 / P8 M-1）**
  - `placeholder_regex` 的 kind 段从 `[A-Z_]+` 改为 `[A-Z0-9_]+`，否则 `IPV4` / `IPV6` 等占位符无法被 `findall` 识别，volume / partial / exfil 三个守卫全部失明，真实值仍被字符串替换还原
  - 三份副本同步：YAML 运行时值、`security_rules.py` 代码默认、`restoration.py` 缺 key 时的兜底字面量

- **上游 400 错误：tool name 包含非法字符**
  - OpenAI Responses API 要求 `input[].name` 匹配 `^[a-zA-Z0-9_-]+`，包含中文等字符时被拒绝
  - 在 `_sanitize_responses_input_for_upstream` 中对 `function_call` / `function` / `function_call_output` 类型的 `name` 字段做合规清洗（非法字符替换为 `_`）
  - 非函数类型的 `name` 字段（如用户名）保持不变


- **[Critical] tool_call_guard `review` 动作在流式模式下被当作 `block` 处理**
  - `_stream_block_reason()` 只要检测到 `tool_call_violation` 标签就触发流阻断，不区分 `block`/`review`
  - 导致 `apply_patch`、`write` 等编码工具的正常 tool call 被整体替换为 `【AegisGate已处理危险疑似片段】`
  - 修复：仅在 `tool_call_guard:*:block` 动作存在时才触发流阻断，`review` 动作不再阻断流

- **tool_call_guard 对编码工具参数的误拦截**
  - `apply_patch` 等工具的参数是代码/diff 内容，其中可能包含看起来像危险命令的文本
  - 新增 `_CODE_CONTENT_TOOLS` 白名单（25+ 编码工具），跳过 `dangerous_param_patterns` 扫描
  - `dangerous_param` action 从 `block` 降为 `review`，避免过度拦截
  - > **已过期**：常量现名为 `_FILE_WRITE_CONTENT_TOOLS`（11 项），且**不再**跳过全部 `dangerous_param_patterns`，只跳过 `sensitive_file_access` / `path_traversal` / `ssh_key_access` 三条路径引用类规则，执行类危险参数扫描仍然运行。另有独立的 `_READ_ONLY_CONTENT_TOOLS`。当前行为见 README_zh §1.3。
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

### Security

- **HTTP 走私检测正则线性化（P1 ReDoS）**
  - `te_te` 改为逗号唯一切分，`cl_te` / `te_cl` 两侧空白收窄为水平空白，消除量词与换行类重叠。检测面保留数字后尾随空格、头名前缩进、以及 5 行以上空行
  - 三处规则源同步：YAML 的 anomaly / sanitizer / force_block 三段、`security_rules.py` 代码默认（含此前缺失的 anomaly 走私 5 条）、以及 v2 代理硬编码 `_DEFAULT_DANGEROUS_COMMAND_PATTERNS`
  - 本轮不加扫描窗口或 16KB 截断（那会在签名前填充即可绕过）；有界扫描与 v2 现有截断策略收敛到后续规则引擎工作

- **合并两份分叉的 `security_filters.yaml`（P0）**
  - 此前 `config/security_filters.yaml` 与 `aegisgate/policies/rules/security_filters.yaml` 都在版本控制内，且内容已经分叉。Docker 部署把 `./config` 挂载覆盖到包内规则目录（`AEGIS_SECURITY_RULES_PATH` 指向那里），裸机部署读包内那份，于是同一条安全修复只落到其中一份，两种部署加载了**不同的安全规则**
  - 以严格的那份为准合并，包内副本随之变化：`action_map.injection_detector.tool_call_injection` `review` → `block`，`tool_call_injection` severity `6` → `9`，`non_reducible_categories` 增加 `obfuscated` 与 `tool_call_injection`
  - 同一次合并中，`action_map.tool_call_guard.dangerous_param` 由 `block` 改为 `review`。这不是新的放宽，而是补上一个早就定下、却只落到 config 副本的调整（见下方本节 `### Fixed` →「tool_call_guard 对编码工具参数的误拦截」中「`dangerous_param` action 从 `block` 降为 `review`」）。`aegisgate/config/security_rules.py` 的内置默认值同步改为 `review`，避免 YAML 缺失时行为翻转
  - `config/security_filters.yaml` 移出版本控制并加入 `.gitignore`，改由 `init_config` 在首次启动时从镜像内的只读模板生成。唯一事实来源是 `aegisgate/policies/rules/security_filters.yaml`
  - 新增 `test_config_rules_copy_matches_package_copy` 守卫：一旦 `config/` 下重新出现一份副本且与包内不一致，测试失败

  **升级动作（必读）**

  1. **Docker 必须重建镜像，不能只重启。** 补写规则的模板来自镜像内的 `/app/bootstrap/rules`（由 `Dockerfile` 烘焙）。`git pull` 会删掉宿主机上的 `config/security_filters.yaml`，若只执行 `docker compose up -d`，`init_config` 会用**旧镜像里的旧规则**补写，`tool_call_injection` 会被静默降回 `review`。正确步骤：`git pull && docker compose build aegisgate && docker compose up -d`
     - **这一步做错不会自愈**：`init_config` 只在文件缺失或为空时写入，从不覆盖已存在的文件，所以事后再补 `build` 也不会把旧规则纠正回来。一旦踩中，需 `rm config/security_filters.yaml` 后重启，让新镜像重新生成。
     - 起服务后建议验证一次：`docker compose exec aegisgate grep -n 'tool_call_injection' /app/aegisgate/policies/rules/security_filters.yaml`，确认 `action_map` 下是 `block` 而非 `review`
  2. **用 Web UI 改过规则的实例，`git pull` 会被 git 中止**（本地已修改的文件被上游删除）。先 `cp config/security_filters.yaml /tmp/rules.bak`，再 `git checkout -- config/security_filters.yaml && git pull`，然后把自定义项手工并回 `aegisgate/policies/rules/security_filters.yaml`
  3. **裸机部署的拦截行为会收紧**：`tool_call_injection` 变为强制拦截且不再被「研究/教学/引用」上下文降分，`obfuscated` 同样不再可降分。若上游会正常回传工具调用的文本表示，按 [config/README.md](config/README.md) 的说明放宽

- **请求侧脱敏覆盖修复（P0）**
  - base64 二进制启发式不再豁免高置信凭据：PEM 私钥、长 JWT、`sk-`/`AKIA`/`ghp_`/`xox`/`xprv` 等即使整段像 base64 也会被脱敏（此前 ≥256 字符且 base64 字符占比 >92% 的字符串被整段跳过，实测 PEM 私钥与 481 字符 JWT 均未脱敏）。凭据探测覆盖**整个字符串**而非固定前缀：此前只看前 4096 字符，用 4KB base64 前缀垫一下就能让其后的密钥被整段跳过；改为 `str.find` 定位 + 定点匹配后，12MB 媒体的探测开销约 35ms
  - `PRIVATE_KEY_PEM` 规则修正：此前 `-----BEGIN RSA PRIVATE KEY-----` 等带标签的常见形态不匹配；现覆盖全部标签形态，并在 `END` 标记存在时脱敏整个 PEM 块（而不仅是首行）。块内间隔使用 `(?:[^-]|-(?!----))` 而非 `[\s\S]`，无法越过下一段 `-----`，因此没有 END 标记的头部会立即失配而不是探测 16384 个偏移——1MB 的 BEGIN 头部洪水从 ~6.2s 降到 ~8ms（正则本身），规则整体保持线性
  - 通用代理子路径（`/v1/embeddings`、`/v1/rerank` 等）接入保形脱敏：此前流水线只对展平文本打分，转发的仍是原始 payload。转发路径与 `RedactionFilter` 共用同一条路由判据（`is_low_false_positive_route`），因此通用路由跑**完整**规则集——否则 EMAIL/手机/身份证/银行卡会被打分却仍以明文转发
  - Responses `instructions`（系统提示词）与三条路由的工具定义（`tools` 与旧版 `functions` 的 `description`、`parameters` 默认值/枚举值）纳入脱敏；工具名、tool call 关联 id、媒体定位符仍原样转发
  - 工具定义脱敏移到 tools 缓存回填**之后**：缓存与 passthrough 构造器共用，passthrough 回合按设计缓存原始 tools，此前只在写缓存前脱敏，导致同一 conversation 的后续「已过滤」请求回填时把原文转发出去
  - 脱敏过滤器纳入 `_SECURITY_CRITICAL_FILTER_NAMES`：过滤器异常时一律 fail-closed，不再受 `AEGIS_STORAGE_FAILURE_ACTION=forward` 影响而转发半脱敏内容；映射持久化失败仍遵循该开关，降级为「已脱敏但不可还原」并打审计标记 `redaction_mapping_persist_failed`
  - 通用代理的结构遍历加了嵌套深度上限（超限按 `payload_depth_shape_violation` 返回 400，而不是 `RecursionError` 500）与脱敏命中行数上限；`_preserves_json_shape` 改为短路比较，不再为两棵树各物化一份逐节点签名

## [Previous]

> **历史记录（仅供追溯）**：以下条目描述的是当时的实现，其中部分行为已被后续提交推翻，请勿当作当前规格使用。已知与当前实现不符的条目已就地标注。**当前行为一律以 [README.md](README.md) / [README_zh.md](README_zh.md) 与代码为准。**

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
  - 匹配高危模式（`rm -rf`、SQL 注入、反弹 shell、fork bomb、`curl|bash`、`dd if=of=`、`mkfs`、`powershell -enc` 等）的片段被替换为 `【AegisGate已处理危险疑似片段】`，原文**不会出现在返回中**（条数随 `security_filters.yaml` 变动，不再在文档中固化具体数字）
  - 一般危险片段仍使用 chunked-hyphen 分词变形
  - 模式来源：`anomaly_detector.command_patterns` + `sanitizer.force_block_command_patterns` + `privilege_guard.blocked_patterns` + 硬编码高危 shell 命令（13 条）

- **语义模块（TF-IDF 资产 + 可选语义复核）**
  - 仓库包含轻量 TF-IDF + LogisticRegression 模型文件与训练脚本（离线实验/维护用）：`aegisgate/models/tfidf/*`、`scripts/train_tfidf.py`
  - 网关主链路语义复核（可选）：
    - 开关：`AEGIS_ENABLE_SEMANTIC_MODULE`（默认 `true`）
    - 灰区门控：仅当风险评分落在 `(AEGIS_SEMANTIC_GRAY_LOW, AEGIS_SEMANTIC_GRAY_HIGH)` 才触发
    - 执行方式：调用 `AEGIS_SEMANTIC_SERVICE_URL` 指向的语义服务；URL 为空时仅灰区触发记录 `semantic_service_unconfigured` 并降级（不做语义风险抬升）
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

- **默认安全级别改为 `medium`**：宽松模式，大部分"可能危险"指令不拦截，仅高危 + 脱敏；高危指令（系统提示泄露、编码攻击、凭据泄露）仍通过 disposition=block 强制拦截。语义复核开关（`AEGIS_ENABLE_SEMANTIC_MODULE`，灰区门控）默认开启；未配置语义服务 URL 时仅在灰区触发降级记录，不做语义风险抬升。
- **`AEGIS_ENABLE_THREAD_OFFLOAD` 默认保持为 `false`**：当前 Store I/O 与过滤管道已通过独立执行器 offload；该开关主要作为兼容字段保留。（**已过期**：该配置项此后已被删除，见 Unreleased 的「删除无效配置 `AEGIS_ENABLE_THREAD_OFFLOAD`」。）
- **`confirmation_ttl_seconds` 从 300s 增加到 600s**：给用户更充裕的时间做 yes/no 决策。
  - > **已过期**：yes/no 确认流程已整体移除，该配置项已无运行期消费者。
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
  - > **已过期**：该叠加文件已在后续版本移除，仓库当前只有 `docker-compose.yml`。Caddy 需自行部署，参考 [Caddyfile.example](Caddyfile.example) 与 `scripts/caddy-entrypoint.sh`。

### Fixed

- **[Critical] 网关卡死：`_flatten_text` 无法处理 Responses API 的 `function_call` 类型输出**
  - `gpt-5.3-codex` 等模型在 `output` 中返回 `function_call`/`computer_call`/`bash` 类型 item 时，`_flatten_text` 返回空字符串，导致 `_extract_responses_output_text` / `_extract_chat_output_text` 回退到 `json.dumps(upstream_body)`。
  - 上游响应 body 包含完整 `instructions` 字段（Codex CLI 系统提示词，可达 40k+ 字符），被当作"模型输出文本"传给全部响应过滤器，导致过滤器在巨大文本上执行正则、循环等 CPU 密集操作。
  - **修复**：`_flatten_text` 新增对 `function_call`/`computer_call`/`bash` 类型的简短摘要生成，永远不再产生空字符串迫使调用方 fallback。
  - **修复**：`_extract_responses_output_text` 与 `_extract_chat_output_text` 安全回退改为仅提取 `status`/`error` 字段的短字符串，**不再** `json.dumps` 整个 body。

- **[Critical] 网关卡死：过滤管道同步执行阻塞 event loop**
  - 过滤管道（request/response）当前始终在独立线程池执行（不会在 event loop 同步运行）。
  - `AEGIS_FILTER_PIPELINE_TIMEOUT_S`（默认 `90.0`）用于限制过滤管道最大执行时间；设为 `0` 表示不限制。
  - 请求侧超时动作由 `AEGIS_REQUEST_PIPELINE_TIMEOUT_ACTION` 控制：`block`（默认）或 `pass`。
  - 响应侧超时：固定 `block` 并返回简短超时提示文本。

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

## 使用说明（历史）

> 本节是随「修复卡死」变更一起写下的操作说明，保留在此仅供追溯。**当前的配置说明请看 [README.md](README.md) 的 Configuration 章节、[README_zh.md](README_zh.md) §5 与 [config/.env.example](config/.env.example)。**

### 修复卡死问题后的配置项

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AEGIS_FILTER_PIPELINE_TIMEOUT_S` | `90.0` | 过滤管道最大执行时间（秒）；请求侧按 `AEGIS_REQUEST_PIPELINE_TIMEOUT_ACTION` 处理，响应侧固定拦截；`0` 表示不限制 |
| `AEGIS_REQUEST_PIPELINE_TIMEOUT_ACTION` | `block` | 请求过滤管道超时动作：`block`（安全默认）或 `pass`（兼容旧行为） |
| `AEGIS_ENABLE_THREAD_OFFLOAD` | `false` | **[已删除]** 该字段从未接线，已在 Unreleased 的「删除无效配置」条目中移除；旧 `.env` 里的残留键不会导致启动失败 |
| `AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK` | `false` | **[已废弃]** 放行确认流程已移除，无论值为何均自动遮挡/分割后返回 |

### 调试日志配置

> **以下两条已过期**：`AEGIS_DEBUG_EXCERPT_MAX_LEN=0` 不再关闭截断——出于防误配泄漏原文的考虑，`debug_excerpt.py::_resolve_max_len()` 现在只接受正整数，`0` 与负数一律回落到调用方默认值（原文摘要 500 字符，处理后内容 800 字符）。配套的 `debug_excerpt label=...` 诊断日志也已移除。

- **放宽摘要长度**：设置正整数，例如 `AEGIS_DEBUG_EXCERPT_MAX_LEN=20000`（Docker 需在 compose 的 `environment` 中配置并重启容器）。这是目前唯一生效的调节方式。
- ~~**完整打印 request/response 原文**：设置 `AEGIS_DEBUG_EXCERPT_MAX_LEN=0`。~~ 已失效，见上方说明。
- ~~若设置后仍看到截断，请查看 `debug_excerpt` 诊断行。~~ 该诊断日志已移除。
- 打印请求体本身仍需 `AEGIS_LOG_LEVEL=debug` 且 `AEGIS_LOG_FULL_REQUEST_BODY=true`，仅建议在受控环境短时开启。
