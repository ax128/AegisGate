# 网关职责与过度处理全局检查

本文档对 AegisGate 做**职责边界**与**是否过度处理消息**的全局检查，不修改代码，仅给出结论与优化建议。

---

## 1. 网关职责是否到位

### 1.1 声明目标（来自 README）

- 应用层 baseUrl 固定指向网关 token 路由：`/v1/__gw__/t/<token>/...`。
- 上游绑定信息通过注册接口维护（`/__gw__/register|lookup|unregister`）。
- 网关执行过滤/脱敏后转发到上游，收到响应后再执行安全检查并返回。
- 支持安全等级、审计、策略化过滤；可选 loopback、HMAC+nonce；确认流程（高风险需用户 yes/no 后放行）。

### 1.2 职责对照

| 职责项 | 是否到位 | 说明 |
|--------|----------|------|
| **转发与路由** | 是 | 按 token 映射到上游 URL 转发，符合“网关只做转发与安全”的边界。 |
| **鉴权** | 是 | token 路由鉴权、可选 HMAC 验签与 nonce 防重放，均在边界层，未涉及业务鉴权。 |
| **请求侧脱敏与最小充分检查** | 是 | Redaction（PII 占位符）+ RequestSanitizer（泄露/强意图/形状异常/命令/编码的拦截或清洗），属于安全网关应有能力。 |
| **响应侧安全检查** | 是 | 异常、注入、权限、工具调用、恢复占位符、恢复后泄露兜底、输出清洗，形成完整响应安全链。 |
| **审计** | 是 | 写 audit.jsonl，记录 request_id、风险分、disposition、tags 等，不落完整 content，职责合理。 |
| **策略化过滤** | 是 | PolicyEngine 按 YAML 决定启用哪些 filter 与风险阈值，安全等级调节灵敏度，属策略配置范畴，未做业务策略。 |
| **高风险确认** | 是 | 高风险时返回确认模板、缓存 pending、解析 yes/no 后一次性放行或取消，属于“安全策略下的人工确认”，未替代业务做决策。 |
| **入口与负载防护** | 是 | body/条数/长度限制、pending 大包瘦身、多模态占位化等（若已实现），均在网关边界内。 |

### 1.3 是否越界（做了不该网关做的事）

- **未发现业务逻辑越界**：网关未做与安全无关的内容改写（如摘要、翻译、业务路由）；Redaction/Restoration 是脱敏与还原，RequestSanitizer/OutputSanitizer 的替换均为安全相关（如 [REDACTED:command]）。
- **确认流程**：pending 存储与 yes/no 解析是为“高风险放行前需人工确认”服务，属于安全策略的一部分，不视为越界。
- **策略与语义**：按 policy 启用 filter、灰区触发语义，都是“安全策略/风险判定”的范畴，在网关职责内。

**结论**：网关职责**基本到位**，未发现明显越界；声明能力均有对应实现，且未掺入与安全无关的业务逻辑。

---

## 2. 是否过度处理消息

### 2.1 处理链概览

- **请求侧**：Redaction（全文正则）→ RequestSanitizer（leak_check / strong_intent / shape_anomaly / command / encoded / invisible / bidi，及截断）。
- **响应侧**：AnomalyDetector → PromptInjectionDetector → PrivilegeGuard → ToolCallGuard → RestorationFilter → PostRestoreGuard → OutputSanitizer；之后在灰区可能再跑**语义模块**（当前为正则占位：injection/leak/privilege/discussion）。

同一请求的**用户输入**会先被请求侧扫一遍，上游返回的**模型输出**再被响应侧多级 filter 与语义各扫一遍。

### 2.2 重复检测（同类风险在多处扫描）

下表为“同一类风险意图/模式”在哪些 filter 中出现，便于判断重复度。

| 风险类别 | 请求侧 | 响应侧 | 语义模块（灰区） |
|----------|--------|--------|------------------|
| **泄露 / 系统提示 / 密钥** | RequestSanitizer：leak_check_patterns | InjectionDetector：system_exfil；PrivilegeGuard：blocked（含 leak）；OutputSanitizer：system_leak_patterns | SemanticAnalyzer：_leak_re |
| **注入 / 绕过指令** | RequestSanitizer：strong_intent_patterns | InjectionDetector：direct_patterns、system_exfil、obfuscated 等 | SemanticAnalyzer：_injection_re |
| **权限 / 命令执行** | RequestSanitizer：command_patterns | PrivilegeGuard：blocked_patterns；OutputSanitizer：command_patterns | SemanticAnalyzer：_privilege_re |
| **长编码 / Base64 / 异常负载** | RequestSanitizer：encoded_payload_patterns、shape_anomaly | AnomalyDetector：base64/hex/url_encoded；InjectionDetector：obfuscated（解码后关键词）；OutputSanitizer：encoded_payload_patterns | — |
| **Unicode 异常 / Bidi** | RequestSanitizer：invisible_char/bidi 检测 | InjectionDetector：unicode_invisible/unicode_bidi；OutputSanitizer：对 response_injection_unicode_bidi 直接 block | — |
| **讨论/引用上下文（降误报）** | RequestSanitizer：discussion_context 影响是否 block | InjectionDetector：discussion_patterns 降风险；OutputSanitizer：discussion_context 影响是否 block | SemanticAnalyzer：_discussion_re 降风险 |

可以看出：

- **泄露、注入、权限、命令**类意图在**请求侧（RequestSanitizer）、响应侧（Injection/Privilege/OutputSanitizer）、语义模块**中都有覆盖，且规则语义高度相似（如 reveal/system prompt、ignore instruction、execute command），属于**同一类风险被多层级、多 filter 重复扫描**。
- **编码/异常**在请求侧与 Anomaly/Injection/Output 多处出现；**Unicode/Bidi** 在 RequestSanitizer 与 Injection、OutputSanitizer 中都有处理。
- **讨论上下文**在请求、响应、语义三处都用于“降低误报”，逻辑一致但分散在三处实现。

### 2.3 是否算“过度”

- **从安全角度**：请求侧拦截/清洗 + 响应侧多级检测 + 灰区语义，构成**纵深防御**，对漏报有一定补偿；且请求侧与响应侧面对的是不同对象（用户输入 vs 模型输出），并非完全重复。
- **从成本与维护角度**：同类模式在多个 filter 和语义模块中重复维护，存在**规则重复、行为不一致**的风险；且同一段文本（尤其是响应）会被 Anomaly → Injection → Privilege → OutputSanitizer 依次全文扫描，**CPU 与延迟**随链长与规则数增加，可视为一定程度的**过度处理**。
- **语义模块**：当前实现为正则占位（injection/leak/privilege/discussion），与 InjectionDetector、PrivilegeGuard、OutputSanitizer 的规则高度同质，在灰区再扫一遍属于**明显重复**；若未来接入真实语义模型，更合理的分工是“语义做规则难以表达的 paraphrasing/意图”，而不是再做一遍同质规则。

**结论**：存在**多层级对同类风险的重复检测**（尤其是泄露、注入、权限、命令、编码、Unicode）；在“纵深防御”与“避免过度处理”之间，当前偏向前者，有一定过度处理与维护成本。

---

## 3. 问题归纳与优化建议（不改代码，仅建议）

### 3.1 职责边界

- **现状**：职责到位，未越界。
- **建议**：保持“只做安全与转发”的边界；新增能力时避免引入业务语义（如按业务类型路由、业务级鉴权）。

### 3.2 重复检测与过度处理

| 问题 | 建议方向 |
|------|----------|
| 泄露/注入/权限/命令在 RequestSanitizer、Injection、Privilege、OutputSanitizer、Semantic 多处同质检测 | ① 规则收敛：将“泄露/系统提示”“注入意图”“权限/命令”的**正则定义**集中到少量 YAML 块，各 filter 引用同一套规则，避免多处维护。② 语义与规则分工：语义模块只做“规则难以覆盖”的语义（如换说法、意图分类），关闭或弱化与规则完全同质的正则路径。 |
| 响应侧 filter 链长，同一响应被多 filter 全文扫描 | ① 按策略合并：若某策略下 Injection 与 Privilege 的 action 一致（如都 block），可考虑合并为一层“意图+权限”检测，减少遍历次数。② 顺序与短路：对“一击必杀”类（如 unicode_bidi、system_leak）保留在前段并尽量短路，避免后续 filter 仍对已决定 block 的内容做无谓扫描。 |
| 讨论上下文降误报在请求/响应/语义三处分散 | 统一“讨论上下文”的判定逻辑（如同一组正则或同一函数），三处共用，避免行为不一致与重复维护。 |
| 语义模块（当前正则占位）与规则引擎同质 | 若暂不接入真实语义模型，可考虑**默认关闭语义模块**或仅对极少数策略开启，减少灰区时对同一段文本的又一次规则级扫描。 |

### 3.3 可落地的文档与配置

- 在**安全规则 YAML** 或单独文档中注明：哪些规则被哪些 filter 引用，避免同一模式在多处重复定义。
- 策略 YAML 中明确：各 filter 的**启用组合**与**预期作用**（如 request_sanitizer 做请求侧最小充分检查，response 侧做强检查），便于后续做“合并同类检测”或“短路”时评估影响。

---

## 4. 小结

| 维度 | 结论 |
|------|------|
| **网关职责是否到位** | **到位**。转发、鉴权、请求/响应安全、审计、策略、确认流程均在安全网关边界内，未发现业务越界。 |
| **是否过度处理消息** | **存在一定过度**。同类风险（泄露、注入、权限、命令、编码、Unicode）在请求侧、响应侧多 filter、以及语义模块中重复检测；响应链较长，同一响应被多次全文扫描；语义模块当前与规则同质，加重重复。 |
| **建议** | 规则收敛与引用统一、语义与规则分工、讨论上下文逻辑统一、可选关闭或收紧语义模块；保持网关只做安全与转发的职责边界。 |
