# Roadmap

本文件只记录**尚未落地**的架构级工作与已知取舍。已经完成的改动一律记在 [CHANGELOG.md](CHANGELOG.md)，不在这里重复。

约定：

- 这里写方向、范围与验收口径，**不写绕过方式与攻击载荷**。具体的安全问题请私下反馈给维护者，不要开公开 issue。
- 每条都标注了成本量级：S（半天内）/ M（1–3 天）/ L（1–2 周）/ XL（需专门排期）。
- 条目里的坐标是写作时的现状，动手前请以打开代码确认到的语义为准。

## 架构级

### R1 — 拆分 `router.py`，统一流式状态机（XL）

`aegisgate/adapters/openai_compat/router.py` 目前约 6.8k 行，含 9 个 `_execute_*` 入口：chat / responses / messages / generic 各自的流式与非流式，外加 multipart。同一段逻辑在四条协议路径上各有一份实现，历史上多数流式缺陷都出在「改了一处、漏了另外三处」。

目标是把「上游事件流 → 中间事件模型 → 目标协议事件」抽成单一状态机，`_execute_*` 收敛为统一模板，差异只保留在 payload builder 与 renderer。

前置条件已具备：`aegisgate/tests/test_streaming_router.py` 已经把四条流式路径的回归基线建起来（四个 `_execute_*_stream_once` 都在其覆盖内），重构必须全程保持它绿。

### R2 — 协议映射收敛为双向查表（L–XL）

`tool_choice`、`usage`、`finish_reason` ↔ `stop_reason`、tool-call 增量等映射知识散落在 `adapters/openai_compat/mapper.py` 与 `compat_bridge.py`，两侧各自演化。收敛为双向查表函数并配 round-trip 属性测试后，「请求侧映射了、响应侧没映射」这类分歧才能从结构上消除。

### R3 — 规则与正则的单一真源（L）

同一套危险命令规则目前在三处各有定义：

- `aegisgate/config/security_rules.py` 的代码默认；
- `aegisgate/policies/rules/security_filters.yaml`（运行时的可编辑真源，Web 控制台改的就是它）；
- `aegisgate/adapters/v2_proxy/router.py` 的内置表 —— 注意 `_compile_patterns()` 是**先无条件编译内置表、再追加 YAML 条目**，不是「YAML 缺失时才兜底」，因此同名规则会被编译两遍。

三件事：

1. 规则收敛到单一真源，另外两处退化为读取方，并补一条「副本数量/内容一致」的守护测试；
2. 统一扫描窗口口径 —— v2 响应过滤的上限（`AEGIS_V2_RESPONSE_FILTER_MAX_CHARS`）与流式探测窗口目前是两套算法，需要收敛成一条，并把最终语义明确写进部署文档；
3. 正则侧引入线性时间引擎（如 `google-re2`），或把 `aegisgate/tests/test_redos_guard.py` 的计时守护升级为静态 lint —— 计时守护能挡住已知形态，挡不住新写进来的回溯型正则。

### R4 — 进程模型固化（S + 视需求 XL）

stats、LRU 缓存、后台 worker、限流窗口全是**进程内单例**，只在单进程下语义正确。以 `--workers > 1` 或多实例形态部署时，这些语义会**静默破裂**而不是报错，而当前文档没有任何一处写明这个约束。

分两层做，顺序不能反：

1. ~~**必做（S）**：启动时把 pid 与实例标识写进日志和 `/health`；能读到 `WEB_CONCURRENCY` 或 `--workers` 时打 ERROR 级告警；README 与部署文档写明「仅支持单进程」。~~
   **已完成** —— 见 `aegisgate/core/process_identity.py`：启动日志与 `/health`、`/ready` 都带 `pid` 与 `instance`；
   命中 `WEB_CONCURRENCY` / `UVICORN_WORKERS` / `GUNICORN_WORKERS` / `GUNICORN_CMD_ARGS` / `--workers N` 时打 ERROR 并在探针 body 里带 `multiprocess_warning`。
2. **视需求（XL）**：确有水平扩展需求时，再把进程内单例改造为跨进程安全（Redis 后端天然可用）。

不要把「检测到多进程就拒绝启动」当成唯一防线：worker 子进程通常看不到父进程的启动参数，会同时制造「检测不到 → 静默破裂」和「误检测 → 无法启动」两种反向故障。可靠的那一层是告警与文档，第 1 层就是按这个口径实现的——只告警，不阻止启动。

### R5 — 可部署性打磨（M）

- `docker-compose.yml` 硬依赖两个 `external: true` 网络，环境里没有这两个网络时 `docker compose up` 直接失败 —— 基线 compose 应当能独立起来，外部网络接入下沉为可选覆盖文件。
- compose 与 Dockerfile 都缺 `healthcheck` / `HEALTHCHECK`，容器挂死时编排层看不出来。
- Dockerfile 先 `COPY` 源码、后 `pip install`，任何源码改动都会击穿依赖层缓存；镜像里还带着 `aegisgate/tests`。调整 COPY 顺序并排除测试即可，属纯收益改动。

### R6 — 风险阈值与 `block` 语义的一致性（M，**需先决策**）

两处实测行为与文档/控制台呈现出的语义不一致。都属于「行为变更」，要单独 PR、单独回归，不要混进文档 PR。

1. **`medium` 也参与阈值缩放**。`policy_engine.resolve()` 对所有档位都调 `apply_threshold()`，
   `medium` 的系数是 `1.30`。配 `default` 策略（`risk_threshold: 0.85`）时
   `0.85 × 1.30 = 1.105`，clamp 后是 **1.0**；`low`（×1.60）同样是 1.0。于是：

   - `low` 与 `medium` 在默认策略下**完全等价**，与「三档分层」的产品语义不符；
   - `action_map` 的 `block` 最高把风险分抬到 `0.95`，所以 `OutputSanitizer` 里
     `risk_score >= max(ctx.risk_threshold, self._block_threshold)` 这条**基于分数**的拦截分支
     在默认配置下永不触发。

   要么把 `medium` 的系数改回 `1.0`，要么把 `default.yaml` 的 `risk_threshold` 降到缩放后仍
   `< 1.0` 的值。改哪个都会**提高**默认部署的拦截率，需要评估误拦。

2. **`block` 在不同 filter 里语义不同**。`injection_detector` 与 `rag_poison_guard` 的 `block`
   直接设置 `request_disposition` / `response_disposition`（不依赖阈值）；`restoration` 与
   `sanitizer` 的 `block` 只做 `risk_score = max(..., 0.95)`，仍受阈值约束——叠加上面第 1 点，
   在默认配置下不会拦截。控制台「动作映射」页把这四种动作呈现为统一语义，用户无从看出差别。

### R7 — 无消费者的配置项（S）

- `AEGIS_RISK_SCORE_THRESHOLD` 此前没有任何运行时读取者；现已接为「策略 YAML 未声明
  `risk_threshold` 时的全局兜底值」。但仓库自带的三个策略都声明了该键，所以它对默认部署仍然
  不起作用。是否要让它成为真正的全局下限，取决于 R6 的决策。
  策略文件缺失时走的 `policy_engine._BUILTIN_DEFAULT_POLICY` 同样显式声明该键并固定为 `0.85`，
  那条路径也读不到该环境变量——这是刻意的（配置目录为空不应连带改变阈值），一致性已由
  `test_builtin_default_policy_pins_default_yaml_threshold` 钉在 `default.yaml` 上。
- `AEGIS_TENANT_ID_HEADER` 已删除：租户 id 由 `_trusted_scope_id()` / `x-aegis-token-hint` 推导，
  该字段从来没有读取者，却在控制台可编辑。
- `require_confirmation_on_block` 仍保留在 `Settings` 里做配置兼容（不在控制台开放）。确认没有
  部署依赖旧键之后可以删除。

### R8 — 请求侧脱敏的六执行面收敛（M–L，**部分需先决策**）

请求侧脱敏当前是**六个执行面**，不是「V1 / V2」两桶。生效面已由 `core/request_redaction_settings.py`
的 `SURFACES` 服务端算好并在控制台呈现，README / README_zh / config/README 也已按这个模型改写；
剩下的是把模型分裂本身消掉。以下四条原先只记录在本地未入库的实施规格里，现在收进这里。

1. ~~**V2 的 relaxed 集配置化**~~ **已完成**。V2 现在与 V1 读同一个 `redaction.relaxed_pii_ids`，
   `V2_RELAXED_PII_IDS` 已删除。实测两侧在 `pii_patterns` 口径上只差 `COOKIE_SESSION` 一项
   （`AUTH_BEARER` / `FIELD_SECRET` 属 `field_value_patterns` 层，两侧本就恒跑），因此把
   `COOKIE_SESSION` 并入共享默认集即可完成收敛，**两侧都不丢覆盖**。守护见
   `aegisgate/tests/test_relaxed_pii_convergence.py`。
2. ~~**转发层判据从按角色改为按路由**~~ **已完成**。原先的角色推导集合含全部真实角色，
   等价于「永远 relaxed」；multipart 因此出现「全量集打分、relaxed 集改写」的分歧。
   现在五个转发入口都接收 `route` 并内部推导，`relaxed_patterns` 改为必填参数，
   角色集合已删除。守护见 `aegisgate/tests/test_forward_redaction_route_derived.py`。
3. **field 规则语义跨 V1/V2 统一**：默认列表与显式列表的关系、`field_value_min_len` 各层下限不同；
   顺带把精确值脱敏的覆盖面扩到 V1 结构化内容、通用 JSON 与 multipart（目前只覆盖扁平消息文本）。
4. **按执行层 / 规则 ID 的命中统计**。控制台现在的统计卡是去重后的唯一值数且含 field 规则，
   无法回答「哪条规则在哪一层命中了多少次」。

另有两条与 R3 重叠、不重复展开：不可变规则快照 + 请求级 generation 绑定（V2 侧目前没有等价的请求
上下文，需新建一套），以及带运行时超时保证的正则引擎。

## 单点待办

- **messages / generic 的 EOF 恢复**：上游 EOF 且无 `[DONE]` 时，chat / responses 会补一条断开提示，messages / generic 没有该分支（见 CHANGELOG 中「EOF 无 `[DONE]`」条目，这是记录在案的当前行为）。补上属于**新增行为**而非缺陷修复，要单独评估客户端兼容性，不要混进 bug 修复 PR。
- **TF-IDF 资产去留**：`aegisgate/models/tfidf/` 目前定位是「保留的离线实验资产」。这是产品决策 —— 要么接回主链路并给出评估口径，要么整体下架，不要长期挂在中间态。
- ~~**README 与 UPSTREAM-QUICKSTART 的上游章节仍有重复**~~ **已完成**：`README_zh.md §上游接入`
  只剩上游表 + 三场景判断依据 + 两条安全默认，Docker 服务名、网络连通性排查与 Caddy 要点全部
  下沉到 `UPSTREAM-QUICKSTART.md`。
- **CHANGELOG 结构**：`## [Unreleased]` 下同名小节反复出现 —— `### Added` ×5、`### Changed` ×6、
  `### Fixed` ×3、`### Security` ×2，`### Breaking Changes` 被埋在中间；`## [Previous]` 更乱。
  文件顶部原先声明遵循 Keep a Changelog 而实际没有版本节，该声明已改成如实描述当前结构。
  真正的收敛（合并同名小节、切出带日期的版本节）是纯文本搬运，但 diff 很大，建议单独一个 PR 做。
- **低优先级项**：日志脱敏粒度、权限窗口、局部性能与一致性问题，按需单独立项，不要顺手夹带进相邻 PR。

## 横切验收口径

落到上面任一条的 PR，除常规单测外还要带一条**副本一致性守护**。

本仓库最高频的缺陷来源不是单个逻辑写错，而是同一逻辑存在多份平行实现、其中一份没跟上改动；针对性单测通常只覆盖被改的那一份，于是出现假绿。守护「副本有几份、内容是否一致」比守护单个缺陷更划算。现成的例子见 `aegisgate/tests/test_redos_guard.py`（正则副本 + ReDoS 计时）与 `test_doc_alignment.py`（文档与代码事实对齐）。
