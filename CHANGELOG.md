# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
| `AEGIS_ENABLE_THREAD_OFFLOAD` | `false` | 旧开关，现已冗余（管道强制在线程池执行），保留向后兼容 |

### 调试日志配置

- **完整打印 request/response 原文**：启动前设置 `AEGIS_DEBUG_EXCERPT_MAX_LEN=0`（Docker 需在 compose 的 `environment` 中配置并重启容器）。
- **仅放宽长度**：例如 `AEGIS_DEBUG_EXCERPT_MAX_LEN=20000`。
- 若设置后仍看到截断，请查看同一次请求的 `debug_excerpt` 诊断行中 `AEGIS_DEBUG_EXCERPT_MAX_LEN` 与 `max_len_used` 的值，以判断是环境变量未生效还是下游日志层截断。
