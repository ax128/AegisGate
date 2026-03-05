# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **调试日志：原文摘要长度可配置与诊断**
  - 新增环境变量 `AEGIS_DEBUG_EXCERPT_MAX_LEN`：覆盖默认截断长度（默认 500 字符）。设为 `0` 表示不截断，在 DEBUG 下打印完整 request/response 原文（日志会很长，建议仅在排查问题时临时开启）。
  - `debug_excerpt` 支持 `max_len <= 0` 表示不截断。
  - 每次 `debug_log_original` 调用会多打一条诊断日志：`debug_excerpt label=... AEGIS_DEBUG_EXCERPT_MAX_LEN=... max_len_used=... original_len=... excerpt_len=... truncated=...`，便于排查「为何仍被截断」（例如 Docker 未传入环境变量、或日志驱动截断）。
  - 在 `response_before_filters` 调用前增加 `response_before_filters (chat)|(responses) input_len=... request_id=...` 日志，便于确认传入的响应文本长度。

### Changed

- 无。

### Fixed

- 无。

---

## 使用说明（本次更新）

- **完整打印 request/response 原文**：启动前设置 `AEGIS_DEBUG_EXCERPT_MAX_LEN=0`（Docker 需在 compose 的 `environment` 中配置并重启容器）。
- **仅放宽长度**：例如 `AEGIS_DEBUG_EXCERPT_MAX_LEN=20000`。
- 若设置后仍看到截断，请查看同一次请求的 `debug_excerpt` 诊断行中 `AEGIS_DEBUG_EXCERPT_MAX_LEN` 与 `max_len_used` 的值，以判断是环境变量未生效还是下游日志层截断。
