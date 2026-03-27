# 可挂载参数目录

Docker 运行时挂载本目录。当前版本已支持对部分文件做轮询热更新；为避免旧连接/旧线程残留影响，生产环境修改后仍建议安排一次平滑重启。

## 首次启动（自动生成）

**无需手动复制**：首次 Docker 或本地启动时，若本目录（或容器内挂载的策略目录）缺少策略 YAML，应用会从内置默认自动生成，不覆盖已有文件。若缺少 `config/.env`，应用也会基于 `config/.env.example` 自动生成一份默认 `.env`。

## 两类配置

### 1. 策略与规则（YAML）

宿主机 `./config` 挂载为容器内策略目录。首次启动缺失 YAML 时，程序会自动生成默认策略文件；你也可以手动维护这些文件。

| 文件 | 说明 |
|------|------|
| `default.yaml` | 默认策略（启用哪些 filter、risk_threshold） |
| `security_filters.yaml` | 各 filter 规则与 action_map（如 secret_exfiltration: review/block） |
| `strict.yaml` / `permissive.yaml` | 可选策略，请求里通过 `policy` 指定 |

当前默认策略补充：
- 已默认启用 `untrusted_content_guard`：对 `retrieval/web/tool/document` 等不可信来源做边界包裹与风险抬升。
- 已默认启用 `tool_call_guard`：未命中白名单的工具名默认按 `review` 处理，危险参数默认按 `block` 处理；`tool_whitelist` 默认留空，避免误伤自定义工具。如需严格白名单，可再显式配置。

### 2. 运行参数（.env）

用于调节 **settings** 中的项，如日志等级、安全档位、网关 key、上游超时等。

- **唯一运行时入口**：AegisGate 只读取 `config/.env` 作为文件配置来源；仓库根目录 `.env` 不再作为运行时配置入口。
- **首次使用**：推荐复制 `config/.env.example` 为 `config/.env` 固化参数；若不存在，Compose 仍可启动并使用应用默认值（`env_file` 为可选）：
  ```bash
  cp config/.env.example config/.env
  ```
- 复制后可编辑 `config/.env`；更多可调项见 `config/.env.example` 内注释。

常用示例：

| 变量 | 说明 | 示例 |
|------|------|------|
| `AEGIS_LOG_LEVEL` | 日志等级 | `info` / `debug` |
| `AEGIS_LOG_FULL_REQUEST_BODY` | DEBUG 下是否打印完整请求体 | `false` / `true` |
| `AEGIS_SECURITY_LEVEL` | 安全档位（`medium` 默认：宽松仅高危拦截；`low`：极宽松基本只脱敏；`high`：全量检测） | `low` / `medium` / `high` |
| `AEGIS_ENABLE_SEMANTIC_MODULE` | 启用内置 TF-IDF 语义分类器（无需 GPU） | `true` / `false` |
| `AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK` | **[已废弃]** 放行确认流程已移除，无论值为何均自动遮挡/分割后返回 | `false` |
| `AEGIS_STRICT_COMMAND_BLOCK_ENABLED` | 强制命令拦截开关（命中即直接拦截并自动遮挡/分割返回） | `false` / `true` |
| `AEGIS_GATEWAY_KEY` | 网关密钥（可选，Docker/CI 覆盖用）；默认从 `config/aegis_gateway.key` 加载，首次启动自动生成 | 文件加载 |
| `AEGIS_DEFAULT_POLICY` | 默认策略名 | `default` |
| `AEGIS_UPSTREAM_TIMEOUT_SECONDS` | 上游超时秒数 | `600`（10 分钟） |
| `AEGIS_MAX_REQUEST_BODY_BYTES` | 请求体上限 | `12000000` |

完整列表见项目 README 的「Configuration」章节及 `config/.env.example`。

### 配置交互：Feature Flag / 策略 YAML / Security Level

网关过滤器的激活由三层配置共同决定：

1. **策略 YAML (`enabled_filters`)**：声明哪些过滤器是激活候选。策略文件位于 `aegisgate/policies/rules/`（如 `default.yaml`、`strict.yaml`）。

2. **Feature Flag (`enable_*` in settings.py / .env)**：与策略 YAML 构成 AND 条件——过滤器必须同时列在 YAML 中且对应 feature flag 开启才会激活。
   - 例：`system_prompt_guard` 曾列在 default.yaml 中，但 `AEGIS_ENABLE_SYSTEM_PROMPT_GUARD` 默认为 `false`，因此该过滤器不会激活。
   - 要启用 `system_prompt_guard`，必须 **同时** 在策略 YAML 中保留该条目 **并且** 在 `.env` 中设置 `AEGIS_ENABLE_SYSTEM_PROMPT_GUARD=true`。

3. **`AEGIS_SECURITY_LEVEL`**：不改变运行哪些过滤器，而是通过策略引擎调整 `risk_threshold`：
   - `low`：更高阈值（更宽松，更少拦截）
   - `medium`（默认）：使用 YAML 声明的 `risk_threshold`
   - `high`：更低阈值（更激进，更多拦截）

热更新限制：`security_level` 变更不会在热更新时生效，需重启。

注意：
- 当 `AEGIS_LOG_LEVEL=debug` 且 `AEGIS_LOG_FULL_REQUEST_BODY=true` 时，请求体会完整打印（包括 `responses` 历史里的 function/tool 输出原文）。生产环境建议保持 `false`。

### Observability（可选）

- 安装 `.[observability]` 后，网关会暴露 `/metrics` Prometheus 端点。
- 启动时会初始化 OpenTelemetry provider/exporter；当前版本默认不会自动生成 HTTP 请求 spans。
- OTLP exporter 使用标准 `OTEL_EXPORTER_OTLP_*` 环境变量配置。
- `/metrics` 没有单独鉴权，沿用网关普通请求的网络与鉴权控制；若关闭 loopback/HMAC 保护，端点可能被更广泛访问。
- 未安装该 extra 时，metrics 与 tracing 会自动降级为 no-op，不影响网关启动。

### 3. Token 映射表（gw_tokens.json）

通过 `POST /__gw__/register` 注册的 token 与上游映射会写入 `gw_tokens.json`（路径可由 `AEGIS_GW_TOKENS_PATH` 覆盖）。启动时自动加载，可手动编辑该文件，**同一 upstream_base 建议只保留一条**，重启后生效。

- **Docker 部署（当前默认）**：Compose 设为 `AEGIS_GW_TOKENS_PATH=/app/aegisgate/policies/rules/gw_tokens.json`，并将 `./config` 挂载到该目录，因此会持久化到宿主机 `./config/gw_tokens.json`，重启后不丢失。
- 若你改为 `/tmp/...` 等临时路径，容器重启后 token 可能丢失。

---

热更新说明：
- watcher 默认轮询以下文件：`config/.env`、`security_filters.yaml`、策略 YAML、`gw_tokens.json`。
- `security_filters.yaml` 与策略 YAML 变更后，会清缓存并在下一次请求时重建 filter pipeline。
- `.env` 仅支持**部分**参数热更新。`gateway_key`、`security_level`、`enforce_loopback_only`、HMAC 相关项、`trusted_proxy_ips`、`v2_block_internal_targets`、`local_ui_allow_internal_network` 等安全关键参数不会在热更新时生效。
- 对于长连接、流式会话或 Compose 环境，仍建议在变更后执行一次 `docker compose restart aegisgate` 作为稳妥做法。
