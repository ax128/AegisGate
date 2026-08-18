# 可挂载参数目录

Docker 运行时挂载本目录。当前版本已支持对部分文件做轮询热更新；为避免旧连接/旧线程残留影响，生产环境修改后仍建议安排一次平滑重启。

## 首次启动（自动生成）

**无需手动复制**：首次 Docker 或本地启动时，若本目录（或容器内挂载的策略目录）缺少策略 YAML，应用会从内置默认自动生成，不覆盖已有文件。若缺少 `config/.env`，应用也会基于 `config/.env.example` 自动生成一份默认 `.env`。

## 目录内容

| 文件 | 用途 | 是否入库 | 热更新 | 含密 |
|------|------|:---:|:---:|:---:|
| `default.yaml` / `strict.yaml` / `permissive.yaml` | 策略（启用哪些 filter、`risk_threshold`） | 否（首启生成） | 是 | 否 |
| `security_filters.yaml` | 各 filter 规则与 `action_map` | 否（Docker 首启生成） | 是 | 否 |
| `.env` | 运行参数（见下方「运行参数」小节） | 否（从 `.env.example` 生成） | 部分 | 是 |
| `.env.example` | 完整可调项清单与注释 | 是 | — | 否 |
| `gw_tokens.json` | token → 上游映射 | 否 | 是 | 是 |
| `gw_tokens.json.example` | token 映射模板 | 是 | — | 否 |
| `model_map.json` | compat 模式的全局模型映射 + `allowed_models` 扩展 | 是 | **否，需重启** | 否 |
| `stats.json` | 请求统计持久化（`core/stats.py` 运行时写入） | 否 | — | 否 |
| `aegis_gateway.key` | 网关密钥 / UI 登录密码，首启生成 `0600` | 否 | 否 | **是** |
| `aegis_fernet.key` | 脱敏映射加密密钥（Fernet），首启生成 `0600` | 否 | 否 | **是** |
| `aegis_proxy_token.key` | 反向代理互信凭据（见 README §1.7），首启生成 `0600` | 否 | 否 | **是** |

以下按四类展开说明。

### 1. 策略与规则（YAML）

宿主机 `./config` 挂载为容器内策略目录。首次启动缺失 YAML 时，程序会自动生成默认策略文件；你也可以手动维护这些文件。

| 文件 | 说明 |
|------|------|
| `default.yaml` | 默认策略（启用哪些 filter、risk_threshold） |
| `security_filters.yaml` | 各 filter 规则与 action_map（如 secret_exfiltration: review/block） |
| `strict.yaml` / `permissive.yaml` | 可选策略，请求里通过 `policy` 指定 |

当前默认策略补充：
- `default.yaml` 当前**未**包含 `untrusted_content_guard`。如需对 `retrieval/web/tool/document` 等不可信来源做边界包裹与风险抬升，需要在策略 YAML 中显式加入该 filter，并保持对应 feature flag 开启。
- 已默认启用 `tool_call_guard`：未命中白名单的工具名与危险参数都按 `review` 处理（抬高风险分并标记复核，按阈值处置）；`tool_whitelist` 默认留空，避免误伤自定义工具。如需严格白名单，可再显式配置。
- `security_filters.yaml` 的唯一事实来源是 `aegisgate/policies/rules/security_filters.yaml`，**不入库**——此前本目录下也有一份被版本控制的副本，导致同一条安全修复只落到其中一份，Docker 与裸机部署加载了不同的规则。改规则请改包内那份（或通过 UI 编辑运行时那份，但要清楚它只影响本部署）。
  - Docker 部署：`./config` 被挂载覆盖到包内规则目录，本目录下的同名文件由 `init_config` 首次启动时从镜像内的 `/app/bootstrap/rules` 生成。**升级时必须重建镜像**（`docker compose build aegisgate`），否则补写进来的是旧镜像里的旧规则。
  - 裸机部署：直接读包内那份，本目录下不会生成同名文件。

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
| `AEGIS_ENABLE_SEMANTIC_MODULE` | 启用语义复核（灰区门控：仅当风险评分落在 `(AEGIS_SEMANTIC_GRAY_LOW, AEGIS_SEMANTIC_GRAY_HIGH)` 才触发） | `true` / `false` |
| `AEGIS_SEMANTIC_SERVICE_URL` | 当前主链路使用的语义服务地址；留空时**仅灰区触发**会记录 `semantic_service_unconfigured` 并降级（不做语义风险抬升） | 语义服务 URL / 空 |
| `AEGIS_SEMANTIC_GRAY_LOW` | 语义复核灰区下界（0–1） | `0.25` |
| `AEGIS_SEMANTIC_GRAY_HIGH` | 语义复核灰区上界（0–1） | `0.75` |
| `AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK` | **[已废弃]** 放行确认流程已移除，无论值为何均自动遮挡/分割后返回 | `false` |
| `AEGIS_STRICT_COMMAND_BLOCK_ENABLED` | 强制命令拦截开关（命中即直接拦截并自动遮挡/分割返回） | `false` / `true` |
| `AEGIS_GATEWAY_KEY` | 网关密钥（可选，Docker/CI 覆盖用）；默认从 `config/aegis_gateway.key` 加载，首次启动自动生成 | 文件加载 |
| `AEGIS_DEFAULT_POLICY` | 默认策略名 | `default` |
| `AEGIS_UPSTREAM_BASE_URL` | v1 默认上游；仅 localhost/内网客户端可直连 `/v1/...`（或由反向代理携带 `x-aegis-proxy-token`） | `http://localhost:8317/v1` |
| `AEGIS_UPSTREAM_WHITELIST_URL_LIST` | 命中的上游整体跳过响应侧过滤管道（等同 `__passthrough`，但无公网限制、无审计标签）；仅用于完全受信上游 | 空 |
| `AEGIS_STORAGE_FAILURE_ACTION` | 存储后端故障时：`block`（安全默认）或 `forward`（降级纯转发） | `block` |
| `AEGIS_UPSTREAM_TIMEOUT_SECONDS` | 上游超时秒数 | `600`（10 分钟） |
| `AEGIS_ENABLE_LOCAL_PORT_ROUTING` | 允许纯数字 token 回退到本地主机端口（如 `/v1/__gw__/t/8317/...`） | `false` / `true` |
| `AEGIS_ALLOW_PUBLIC_NUMERIC_TOKENS` | 是否允许公网/非内网客户端使用纯数字端口 token（默认仅内网） | `false` / `true` |
| `AEGIS_ALLOW_PUBLIC_PASSTHROUGH_MODE` | 是否允许公网/非内网客户端使用 `token__passthrough`（危险；默认仅内网） | `false` / `true` |
| `AEGIS_DOCKER_UPSTREAMS` | 启动时注入 `token -> Docker 服务名` 映射；同名映射会覆盖数字端口回退 | `8317:cli-proxy-api,8080:sub2api` |
| `AEGIS_V2_TARGET_ALLOWLIST` | v2 目标主机白名单；留空即拒绝全部外部目标（fail-closed） | `api.openai.com,.anthropic.com` |
| `AEGIS_ENABLE_RELAY_ENDPOINT` | 启用可选 `POST /relay/generate` Relay 兼容端点 | `false` / `true` |
| `AEGIS_MAX_REQUEST_BODY_BYTES` | 请求体上限 | `12000000` |
| `AEGIS_MAX_MULTIPART_BODY_BYTES` | multipart 请求体上限（OpenAI `/v1/images/edits`/`/v1/images/variations`/`/v1/files`） | `60000000` |
| `AEGIS_MAX_MESSAGES_COUNT` | Chat Completions 的 messages 条数上限 | `500` |

完整列表见项目 README 的「Configuration」章节及 `config/.env.example`。

补充：

- `AEGIS_UPSTREAM_BASE_URL` 只对 localhost / 内网来源的非 token `/v1/...` 生效；外部来源会被边界中间件拒绝并返回 `token_route_required`。
- `v2` 没有“默认上游直连”模式；必须走 `/v2/__gw__/t/<token>/...`，并且目标主机需命中 `AEGIS_V2_TARGET_ALLOWLIST`。
- Web UI 的配置页实际写入的也是 `config/.env`；当前 UI 已覆盖 `AEGIS_UPSTREAM_BASE_URL`、`AEGIS_ENABLE_LOCAL_PORT_ROUTING`、`AEGIS_ENABLE_RELAY_ENDPOINT`、`AEGIS_V2_TARGET_ALLOWLIST` 等关键项。

### 配置交互：Feature Flag / 策略 YAML / Security Level

网关过滤器的激活由三层配置共同决定：

1. **策略 YAML (`enabled_filters`)**：声明哪些过滤器是激活候选。策略文件位于 `aegisgate/policies/rules/`（如 `default.yaml`、`strict.yaml`）。

2. **Feature Flag (`enable_*` in settings.py / .env)**：与策略 YAML 构成 AND 条件——过滤器必须同时列在 YAML 中且对应 feature flag 开启才会激活。
   - 例：`system_prompt_guard` 当前既未列在 `default.yaml`，对应的 `AEGIS_ENABLE_SYSTEM_PROMPT_GUARD` 也默认为 `false`——两个条件都不满足，因此该过滤器默认不会激活。
   - 要启用 `system_prompt_guard`，必须 **同时** 在策略 YAML 中加入该条目 **并且** 在 `.env` 中设置 `AEGIS_ENABLE_SYSTEM_PROMPT_GUARD=true`。

3. **`AEGIS_SECURITY_LEVEL`**：不改变运行哪些过滤器，而是通过策略引擎调整 `risk_threshold`：
   - `low`：更高阈值（更宽松，更少拦截）
   - `medium`（默认）：使用 YAML 声明的 `risk_threshold`
   - `high`：更低阈值（更激进，更多拦截）

热更新限制：`security_level` 变更不会在热更新时生效，需重启。

注意：
- 当 `AEGIS_LOG_LEVEL=debug` 且 `AEGIS_LOG_FULL_REQUEST_BODY=true` 时，请求体会完整打印（包括 `responses` 历史里的 function/tool 输出原文）。生产环境建议保持 `false`。

### Observability（可选）

- 安装 `.[observability]` 后，网关会暴露 `/metrics` Prometheus 端点。
- 启动时会初始化 OpenTelemetry provider/exporter；请求处理过程中会创建 `gateway.request` spans，是否真正导出取决于 exporter 配置。
- 若未安装 OTLP exporter，span 默认会被丢弃；可通过 `AEGIS_OTEL_CONSOLE_EXPORTER=true` 临时启用 console exporter。
- OTLP exporter 使用标准 `OTEL_EXPORTER_OTLP_*` 环境变量配置。
- `/metrics` 没有单独鉴权，沿用网关普通请求的网络与鉴权控制；若关闭 loopback/HMAC 保护，端点可能被更广泛访问。
- 未安装该 extra 时，metrics 与 tracing 会自动降级为 no-op，不影响网关启动。

### 3. 全局模型映射（model_map.json）

仅在 token 配置了 `"compat": "openai_chat"` 时生效，用于把 Anthropic 模型名转换为上游 OpenAI 模型名。

- `map`：模型名映射表。优先级为 token 级 `model_map` > 本文件的 `map` > token 级 `default_model` > `gpt-5.4`。
- `allowed_models`：compat 目标模型白名单的**扩展位**，与代码内置清单取并集。内置集合是下界，配置只能增加，不能删除或清空。接入新上游模型时在这里追加即可，无需改代码。
- **该文件只在启动时读取**，不参与热更新；修改后需重启网关。

### 4. Token 映射表（gw_tokens.json）

通过 `POST /__gw__/register` 注册的 token 与上游映射会写入 `gw_tokens.json`（路径可由 `AEGIS_GW_TOKENS_PATH` 覆盖）。启动时自动加载，可手动编辑该文件，**同一 upstream_base 建议只保留一条**，重启后生效。

- **Docker 部署（当前默认）**：Compose 设为 `AEGIS_GW_TOKENS_PATH=/app/aegisgate/policies/rules/gw_tokens.json`，并将 `./config` 挂载到该目录，因此会持久化到宿主机 `./config/gw_tokens.json`，重启后不丢失。
- 若你改为 `/tmp/...` 等临时路径，容器重启后 token 可能丢失。
- 若同时配置了 `AEGIS_DOCKER_UPSTREAMS`，启动时会把其中的同名 token **静默覆盖**到 `gw_tokens.json` 映射上；环境变量在该场景下是权威来源。

---

热更新说明：
- watcher 默认轮询以下文件：`config/.env`、`security_filters.yaml`、策略 YAML、`gw_tokens.json`。
- `security_filters.yaml` 与策略 YAML 变更后，会清缓存并在下一次请求时重建 filter pipeline。
- `.env` 仅支持**部分**参数热更新。以下 11 项安全关键参数在启动时固定，热更新不会生效（以 `aegisgate/core/hot_reload.py` 的 `_IMMUTABLE_FIELDS` 为准）：
  `gateway_key`、`security_level`、`enforce_loopback_only`、`allow_public_numeric_tokens`、`allow_public_passthrough_mode`、`enable_request_hmac_auth`、`request_hmac_secret`、`trusted_proxy_ips`、`xff_strict_internal`、`v2_block_internal_targets`、`local_ui_allow_internal_network`。
- **注意 Web UI 也受此限制**：配置页可以编辑 `AEGIS_SECURITY_LEVEL`、`AEGIS_ENFORCE_LOOPBACK_ONLY`、`AEGIS_TRUSTED_PROXY_IPS`，保存会写入 `config/.env` 并提示成功，但运行时取值要到**下次重启**才更新。改完这些项请用 UI 的「重启网关」或 `docker compose restart aegisgate`。`AEGIS_XFF_STRICT_INTERNAL` 同样需重启；设了 `AEGIS_TRUSTED_PROXY_IPS` 之后，仅把该开关改回 `false` **不能**撤销可信代理对 client IP 与限流键的影响，回退办法是清空该变量并重启。
- `config/model_map.json` **不在** watcher 监听范围内：修改模型映射或 `allowed_models` 后必须重启网关。
- 对于长连接、流式会话或 Compose 环境，仍建议在变更后执行一次 `docker compose restart aegisgate` 作为稳妥做法。
