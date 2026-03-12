# 可挂载参数目录

Docker 运行时挂载本目录。当前版本已支持对部分文件做轮询热更新；为避免旧连接/旧线程残留影响，生产环境修改后仍建议安排一次平滑重启。

## 首次启动（自动生成）

**无需手动复制**：首次 Docker 或本地启动时，若本目录（或容器内挂载的策略目录）缺少策略 YAML，应用会从内置默认自动生成，不覆盖已有文件。`.env` 文件不是必需项，不存在时会直接使用默认配置（不会自动写出 `.env` 文件）。

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
- 已默认启用 `tool_call_guard`：默认优先拦截危险参数；`tool_whitelist` 默认留空，避免误伤自定义工具。如需严格白名单，可再显式配置。

### 2. 运行参数（.env）

用于调节 **settings** 中的项，如日志等级、安全档位、网关 key、上游超时等。

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
| `AEGIS_REQUIRE_CONFIRMATION_ON_BLOCK` | 拦截后是否走 yes/no 确认流程（`false`=直接变形返回，`true`=缓存等待放行） | `false` / `true` |
| `AEGIS_STRICT_COMMAND_BLOCK_ENABLED` | 强制命令拦截开关（命中即进入确认拦截；默认覆盖 SSH/防火墙/Docker 高危） | `false` / `true` |
| `AEGIS_GATEWAY_KEY` | 网关密钥（可选，Docker/CI 覆盖用）；默认从 `config/aegis_gateway.key` 加载，首次启动自动生成 | 文件加载 |
| `AEGIS_DEFAULT_POLICY` | 默认策略名 | `default` |
| `AEGIS_UPSTREAM_TIMEOUT_SECONDS` | 上游超时秒数 | `600`（10 分钟） |
| `AEGIS_MAX_REQUEST_BODY_BYTES` | 请求体上限 | `2000000` |

完整列表见项目 README 的「环境变量」章节。

注意：
- 当 `AEGIS_LOG_LEVEL=debug` 且 `AEGIS_LOG_FULL_REQUEST_BODY=true` 时，请求体会完整打印（包括 `responses` 历史里的 function/tool 输出原文）。生产环境建议保持 `false`。

### 3. Token 映射表（gw_tokens.json）

通过 `POST /__gw__/register` 注册的 token 与上游映射会写入 `gw_tokens.json`（路径可由 `AEGIS_GW_TOKENS_PATH` 覆盖）。启动时自动加载，可手动编辑该文件，**同一组 upstream_base + gateway_key 建议只保留一条**，重启后生效。

- **Docker 部署（当前默认）**：Compose 设为 `AEGIS_GW_TOKENS_PATH=/app/aegisgate/policies/rules/gw_tokens.json`，并将 `./config` 挂载到该目录，因此会持久化到宿主机 `./config/gw_tokens.json`，重启后不丢失。
- 若你改为 `/tmp/...` 等临时路径，容器重启后 token 可能丢失。

---

热更新说明：
- watcher 默认轮询以下文件：`config/.env`、`security_filters.yaml`、策略 YAML、`gw_tokens.json`。
- `security_filters.yaml` 与策略 YAML 变更后，会清缓存并在下一次请求时重建 filter pipeline。
- 对于长连接、流式会话或 Compose 环境，仍建议在变更后执行一次 `docker compose restart aegisgate` 作为稳妥做法。
