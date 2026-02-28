# 可挂载参数目录

Docker 运行时挂载本目录，**改本目录内文件后重启容器即生效**，无需重建镜像。

## 首次启动（自动生成）

**无需手动复制**：首次 Docker 或本地启动时，若本目录（或容器内挂载的策略目录）缺少 `.env` 与策略 YAML，应用会从内置默认自动生成，不覆盖已有文件。直接 `docker compose up -d` 或本地运行即可；生成后可在本目录编辑 `.env` 与 YAML，重启生效。

## 两类配置

### 1. 策略与规则（YAML）

宿主机 `./config` 挂载为容器内策略目录，需包含以下 YAML。

**首次使用**，将仓库中策略文件复制到本目录：

```bash
cp aegisgate/policies/rules/*.yaml config/
```

| 文件 | 说明 |
|------|------|
| `default.yaml` | 默认策略（启用哪些 filter、risk_threshold） |
| `security_filters.yaml` | 各 filter 规则与 action_map（如 secret_exfiltration: review/block） |
| `strict.yaml` / `permissive.yaml` | 可选策略，请求里通过 `policy` 指定 |

### 2. 运行参数（.env）

用于调节 **settings** 中的项，如日志等级、安全档位、网关 key、上游超时等。

- **首次使用**：仓库中只有 `config/.env.example`，需复制为 `config/.env` 后 Compose 才能启动：
  ```bash
  cp config/.env.example config/.env
  ```
- 复制后可编辑 `config/.env`；更多可调项见 `config/.env.example` 内注释。

常用示例：

| 变量 | 说明 | 示例 |
|------|------|------|
| `AEGIS_LOG_LEVEL` | 日志等级 | `info` / `debug` |
| `AEGIS_LOG_FULL_REQUEST_BODY` | DEBUG 下是否打印完整请求体 | `false` / `true` |
| `AEGIS_SECURITY_LEVEL` | 安全档位 | `low` / `medium` / `high` |
| `AEGIS_STRICT_COMMAND_BLOCK_ENABLED` | 强制命令拦截开关（命中即进入确认拦截；默认覆盖 SSH/防火墙/Docker 高危） | `false` / `true` |
| `AEGIS_GATEWAY_KEY` | 网关校验 key | `agent` |
| `AEGIS_DEFAULT_POLICY` | 默认策略名 | `default` |
| `AEGIS_UPSTREAM_TIMEOUT_SECONDS` | 上游超时秒数 | `60` |
| `AEGIS_MAX_REQUEST_BODY_BYTES` | 请求体上限 | `2000000` |

完整列表见项目 README 的「环境变量」章节。

注意：
- 当 `AEGIS_LOG_LEVEL=debug` 且 `AEGIS_LOG_FULL_REQUEST_BODY=true` 时，请求体会完整打印（包括 `responses` 历史里的 function/tool 输出原文）。生产环境建议保持 `false`。

### 3. Token 映射表（gw_tokens.json）

通过 `POST /__gw__/register` 注册的 token 与上游映射会写入 `config/gw_tokens.json`（路径可由 `AEGIS_GW_TOKENS_PATH` 覆盖）。启动时自动加载，可手动编辑该文件，**同一组 upstream_base + gateway_key 建议只保留一条**，重启后生效。

- **Docker 部署**：Compose 默认设 `AEGIS_GW_TOKENS_PATH=/tmp/gw_tokens.json`（与 sqlite/audit 一样用 `/tmp`，保证容器内可写），**重启容器后 token 会丢失，需重新注册**。若需持久化：挂载可写卷并设置路径，例如增加 volume `- ./logs:/data` 且 `AEGIS_GW_TOKENS_PATH=/data/gw_tokens.json`（并确保宿主机 `./logs` 对容器用户可写）。

---

修改 YAML、`.env` 或 `gw_tokens.json` 后执行：`docker compose restart aegisgate`
