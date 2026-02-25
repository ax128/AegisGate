# 可挂载参数目录

Docker 运行时挂载本目录，**改本目录内文件后重启容器即生效**，无需重建镜像。

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

- 已有默认 `config/.env`（含 `AEGIS_LOG_LEVEL`、`AEGIS_SECURITY_LEVEL`、`AEGIS_GATEWAY_KEY`），可直接编辑。
- 更多可调项见 `config/.env.example`（复制为 `.env` 后按需取消注释并修改）。

常用示例：

| 变量 | 说明 | 示例 |
|------|------|------|
| `AEGIS_LOG_LEVEL` | 日志等级 | `info` / `debug` |
| `AEGIS_SECURITY_LEVEL` | 安全档位 | `low` / `medium` / `high` |
| `AEGIS_GATEWAY_KEY` | 网关校验 key | `agent` |
| `AEGIS_DEFAULT_POLICY` | 默认策略名 | `default` |
| `AEGIS_UPSTREAM_TIMEOUT_SECONDS` | 上游超时秒数 | `60` |
| `AEGIS_MAX_REQUEST_BODY_BYTES` | 请求体上限 | `2000000` |

完整列表见项目 README 的「环境变量」章节。

---

修改 YAML 或 `.env` 后执行：`docker compose restart aegisgate`
