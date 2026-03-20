# AegisGate Agent Skill

本技能文档给 Agent 直接使用，目标是：在一台新机器上完成 AegisGate 的安装、启动、注册 token 或配置直连上游、以及客户端接入配置。

## 0) 先读项目要点（必须）

- AegisGate 是 LLM 安全网关：请求侧脱敏/清洗，响应侧检测/自动净化（auto-sanitize）；`responses` 结构化 `input`（含 function/tool 输出）也会在转发上游前做脱敏。
- **两种路由模式**（可同时启用）：
  - **Token 路由**（推荐多租户场景）：每个 token 绑定独立的上游地址；注册/管理 token 时需提供网关密钥。
    - v1（LLM）：`http://<host>:18080/v1/__gw__/t/<TOKEN>/...`
    - v2（通用 HTTP 代理）：`http://<host>:18080/v2/__gw__/t/<TOKEN>`，须携带 `x-target-url: <完整目标URL>` 请求头
  - **直连上游**（单用户/Agent 快速接入）：设置 `AEGIS_UPSTREAM_BASE_URL=<上游地址>` 后，可直接请求 `/v1/...`，无需注册 token。`v2` 仍必须使用 token 路径。
- **脱敏豁免字段（whitelist_key）**：注册 token 时可指定逗号分隔的字段名列表（如 `api_key,secret,token`）。请求体中这些字段的值**不做 PII 脱敏**，直接透传到上游。适用于需要原始凭证通过的场景。支持以下匹配模式：
  - JSON：`"field":"value"` 或 `"field": "value"`
  - 等号赋值：`field=value`
  - 冒号赋值：`field:value`
  - URL 查询参数：`?field=value`
- 管理接口（`/__gw__/register|lookup|unregister|add|remove`）应只允许内网/管理机访问。

## 1) 环境检查

```bash
uname -a
cat /etc/os-release
which docker || true
which docker-compose || true
git --version || true
python3 --version || true
```

## 2) 如果没有 Docker：先安装 Docker（Ubuntu/Debian）

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
docker --version
docker compose version
```

可选（免 sudo）：

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

## 3) 获取源码（Git 或源码包）

### 3.1 Git 方式

```bash
git clone https://github.com/ax128/AegisGate.git
cd AegisGate
```

### 3.2 已有源码目录

```bash
cd /path/to/AegisGate
```

## 4) 推荐安装方式：Docker 一键启动

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f aegisgate
```

健康检查：

```bash
curl -sS http://127.0.0.1:18080/health
```

## 5) 可选安装方式：源码本地运行（无 Docker）

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
uvicorn aegisgate.core.gateway:app --host 127.0.0.1 --port 18080
```

## 6) 接入方式选择

### 6.1 Token 路由（多租户，推荐）

注册上游并生成 token：

```bash
# gateway_key 从 cat config/aegis_gateway.key 获取
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"<AEGIS_GATEWAY_KEY>"}'
```

期望返回：

```json
{
  "token": "Ab3k9Qx7Yp",
  "baseUrl": "http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7Yp"
}
```

注册时可附带脱敏豁免字段（如 `api_key` 字段值不做脱敏）：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"<AEGIS_GATEWAY_KEY>","whitelist_key":["api_key","secret"]}'
```

### 6.2 直连上游（单用户/Agent 快速接入）

在 `config/.env` 中设置：

```env
AEGIS_UPSTREAM_BASE_URL=https://your-upstream.example.com/v1
```

重启后直接请求 `/v1/...`，无需注册 token。`/v2/...` 不支持直连模式，仍需使用 `/v2/__gw__/t/<TOKEN>/...`：

```bash
curl -X POST http://127.0.0.1:18080/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <UPSTREAM_API_KEY>" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

## 7) 验证调用

### Token 路由

```bash
curl -X POST "http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>/responses" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <UPSTREAM_API_KEY>" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

### 直连上游

```bash
curl -X POST "http://127.0.0.1:18080/v1/responses" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <UPSTREAM_API_KEY>" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

## 8) 客户端配置模板（Agent/CLI）

### Token 路由

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>
api_key: <UPSTREAM_API_KEY>
model: gpt-4.1-mini
```

### 直连上游

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1
api_key: <UPSTREAM_API_KEY>
model: gpt-4.1-mini
```

说明：
- 若客户端默认流式输出，网关会处理 `[DONE]` 断流恢复。
- 直连模式下不需要 `base_url` 携带 token 路径段。

## 9) 常用管理命令

查看 token：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/lookup \
  -H "Content-Type: application/json" \
  -d '{"token":"<TOKEN>"}'
```

删除 token：

```bash
curl -X POST http://127.0.0.1:18080/__gw__/unregister \
  -H "Content-Type: application/json" \
  -d '{"token":"<TOKEN>"}'
```

查看所有 token（需要网关密钥）：

```bash
curl http://127.0.0.1:18080/__ui__/api/tokens \
  -H "X-Gateway-Key: <AEGIS_GATEWAY_KEY>"
```

查看日志：

```bash
docker compose logs -f aegisgate
```

重启：

```bash
docker compose restart aegisgate
```

升级：

```bash
git pull
docker compose up -d --build
```

## 10) 故障排查顺序（Agent 执行顺序）

1. `health` 是否正常（`curl http://127.0.0.1:18080/health`）。
2. 确认使用哪种路由模式：token 路由（路径含 `/v1/__gw__/t/<TOKEN>/...`）或直连上游（`AEGIS_UPSTREAM_BASE_URL` 是否已设置）。
3. Token 路由：token 是否存在（`/__gw__/lookup`）；上游地址与 API key 是否正确。
4. 直连模式：`.env` 中 `AEGIS_UPSTREAM_BASE_URL` 是否正确，是否已重启。
5. 看 `docker compose logs -f aegisgate` 是否有 `upstream` 错误、自动净化（auto-sanitize）、阻断原因。

## 11) 安全基线（必须遵守）

- 对外仅暴露业务入口，管理接口仅限内网。
- 默认监听建议使用 `127.0.0.1`，通过反向代理做外部暴露控制。
- 不在日志或工单中明文粘贴密钥、token、cookie、私钥、助记词。
- 生产环境定期轮换 `config/aegis_gateway.key`（替换文件内容后重启服务）。
- `whitelist_key` 字段只填真正需要豁免脱敏的字段名，最小化敏感数据明文透传范围。
