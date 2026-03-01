# AegisGate Agent Skill

本技能文档给 Agent 直接使用，目标是：在一台新机器上完成 AegisGate 的安装、启动、注册 token、以及客户端接入配置。

## 0) 先读项目要点（必须）

- AegisGate 是 LLM 安全网关：请求侧脱敏/清洗，响应侧检测/阻断/确认放行；`responses` 结构化 `input`（含 function/tool 输出）也会在转发上游前做脱敏。
- 当前只支持 **Token 路由**（v1 和 v2 共用同一组 token）：
  - `v1`（LLM）：`http://<host>:18080/v1/__gw__/t/<TOKEN>/...`
  - `v2`（通用 HTTP 代理）：`http://<host>:18080/v2/__gw__/t/<TOKEN>`，须携带 `x-target-url: <完整目标URL>` 请求头
- 管理接口（`/__gw__/register|lookup|unregister`）应只允许内网/管理机访问。

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

## 6) 注册上游并生成 token（必须）

> 注册接口应从管理机/内网访问。

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"agent"}'
```

期望返回：

```json
{
  "token": "Ab3k9Qx7Yp",
  "baseUrl": "http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7Yp"
}
```

## 7) 验证 token 路由调用

```bash
curl -X POST "http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>/responses" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <UPSTREAM_API_KEY>" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

## 8) 客户端配置模板（Agent/CLI）

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>
api_key: <UPSTREAM_API_KEY>
model: gpt-4.1-mini
```

说明：
- `base_url` 使用 token 路由。
- 若客户端默认流式输出，网关会处理 `[DONE]` 断流恢复。

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

1. `health` 是否正常。  
2. 是否使用 token 路由（路径里有 `/v1/__gw__/t/<TOKEN>/...`）。  
3. token 是否存在（`/__gw__/lookup`）。  
4. 上游地址与 API key 是否正确。  
5. 看 `docker compose logs -f aegisgate` 是否有 `upstream` 错误、确认放行、阻断原因。  
6. 若遇到高风险确认，用户必须发送完整指令：  
   - `yes cfm-<id>--act-<token>` 或 `no cfm-<id>--act-<token>`。

## 11) 安全基线（必须遵守）

- 对外仅暴露业务入口，管理接口仅限内网。
- 默认监听建议使用 `127.0.0.1`，通过反向代理做外部暴露控制。
- 不在日志或工单中明文粘贴密钥、token、cookie、私钥、助记词。
- 生产环境定期轮换 `gateway_key` 与上游 API key。
