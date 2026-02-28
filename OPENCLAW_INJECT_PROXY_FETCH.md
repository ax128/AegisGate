# OpenClaw 自动注入脚本说明

本文档说明 `scripts/openclaw-inject-proxy-fetch.py` 的逻辑与使用方式。

## 1. 目标

在不手工改 OpenClaw 业务代码的前提下，自动注入一个 `globalThis.fetch` 包装层，使 OpenClaw 的 HTTP(S) 请求可转发到 AegisGate `v2` 入口进行安全检查。

脚本会自动做两处改动：
1. 新建/更新 `src/infra/proxy-fetch.ts`
2. 在 `src/entry.ts` 早期位置插入 `import "./infra/proxy-fetch.js";`

## 2. 注入后的请求行为

注入模块通过环境变量 `OPENCLAW_PROXY_GATEWAY_URL` 控制是否启用：
- 未设置：不改写 `fetch`（原行为不变）
- 已设置：将请求发往网关 URL（例如 `http://127.0.0.1:18080/v2`）

并在请求头写入原始目标 URL：
- `X-Target-URL: <原始URL>`

同源保护：
- 若请求目标与网关同源（例如 `http://127.0.0.1:18080/v1/...`），不会再次代理，避免 `v1 -> v2 -> v1` 重入。

额外直连白名单：
- 文档站、localhost、内网、常见 LLM API 域名（见脚本内 `NO_PROXY_HOSTS`）。

## 3. 脚本定位 OpenClaw 目录规则

优先级如下：
1. 命令行参数指定目录
2. 环境变量 `OPENCLAW_ROOT`
3. 当前目录 / 当前目录下 `openclaw` 或 `openclaw-main`
4. 从当前目录递归搜索（有限深度）

## 4. 注入与移除

注入：

```bash
python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw-main
```

或：

```bash
set OPENCLAW_ROOT=D:\agent_work\openclaw-main
python scripts/openclaw-inject-proxy-fetch.py
```

移除注入：

```bash
python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw-main --remove
```

调试日志：

```bash
python scripts/openclaw-inject-proxy-fetch.py -v
python scripts/openclaw-inject-proxy-fetch.py -vv
```

## 5. 运行时环境变量

OpenClaw 运行时至少需要：

```bash
OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2
```

`v2` 目标 URL 请求头：
- 注入脚本固定发送 `X-Target-URL`
- AegisGate `v2` 兼容 `X-Target-URL` 与 `x-original-url`

## 6. 注意事项

1. 脚本会校验 `entry.ts` 锚点上下文，避免错位注入。
2. 脚本会维护 OpenClaw 仓库 `.gitignore`，将 `src/infra/proxy-fetch.ts` 设为忽略，减少与上游更新冲突。
3. OpenClaw 升级后如果 `entry.ts` 结构变化，可能需要重新执行注入或更新脚本锚点。
