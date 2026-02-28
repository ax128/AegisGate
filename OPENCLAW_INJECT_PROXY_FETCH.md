# OpenClaw 自动注入脚本说明

本文档说明 `scripts/openclaw-inject-proxy-fetch.py` 的行为、使用方式和常见问题。

## 1. 作用

脚本用于给 OpenClaw 自动注入 `fetch` 代理层，让 HTTP(S) 请求先进入 AegisGate `v2` 再转发。

会自动完成以下修改：
1. 创建或更新 `src/infra/proxy-fetch.ts`
2. 在 `src/entry.ts` 早期插入 `import "./infra/proxy-fetch.js";`
3. 将 `src/infra/proxy-fetch.ts` 写入 OpenClaw 仓库 `.gitignore`
4. 注入成功后自动执行一次 `build`

## 2. 注入后请求行为

是否启用代理由 `OPENCLAW_PROXY_GATEWAY_URL` 决定：
- 未设置：不改写 `fetch`，行为与原始 OpenClaw 一致
- 已设置：把 HTTP(S) 请求改写到网关地址（例如 `http://127.0.0.1:18080/v2`）

改写时会附加原始目标地址头：
- `X-Target-URL: <原始URL>`

保护机制：
- 同源防重入：请求目标与网关同源时不再代理，避免循环转发
- 直连名单：默认放行部分常见站点；可用 `OPENCLAW_PROXY_DIRECT_HOSTS` 覆盖（逗号分隔）

## 3. 目录指定规则（必须显式提供）

脚本不再自动搜索目录。必须按以下二选一显式提供 OpenClaw 根目录（且目录内需存在 `src/entry.ts`）：
1. 命令行参数：`python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw`
2. 环境变量：`OPENCLAW_ROOT=/path/to/openclaw`

## 4. 使用方法

注入并自动 build：

```bash
python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw
```

或用环境变量指定根目录：

```bash
export OPENCLAW_ROOT=/path/to/openclaw
python scripts/openclaw-inject-proxy-fetch.py
```

Windows PowerShell 示例：

```powershell
$env:OPENCLAW_ROOT="D:\agent_work\openclaw"
python scripts/openclaw-inject-proxy-fetch.py
```

移除注入（不执行 build）：

```bash
python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw --remove
```

调试输出：

```bash
python scripts/openclaw-inject-proxy-fetch.py -v
python scripts/openclaw-inject-proxy-fetch.py -vv
```

## 5. build 自动执行规则

注入成功后，脚本会自动检测并执行：
- `pnpm build`（优先）
- `yarn build`
- `npm run build`

检测依据：优先锁文件，再回退到系统可用包管理器。

若自动 build 失败，脚本会返回非 0 退出码并提示手动构建。

## 6. 运行时环境变量

OpenClaw 运行时至少设置：

```bash
export OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2/__gw__/t/XapJ3D0x
```

推荐注入后的最小执行步骤：

```bash
python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw
export OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2/__gw__/t/XapJ3D0x
# 然后重启 openclaw 进程
```

可选：
- `OPENCLAW_PROXY_DIRECT_HOSTS`：覆盖默认直连域名，逗号分隔

网关 `v2` 目标 URL 请求头：
- 注入侧固定发送 `X-Target-URL`
- AegisGate `v2` 兼容 `X-Target-URL` 与 `x-original-url`

## 7. 注意事项

1. 脚本会校验 `entry.ts` 锚点上下文，避免错位注入。
2. OpenClaw 升级后若入口结构变化，可能需要更新脚本锚点再注入。
3. 建议每次 OpenClaw 拉取上游更新后重新执行脚本，以确保注入文件与逻辑同步。
4. 修改 `OPENCLAW_PROXY_GATEWAY_URL` 后，必须重启 OpenClaw 才会生效（已有进程不会自动重新加载该环境变量）。
