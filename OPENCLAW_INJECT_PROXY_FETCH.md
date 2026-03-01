# OpenClaw 自动注入脚本说明

本文档说明 `scripts/openclaw-inject-proxy-fetch.py` 的当前行为与推荐用法。

## 1. 脚本作用

脚本会在 OpenClaw 中注入 `fetch` 代理层，让 HTTP(S) 请求优先走 AegisGate `v2`。

注入时会自动执行：
1. 创建或更新 `src/infra/proxy-fetch.ts`
2. 在 `src/entry.ts` 早期插入 `import "./infra/proxy-fetch.js";`
3. 首次注入前备份改动目标到 `.aegisgate-backups/openclaw-inject-proxy-fetch/`
4. 若检测到“已注入”，先恢复备份再重注入，避免重复注入错位
5. 自动维护 OpenClaw 仓库 `.gitignore`（忽略 `.aegisgate-backups/` 与 `src/infra/proxy-fetch.ts`）
6. 注入成功后自动执行一次 `build`

## 2. 推荐命令（一次完成）

```bash
python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2/__gw__/t/<TOKEN>
```

当命令中携带 `OPENCLAW_PROXY_GATEWAY_URL=...` 时，脚本还会自动：
1. 写入/更新 `~/.config/systemd/user/openclaw-gateway.service.d/90-openclaw-proxy-fetch.conf`
2. 写入 `OPENCLAW_PROXY_GATEWAY_URL`
3. 自动补充 `OPENCLAW_PROXY_DIRECT_HOSTS` 默认值（你不需要手动传）
4. 执行 `systemctl --user daemon-reload`
5. 执行 `systemctl --user restart openclaw-gateway.service`

## 3. 参数规则

脚本不自动搜索目录。必须通过以下方式之一指定 OpenClaw 根目录（目录中必须存在 `src/entry.ts`）：
1. 位置参数：`python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw`
2. 环境变量：`OPENCLAW_ROOT=/path/to/openclaw`

支持在同一命令里追加环境变量赋值参数：
1. `OPENCLAW_PROXY_GATEWAY_URL=...`
2. `OPENCLAW_PROXY_DIRECT_HOSTS=...`（可选；不传则用脚本默认）

## 4. 注入后运行行为

`proxy-fetch` 运行时逻辑：
1. 未设置 `OPENCLAW_PROXY_GATEWAY_URL`：不改写 `fetch`，行为与原始 OpenClaw 一致
2. 已设置 `OPENCLAW_PROXY_GATEWAY_URL`：将 HTTP(S) 请求改写到网关地址
3. 改写请求会附带 `X-Target-URL: <原始URL>`
4. 同源防重入：目标与网关同源时直连，防止循环代理
5. 直连名单：默认内置常见基础站点，可用 `OPENCLAW_PROXY_DIRECT_HOSTS` 覆盖

## 5. 常用命令

仅注入 + build（不改服务环境）：

```bash
python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw
```

移除注入（优先从备份恢复，不执行 build）：

```bash
python scripts/openclaw-inject-proxy-fetch.py /path/to/openclaw --remove
```

调试日志：

```bash
python scripts/openclaw-inject-proxy-fetch.py -v /path/to/openclaw
python scripts/openclaw-inject-proxy-fetch.py -vv /path/to/openclaw
```

## 6. 生效检查

检查 gateway 进程：

```bash
pgrep -af "openclaw.*gateway|openclaw.mjs|dist/entry.js"
```

检查 gateway 进程环境变量（将 `<PID>` 替换为上一步 PID）：

```bash
tr '\0' '\n' < /proc/<PID>/environ | egrep 'OPENCLAW_PROXY_GATEWAY_URL|OPENCLAW_PROXY_DIRECT_HOSTS'
```

若能看到 `OPENCLAW_PROXY_GATEWAY_URL=.../v2/__gw__/t/<TOKEN>`，说明 OpenClaw gateway 已加载 v2 代理配置。

## 7. 注意事项

1. 脚本会校验 `entry.ts` 锚点上下文，校验失败时会终止，避免误注入。
2. OpenClaw 升级后如入口结构变化，可能需要更新脚本锚点逻辑。
3. 建议每次 OpenClaw 升级后重新执行脚本，确保注入文件与最新源码一致。
