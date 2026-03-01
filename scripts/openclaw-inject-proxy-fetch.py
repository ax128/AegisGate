#!/usr/bin/env python3
"""
在 OpenClaw 源码中注入「安全网关代理」逻辑：
- 创建 src/infra/proxy-fetch.ts
- 在 src/index.ts / src/entry.ts 入口处加入 import "./infra/proxy-fetch.js"
- 首次注入前会备份被改动文件到 .aegisgate-backups/openclaw-inject-proxy-fetch/
- 再次运行若检测到已注入：先恢复备份，再重新注入，避免重复注入导致的错位
- 注入后：proxy-fetch.ts 与备份目录写入 .gitignore，不参与提交；git 正常更新（pull）即可，更新完需手动再执行一次本脚本注入
- 注入成功后：自动执行一次前端构建（build）

用法：
  python openclaw-inject-proxy-fetch.py /path/to/openclaw   # 命令行指定根目录
  export OPENCLAW_ROOT=<OpenClaw 根目录路径>   # 或用环境变量指定（二选一，必须显式提供）
  python openclaw-inject-proxy-fetch.py /path/to/openclaw --pin-local-build
  python openclaw-inject-proxy-fetch.py --remove
  python openclaw-inject-proxy-fetch.py -v / -vv
"""

import argparse
import logging
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

# 日志级别：默认 INFO；-v DEBUG；-vv 显示更多上下文
LOG = logging.getLogger("openclaw-inject-proxy-fetch")


def setup_log(verbose: int) -> None:
    level = logging.DEBUG if verbose > 0 else logging.INFO
    logging.basicConfig(
        format="[%(levelname)s] %(message)s",
        level=level,
        stream=sys.stdout,
    )

# 要写入的 src/infra/proxy-fetch.ts 完整内容
PROXY_FETCH_TS = r'''import process from "node:process";

const ENV_PROXY_URL = "OPENCLAW_PROXY_GATEWAY_URL";
const ENV_PROXY_DIRECT_HOSTS = "OPENCLAW_PROXY_DIRECT_HOSTS";
const ENV_PROXY_FETCH_LOG = "OPENCLAW_PROXY_FETCH_LOG";
const TARGET_URL_HEADER = "X-Target-URL";
const LOG_MARKER = "[AG_PROXY_FETCH_V2]";

// Default direct hosts include common infra and channel domains.
// OPENCLAW_PROXY_DIRECT_HOSTS is appended on top (does not replace defaults).
const DEFAULT_DIRECT_HOSTS = new Set([
  "registry.npmjs.org",
  "api.github.com",
  "raw.githubusercontent.com",
  "codeload.github.com",
  "objects.githubusercontent.com",
  "pypi.org",
  "pypi.python.org",
  "docs.openclaw.ai",
  "openclaw.ai",
  "google.com",
  "www.google.com",
  "apis.google.com",
  "accounts.google.com",
  "gstatic.com",
  "mail.google.com",
  "drive.google.com",
  "docs.google.com",
  "maps.google.com",
  "twitter.com",
  "www.twitter.com",
  "x.com",
  "api.twitter.com",
  "amazon.com",
  "www.amazon.com",
  "aws.amazon.com",
  "microsoft.com",
  "www.microsoft.com",
  "login.microsoftonline.com",
  "outlook.com",
  "live.com",
  "office.com",
  "facebook.com",
  "www.facebook.com",
  "fb.com",
  "fbcdn.net",
  "instagram.com",
  "apple.com",
  "www.apple.com",
  "cloudflare.com",
  "netflix.com",
  "www.netflix.com",
  "linkedin.com",
  "www.linkedin.com",
  "youtube.com",
  "www.youtube.com",
  "reddit.com",
  "www.reddit.com",
  "wikipedia.org",
  "www.wikipedia.org",
  "openai.com",
  "api.openai.com",
  "anthropic.com",
  "api.anthropic.com",
  "api.telegram.org",
  "telegram.org",
  "t.me",
  "discord.com",
  "cdn.discordapp.com",
  "media.discordapp.net",
  "gateway.discord.gg",
  "api.pluralkit.me",
  "slack.com",
  "api.slack.com",
  "files.slack.com",
  "hooks.slack.com",
  "cdn.slack.com",
  "slack-edge.com",
  "slack-files.com",
  "line.me",
  "api.line.me",
  "api-data.line.me",
  "whatsapp.com",
  "web.whatsapp.com",
  "api.whatsapp.com",
  "s.whatsapp.net",
  "static.whatsapp.net",
  "mmg.whatsapp.net",
  "signal.org",
]);

const DEFAULT_DIRECT_SUFFIXES = [
  "googleapis.com",
  "amazonaws.com",
  "azure.com",
  "azurewebsites.net",
  "cloudfront.net",
  "telegram.org",
  "discord.com",
  "discordapp.com",
  "discord.gg",
  "slack.com",
  "slack-edge.com",
  "slack-files.com",
  "line.me",
  "whatsapp.com",
  "whatsapp.net",
];

function isProxyFetchLogEnabled(): boolean {
  const raw = (process.env[ENV_PROXY_FETCH_LOG] || "1").trim().toLowerCase();
  return !(raw === "0" || raw === "false" || raw === "off" || raw === "no");
}

function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

function safeLog(enabled: boolean, event: string, payload: Record<string, unknown>): void {
  if (!enabled) {
    return;
  }
  try {
    console.info(`${LOG_MARKER} ${event} ${JSON.stringify(payload)}`);
  } catch {
    console.info(`${LOG_MARKER} ${event}`);
  }
}

function getDirectHosts(): { exact: Set<string>; suffixes: string[] } {
  const exact = new Set(DEFAULT_DIRECT_HOSTS);
  const suffixes = new Set(DEFAULT_DIRECT_SUFFIXES);
  const raw = process.env[ENV_PROXY_DIRECT_HOSTS]?.trim();
  if (raw) {
    for (const token of raw.split(",")) {
      const value = token.trim().toLowerCase();
      if (!value) {
        continue;
      }
      // Support suffix style: "*.example.com" or ".example.com"
      if (value.startsWith("*.")) {
        suffixes.add(value.slice(2));
        continue;
      }
      if (value.startsWith(".")) {
        suffixes.add(value.slice(1));
        continue;
      }
      exact.add(value);
    }
  }
  return { exact, suffixes: [...suffixes] };
}

function getProxyConfig(): { proxyUrl: string; proxyOrigin: string } | null {
  const url = process.env[ENV_PROXY_URL]?.trim();
  if (!url || !url.startsWith("http")) {
    return null;
  }
  let proxyOrigin: string;
  try {
    const parsed = new URL(url);
    proxyOrigin = `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
  return {
    proxyUrl: url.replace(/\/+$/, ""),
    proxyOrigin,
  };
}

function getRequestOrigin(url: string): string | null {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

export function installProxyFetchIfConfigured(): void {
  const config = getProxyConfig();
  if (!config) {
    return;
  }

  const { proxyUrl, proxyOrigin } = config;
  const directHosts = getDirectHosts();
  const originalFetch = globalThis.fetch;
  const logEnabled = isProxyFetchLogEnabled();

  if (!originalFetch) {
    return;
  }

  safeLog(logEnabled, "install", {
    use_v2: true,
    proxy_url: proxyUrl,
    proxy_origin: proxyOrigin,
  });

  function isDirectHost(hostname: string): boolean {
    const h = hostname.toLowerCase();
    if (directHosts.exact.has(h)) {
      return true;
    }
    for (const suffix of directHosts.suffixes) {
      if (h === suffix || h.endsWith("." + suffix)) {
        return true;
      }
    }
    return false;
  }

  const wrapped: typeof fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const originalUrl =
      typeof input === "string"
        ? input
        : input instanceof Request
          ? input.url
          : (input as URL).href;

    const trimmed = originalUrl.trim();
    if (!/^https?:\/\//i.test(trimmed)) {
      safeLog(logEnabled, "bypass", {
        use_v2: false,
        reason: "non_http_url",
        original_url: trimmed,
      });
      return originalFetch(input, init);
    }

    const requestOrigin = getRequestOrigin(trimmed);
    if (requestOrigin === proxyOrigin) {
      safeLog(logEnabled, "bypass", {
        use_v2: false,
        reason: "same_proxy_origin",
        original_url: trimmed,
        proxy_origin: proxyOrigin,
      });
      return originalFetch(input, init);
    }

    try {
      const hostname = new URL(trimmed).hostname;
      if (isDirectHost(hostname)) {
        // White-listed direct hosts are intentionally silent in AG proxy logs.
        return originalFetch(input, init);
      }
    } catch {
      /* ignore */
    }

    const newHeaders = new Headers(
      input instanceof Request ? (input as Request).headers : (init?.headers as HeadersInit),
    );
    newHeaders.set(TARGET_URL_HEADER, trimmed);
    const method = input instanceof Request ? input.method : (init?.method || "GET");

    safeLog(logEnabled, "route_v2", {
      use_v2: true,
      method,
      original_url: trimmed,
      gateway_url: proxyUrl,
      target_header: TARGET_URL_HEADER,
      request_headers: headersToObject(newHeaders),
    });

    const startedAt = Date.now();
    const withResponseLog = (p: Promise<Response>): Promise<Response> =>
      p
        .then((res) => {
          safeLog(logEnabled, "response", {
            use_v2: true,
            method,
            original_url: trimmed,
            gateway_url: proxyUrl,
            status: res.status,
            duration_ms: Date.now() - startedAt,
          });
          return res;
        })
        .catch((err) => {
          safeLog(logEnabled, "error", {
            use_v2: true,
            method,
            original_url: trimmed,
            gateway_url: proxyUrl,
            duration_ms: Date.now() - startedAt,
            error: String(err),
          });
          throw err;
        });

    if (input instanceof Request) {
      const req = input as Request;
      const initFromReq: RequestInit = {
        method: req.method,
        headers: newHeaders,
        mode: req.mode,
        credentials: req.credentials,
        cache: req.cache,
        redirect: req.redirect,
        referrer: req.referrer,
        referrerPolicy: req.referrerPolicy,
        integrity: req.integrity,
        keepalive: req.keepalive,
        signal: req.signal,
        duplex: "half",
      };
      if (req.body != null) {
        initFromReq.body = req.body;
      }
      return withResponseLog(originalFetch(proxyUrl, initFromReq));
    }

    return withResponseLog(originalFetch(proxyUrl, { ...init, headers: newHeaders }));
  };

  (globalThis as unknown as { fetch: typeof fetch }).fetch = wrapped;
}

installProxyFetchIfConfigured();
'''

# 入口文件中要插入的几行
PROXY_IMPORT_LINES = '''import "./infra/proxy-fetch.js";
'''

MARKER_IMPORT = 'import "./infra/proxy-fetch.js";'
MARKER_AFTER = 'import { fileURLToPath } from "node:url";'
ENTRY_RELATIVE_PATHS = ("src/index.ts", "src/entry.ts")

# 环境变量：未提供命令行参数时，用于指定 OpenClaw 目标路径
ENV_OPENCLAW_ROOT = "OPENCLAW_ROOT"
ENV_PROXY_GATEWAY_URL = "OPENCLAW_PROXY_GATEWAY_URL"
ENV_PROXY_DIRECT_HOSTS = "OPENCLAW_PROXY_DIRECT_HOSTS"
SUPPORTED_PROXY_ENV_KEYS = (ENV_PROXY_GATEWAY_URL, ENV_PROXY_DIRECT_HOSTS)
DEFAULT_GATEWAY_SYSTEMD_UNIT = "openclaw-gateway.service"
DEFAULT_PROXY_DIRECT_HOSTS = (
    "registry.npmjs.org,api.github.com,raw.githubusercontent.com,codeload.github.com,"
    "objects.githubusercontent.com,pypi.org,pypi.python.org,docs.openclaw.ai,openclaw.ai,"
    "api.telegram.org,telegram.org,t.me,discord.com,cdn.discordapp.com,media.discordapp.net,gateway.discord.gg,"
    "api.pluralkit.me,slack.com,api.slack.com,files.slack.com,hooks.slack.com,cdn.slack.com,"
    "slack-edge.com,slack-files.com,line.me,api.line.me,api-data.line.me,whatsapp.com,web.whatsapp.com,"
    "api.whatsapp.com,s.whatsapp.net,static.whatsapp.net,mmg.whatsapp.net,signal.org"
)
LOCAL_EXECSTART_OVERRIDE_FILENAME = "91-openclaw-local-build.conf"

# entry.ts 注入前上下文校验：避免项目迭代后误注入
ENTRY_ANCHOR = 'import { fileURLToPath } from "node:url";'
ENTRY_NEXT_IMPORT_CONTAINS = 'from "./cli/profile.js"'
ENTRY_CONTEXT_LOOKAHEAD = 6  # 锚点后最多看几行内要出现 profile.js import

# 注入生成的文件，加入 .gitignore 以便 git 忽略
GITIGNORE_MARKER = "# openclaw-inject-proxy-fetch"
GITIGNORE_PROXY_FETCH_ENTRY = "src/infra/proxy-fetch.ts"
GITIGNORE_BACKUP_DIR_ENTRY = ".aegisgate-backups/"

# 备份目录（位于 OpenClaw 目标项目根目录）
BACKUP_DIR_REL = os.path.join(".aegisgate-backups", "openclaw-inject-proxy-fetch")
ENTRY_BACKUP_FILENAMES = {
    "src/index.ts": "src__index.ts.bak",
    "src/entry.ts": "src__entry.ts.bak",
}
PROXY_FETCH_BACKUP_FILENAME = "src__infra__proxy-fetch.ts.bak"
PROXY_FETCH_MISSING_MARKER_FILENAME = "src__infra__proxy-fetch.ts.missing"


def _is_valid_openclaw_root(path: str) -> bool:
    """目录是否符合注入条件：至少存在一个可注入入口文件。"""
    if not os.path.isdir(path):
        return False
    return any(os.path.isfile(os.path.join(path, rel)) for rel in ENTRY_RELATIVE_PATHS)


def _resolve_entry_paths(root: str) -> list[str]:
    """返回可注入入口文件的绝对路径列表。"""
    paths: list[str] = []
    for rel in ENTRY_RELATIVE_PATHS:
        abs_path = os.path.join(root, rel)
        if os.path.isfile(abs_path):
            paths.append(abs_path)
    return paths


def find_openclaw_root(given: str | None) -> str | None:
    """
    确定 OpenClaw 源码根目录（必须显式指定）：
    1) 命令行参数
    2) 环境变量 OPENCLAW_ROOT
    """
    if given and given.strip():
        root = os.path.abspath(given.strip())
        if _is_valid_openclaw_root(root):
            LOG.debug("使用命令行指定根目录: %s", root)
            return root
        LOG.error("命令行指定路径不符合条件（需存在 src/index.ts 或 src/entry.ts）: %s", root)
        return None

    env_root = os.environ.get(ENV_OPENCLAW_ROOT, "").strip()
    if env_root:
        root = os.path.abspath(env_root)
        if _is_valid_openclaw_root(root):
            LOG.debug("使用环境变量 %s 指定根目录: %s", ENV_OPENCLAW_ROOT, root)
            return root
        LOG.error(
            "环境变量 %s 指向路径不符合条件（需存在 src/index.ts 或 src/entry.ts）: %s",
            ENV_OPENCLAW_ROOT,
            root,
        )
        return None

    LOG.error("未提供 OpenClaw 根目录。必须通过参数或环境变量显式指定。")
    LOG.error("示例：")
    LOG.error("  python openclaw-inject-proxy-fetch.py /path/to/openclaw")
    LOG.error("  export %s=/path/to/openclaw", ENV_OPENCLAW_ROOT)
    LOG.error("  python openclaw-inject-proxy-fetch.py")
    return None


def _parse_root_and_proxy_env_tokens(tokens: list[str]) -> tuple[str | None, dict[str, str]]:
    """解析参数：支持 [openclaw_root] + KEY=VALUE(代理环境变量) 混合输入。"""
    root: str | None = None
    env_assignments: dict[str, str] = {}
    for raw in tokens:
        token = (raw or "").strip()
        if not token:
            continue
        if "=" in token:
            key, value = token.split("=", 1)
            key = key.strip()
            if key in SUPPORTED_PROXY_ENV_KEYS:
                env_assignments[key] = value
                continue
        if root is None:
            root = token
            continue
        raise ValueError(
            f"无法识别参数: {token!r}。只支持路径参数和以下环境变量赋值："
            + ", ".join(f"{name}=..." for name in SUPPORTED_PROXY_ENV_KEYS)
        )
    return root, env_assignments


def _normalize_proxy_env_assignments(env_assignments: dict[str, str]) -> dict[str, str]:
    normalized = {k: str(v) for k, v in env_assignments.items() if k in SUPPORTED_PROXY_ENV_KEYS}
    gateway_url = normalized.get(ENV_PROXY_GATEWAY_URL, "").strip()
    if gateway_url and not normalized.get(ENV_PROXY_DIRECT_HOSTS, "").strip():
        normalized[ENV_PROXY_DIRECT_HOSTS] = DEFAULT_PROXY_DIRECT_HOSTS
        LOG.info("未提供 %s，已自动使用默认直连白名单。", ENV_PROXY_DIRECT_HOSTS)
    return normalized


def _systemd_escape_env_value(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _resolve_gateway_systemd_unit(env: dict[str, str] | None = None) -> str:
    source = env or os.environ
    hinted = str(source.get("OPENCLAW_SYSTEMD_UNIT", "")).strip()
    if hinted:
        return hinted
    return DEFAULT_GATEWAY_SYSTEMD_UNIT


def _write_systemd_override(unit: str, env_assignments: dict[str, str]) -> Path:
    unit_name = unit.strip() or DEFAULT_GATEWAY_SYSTEMD_UNIT
    override_dir = Path.home() / ".config" / "systemd" / "user" / f"{unit_name}.d"
    override_dir.mkdir(parents=True, exist_ok=True)
    override_file = override_dir / "90-openclaw-proxy-fetch.conf"

    lines = ["[Service]"]
    for key in SUPPORTED_PROXY_ENV_KEYS:
        if key in env_assignments:
            lines.append(f"Environment={key}={_systemd_escape_env_value(env_assignments[key])}")
    content = "\n".join(lines).rstrip() + "\n"

    old_content = ""
    if override_file.exists():
        old_content = override_file.read_text(encoding="utf-8")
    if content != old_content:
        override_file.write_text(content, encoding="utf-8")
        LOG.info("已写入 systemd 覆盖配置: %s", override_file)
    else:
        LOG.debug("systemd 覆盖配置未变化: %s", override_file)
    return override_file


def _extract_execstart_argv(raw_value: str) -> list[str] | None:
    """解析 `systemctl show -p ExecStart --value` 输出中的 argv。"""
    text = (raw_value or "").strip()
    if not text:
        return None
    value = text
    marker = "argv[]="
    marker_idx = text.find(marker)
    if marker_idx >= 0:
        value = text[marker_idx + len(marker) :]
        sep = value.find(" ;")
        if sep >= 0:
            value = value[:sep]
    value = value.strip()
    if not value:
        return None
    try:
        tokens = shlex.split(value)
    except ValueError:
        return None
    return tokens or None


def _get_systemd_execstart_argv(unit: str) -> list[str] | None:
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "show", unit, "-p", "ExecStart", "--value"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return _extract_execstart_argv(proc.stdout)


def _format_systemd_execstart(tokens: list[str]) -> str:
    return " ".join(_systemd_escape_env_value(token) for token in tokens)


def _build_local_execstart_tokens(unit: str, root: str) -> list[str]:
    local_dist_index = os.path.abspath(os.path.join(root, "dist", "index.js"))
    existing = _get_systemd_execstart_argv(unit) or []

    # 优先保留现有命令形态，只替换 dist/index.js 路径，最大限度兼容上游参数。
    if len(existing) >= 2:
        replaced = False
        updated = list(existing)
        for i, token in enumerate(updated):
            if token.endswith("/dist/index.js"):
                updated[i] = local_dist_index
                replaced = True
                break
        if not replaced:
            updated[1] = local_dist_index
        return updated

    node_bin = shutil.which("node") or "/usr/local/bin/node"
    port = os.environ.get("OPENCLAW_GATEWAY_PORT", "18789").strip() or "18789"
    return [node_bin, local_dist_index, "gateway", "--port", port]


def _write_local_execstart_override(unit: str, tokens: list[str]) -> Path:
    unit_name = unit.strip() or DEFAULT_GATEWAY_SYSTEMD_UNIT
    override_dir = Path.home() / ".config" / "systemd" / "user" / f"{unit_name}.d"
    override_dir.mkdir(parents=True, exist_ok=True)
    override_file = override_dir / LOCAL_EXECSTART_OVERRIDE_FILENAME
    content = (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart={_format_systemd_execstart(tokens)}\n"
    )

    old_content = ""
    if override_file.exists():
        old_content = override_file.read_text(encoding="utf-8")
    if content != old_content:
        override_file.write_text(content, encoding="utf-8")
        LOG.info("已写入本地构建 ExecStart 覆盖配置: %s", override_file)
    else:
        LOG.debug("本地构建 ExecStart 覆盖配置未变化: %s", override_file)
    return override_file


def _detect_execstart_script_path(tokens: list[str] | None) -> str | None:
    if not tokens:
        return None
    for token in tokens:
        if token.endswith("/dist/index.js"):
            return token
    if len(tokens) >= 2 and tokens[1].endswith(".js"):
        return tokens[1]
    return None


def _warn_if_service_not_using_local_build(root: str, unit: str) -> None:
    if shutil.which("systemctl") is None:
        return
    tokens = _get_systemd_execstart_argv(unit)
    script_path = _detect_execstart_script_path(tokens)
    local_dist_index = os.path.abspath(os.path.join(root, "dist", "index.js"))
    if not script_path:
        LOG.warning("无法识别当前 %s 的 ExecStart 脚本路径，建议手动检查 systemd 配置。", unit)
        return
    try:
        same = os.path.realpath(script_path) == os.path.realpath(local_dist_index)
    except OSError:
        same = script_path == local_dist_index
    if same:
        LOG.info("当前 %s 已使用本地构建: %s", unit, script_path)
        return
    LOG.warning("当前 %s ExecStart 指向: %s", unit, script_path)
    LOG.warning("注入源码路径为: %s", local_dist_index)
    LOG.warning("若需让注入立即生效，请加参数 --pin-local-build 重新执行脚本。")


def _configure_gateway_service(env_assignments: dict[str, str], root: str, pin_local_build: bool) -> bool:
    """持久化代理环境变量，并可选覆盖 ExecStart 到本地构建，再重启服务。"""
    env_assignments = _normalize_proxy_env_assignments(env_assignments)
    if not env_assignments and not pin_local_build:
        return False

    for key, value in env_assignments.items():
        os.environ[key] = value

    if shutil.which("systemctl") is None:
        LOG.warning("未检测到 systemctl，已仅设置当前进程环境变量（不会持久化到服务）。")
        return False

    unit = _resolve_gateway_systemd_unit()
    if env_assignments:
        _write_systemd_override(unit, env_assignments)
    if pin_local_build:
        tokens = _build_local_execstart_tokens(unit, root)
        _write_local_execstart_override(unit, tokens)

    LOG.info("正在应用 systemd 用户服务环境并重启: %s", unit)
    try:
        reload_proc = subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        if reload_proc.returncode != 0:
            LOG.error("systemd daemon-reload 失败，退出码: %s", reload_proc.returncode)
            return False
        restart_proc = subprocess.run(["systemctl", "--user", "restart", unit], check=False)
        if restart_proc.returncode != 0:
            LOG.error("重启服务失败: %s（退出码: %s）", unit, restart_proc.returncode)
            return False
    except OSError as exc:
        LOG.error("执行 systemctl 失败: %s", exc)
        return False

    LOG.info("已完成服务配置注入并重启：%s", unit)
    _warn_if_service_not_using_local_build(root, unit)
    return True


def _check_entry_context(lines: list[str], entry_path: str) -> tuple[bool, str]:
    """
    检查 entry.ts 锚点附近是否与预期一致，避免项目迭代导致注入错位。
    返回 (ok, message)。
    """
    anchor_stripped = ENTRY_ANCHOR.strip()
    for i, line in enumerate(lines):
        if line.rstrip() == ENTRY_ANCHOR or line.strip() == anchor_stripped:
            break
    else:
        return False, f"未找到锚点行: {ENTRY_ANCHOR!r}"

    # 锚点后若干行内应出现 profile.js 的 import（中间可有我们的注释+import）
    for j in range(i + 1, min(i + 1 + ENTRY_CONTEXT_LOOKAHEAD, len(lines))):
        stripped = lines[j].strip()
        if not stripped:
            continue
        if MARKER_IMPORT in stripped or ("./infra/proxy-fetch.js" in stripped):
            continue
        if "Must run before any fetch" in stripped:
            continue
        if ENTRY_NEXT_IMPORT_CONTAINS in stripped:
            LOG.debug("Context OK: anchor at line %s, profile import at line %s", i + 1, j + 1)
            return True, ""
        # 第一个非空、非本脚本注入的行不是 profile import → 结构可能已变
        snippet = "".join(lines[max(0, i) : min(len(lines), j + 3)])
        LOG.debug("锚点附近实际内容:\n%s", snippet)
        return False, (
            f"锚点后第 {j - i} 行应为 profile.js 的 import，实际为: {stripped[:60]!r}... "
            "（项目可能已迭代，请确认 entry.ts 结构）"
        )

    snippet = "".join(lines[max(0, i) : min(len(lines), i + ENTRY_CONTEXT_LOOKAHEAD + 1)])
    LOG.debug("锚点后未找到 profile import，实际内容:\n%s", snippet)
    return False, "锚点后未找到 profile.js 的 import，entry.ts 结构可能与预期不符"


def _entry_already_injected(content: str) -> bool:
    return MARKER_IMPORT in content


def _backup_paths(root: str) -> tuple[dict[str, str], str, str]:
    """返回 (entry_backup_paths, proxy_fetch_backup_path, proxy_fetch_missing_marker_path)。"""
    backup_dir = os.path.join(root, BACKUP_DIR_REL)
    entry_backups: dict[str, str] = {}
    for rel, backup_name in ENTRY_BACKUP_FILENAMES.items():
        entry_backups[os.path.join(root, rel)] = os.path.join(backup_dir, backup_name)
    return (
        entry_backups,
        os.path.join(backup_dir, PROXY_FETCH_BACKUP_FILENAME),
        os.path.join(backup_dir, PROXY_FETCH_MISSING_MARKER_FILENAME),
    )


def _has_any_entry_backup(root: str, entry_paths: list[str]) -> bool:
    entry_backups, _, _ = _backup_paths(root)
    for entry_path in entry_paths:
        backup_path = entry_backups.get(entry_path)
        if backup_path and os.path.isfile(backup_path):
            return True
    return False


def _ensure_backup_baseline(root: str, entry_paths: list[str], proxy_fetch_path: str) -> bool:
    """
    首次注入时建立“原始基线”备份。
    已存在备份时不会覆盖，避免把“已注入状态”覆盖成基线。
    """
    backup_dir = os.path.join(root, BACKUP_DIR_REL)
    entry_backups, proxy_backup_path, proxy_missing_marker_path = _backup_paths(root)
    try:
        os.makedirs(backup_dir, exist_ok=True)
        for entry_path in entry_paths:
            entry_backup_path = entry_backups.get(entry_path)
            if not entry_backup_path:
                continue
            if not os.path.isfile(entry_backup_path):
                shutil.copy2(entry_path, entry_backup_path)
                LOG.info("已创建备份: %s", entry_backup_path)
            else:
                LOG.debug("入口文件备份已存在，跳过: %s", entry_backup_path)

        if os.path.isfile(proxy_fetch_path):
            if not os.path.isfile(proxy_backup_path):
                shutil.copy2(proxy_fetch_path, proxy_backup_path)
                LOG.info("已创建备份: %s", proxy_backup_path)
            else:
                LOG.debug("proxy-fetch.ts 备份已存在，跳过: %s", proxy_backup_path)
        else:
            if not os.path.isfile(proxy_backup_path) and not os.path.isfile(proxy_missing_marker_path):
                with open(proxy_missing_marker_path, "w", encoding="utf-8") as f:
                    f.write("missing\n")
                LOG.debug("记录原始状态（proxy-fetch.ts 不存在）: %s", proxy_missing_marker_path)
        return True
    except OSError as exc:
        LOG.error("创建备份失败: %s", exc)
        return False


def _restore_from_backup(root: str, entry_paths: list[str], proxy_fetch_path: str) -> bool:
    """从备份恢复基线文件。成功恢复任一文件返回 True。"""
    entry_backups, proxy_backup_path, proxy_missing_marker_path = _backup_paths(root)
    restored = False
    try:
        for entry_path in entry_paths:
            entry_backup_path = entry_backups.get(entry_path)
            if entry_backup_path and os.path.isfile(entry_backup_path):
                shutil.copy2(entry_backup_path, entry_path)
                LOG.info("已恢复备份: %s -> %s", entry_backup_path, entry_path)
                restored = True

        if os.path.isfile(proxy_backup_path):
            os.makedirs(os.path.dirname(proxy_fetch_path), exist_ok=True)
            shutil.copy2(proxy_backup_path, proxy_fetch_path)
            LOG.info("已恢复备份: %s -> %s", proxy_backup_path, proxy_fetch_path)
            restored = True
        elif os.path.isfile(proxy_missing_marker_path):
            if os.path.isfile(proxy_fetch_path):
                os.remove(proxy_fetch_path)
                LOG.info("已恢复原始状态（删除注入文件）: %s", proxy_fetch_path)
                restored = True
        return restored
    except OSError as exc:
        LOG.error("恢复备份失败: %s", exc)
        return False


def _update_gitignore(root: str, add_proxy_file: bool) -> None:
    """维护 .gitignore：始终忽略备份目录；按需忽略 proxy-fetch.ts。"""
    path = os.path.join(root, ".gitignore")
    managed_entries = {GITIGNORE_PROXY_FETCH_ENTRY, GITIGNORE_BACKUP_DIR_ENTRY}
    desired_entries = [GITIGNORE_BACKUP_DIR_ENTRY]
    if add_proxy_file:
        desired_entries.append(GITIGNORE_PROXY_FETCH_ENTRY)

    existing_lines: list[str] = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            existing_lines = f.read().splitlines()

    cleaned_lines: list[str] = []
    i = 0
    while i < len(existing_lines):
        stripped = existing_lines[i].strip()
        if stripped == GITIGNORE_MARKER:
            i += 1
            while i < len(existing_lines) and existing_lines[i].strip() in managed_entries:
                i += 1
            continue
        if stripped in managed_entries:
            i += 1
            continue
        cleaned_lines.append(existing_lines[i])
        i += 1

    if cleaned_lines and cleaned_lines[-1].strip() != "":
        cleaned_lines.append("")
    cleaned_lines.append(GITIGNORE_MARKER)
    cleaned_lines.extend(desired_entries)
    new_content = "\n".join(cleaned_lines).rstrip() + "\n"

    old_content = ""
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            old_content = f.read()

    if new_content != old_content:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        LOG.info(
            "已更新 .gitignore（忽略备份目录%s）%s",
            GITIGNORE_BACKUP_DIR_ENTRY,
            f"，并忽略 {GITIGNORE_PROXY_FETCH_ENTRY}" if add_proxy_file else "，并移除 proxy-fetch 忽略项",
        )
    else:
        LOG.debug(".gitignore 已是最新，跳过更新")


def _inject_import_to_entry_file(entry_path: str, strict_context: bool) -> bool:
    with open(entry_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    content = "".join(lines)
    if _entry_already_injected(content):
        LOG.debug("入口文件已注入，跳过: %s", entry_path)
        return True

    if strict_context:
        ok, msg = _check_entry_context(lines, entry_path)
        if not ok:
            LOG.error("entry.ts 上下文校验未通过: %s", msg)
            LOG.debug("锚点行期望: %s", ENTRY_ANCHOR)
            LOG.debug("锚点后应出现包含 %s 的 import", ENTRY_NEXT_IMPORT_CONTAINS)
            return False

    if MARKER_AFTER in content:
        new_content = content.replace(
            MARKER_AFTER + "\n",
            MARKER_AFTER + "\n" + PROXY_IMPORT_LINES,
            1,
        )
    else:
        # 回退策略：在首个 import 前插入（保留 shebang）。
        insert_at = 1 if lines and lines[0].startswith("#!") else 0
        for i in range(insert_at, len(lines)):
            if lines[i].lstrip().startswith("import "):
                insert_at = i
                break
        new_lines = list(lines)
        new_lines.insert(insert_at, PROXY_IMPORT_LINES)
        new_content = "".join(new_lines)

    if new_content == content:
        LOG.error("入口文件注入替换未生效: %s", entry_path)
        return False
    with open(entry_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    LOG.info("已在入口文件中注入 proxy-fetch import: %s", entry_path)
    return True


def inject(root: str) -> bool:
    """注入 proxy-fetch：覆盖 index.ts/entry.ts，若已注入则先恢复备份再重注入。"""
    infra_dir = os.path.join(root, "src", "infra")
    proxy_fetch_path = os.path.join(root, "src", "infra", "proxy-fetch.ts")
    entry_paths = _resolve_entry_paths(root)

    LOG.info("注入目标根目录: %s", root)
    if not entry_paths:
        LOG.error("未找到可注入入口文件（src/index.ts 或 src/entry.ts）")
        return False
    for entry_path in entry_paths:
        LOG.info("找到入口文件: %s", entry_path)

    injected_detected = False
    for entry_path in entry_paths:
        with open(entry_path, "r", encoding="utf-8") as f:
            if _entry_already_injected(f.read()):
                injected_detected = True
                break

    if injected_detected:
        LOG.info("检测到已注入：先恢复备份，再重新注入。")
        if _has_any_entry_backup(root, entry_paths):
            if not _restore_from_backup(root, entry_paths, proxy_fetch_path):
                LOG.error("已注入状态下恢复备份失败，终止以避免错误覆盖。")
                return False
        else:
            LOG.warning("检测到已注入，但未找到备份；先执行一次移除，再继续重注入。")
            remove(root)

        for entry_path in entry_paths:
            with open(entry_path, "r", encoding="utf-8") as f:
                if _entry_already_injected(f.read()):
                    LOG.error("恢复后入口文件仍检测到注入标记，终止以避免重复注入: %s", entry_path)
                    return False

    if not _ensure_backup_baseline(root, entry_paths, proxy_fetch_path):
        return False

    # 1) 写入 proxy-fetch.ts
    os.makedirs(infra_dir, exist_ok=True)
    if not os.path.exists(proxy_fetch_path):
        LOG.info("创建 proxy-fetch.ts（不存在）: %s", proxy_fetch_path)
        with open(proxy_fetch_path, "w", encoding="utf-8") as f:
            f.write(PROXY_FETCH_TS)
    else:
        existing = open(proxy_fetch_path, encoding="utf-8").read()
        if existing != PROXY_FETCH_TS:
            LOG.info("更新 proxy-fetch.ts（内容与脚本不一致）: %s", proxy_fetch_path)
            with open(proxy_fetch_path, "w", encoding="utf-8") as f:
                f.write(PROXY_FETCH_TS)
        else:
            LOG.debug("proxy-fetch.ts 已存在且内容一致，跳过写入")

    # 2) 在入口文件执行注入：index.ts + entry.ts
    for entry_path in entry_paths:
        strict = entry_path.endswith(os.path.join("src", "entry.ts"))
        if not _inject_import_to_entry_file(entry_path, strict_context=strict):
            return False

    _update_gitignore(root, True)
    return True


def remove(root: str) -> bool:
    """移除注入：删除 proxy-fetch.ts 并从入口文件去掉 import。返回是否做了修改。"""
    proxy_fetch_path = os.path.join(root, "src", "infra", "proxy-fetch.ts")
    entry_paths = _resolve_entry_paths(root)

    LOG.info("移除注入，根目录: %s", root)

    restored = _restore_from_backup(root, entry_paths, proxy_fetch_path)
    if restored:
        LOG.info("已优先从备份恢复原始状态。")
        _update_gitignore(root, False)
        return True

    changed = False
    if os.path.isfile(proxy_fetch_path):
        os.remove(proxy_fetch_path)
        LOG.info("已删除: %s", proxy_fetch_path)
        changed = True
    else:
        LOG.debug("proxy-fetch.ts 不存在，跳过删除")

    for entry_path in entry_paths:
        with open(entry_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines: list[str] = []
        removed_what: list[str] = []
        for line in lines:
            if MARKER_IMPORT in line or ("./infra/proxy-fetch.js" in line and "import" in line):
                changed = True
                removed_what.append("import proxy-fetch.js")
                continue
            stripped = line.strip()
            if stripped.startswith("//") and (
                "Must run before any fetch" in line
                or "OPENCLAW_PROXY_GATEWAY_URL" in line
                or "X-Target-URL" in line
            ):
                changed = True
                removed_what.append("proxy-fetch 注释行")
                continue
            new_lines.append(line)

        if new_lines != lines:
            with open(entry_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            LOG.info("已从入口文件移除(%s): %s", entry_path, ", ".join(removed_what))
            changed = True

    if not changed:
        LOG.info("未发现 proxy-fetch 注入内容，无需移除")
    if changed:
        _update_gitignore(root, False)
    return changed


def _detect_build_command(root: str) -> list[str] | None:
    """根据锁文件和可执行程序检测 build 命令。"""
    package_json = os.path.join(root, "package.json")
    if not os.path.isfile(package_json):
        return None

    pnpm_lock = os.path.join(root, "pnpm-lock.yaml")
    yarn_lock = os.path.join(root, "yarn.lock")
    npm_lock = os.path.join(root, "package-lock.json")

    if os.path.isfile(pnpm_lock) and shutil.which("pnpm"):
        return ["pnpm", "build"]
    if os.path.isfile(yarn_lock) and shutil.which("yarn"):
        return ["yarn", "build"]
    if os.path.isfile(npm_lock) and shutil.which("npm"):
        return ["npm", "run", "build"]

    if shutil.which("pnpm"):
        return ["pnpm", "build"]
    if shutil.which("yarn"):
        return ["yarn", "build"]
    if shutil.which("npm"):
        return ["npm", "run", "build"]
    return None


def run_build(root: str) -> bool:
    """注入成功后自动执行构建。"""
    cmd = _detect_build_command(root)
    if not cmd:
        LOG.error("未检测到可用的构建命令（pnpm/yarn/npm），无法自动 build。")
        return False

    LOG.info("开始自动执行 build: %s (cwd=%s)", " ".join(cmd), root)
    try:
        proc = subprocess.run(cmd, cwd=root, check=False)
    except OSError as exc:
        LOG.error("执行 build 失败: %s", exc)
        return False

    if proc.returncode != 0:
        LOG.error("build 失败，退出码: %s", proc.returncode)
        return False

    LOG.info("build 完成。")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject or remove OpenClaw proxy-fetch (gateway proxy).")
    parser.add_argument(
        "targets",
        nargs="*",
        help=(
            "参数列表：可包含 OpenClaw 根目录 + 代理环境变量赋值。示例："
            " /root/openclaw OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2/__gw__/t/xxx"
        ),
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove the injection instead of applying it.",
    )
    parser.add_argument(
        "--pin-local-build",
        action="store_true",
        help=(
            "为 openclaw-gateway.service 生成 ExecStart 覆盖，"
            "将服务固定到 <openclaw_root>/dist/index.js（避免注入源码未被加载）"
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Verbose (use -v or -vv for debug)",
    )
    args = parser.parse_args()

    setup_log(args.verbose)

    try:
        root_arg, proxy_env_assignments = _parse_root_and_proxy_env_tokens(list(args.targets or []))
    except ValueError as exc:
        LOG.error("%s", exc)
        sys.exit(1)
    proxy_env_assignments = _normalize_proxy_env_assignments(proxy_env_assignments)

    root = find_openclaw_root(root_arg)
    if root is None:
        sys.exit(1)
    LOG.info("OpenClaw 根目录: %s", root)

    if args.remove:
        remove(root)
        sys.exit(0)
    ok = inject(root)
    if ok:
        if not run_build(root):
            LOG.error("注入成功，但自动 build 失败。请在 OpenClaw 根目录手动执行构建命令。")
            sys.exit(1)
        unit = _resolve_gateway_systemd_unit()
        if proxy_env_assignments or args.pin_local_build:
            applied = _configure_gateway_service(proxy_env_assignments, root, args.pin_local_build)
            if not applied:
                LOG.warning("未能自动注入服务环境，请手动配置并重启 OpenClaw gateway。")
            else:
                LOG.info("systemd 服务配置已更新，注入流程完成。")
        else:
            LOG.info("build完成。可直接在命令里附带网关环境变量自动注入，例如：")
            LOG.info(
                "python openclaw-inject-proxy-fetch.py %s %s=http://127.0.0.1:18080/v2/__gw__/t/XapJ3D0x",
                root,
                ENV_PROXY_GATEWAY_URL,
            )
            _warn_if_service_not_using_local_build(root, unit)
    else:
        LOG.error("注入未成功，请根据上述错误检查 entry.ts 或更新脚本适配当前项目结构。")
        sys.exit(1)


if __name__ == "__main__":
    main()

# 用法（仅支持通过环境变量指定网关 URL；原 URL 固定用 X-Target-URL 传给网关）：
#   export OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2
#   openclaw status
