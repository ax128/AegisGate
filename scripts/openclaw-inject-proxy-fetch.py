#!/usr/bin/env python3
"""
在 OpenClaw 源码中注入「安全网关代理」逻辑：
- 创建 src/infra/proxy-fetch.ts
- 在 src/entry.ts 最早处加入 import "./infra/proxy-fetch.js"
- 注入后：proxy-fetch.ts 写入 .gitignore，不参与提交；git 正常更新（pull）即可，更新完需手动再执行一次本脚本注入
- 注入成功后：自动执行一次前端构建（build）

用法：
  python openclaw-inject-proxy-fetch.py                  # 自动定位：同级/子目录/全局搜索名为 openclaw 的目录
  python openclaw-inject-proxy-fetch.py /path/to/openclaw   # 命令行指定根目录
  export OPENCLAW_ROOT=<OpenClaw 根目录路径>   # 或用环境变量指定（未找到或找到多个时提示）
  python openclaw-inject-proxy-fetch.py --remove
  python openclaw-inject-proxy-fetch.py -v / -vv
"""

import argparse
import logging
import os
import shutil
import subprocess
import sys

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
const TARGET_URL_HEADER = "X-Target-URL";

// Chat channels (Telegram, WhatsApp, Discord, Slack, Signal, etc.) are not included so they go through the gateway.
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
]);

const DEFAULT_DIRECT_SUFFIXES = [
  "googleapis.com",
  "amazonaws.com",
  "azure.com",
  "azurewebsites.net",
  "cloudfront.net",
];

function getDirectHosts(): { exact: Set<string>; suffixes: string[] } {
  const raw = process.env[ENV_PROXY_DIRECT_HOSTS]?.trim();
  if (raw) {
    const exact = new Set(
      raw
        .split(",")
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean),
    );
    return { exact, suffixes: [] };
  }
  return { exact: DEFAULT_DIRECT_HOSTS, suffixes: DEFAULT_DIRECT_SUFFIXES };
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

  if (!originalFetch) {
    return;
  }

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
      return originalFetch(input, init);
    }
    const requestOrigin = getRequestOrigin(trimmed);
    if (requestOrigin === proxyOrigin) {
      return originalFetch(input, init);
    }
    try {
      const hostname = new URL(trimmed).hostname;
      if (isDirectHost(hostname)) {
        return originalFetch(input, init);
      }
    } catch {
      /* ignore */
    }

    const newHeaders = new Headers(
      input instanceof Request ? (input as Request).headers : (init?.headers as HeadersInit),
    );
    newHeaders.set(TARGET_URL_HEADER, trimmed);

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
      return originalFetch(proxyUrl, initFromReq);
    }

    return originalFetch(proxyUrl, { ...init, headers: newHeaders });
  };

  (globalThis as unknown as { fetch: typeof fetch }).fetch = wrapped;
}

installProxyFetchIfConfigured();
'''

# entry.ts 中要在 node:url 之后插入的几行
PROXY_IMPORT_LINES = '''import "./infra/proxy-fetch.js";
'''

MARKER_IMPORT = 'import "./infra/proxy-fetch.js";'
MARKER_AFTER = 'import { fileURLToPath } from "node:url";'

# 环境变量：未找到或找到多个 openclaw 目录时，由用户指定目标路径
ENV_OPENCLAW_ROOT = "OPENCLAW_ROOT"

# 注入前上下文校验：锚点行及其后必须出现的特征（避免项目迭代后误注入）
ENTRY_ANCHOR = 'import { fileURLToPath } from "node:url";'
ENTRY_NEXT_IMPORT_CONTAINS = 'from "./cli/profile.js"'
ENTRY_CONTEXT_LOOKAHEAD = 6  # 锚点后最多看几行内要出现 profile.js import

# 全局搜索：目录名必须为 openclaw，且包含 src/entry.ts
OPENCLAW_DIR_NAMES = ("openclaw",)
# 搜索时跳过的目录名（避免进入 node_modules、.git 等）
SEARCH_SKIP_DIRS = frozenset({"node_modules", ".git", ".svn", ".hg", "dist", "build", "__pycache__"})

# 注入生成的文件，加入 .gitignore 以便 git 忽略
GITIGNORE_ENTRY = "src/infra/proxy-fetch.ts"


def _is_valid_openclaw_root(path: str) -> bool:
    """目录是否符合注入条件：存在 src/entry.ts。"""
    return os.path.isdir(path) and os.path.isfile(os.path.join(path, "src", "entry.ts"))


def _search_openclaw_dirs(start: str, max_depth: int = 5) -> list[str]:
    """
    从 start 目录起有限深度搜索：名为 openclaw 且含 src/entry.ts 的目录。
    返回绝对路径列表（可能为空或多个）。
    """
    start = os.path.abspath(start)
    if not os.path.isdir(start):
        return []
    results: list[str] = []

    def scan(dir_path: str, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = os.listdir(dir_path)
        except OSError:
            return
        for name in entries:
            if name in SEARCH_SKIP_DIRS:
                continue
            full = os.path.join(dir_path, name)
            if not os.path.isdir(full):
                continue
            if name in OPENCLAW_DIR_NAMES and _is_valid_openclaw_root(full):
                results.append(os.path.normpath(full))
            scan(full, depth + 1)

    scan(start, 0)
    return results


def find_openclaw_root(given: str | None) -> tuple[str | None, list[str] | None]:
    """
    确定 OpenClaw 源码根目录。
    返回 (root, multiple_found):
      - (path, None): 找到唯一目标，使用 path
      - (None, None): 未找到
      - (None, [path1, path2, ...]): 找到多个同名目录，需用户通过环境变量指定
    """
    # 1) 命令行参数
    if given:
        root = os.path.abspath(given)
        if _is_valid_openclaw_root(root):
            LOG.debug("使用命令行指定根目录: %s", root)
            return root, None
        LOG.debug("命令行指定路径不符合条件（需存在 src/entry.ts）: %s", root)
        return None, None

    # 2) 环境变量
    env_root = os.environ.get(ENV_OPENCLAW_ROOT)
    if env_root:
        root = os.path.abspath(env_root.strip())
        if _is_valid_openclaw_root(root):
            LOG.debug("使用环境变量 %s 指定根目录: %s", ENV_OPENCLAW_ROOT, root)
            return root, None
        LOG.debug("环境变量 %s 指向路径不符合条件: %s", ENV_OPENCLAW_ROOT, root)
        return None, None

    cwd = os.getcwd()

    # 3) 同级/子目录：当前目录即仓库根，或当前目录下 openclaw 子目录
    if _is_valid_openclaw_root(cwd):
        LOG.debug("使用当前目录为根目录: %s", cwd)
        return cwd, None
    for name in OPENCLAW_DIR_NAMES:
        cand = os.path.join(cwd, name)
        if _is_valid_openclaw_root(cand):
            LOG.debug("使用当前目录下子目录: %s", cand)
            return os.path.normpath(cand), None

    # 4) 全局搜索：从 cwd、父目录、上级目录递归搜索名为 openclaw 的目录
    search_roots: list[str] = []
    seen: set[str] = set()
    for cand in (cwd, os.path.dirname(cwd), os.path.dirname(os.path.dirname(cwd))):
        c = os.path.abspath(cand)
        if c and c not in seen and os.path.isdir(c):
            seen.add(c)
            search_roots.append(c)

    LOG.debug("同级/子目录未找到，开始递归搜索名为 openclaw 的目录，roots=%s", search_roots)
    all_found: list[str] = []
    for base in search_roots:
        sub = _search_openclaw_dirs(base)
        if sub:
            LOG.debug("在 %s 下找到: %s", base, sub)
            all_found.extend(sub)

    # 去重并保持顺序
    found: list[str] = []
    seen_found: set[str] = set()
    for p in all_found:
        if p not in seen_found:
            seen_found.add(p)
            found.append(p)

    if len(found) == 0:
        LOG.debug("未找到任何符合条件的 openclaw 目录")
        return None, None
    if len(found) == 1:
        LOG.debug("全局搜索到唯一目录: %s", found[0])
        return found[0], None
    LOG.debug("全局搜索到多个同名目录: %s", found)
    return None, found


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


def _update_gitignore(root: str, add: bool) -> None:
    """注入时把 proxy-fetch.ts 加入 .gitignore，移除时删掉该条。"""
    path = os.path.join(root, ".gitignore")
    if not os.path.isfile(path):
        if add:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# openclaw-inject-proxy-fetch\n{GITIGNORE_ENTRY}\n")
            LOG.info("已创建 .gitignore 并加入 %s", GITIGNORE_ENTRY)
        return
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    marker = "# openclaw-inject-proxy-fetch\n"
    entry_line = GITIGNORE_ENTRY + "\n"
    if add:
        if any(line.rstrip() == GITIGNORE_ENTRY for line in lines):
            LOG.debug(".gitignore 已包含 %s，跳过", GITIGNORE_ENTRY)
            return
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(marker)
        lines.append(entry_line)
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        LOG.info("已在 .gitignore 中加入 %s", GITIGNORE_ENTRY)
    else:
        new_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.rstrip()
            if stripped == "# openclaw-inject-proxy-fetch" and i + 1 < len(lines) and lines[i + 1].rstrip() == GITIGNORE_ENTRY:
                i += 2
                continue
            if stripped == GITIGNORE_ENTRY:
                i += 1
                continue
            new_lines.append(line)
            i += 1
        if new_lines != lines:
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            LOG.info("已从 .gitignore 移除 %s", GITIGNORE_ENTRY)


def inject(root: str) -> bool:
    """注入 proxy-fetch：创建文件并修改 entry.ts。返回是否成功（含已注入视为成功）。"""
    infra_dir = os.path.join(root, "src", "infra")
    proxy_fetch_path = os.path.join(root, "src", "infra", "proxy-fetch.ts")
    entry_path = os.path.join(root, "src", "entry.ts")

    LOG.info("注入目标根目录: %s", root)
    if not os.path.isfile(entry_path):
        LOG.error("未找到 entry.ts: %s", entry_path)
        return False
    LOG.info("找到 entry.ts: %s", entry_path)

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

    # 2) 读取 entry.ts 并做上下文校验
    with open(entry_path, "r", encoding="utf-8") as f:
        entry_lines = f.readlines()
    entry_content = "".join(entry_lines)

    if _entry_already_injected(entry_content):
        LOG.info("entry.ts 已包含 proxy-fetch 注入，无需重复注入")
        _update_gitignore(root, True)
        return True

    ok, msg = _check_entry_context(entry_lines, entry_path)
    if not ok:
        LOG.error("entry.ts 上下文校验未通过: %s", msg)
        LOG.debug("锚点行期望: %s", ENTRY_ANCHOR)
        LOG.debug("锚点后应出现包含 %s 的 import", ENTRY_NEXT_IMPORT_CONTAINS)
        return False

    # 3) 执行注入
    if MARKER_AFTER not in entry_content:
        LOG.error("entry.ts 中未找到锚点行，无法注入: %s", MARKER_AFTER)
        return False
    new_content = entry_content.replace(
        MARKER_AFTER + "\n",
        MARKER_AFTER + "\n" + PROXY_IMPORT_LINES,
        1,
    )
    if new_content == entry_content:
        LOG.error("替换未生效（锚点行格式可能不一致）")
        return False
    with open(entry_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    LOG.info("已在 entry.ts 中注入 proxy-fetch import")
    _update_gitignore(root, True)
    return True


def remove(root: str) -> bool:
    """移除注入：删除 proxy-fetch.ts 并从 entry.ts 去掉 import。返回是否做了修改。"""
    proxy_fetch_path = os.path.join(root, "src", "infra", "proxy-fetch.ts")
    entry_path = os.path.join(root, "src", "entry.ts")

    LOG.info("移除注入，根目录: %s", root)
    if not os.path.isfile(entry_path):
        LOG.error("未找到 entry.ts: %s", entry_path)
        return False

    changed = False
    if os.path.isfile(proxy_fetch_path):
        os.remove(proxy_fetch_path)
        LOG.info("已删除: %s", proxy_fetch_path)
        changed = True
    else:
        LOG.debug("proxy-fetch.ts 不存在，跳过删除")

    with open(entry_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    removed_what = []
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
        LOG.info("已从 entry.ts 移除: %s", ", ".join(removed_what))
        changed = True
    elif not changed:
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
        "openclaw_root",
        nargs="?",
        default=None,
        help="OpenClaw 根目录（可选；未指定时自动定位或使用环境变量 OPENCLAW_ROOT）",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove the injection instead of applying it.",
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

    root, multiple = find_openclaw_root(args.openclaw_root)
    if root is None and multiple is not None:
        LOG.error("找到多个名为 openclaw 的目录，无法自动选择：")
        for p in multiple:
            LOG.error("  - %s", p)
        LOG.error("请通过环境变量指定目标路径，例如：")
        LOG.error("  export %s=<上述其中一个路径>", ENV_OPENCLAW_ROOT)
        LOG.error("  python openclaw-inject-proxy-fetch.py")
        sys.exit(1)
    if root is None:
        LOG.error("未找到符合注入条件的 OpenClaw 目录（需包含 src/entry.ts）。")
        LOG.error("请任选其一：")
        LOG.error("  1) 在 OpenClaw 仓库根目录下执行本脚本；")
        LOG.error("  2) 或传入路径：python openclaw-inject-proxy-fetch.py <路径>；")
        LOG.error("  3) 或设置环境变量：export %s=<OpenClaw 根目录路径>", ENV_OPENCLAW_ROOT)
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
        LOG.info("注入并 build 完成。运行 openclaw 时设置 OPENCLAW_PROXY_GATEWAY_URL 即可走网关。")
    else:
        LOG.error("注入未成功，请根据上述错误检查 entry.ts 或更新脚本适配当前项目结构。")
        sys.exit(1)


if __name__ == "__main__":
    main()

# 用法（仅支持通过环境变量指定网关 URL；原 URL 固定用 X-Target-URL 传给网关）：
#   export OPENCLAW_PROXY_GATEWAY_URL=http://127.0.0.1:18080/v2
#   openclaw status
