#!/usr/bin/env python3
"""Cross-platform local launcher for AegisGate."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import sqlite3
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VENV_DIR = ROOT / ".venv"
LOG_DIR = ROOT / "logs"
RUN_DIR = LOG_DIR / "launcher"
PID_FILE = RUN_DIR / "gateway.pid"
STATE_FILE = RUN_DIR / "gateway_state.json"
OUT_LOG = RUN_DIR / "gateway.stdout.log"
ERR_LOG = RUN_DIR / "gateway.stderr.log"
ENV_FILE = ROOT / "config" / ".env"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18080
DEFAULT_UI_PATH = "/__ui__/login"


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    command = args.command or "start"
    return int(COMMANDS[command](args) or 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AegisGate local launcher")
    sub = parser.add_subparsers(dest="command")

    start = sub.add_parser("start", help="Install if needed and start gateway in background")
    add_common_start_args(start)

    install = sub.add_parser("install", help="Create venv and install project")
    install.add_argument("--python", dest="python_bin", default="", help="Python executable override")
    install.add_argument("--extras", default="", help="Optional extras, e.g. semantic,redis")
    install.add_argument("--force", action="store_true", help="Reinstall even if venv exists")

    init = sub.add_parser("init", help="Bootstrap local config files")
    init.add_argument("--python", dest="python_bin", default="", help="Python executable override")

    stop = sub.add_parser("stop", help="Stop background gateway")
    stop.add_argument("--graceful-seconds", type=float, default=8.0, help="Wait before force kill")

    restart = sub.add_parser("restart", help="Restart background gateway")
    add_common_start_args(restart)
    restart.add_argument("--graceful-seconds", type=float, default=8.0, help="Wait before force kill")

    sub.add_parser("status", help="Show gateway status")

    logs = sub.add_parser("logs", help="Print launcher log file paths")
    logs.add_argument("--tail", type=int, default=0, help="Print last N lines from stdout log")

    ui = sub.add_parser("open-ui", help="Open local UI in browser")
    ui.add_argument("--host", default="", help="UI host override")
    ui.add_argument("--port", type=int, default=0, help="UI port override")
    ui.add_argument("--path", default=DEFAULT_UI_PATH, help="UI path")

    return parser


def add_common_start_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="", help="Gateway host override")
    parser.add_argument("--port", type=int, default=0, help="Gateway port override")
    parser.add_argument("--python", dest="python_bin", default="", help="Python executable override")
    parser.add_argument("--extras", default="", help="Optional extras, e.g. semantic,redis")
    parser.add_argument("--foreground", action="store_true", help="Run in foreground")
    parser.add_argument("--skip-install", action="store_true", help="Skip venv install step")
    parser.add_argument("--open-ui", action="store_true", help="Open local UI after start")


def cmd_install(args: argparse.Namespace) -> int:
    ensure_runtime_dirs()
    python_bin = resolve_python(args.python_bin)
    ensure_venv(python_bin, force=args.force)
    install_project(args.extras)
    print("Install complete")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    ensure_runtime_dirs()
    python_bin = resolve_python(args.python_bin)
    run_subprocess([python_bin, "-m", "aegisgate.init_config"], env=os.environ.copy())
    print(f"Config ready: {ENV_FILE}")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    ensure_runtime_dirs()
    if is_running():
        print_status()
        return 0
    if not args.skip_install:
        python_bin = resolve_python(args.python_bin)
        if not venv_ready():
            ensure_venv(python_bin)
            install_project(args.extras)
        elif args.extras:
            install_project(args.extras)
    run_init()
    host, port = resolve_runtime_host_port(args.host, args.port)
    env = build_runtime_env(host, port)
    cmd = [str(venv_python()), "-m", "uvicorn", "aegisgate.core.gateway:app", "--host", host, "--port", str(port)]
    if args.foreground:
        print(f"Starting foreground gateway on http://{display_host(host)}:{port}")
        return subprocess.call(cmd, cwd=str(ROOT), env=env)
    start_background(cmd, env, host, port)
    try:
        wait_until_ready(host, port)
    except SystemExit:
        if not is_running():
            cleanup_runtime_files()
        raise
    print(f"AegisGate started in background: http://{display_host(host)}:{port}")
    print(f"UI: http://{display_host(host)}:{port}{DEFAULT_UI_PATH}")
    print(f"Logs: {OUT_LOG} | {ERR_LOG}")
    if args.open_ui:
        webbrowser.open(f"http://{display_host(host)}:{port}{DEFAULT_UI_PATH}")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    if not PID_FILE.exists():
        print("Gateway is not running")
        return 0
    pid = read_pid()
    if pid is None or not process_exists(pid):
        cleanup_runtime_files()
        print("Removed stale launcher state")
        return 0
    stop_process(pid, args.graceful_seconds)
    cleanup_runtime_files()
    print("Gateway stopped")
    return 0


def cmd_restart(args: argparse.Namespace) -> int:
    cmd_stop(argparse.Namespace(graceful_seconds=args.graceful_seconds))
    return cmd_start(args)


def cmd_status(_args: argparse.Namespace) -> int:
    print_status()
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    ensure_runtime_dirs()
    print(f"stdout: {OUT_LOG}")
    print(f"stderr: {ERR_LOG}")
    print(f"pid:    {PID_FILE}")
    if args.tail > 0 and OUT_LOG.exists():
        lines = OUT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-args.tail :]:
            print(line)
    return 0


def cmd_open_ui(args: argparse.Namespace) -> int:
    host, port = resolve_runtime_host_port(args.host, args.port)
    url = f"http://{display_host(host)}:{port}{args.path}"
    webbrowser.open(url)
    print(f"Opened {url}")
    return 0


COMMANDS = {
    "start": cmd_start,
    "install": cmd_install,
    "init": cmd_init,
    "stop": cmd_stop,
    "restart": cmd_restart,
    "status": cmd_status,
    "logs": cmd_logs,
    "open-ui": cmd_open_ui,
}


def resolve_python(override: str) -> str:
    return override or sys.executable


def ensure_runtime_dirs() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    RUN_DIR.mkdir(parents=True, exist_ok=True)


def ensure_venv(python_bin: str, force: bool = False) -> None:
    if force and VENV_DIR.exists():
        raise SystemExit("--force reinstall requires manual removal of .venv for safety")
    if VENV_DIR.exists() and venv_python().exists():
        return
    print(f"Creating virtualenv: {VENV_DIR}")
    run_subprocess([python_bin, "-m", "venv", str(VENV_DIR)])


def venv_ready() -> bool:
    return VENV_DIR.exists() and venv_python().exists()


def venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def install_project(extras: str) -> None:
    python_bin = str(venv_python())
    run_subprocess([python_bin, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    target = "."
    normalized = normalize_extras(extras)
    if normalized:
        target = f".[{normalized}]"
    run_subprocess([python_bin, "-m", "pip", "install", "-e", target])


def normalize_extras(raw: str) -> str:
    extras = [part.strip() for part in raw.split(",") if part.strip()]
    return ",".join(dict.fromkeys(extras))


def run_init() -> None:
    run_subprocess([str(venv_python()), "-m", "aegisgate.init_config"], env=os.environ.copy())


def run_subprocess(cmd: list[str], env: dict[str, str] | None = None) -> None:
    print("+", " ".join(shlex.quote(part) for part in cmd))
    subprocess.run(cmd, cwd=str(ROOT), env=env, check=True)


def parse_env_file() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_FILE.exists():
        return values
    for raw_line in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = raw_line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def resolve_runtime_host_port(host_override: str, port_override: int) -> tuple[str, int]:
    env_values = parse_env_file()
    host = host_override or env_values.get("AEGIS_HOST") or DEFAULT_HOST
    port_raw = port_override or int(env_values.get("AEGIS_PORT") or DEFAULT_PORT)
    return host, int(port_raw)


def build_runtime_env(host: str, port: int) -> dict[str, str]:
    env = os.environ.copy()
    env_values = parse_env_file()
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("AEGIS_HOST", host)
    env.setdefault("AEGIS_PORT", str(port))
    sqlite_override = resolve_sqlite_runtime_override(env, env_values)
    if sqlite_override:
        env["AEGIS_SQLITE_DB_PATH"] = sqlite_override
        print(f"Using launcher sqlite path: {sqlite_override}")
    return env


def start_background(cmd: list[str], env: dict[str, str], host: str, port: int) -> None:
    ensure_runtime_dirs()
    out_handle = OUT_LOG.open("a", encoding="utf-8")
    err_handle = ERR_LOG.open("a", encoding="utf-8")
    creationflags = 0
    popen_kwargs: dict[str, Any] = {
        "cwd": str(ROOT),
        "env": env,
        "stdout": out_handle,
        "stderr": err_handle,
        "stdin": subprocess.DEVNULL,
    }
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
        popen_kwargs["creationflags"] = creationflags
    else:
        popen_kwargs["start_new_session"] = True
    process = subprocess.Popen(cmd, **popen_kwargs)
    out_handle.close()
    err_handle.close()
    write_state(process.pid, cmd, host, port)


def write_state(pid: int, cmd: list[str], host: str, port: int) -> None:
    PID_FILE.write_text(str(pid), encoding="utf-8")
    STATE_FILE.write_text(
        json.dumps(
            {
                "pid": pid,
                "cmd": cmd,
                "host": host,
                "port": port,
                "started_at": int(time.time()),
                "stdout_log": str(OUT_LOG),
                "stderr_log": str(ERR_LOG),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def wait_until_ready(host: str, port: int, timeout_seconds: float = 20.0) -> None:
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout_seconds
    health_host = runtime_connect_host(host)
    url = f"http://{health_host}:{port}/health"
    while time.time() < deadline:
        pid = read_pid()
        if pid is not None and not process_exists(pid):
            break
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.5)
    raise SystemExit(f"Gateway did not become ready in time. Check logs: {ERR_LOG}")


def read_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except ValueError:
        return None


def process_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def is_running() -> bool:
    pid = read_pid()
    return pid is not None and process_exists(pid)


def stop_process(pid: int, graceful_seconds: float) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + graceful_seconds
        while time.time() < deadline and process_exists(pid):
            time.sleep(0.3)
        if process_exists(pid):
            subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.time() + graceful_seconds
    while time.time() < deadline:
        if not process_exists(pid):
            return
        time.sleep(0.3)
    if process_exists(pid):
        os.kill(pid, signal.SIGKILL)


def cleanup_runtime_files() -> None:
    for path in (PID_FILE, STATE_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def print_status() -> None:
    pid = read_pid()
    if pid is None:
        print("AegisGate is not running")
        print(f"UI: http://{DEFAULT_HOST}:{DEFAULT_PORT}{DEFAULT_UI_PATH}")
        return
    if not process_exists(pid):
        print("AegisGate is not running (stale pid file found)")
        print(f"Logs: {OUT_LOG} | {ERR_LOG}")
        return
    state = read_state()
    host = state.get("host", DEFAULT_HOST)
    port = state.get("port", DEFAULT_PORT)
    print(f"AegisGate is running (pid={pid})")
    print(f"Gateway: http://{display_host(host)}:{port}")
    print(f"UI:      http://{display_host(host)}:{port}{DEFAULT_UI_PATH}")
    print(f"Logs:    {OUT_LOG} | {ERR_LOG}")


def read_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def runtime_connect_host(host: str) -> str:
    if host in {"0.0.0.0", "::", "[::]"}:
        return "127.0.0.1"
    return host


def display_host(host: str) -> str:
    return runtime_connect_host(host)


def resolve_sqlite_runtime_override(env: dict[str, str], env_values: dict[str, str]) -> str | None:
    storage_backend = (env.get("AEGIS_STORAGE_BACKEND") or env_values.get("AEGIS_STORAGE_BACKEND") or "sqlite").strip().lower()
    if storage_backend != "sqlite":
        return None
    configured = (env.get("AEGIS_SQLITE_DB_PATH") or env_values.get("AEGIS_SQLITE_DB_PATH") or "logs/aegisgate.db").strip()
    if not configured:
        return None
    target = Path(configured).expanduser()
    if not target.is_absolute():
        target = ROOT / target
    if sqlite_path_usable(target):
        return None
    fallback = launcher_state_dir() / "aegisgate.db"
    if not sqlite_path_usable(fallback):
        raise SystemExit(f"SQLite path is not writable: {target} and fallback failed: {fallback}")
    return str(fallback)


def launcher_state_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or Path.home() / "AppData" / "Local")
        path = base / "AegisGate"
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / "AegisGate"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
        path = base / "aegisgate"
    path.mkdir(parents=True, exist_ok=True)
    return path


def sqlite_path_usable(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        finally:
            conn.close()
        return True
    except sqlite3.Error:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
