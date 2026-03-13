"""
首次启动时自动生成必须的配置文件：若 config 目录（或策略目录）缺少 .env 与策略 YAML，
则从内置默认复制，保证 Docker 挂载或本地直接启动都能跑通。
可在应用 startup 时调用，也可单独执行：python -m aegisgate.init_config
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

# 必须存在的策略 YAML（少则从内置复制）
_POLICY_YAML = ("default.yaml", "permissive.yaml", "strict.yaml")
_SECURITY_RULES_YAML = "security_filters.yaml"
_REQUIRED_YAML = (*_POLICY_YAML, _SECURITY_RULES_YAML)
# 内置策略目录（包内）
_PACKAGE_RULES_DIR = Path(__file__).resolve().parent / "policies" / "rules"
# 项目根目录（如 /app）
_APP_ROOT_DIR = Path(__file__).resolve().parent.parent
# Docker 镜像内的只读 bootstrap 目录（避免被 rules 挂载覆盖）
_BOOTSTRAP_RULES_DIR = _APP_ROOT_DIR / "bootstrap" / "rules"
# 内置 .env 示例名
_ENV_EXAMPLE = ".env.example"
_RUNTIME_FALLBACK_DIR = Path("/tmp") / "aegisgate"


def _resolve_path(path_str: str) -> Path:
    path = Path(path_str)
    if path.is_absolute():
        return path
    candidates = [Path.cwd() / path, _APP_ROOT_DIR / path]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[-1].resolve()


def _config_dir() -> Path:
    """策略/config 目录：环境变量 AEGIS_CONFIG_DIR 或 security_rules_path 的父目录。"""
    if os.environ.get("AEGIS_CONFIG_DIR"):
        return Path(os.environ["AEGIS_CONFIG_DIR"]).resolve()
    return _resolve_path(settings.security_rules_path).parent


def _env_example_path() -> Path | None:
    """内置 .env.example 路径：先 cwd/config，再包上级 config（本地开发）。"""
    cwd = Path.cwd()
    for base in (cwd, cwd.parent, Path(__file__).resolve().parent.parent):
        p = base / "config" / _ENV_EXAMPLE
        if p.is_file():
            return p
    return None


def _rules_source_dir() -> Path | None:
    configured = os.environ.get("AEGIS_BOOTSTRAP_RULES_DIR", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).resolve())
    candidates.extend((_BOOTSTRAP_RULES_DIR, _PACKAGE_RULES_DIR))
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        has_required = any((candidate / name).is_file() for name in _REQUIRED_YAML)
        if has_required:
            return candidate
    return None


def missing_required_rules(config_dir: Path | None = None) -> list[str]:
    rules_dir = config_dir or _config_dir()
    missing: list[str] = []
    for name in _REQUIRED_YAML:
        p = rules_dir / name
        if not p.exists() or p.stat().st_size == 0:
            missing.append(name)
    return missing


def _file_ready(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def _bootstrap_has_all_policy_rules() -> bool:
    src = _rules_source_dir()
    if src is None:
        return False
    return all(_file_ready(src / name) for name in _POLICY_YAML)


def _bootstrap_has_security_rules() -> bool:
    src = _rules_source_dir()
    if src is None:
        return False
    return _file_ready(src / _SECURITY_RULES_YAML)


def assert_security_bootstrap_ready(config_dir: Path | None = None) -> None:
    rules_dir = config_dir or _config_dir()
    missing: list[str] = []

    # PolicyEngine 只要发现挂载目录没有 default.yaml，就会整体回退到 bootstrap 目录。
    if _file_ready(rules_dir / "default.yaml"):
        for name in _POLICY_YAML:
            if not _file_ready(rules_dir / name):
                missing.append(name)
    elif not _bootstrap_has_all_policy_rules():
        missing.extend(name for name in _POLICY_YAML if not _file_ready(rules_dir / name))

    # security_filters.yaml 单文件独立解析；缺失时允许单独回退到 bootstrap。
    if not _file_ready(rules_dir / _SECURITY_RULES_YAML) and not _bootstrap_has_security_rules():
        missing.append(_SECURITY_RULES_YAML)

    if missing:
        raise RuntimeError(f"missing required security policy files in {rules_dir}: {', '.join(missing)}")


def ensure_config_dir() -> None:
    """
    若 config/策略 目录缺少必须文件，则从内置默认复制，不覆盖已有文件。
    Docker 下挂载的目录首次为空时会被自动填充；本地首次启动同理。
    """
    config_dir = _config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)

    # 1. 策略 YAML：从包内 aegisgate/policies/rules 复制
    src_dir = _rules_source_dir()
    if src_dir is not None:
        for name in _REQUIRED_YAML:
            src = src_dir / name
            dst = config_dir / name
            if not src.is_file():
                continue
            if not dst.exists() or dst.stat().st_size == 0:
                try:
                    shutil.copy2(src, dst)
                    logger.info("init_config: created %s from default", dst)
                except OSError as e:
                    logger.warning("init_config: could not write %s: %s", dst, e)
    else:
        logger.warning(
            "init_config: no bootstrap rules source found candidates=%s,%s",
            _BOOTSTRAP_RULES_DIR,
            _PACKAGE_RULES_DIR,
        )

    # 2. .env：从 config/.env.example 复制（Docker 构建时需 COPY config/.env.example 到镜像）
    env_dst = config_dir / ".env"
    if not env_dst.exists() or env_dst.stat().st_size == 0:
        env_src = _env_example_path()
        if env_src and env_src.is_file():
            try:
                shutil.copy2(env_src, env_dst)
                logger.info("init_config: created %s from %s", env_dst, env_src.name)
            except OSError as e:
                logger.warning("init_config: could not write %s: %s", env_dst, e)
        else:
            logger.debug("init_config: no .env.example found, skip creating .env")


def _can_append_file(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8"):
            pass
        return True
    except OSError:
        return False


def _can_use_sqlite_path(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path, timeout=1.0) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS __aegisgate_write_probe__(id INTEGER)")
            conn.execute("DROP TABLE IF EXISTS __aegisgate_write_probe__")
            conn.commit()
        return True
    except (sqlite3.Error, OSError):
        return False


def ensure_runtime_storage_paths() -> None:
    """Ensure runtime-write paths are usable; fallback to /tmp when needed."""
    fallback_dir = _RUNTIME_FALLBACK_DIR
    fallback_dir.mkdir(parents=True, exist_ok=True)

    backend = (settings.storage_backend or "sqlite").strip().lower()
    if backend in {"", "sqlite"}:
        configured_db = Path(settings.sqlite_db_path)
        if not _can_use_sqlite_path(configured_db):
            fallback_db = fallback_dir / "aegisgate.db"
            if not _can_use_sqlite_path(fallback_db):
                raise RuntimeError(
                    "sqlite storage path is not writable and fallback also failed: "
                    f"configured={configured_db} fallback={fallback_db}"
                )
            settings.sqlite_db_path = str(fallback_db)
            logger.warning(
                "init_config: sqlite path not writable, switched to fallback configured=%s fallback=%s",
                configured_db,
                fallback_db,
            )

    audit_path = (settings.audit_log_path or "").strip()
    if audit_path:
        configured_audit = Path(audit_path)
        if not _can_append_file(configured_audit):
            fallback_audit = fallback_dir / "audit.jsonl"
            if _can_append_file(fallback_audit):
                settings.audit_log_path = str(fallback_audit)
                logger.warning(
                    "init_config: audit path not writable, switched to fallback configured=%s fallback=%s",
                    configured_audit,
                    fallback_audit,
                )
            else:
                settings.audit_log_path = ""
                logger.warning(
                    "init_config: audit path not writable and fallback failed, disable audit file configured=%s fallback=%s",
                    configured_audit,
                    fallback_audit,
                )


def main() -> None:
    """命令行或 one-off 容器执行时调用。"""
    ensure_config_dir()
    ensure_runtime_storage_paths()
    strict = os.environ.get("AEGIS_INIT_STRICT", "true").strip().lower() not in {"0", "false", "no", "off"}
    if strict:
        assert_security_bootstrap_ready()
        logger.info("init_config: security bootstrap ready")


if __name__ == "__main__":
    main()
