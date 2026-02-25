"""
首次启动时自动生成必须的配置文件：若 config 目录（或策略目录）缺少 .env 与策略 YAML，
则从内置默认复制，保证 Docker 挂载或本地直接启动都能跑通。
可在应用 startup 时调用，也可单独执行：python -m aegisgate.init_config
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

# 必须存在的策略 YAML（少则从内置复制）
_REQUIRED_YAML = ("default.yaml", "security_filters.yaml", "permissive.yaml", "strict.yaml")
# 内置策略目录（包内）
_PACKAGE_RULES_DIR = Path(__file__).resolve().parent / "policies" / "rules"
# 内置 .env 示例名
_ENV_EXAMPLE = ".env.example"


def _config_dir() -> Path:
    """策略/config 目录：环境变量 AEGIS_CONFIG_DIR 或 security_rules_path 的父目录。"""
    if os.environ.get("AEGIS_CONFIG_DIR"):
        return Path(os.environ["AEGIS_CONFIG_DIR"]).resolve()
    return Path(settings.security_rules_path).resolve().parent


def _env_example_path() -> Path | None:
    """内置 .env.example 路径：先 cwd/config，再包上级 config（本地开发）。"""
    cwd = Path.cwd()
    for base in (cwd, cwd.parent, Path(__file__).resolve().parent.parent):
        p = base / "config" / _ENV_EXAMPLE
        if p.is_file():
            return p
    return None


def ensure_config_dir() -> None:
    """
    若 config/策略 目录缺少必须文件，则从内置默认复制，不覆盖已有文件。
    Docker 下挂载的目录首次为空时会被自动填充；本地首次启动同理。
    """
    config_dir = _config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)

    # 1. 策略 YAML：从包内 aegisgate/policies/rules 复制
    if _PACKAGE_RULES_DIR.is_dir():
        for name in _REQUIRED_YAML:
            src = _PACKAGE_RULES_DIR / name
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
        logger.debug("init_config: package rules dir not found path=%s", _PACKAGE_RULES_DIR)

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


def main() -> None:
    """命令行或 one-off 容器执行时调用。"""
    ensure_config_dir()


if __name__ == "__main__":
    main()
