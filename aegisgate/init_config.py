"""
Generate the required config files on first start: when the runtime config directory has no .env,
or the policy directory has no policy YAML, they are copied from the built-in defaults, so both a
Docker mount and a plain local start work.
Call it during application startup, or run it standalone: python -m aegisgate.init_config
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import yaml

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

# Policy YAML files that must exist (missing ones are copied from the built-in defaults)
_POLICY_YAML = ("default.yaml", "permissive.yaml", "strict.yaml")
_SECURITY_RULES_YAML = "security_filters.yaml"
_REQUIRED_YAML = (*_POLICY_YAML, _SECURITY_RULES_YAML)
_SMUGGLING_PATTERN_SECTIONS: tuple[tuple[str, ...], ...] = (
    ("anomaly_detector", "command_patterns"),
    ("sanitizer", "command_patterns"),
    ("sanitizer", "force_block_command_patterns"),
)
_SMUGGLING_ID_PREFIXES = ("http_smuggling_", "web_http_smuggling_")
# Built-in policy directory (inside the package)
_PACKAGE_RULES_DIR = Path(__file__).resolve().parent / "policies" / "rules"
# Project root directory (e.g. /app)
_APP_ROOT_DIR = Path(__file__).resolve().parent.parent
# Read-only bootstrap directory inside the Docker image (never shadowed by a rules mount)
_BOOTSTRAP_RULES_DIR = _APP_ROOT_DIR / "bootstrap" / "rules"
# Name of the bundled .env example
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
    if os.environ.get("AEGIS_CONFIG_DIR"):
        return Path(os.environ["AEGIS_CONFIG_DIR"]).resolve()
    return _resolve_path(settings.security_rules_path).parent


def _runtime_env_dir() -> Path:
    return (Path.cwd() / "config").resolve()


def _env_example_path() -> Path | None:
    """Path to the bundled .env.example: first cwd/config, then the package parent config (local development)."""
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

    # As soon as PolicyEngine finds no default.yaml in the mounted directory, it falls back to the
    # bootstrap directory as a whole.
    if _file_ready(rules_dir / "default.yaml"):
        for name in _POLICY_YAML:
            if not _file_ready(rules_dir / name):
                missing.append(name)
    elif not _bootstrap_has_all_policy_rules():
        missing.extend(
            name for name in _POLICY_YAML if not _file_ready(rules_dir / name)
        )

    # security_filters.yaml is parsed on its own; when missing it may fall back to bootstrap alone.
    if (
        not _file_ready(rules_dir / _SECURITY_RULES_YAML)
        and not _bootstrap_has_security_rules()
    ):
        missing.append(_SECURITY_RULES_YAML)

    if missing:
        raise RuntimeError(
            f"missing required security policy files in {rules_dir}: {', '.join(missing)}"
        )


def _section_items(rules: dict, keys: tuple[str, ...]) -> list:
    node: object = rules
    for key in keys:
        if not isinstance(node, dict):
            return []
        node = node.get(key)
    return node if isinstance(node, list) else []


def _smuggling_regex_index(rules: dict) -> dict[tuple[tuple[str, ...], str], str]:
    index: dict[tuple[tuple[str, ...], str], str] = {}
    for keys in _SMUGGLING_PATTERN_SECTIONS:
        for item in _section_items(rules, keys):
            if not isinstance(item, dict):
                continue
            pattern_id = str(item.get("id") or "")
            regex = item.get("regex")
            if not pattern_id.startswith(_SMUGGLING_ID_PREFIXES):
                continue
            if not isinstance(regex, str) or not regex:
                continue
            index[(keys, pattern_id)] = regex
    return index


def _is_package_rules_file(path: Path) -> bool:
    package_copy = (_PACKAGE_RULES_DIR / _SECURITY_RULES_YAML).resolve()
    try:
        return path.resolve() == package_copy
    except OSError:
        return False


def migrate_http_smuggling_regex(config_dir: Path | None = None) -> list[str]:
    """Point-update http_smuggling_* regexes in the runtime YAML copy.

    Existing Docker mounts keep a user-edited security_filters.yaml that
    ``ensure_config_dir`` will not overwrite. Only matching rule ids in the
    three command_patterns sections are rewritten; everything else is kept.
    Returns the ids that actually changed.
    """
    rules_dir = config_dir or _config_dir()
    dst = rules_dir / _SECURITY_RULES_YAML
    if not _file_ready(dst) or _is_package_rules_file(dst):
        return []

    src_dir = _rules_source_dir() or _PACKAGE_RULES_DIR
    src = src_dir / _SECURITY_RULES_YAML
    if not _file_ready(src):
        src = _PACKAGE_RULES_DIR / _SECURITY_RULES_YAML
    if not _file_ready(src):
        return []

    try:
        desired = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
        current = yaml.safe_load(dst.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("init_config: smuggling regex migrate skipped parse error=%s", exc)
        return []
    if not isinstance(desired, dict) or not isinstance(current, dict):
        return []

    desired_index = _smuggling_regex_index(desired)
    changed: list[str] = []
    for keys in _SMUGGLING_PATTERN_SECTIONS:
        for item in _section_items(current, keys):
            if not isinstance(item, dict):
                continue
            pattern_id = str(item.get("id") or "")
            new_regex = desired_index.get((keys, pattern_id))
            if new_regex is None:
                continue
            if item.get("regex") == new_regex:
                continue
            item["regex"] = new_regex
            changed.append(f"{'.'.join(keys)}:{pattern_id}")

    if not changed:
        return []

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = dst.with_name(f"{dst.name}.bak-{timestamp}")
    try:
        shutil.copy2(dst, backup)
    except OSError as exc:
        logger.warning("init_config: could not backup %s: %s", dst, exc)
        return []

    try:
        tmp_path = dst.with_name(f"{dst.name}.migrate-tmp")
        tmp_path.write_text(
            yaml.dump(current, allow_unicode=True, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        tmp_path.replace(dst)
    except OSError as exc:
        logger.warning("init_config: smuggling regex migrate write failed path=%s error=%s", dst, exc)
        return []

    logger.warning(
        "init_config: migrated http smuggling regex ids=%s backup=%s",
        changed,
        backup,
    )
    return changed


def ensure_config_dir() -> None:
    """
    Copy the built-in defaults into the config/policy directory for any required file that is
    missing, never overwriting an existing file.
    A Docker mount that starts out empty is populated automatically, as is a first local start.
    """
    config_dir = _config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)

    # 1. Policy YAML: copied from aegisgate/policies/rules inside the package
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
        try:
            migrate_http_smuggling_regex(config_dir)
        except Exception as exc:  # pragma: no cover - operational safeguard
            logger.warning("init_config: smuggling regex migrate failed: %s", exc)
    else:
        logger.warning(
            "init_config: no bootstrap rules source found candidates=%s,%s",
            _BOOTSTRAP_RULES_DIR,
            _PACKAGE_RULES_DIR,
        )

    env_dir = _runtime_env_dir()
    env_dst = env_dir / ".env"
    if not env_dst.exists() or env_dst.stat().st_size == 0:
        env_src = _env_example_path()
        if env_src and env_src.is_file():
            try:
                env_dir.mkdir(parents=True, exist_ok=True)
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
            conn.execute(
                "CREATE TABLE IF NOT EXISTS __aegisgate_write_probe__(id INTEGER)"
            )
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
    """Entry point for command-line or one-off container runs."""
    ensure_config_dir()
    ensure_runtime_storage_paths()
    strict = os.environ.get("AEGIS_INIT_STRICT", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
    if strict:
        assert_security_bootstrap_ready()
        logger.info("init_config: security bootstrap ready")


if __name__ == "__main__":
    main()
