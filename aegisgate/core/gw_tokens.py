"""
网关 Token 映射：注册口子返回短 token，请求时通过 /v1/__gw__/t/{token}/... 解析上游。
映射表存 config/gw_tokens.json，启动时加载，支持手动编辑。
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import tempfile
import threading
from pathlib import Path
from typing import Any

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys

# 内存映射：token -> {"upstream_base": str, "whitelist_key": list[str]}
_tokens: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_TOKEN_LEN = 24
_GW_TOKENS_KEY = "tokens"
_WHITELIST_UNSET = object()


def _generate_alnum_token(length: int) -> str:
    """生成纯字母数字 token（a-zA-Z0-9），不含 - _ 等符号。"""
    chars: list[str] = []
    while len(chars) < length:
        raw = secrets.token_urlsafe(length * 2)
        chars.extend(c for c in raw if c.isalnum())
    return "".join(chars[:length])


def _path() -> Path:
    p = settings.gw_tokens_path
    return Path(p) if os.path.isabs(p) else Path.cwd() / p


def load(*, replace: bool = False) -> None:
    """从磁盘加载映射表。

    ``replace=False`` 时保留原有兼容行为：文件缺失或解析失败只记录日志，不清空内存。
    ``replace=True`` 时以磁盘内容为准；文件缺失、格式非法或解析失败都会清空内存映射，
    以避免热重载后继续放行已被删除的旧 token。
    """
    path = _path()
    with _lock:
        if not path.is_file():
            if replace:
                _tokens.clear()
                logger.info("gw_tokens file missing path=%s, cleared in-memory tokens", path)
            else:
                logger.debug("gw_tokens file not found path=%s, skip load", path)
            return
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            tokens = data.get(_GW_TOKENS_KEY)
            if not isinstance(tokens, dict):
                if replace:
                    _tokens.clear()
                    logger.warning("gw_tokens load failed path=%s error=invalid tokens payload; in-memory tokens cleared", path)
                return
            _tokens.clear()
            for k, v in tokens.items():
                if not isinstance(v, dict):
                    continue
                # compat token 允许省略 upstream_base（走端口路径时动态覆盖）
                if "upstream_base" not in v and not v.get("compat"):
                    continue
                entry: dict[str, Any] = {
                    "upstream_base": str(v.get("upstream_base") or ""),
                    "whitelist_key": normalize_whitelist_keys(v.get("whitelist_key")),
                }
                # 协议兼容层：compat 模式 + 模型映射
                if v.get("compat"):
                    entry["compat"] = str(v["compat"])
                if v.get("default_model"):
                    entry["default_model"] = str(v["default_model"])
                if isinstance(v.get("model_map"), dict):
                    entry["model_map"] = dict(v["model_map"])
                _tokens[str(k)] = entry
            logger.info("gw_tokens loaded path=%s count=%d", path, len(_tokens))
        except (json.JSONDecodeError, OSError, ValueError, KeyError, TypeError) as exc:
            if replace:
                _tokens.clear()
            logger.warning("gw_tokens load failed path=%s error=%s", path, exc)


def _save() -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {_GW_TOKENS_KEY: dict(_tokens)}
    tmp_path: Path | None = None
    try:
        # Write to a sibling temp file first so readers never observe a
        # partially-written gw_tokens.json during concurrent reloads.
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as tmp:
            tmp.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        logger.debug("gw_tokens saved path=%s count=%d", path, len(_tokens))
    except OSError as exc:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        logger.warning("gw_tokens: could not persist to %s: %s (in-memory state intact)", path, exc)


def get(token: str) -> dict[str, Any] | None:
    """根据 token 取映射，不存在返回 None。

    当 ``settings.enable_local_port_routing`` 为 True 且 token 为纯数字端口
    （1024-65535）时，自动生成本地端口映射，无需预注册。
    """
    with _lock:
        mapping = _tokens.get(token)
        if mapping is not None:
            return copy.deepcopy(mapping)

    # 本地端口自动路由 fallback
    if settings.enable_local_port_routing and token.isdigit():
        port = int(token)
        if 1024 <= port <= 65535:
            host = (settings.local_port_routing_host or "host.docker.internal").strip()
            return {
                "upstream_base": f"http://{host}:{port}/v1",
                "whitelist_key": [],
            }
    return None


def _normalize_upstream(s: str) -> str:
    return (s or "").strip().rstrip("/")


def _find_token_holding_lock(ub: str) -> str | None:
    """在已持有 _lock 时根据 upstream_base 查找 token。"""
    for token, m in _tokens.items():
        if _normalize_upstream(m["upstream_base"]) == ub:
            return token
    return None


def find_token(upstream_base: str, gateway_key: str | None = None, **_kwargs: Any) -> str | None:
    """
    根据 upstream_base 查找已注册的 token。
    不存在返回 None。比较时做与 register 一致的规范化。

    .. deprecated:: gateway_key 参数已废弃，传入时忽略。
    """
    ub = _normalize_upstream(upstream_base)
    if not ub:
        return None
    with _lock:
        return _find_token_holding_lock(ub)


def register(upstream_base: str, gateway_key: Any = None, whitelist_key: Any = _WHITELIST_UNSET, **_kwargs: Any) -> tuple[str, bool]:
    """
    注册：同一 upstream_base 只保留一个 token。
    若已存在则返回 (已有 token, True)，否则新建并返回 (新 token, False)。
    未传 whitelist_key 时，已存在映射的 whitelist_key 保持不变。

    .. deprecated:: gateway_key 参数已废弃，传入时忽略。
    """
    # Backward compat: register(ub, ["key1"]) — positional list was whitelist_key
    if whitelist_key is _WHITELIST_UNSET and gateway_key is not None and not isinstance(gateway_key, str):
        whitelist_key = gateway_key
    upstream_base = _normalize_upstream(upstream_base)
    if not upstream_base:
        raise ValueError("upstream_base required")
    whitelist_provided = whitelist_key is not _WHITELIST_UNSET
    whitelist_keys = normalize_whitelist_keys(whitelist_key) if whitelist_provided else []
    with _lock:
        existing = _find_token_holding_lock(upstream_base)
        if existing is not None:
            if whitelist_provided:
                mapping = _tokens.get(existing) or {}
                current = normalize_whitelist_keys(mapping.get("whitelist_key"))
                if current != whitelist_keys:
                    mapping["whitelist_key"] = whitelist_keys
                    _tokens[existing] = mapping
                    _save()
            return existing, True
        for attempt in range(20):
            token = _generate_alnum_token(_TOKEN_LEN)
            if token not in _tokens:
                break
        else:
            raise RuntimeError("failed to generate unique gw_token after 20 attempts")
        _tokens[token] = {
            "upstream_base": upstream_base,
            "whitelist_key": whitelist_keys if whitelist_provided else [],
        }
        _save()
    return token, False


def unregister(token: str) -> bool:
    """删除 token 映射，存在则删并写回文件返回 True，否则返回 False。"""
    with _lock:
        if token not in _tokens:
            return False
        del _tokens[token]
        _save()
        return True


def update(token: str, *, upstream_base: str | None = None, gateway_key: str | None = None, whitelist_key: Any = None, **_kwargs: Any) -> bool:
    """按 token 更新映射并持久化。token 不存在返回 False。

    .. deprecated:: gateway_key 参数已废弃，传入时忽略。
    """
    with _lock:
        mapping = _tokens.get(token)
        if mapping is None:
            return False
        next_mapping = dict(mapping)
        if upstream_base is not None:
            normalized_upstream = _normalize_upstream(upstream_base)
            if not normalized_upstream:
                raise ValueError("upstream_base required")
            next_mapping["upstream_base"] = normalized_upstream
        if whitelist_key is not None:
            next_mapping["whitelist_key"] = normalize_whitelist_keys(whitelist_key)
        _tokens[token] = next_mapping
        _save()
        return True


def update_and_rename(
    token: str,
    *,
    upstream_base: str | None = None,
    gateway_key: str | None = None,
    whitelist_key: Any = None,
    new_token: str | None = None,
    **_kwargs: Any,
) -> bool:
    """在单一锁内同时更新映射字段并可选地重命名 token，保证原子性。
    token 不存在返回 False；new_token 已存在或字段非法抛 ValueError。

    .. deprecated:: gateway_key 参数已废弃，传入时忽略。
    """
    with _lock:
        mapping = _tokens.get(token)
        if mapping is None:
            return False
        next_mapping = dict(mapping)
        if upstream_base is not None:
            normalized_upstream = _normalize_upstream(upstream_base)
            if not normalized_upstream:
                raise ValueError("upstream_base required")
            next_mapping["upstream_base"] = normalized_upstream
        if whitelist_key is not None:
            next_mapping["whitelist_key"] = normalize_whitelist_keys(whitelist_key)
        if new_token and new_token != token:
            if new_token in _tokens:
                raise ValueError(f"token already exists: {new_token}")
            _tokens[new_token] = next_mapping
            del _tokens[token]
        else:
            _tokens[token] = next_mapping
        _save()
        return True


def list_tokens() -> dict[str, dict[str, Any]]:
    """返回当前所有 token 映射（副本）。"""
    with _lock:
        return copy.deepcopy(_tokens)


def inject_builtin_compat_tokens() -> None:
    """注入系统内置的 compat token。启动时自动调用，无需配置。

    若用户已在 gw_tokens.json 中自定义了同名 token，保留用户配置不覆盖。
    """
    _BUILTIN_COMPAT = {
        "claude-to-gpt": {
            "upstream_base": "",
            "whitelist_key": [],
            "compat": "openai_chat",
        },
    }
    with _lock:
        injected = []
        for token, mapping in _BUILTIN_COMPAT.items():
            if token not in _tokens:
                _tokens[token] = dict(mapping)
                injected.append(token)
        if injected:
            _save()
            logger.info("builtin compat tokens injected: %s", ", ".join(injected))


def inject_docker_upstreams() -> int:
    """解析 AEGIS_DOCKER_UPSTREAMS 环境变量，自动注入 Docker 服务名 token 映射。

    格式：逗号分隔，每项为 ``token:service[:port]``。port 省略时默认等于 token。
    示例：``8317:cli-proxy-api,8080:sub2api,3000:aiclient2api:3000``
    生成：token="8317" → upstream_base="http://cli-proxy-api:8317/v1"

    已存在的同名 token 会被**静默覆盖**（确保 compose 环境变量始终是权威来源）。
    返回注入的条目数。
    """
    raw = (settings.docker_upstreams or "").strip()
    if not raw:
        return 0
    pending: dict[str, dict[str, Any]] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) < 2:
            logger.warning("docker_upstreams: invalid entry %r (expected token:service[:port]), skipped", entry)
            continue
        token = parts[0].strip()
        service = parts[1].strip()
        port = parts[2].strip() if len(parts) >= 3 else token
        if not token or not service or not port:
            logger.warning("docker_upstreams: empty field in %r, skipped", entry)
            continue
        upstream_base = f"http://{service}:{port}/v1"
        pending[token] = {
            "upstream_base": upstream_base,
            "whitelist_key": [],
        }
    injected = len(pending)
    if injected:
        with _lock:
            _tokens.update(pending)
            _save()
        logger.info("docker_upstreams injected %d token(s): %s", injected, raw)
    return injected
