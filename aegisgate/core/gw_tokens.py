"""
网关 Token 映射：注册口子返回短 token，请求时通过 /v1/__gw__/t/{token}/... 解析上游。
映射表存 config/gw_tokens.json，启动时加载，支持手动编辑。
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys

# 内存映射：token -> {"upstream_base": str, "gateway_key": str, "whitelist_key": list[str]}
_tokens: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_TOKEN_LEN = 10
_GW_TOKENS_KEY = "tokens"
_WHITELIST_UNSET = object()


def _path() -> Path:
    p = settings.gw_tokens_path
    return Path(p) if os.path.isabs(p) else Path.cwd() / p


def load() -> None:
    """启动时加载映射表；无文件或空则不变。"""
    path = _path()
    if not path.is_file():
        logger.debug("gw_tokens file not found path=%s, skip load", path)
        return
    with _lock:
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            tokens = data.get(_GW_TOKENS_KEY)
            if isinstance(tokens, dict):
                _tokens.clear()
                for k, v in tokens.items():
                    if isinstance(v, dict) and "upstream_base" in v and "gateway_key" in v:
                        _tokens[str(k)] = {
                            "upstream_base": str(v["upstream_base"]),
                            "gateway_key": str(v["gateway_key"]),
                            "whitelist_key": normalize_whitelist_keys(v.get("whitelist_key")),
                        }
                logger.info("gw_tokens loaded path=%s count=%d", path, len(_tokens))
        except Exception as exc:
            logger.warning("gw_tokens load failed path=%s error=%s", path, exc)


def _save() -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {_GW_TOKENS_KEY: dict(_tokens)}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.debug("gw_tokens saved path=%s count=%d", path, len(_tokens))


def get(token: str) -> dict[str, Any] | None:
    """根据 token 取映射，不存在返回 None。"""
    with _lock:
        mapping = _tokens.get(token)
        if mapping is None:
            return None
        return copy.deepcopy(mapping)


def _normalize_upstream(s: str) -> str:
    return (s or "").strip().rstrip("/")


def _find_token_holding_lock(ub: str, gk: str) -> str | None:
    """在已持有 _lock 时根据 (upstream_base, gateway_key) 查找 token。"""
    for token, m in _tokens.items():
        if _normalize_upstream(m["upstream_base"]) == ub and (m.get("gateway_key") or "").strip() == gk:
            return token
    return None


def find_token(upstream_base: str, gateway_key: str) -> str | None:
    """
    根据 upstream_base + gateway_key 查找已注册的 token。
    不存在返回 None。比较时做与 register 一致的规范化。
    """
    ub = _normalize_upstream(upstream_base)
    gk = (gateway_key or "").strip()
    if not ub or not gk:
        return None
    with _lock:
        return _find_token_holding_lock(ub, gk)


def register(upstream_base: str, gateway_key: str, whitelist_key: Any = _WHITELIST_UNSET) -> tuple[str, bool]:
    """
    注册：同一 (upstream_base, gateway_key) 只保留一个 token。
    若已存在则返回 (已有 token, True)，否则新建并返回 (新 token, False)。
    未传 whitelist_key 时，已存在映射的 whitelist_key 保持不变。
    """
    upstream_base = _normalize_upstream(upstream_base)
    if not upstream_base:
        raise ValueError("upstream_base required")
    gateway_key = (gateway_key or "").strip()
    if not gateway_key:
        raise ValueError("gateway_key required")
    whitelist_provided = whitelist_key is not _WHITELIST_UNSET
    whitelist_keys = normalize_whitelist_keys(whitelist_key) if whitelist_provided else []
    with _lock:
        existing = _find_token_holding_lock(upstream_base, gateway_key)
        if existing is not None:
            if whitelist_provided:
                mapping = _tokens.get(existing) or {}
                current = normalize_whitelist_keys(mapping.get("whitelist_key"))
                if current != whitelist_keys:
                    mapping["whitelist_key"] = whitelist_keys
                    _tokens[existing] = mapping
                    _save()
            return existing, True
        for _ in range(10):
            token = secrets.token_urlsafe(_TOKEN_LEN)[:_TOKEN_LEN]
            if token not in _tokens:
                break
        else:
            token = secrets.token_hex(_TOKEN_LEN // 2)[:_TOKEN_LEN]
        _tokens[token] = {
            "upstream_base": upstream_base,
            "gateway_key": gateway_key,
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


def update(token: str, *, upstream_base: str | None = None, gateway_key: str | None = None, whitelist_key: Any = None) -> bool:
    """按 token 更新映射并持久化。token 不存在返回 False。"""
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
        if gateway_key is not None:
            normalized_gateway_key = (gateway_key or "").strip()
            if not normalized_gateway_key:
                raise ValueError("gateway_key required")
            next_mapping["gateway_key"] = normalized_gateway_key
        if whitelist_key is not None:
            next_mapping["whitelist_key"] = normalize_whitelist_keys(whitelist_key)
        _tokens[token] = next_mapping
        _save()
        return True


def list_tokens() -> dict[str, dict[str, Any]]:
    """返回当前所有 token 映射（副本）。"""
    with _lock:
        return copy.deepcopy(_tokens)
