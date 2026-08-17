"""
Gateway token mapping: the register endpoint returns a short token, and requests resolve their
upstream through /v1/__gw__/t/{token}/... .
The mapping table lives in config/gw_tokens.json, is loaded at startup, and can be hand-edited.
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

try:
    from aegisgate.storage.crypto import encrypt_whitelist_key, decrypt_whitelist_key
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

    def encrypt_whitelist_key(v: str) -> str:  # type: ignore[misc]
        return v

    def decrypt_whitelist_key(v: str) -> str:  # type: ignore[misc]
        return v

# In-memory mapping: token -> {"upstream_base": str, "whitelist_key": list[str]}
_tokens: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_TOKEN_LEN = 24
_GW_TOKENS_KEY = "tokens"
_WHITELIST_UNSET = object()


def _generate_alnum_token(length: int) -> str:
    """Generate a purely alphanumeric token (a-zA-Z0-9), free of symbols such as - and _."""
    chars: list[str] = []
    while len(chars) < length:
        raw = secrets.token_urlsafe(length * 2)
        chars.extend(c for c in raw if c.isalnum())
    return "".join(chars[:length])


def _path() -> Path:
    p = settings.gw_tokens_path
    return Path(p) if os.path.isabs(p) else Path.cwd() / p


def load(*, replace: bool = False) -> None:
    """Load the mapping table from disk.

    With ``replace=False`` the legacy behaviour is kept: a missing file or a parse failure is only
    logged and the in-memory table is left alone.
    With ``replace=True`` disk wins; a missing file, an invalid format, or a parse failure all clear
    the in-memory mapping, so a hot reload cannot keep honouring tokens that were deleted.
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
                # compat tokens may omit upstream_base (port routing overrides it at request time)
                if "upstream_base" not in v and not v.get("compat"):
                    continue
                raw_wk = v.get("whitelist_key")
                if isinstance(raw_wk, list):
                    raw_wk = [decrypt_whitelist_key(x) if isinstance(x, str) else x for x in raw_wk]
                elif isinstance(raw_wk, str):
                    raw_wk = decrypt_whitelist_key(raw_wk)
                entry: dict[str, Any] = {
                    "upstream_base": str(v.get("upstream_base") or ""),
                    "whitelist_key": normalize_whitelist_keys(raw_wk),
                }
                # Protocol compatibility layer: compat mode + model mapping
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
    serializable: dict[str, dict[str, Any]] = {}
    for tok, mapping in _tokens.items():
        entry = dict(mapping)
        wk = entry.get("whitelist_key")
        if isinstance(wk, list) and _HAS_CRYPTO:
            entry["whitelist_key"] = [encrypt_whitelist_key(x) if isinstance(x, str) and x else x for x in wk]
        serializable[tok] = entry
    data: dict[str, Any] = {_GW_TOKENS_KEY: serializable}
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
        logger.warning("gw_tokens: could not persist to %s: %s", path, exc)
        raise


def _restore_tokens(snapshot: dict[str, dict[str, Any]]) -> None:
    _tokens.clear()
    _tokens.update(copy.deepcopy(snapshot))


def get(token: str) -> dict[str, Any] | None:
    """Look up the mapping for a token, returning None when it does not exist.

    When ``settings.enable_local_port_routing`` is True and the token is a purely numeric port
    (1024-65535), a local port mapping is generated on the fly, so no pre-registration is needed.
    """
    with _lock:
        mapping = _tokens.get(token)
        if mapping is not None:
            return copy.deepcopy(mapping)

    # Automatic local-port routing fallback
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
    """Find a token by upstream_base; callers must already hold ``_lock``."""
    for token, m in _tokens.items():
        if _normalize_upstream(m["upstream_base"]) == ub:
            return token
    return None


def find_token(upstream_base: str, gateway_key: str | None = None, **_kwargs: Any) -> str | None:
    """
    Find the registered token for an upstream_base.
    Returns None when there is none. The comparison normalises the value the same way register does.

    .. deprecated:: the gateway_key parameter is obsolete and ignored when passed.
    """
    ub = _normalize_upstream(upstream_base)
    if not ub:
        return None
    with _lock:
        return _find_token_holding_lock(ub)


def register(upstream_base: str, gateway_key: Any = None, whitelist_key: Any = _WHITELIST_UNSET, **_kwargs: Any) -> tuple[str, bool]:
    """
    Register: each upstream_base keeps exactly one token.
    Returns (existing token, True) when one already exists, otherwise creates one and returns
    (new token, False).
    When whitelist_key is not supplied, an existing mapping keeps its current whitelist_key.

    .. deprecated:: the gateway_key parameter is obsolete and ignored when passed.
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
                    snapshot = copy.deepcopy(_tokens)
                    mapping["whitelist_key"] = whitelist_keys
                    _tokens[existing] = mapping
                    try:
                        _save()
                    except OSError:
                        _restore_tokens(snapshot)
                        raise
            return existing, True
        for attempt in range(20):
            token = _generate_alnum_token(_TOKEN_LEN)
            if token not in _tokens:
                break
        else:
            raise RuntimeError("failed to generate unique gw_token after 20 attempts")
        snapshot = copy.deepcopy(_tokens)
        _tokens[token] = {
            "upstream_base": upstream_base,
            "whitelist_key": whitelist_keys if whitelist_provided else [],
        }
        try:
            _save()
        except OSError:
            _restore_tokens(snapshot)
            raise
    return token, False


def unregister(token: str) -> bool:
    """Delete a token mapping: if present, remove it, write the file back, and return True;
    otherwise return False."""
    with _lock:
        if token not in _tokens:
            return False
        snapshot = copy.deepcopy(_tokens)
        del _tokens[token]
        try:
            _save()
        except OSError:
            _restore_tokens(snapshot)
            raise
        return True


def update(token: str, *, upstream_base: str | None = None, gateway_key: str | None = None, whitelist_key: Any = None, **_kwargs: Any) -> bool:
    """Update the mapping for a token and persist it. Returns False when the token does not exist.

    .. deprecated:: the gateway_key parameter is obsolete and ignored when passed.
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
        snapshot = copy.deepcopy(_tokens)
        _tokens[token] = next_mapping
        try:
            _save()
        except OSError:
            _restore_tokens(snapshot)
            raise
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
    """Update mapping fields and optionally rename the token under a single lock, atomically.
    Returns False when the token does not exist; raises ValueError when new_token already exists or
    a field is invalid.

    .. deprecated:: the gateway_key parameter is obsolete and ignored when passed.
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
        snapshot = copy.deepcopy(_tokens)
        if new_token and new_token != token:
            if new_token in _tokens:
                raise ValueError(f"token already exists: {new_token}")
            _tokens[new_token] = next_mapping
            del _tokens[token]
        else:
            _tokens[token] = next_mapping
        try:
            _save()
        except OSError:
            _restore_tokens(snapshot)
            raise
        return True


def list_tokens() -> dict[str, dict[str, Any]]:
    """Return a copy of every current token mapping."""
    with _lock:
        return copy.deepcopy(_tokens)


def inject_builtin_compat_tokens() -> None:
    """Inject the built-in compat tokens (gated by a config switch).

    If the user already defined a token with the same name in gw_tokens.json, their configuration
    is kept and not overwritten.
    """
    if not bool(getattr(settings, "enable_builtin_compat_tokens", False)):
        return
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
            try:
                _save()
            except OSError:
                logger.warning(
                    "builtin compat tokens persistence failed; keeping in-memory tokens: %s",
                    ", ".join(injected),
                )
            logger.info("builtin compat tokens injected: %s", ", ".join(injected))


def inject_docker_upstreams() -> int:
    """Parse the AEGIS_DOCKER_UPSTREAMS environment variable and inject Docker service-name token
    mappings automatically.

    Format: comma-separated, each item ``token:service[:port]``. An omitted port defaults to token.
    Example: ``8317:cli-proxy-api,8080:sub2api,3000:aiclient2api:3000``
    Produces: token="8317" → upstream_base="http://cli-proxy-api:8317/v1"

    An existing token of the same name is **silently overwritten**, so the compose environment
    variable always stays authoritative.
    Returns the number of injected entries.
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
            try:
                _save()
            except OSError:
                logger.warning(
                    "docker_upstreams persistence failed; keeping in-memory tokens: %s",
                    raw,
                )
        logger.info("docker_upstreams injected %d token(s): %s", injected, raw)
    return injected
