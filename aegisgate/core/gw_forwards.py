"""Host-based gateway forwarding table: ``config/gw_forwards.json``.

Each entry forwards a whole client-facing hostname (``Host`` becomes the routing
key instead of the ``/v1/__gw__/t/<token>`` path) to an operator-written upstream
base URL. The mapping is loaded at startup, watched for hot reload, and edited by
the console.

Security posture — the same one ``gw_tokens`` established:

* the file is fail-closed. A parse failure, an invalid ``version`` or a broken
  top-level structure clears the live table and parks every previously known host
  in ``_denied`` so it answers 403 rather than silently falling back to the
  default-upstream branch. A single invalid entry only denies that host.
* ``expose: "public"`` rules that turn the baseline redaction filters off are
  refused unless the startup-pinned ``AEGIS_FORWARD_ALLOW_PUBLIC_BASELINE_OFF``
  authorises it. Weakening the public surface may not come from a hot-editable
  file, exactly like ``allow_public_passthrough_mode``.
* ``AEGIS_ENABLE_REQUEST_HMAC_AUTH`` and forwarding are mutually exclusive: HMAC
  forces signatures on every non-passthrough request, which a browser hitting a
  forwarded domain cannot provide. Enabling both refuses to load the table.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

_VERSION = 1
_DOCUMENT_KEY = "forwards"

# Hosts that may be forwarded and the deny reasons a request can observe.
REASON_RULE_INVALID = "forward_rule_invalid"
REASON_RULE_DISABLED = "forward_rule_disabled"
REASON_CONFIG_INVALID = "forward_config_invalid"

_EXPOSE_VALUES = frozenset({"public", "internal"})
_FILTER_MODES = frozenset({"policy", "custom"})

# A forward key is a hostname, never an IP literal or a host:port pair: the
# routing key is what the client puts in ``Host``, and an IP would make the rule
# ambiguous with the gateway's own address.
_HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Derived tables (guarded by ``_lock``):
#   ``_forwards``  every valid rule, enabled or disabled
#   ``_denied``    host -> {"reason", "detail"} for entries that must answer 403
# ``_document`` is the raw JSON document the console edits, so an entry the
# operator is still fixing is preserved verbatim across console writes.
_forwards: dict[str, "ForwardRule"] = {}
_denied: dict[str, dict[str, str]] = {}
_document: dict[str, Any] = {"version": _VERSION, _DOCUMENT_KEY: {}}
_lock = threading.Lock()


@dataclass(frozen=True)
class ForwardRule:
    host: str
    upstream_base: str
    note: str = ""
    expose: str = "internal"
    enabled: bool = True
    filters_mode: str = "policy"
    custom_filters: dict[str, bool] = field(default_factory=dict)

    @property
    def baseline_off(self) -> bool:
        """True when this rule explicitly turns a baseline redaction filter off.

        The baseline pair is ``redaction`` / ``exact_value_redaction``; either one
        off is enough for the startup gate, the posture warnings and the
        per-request audit tag.
        """
        if self.filters_mode != "custom":
            return False
        return (
            self.custom_filters.get("redaction") is False
            or self.custom_filters.get("exact_value_redaction") is False
        )

    def resolved_filter_overrides(self) -> dict[str, bool]:
        """Explicit per-filter overrides, or an empty mapping for ``mode: policy``."""
        if self.filters_mode != "custom":
            return {}
        return dict(self.custom_filters)

    def to_payload(self) -> dict[str, Any]:
        filters: dict[str, Any] = {"mode": self.filters_mode}
        if self.filters_mode == "custom":
            filters["custom"] = dict(self.custom_filters)
        return {
            "enabled": self.enabled,
            "upstream_base": self.upstream_base,
            "note": self.note,
            "expose": self.expose,
            "filters": filters,
        }


def _path() -> Path:
    p = settings.gw_forwards_path
    return Path(p) if os.path.isabs(p) else Path.cwd() / p


def _normalize_host(value: object) -> str:
    return str(value or "").strip().lower().rstrip(".")


def host_error(value: object) -> str | None:
    """Why *value* is unusable as a forward host key, or ``None`` when it is fine."""
    host = _normalize_host(value)
    if not host:
        return "网关域名为必填"
    if len(host) > 253:
        return "网关域名过长"
    if any(ch in host for ch in (":", "/", " ", "\\", "@", "?")):
        return "网关域名不能包含端口、路径或空白"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return "网关域名不能是 IP 字面量"
    labels = host.split(".")
    if not all(_HOST_LABEL_RE.match(label) for label in labels):
        return "网关域名格式无效"
    return None


def _allowed_filter_names() -> frozenset[str]:
    """The 13 filter names ``filters.custom`` accepts.

    Read from ``FeatureFlags`` so adding a filter to the global flag set surfaces
    it here (and therefore in the console) without a second hand-maintained list.
    """
    from aegisgate.config.feature_flags import FeatureFlags

    return frozenset(FeatureFlags.__dataclass_fields__)


def validate_rule(
    host_raw: object,
    raw: object,
) -> tuple[ForwardRule | None, str | None]:
    """Validate one ``host -> entry`` pair. Shared by the loader and the console.

    Returning ``(None, reason)`` means the entry is invalid and must not load;
    the caller decides whether that is a deny entry (loader) or a 400 (console).
    """
    host = _normalize_host(host_raw)
    err = host_error(host)
    if err is not None:
        return None, err
    if not isinstance(raw, dict):
        return None, "规则必须是 JSON 对象"

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        return None, "enabled 必须是布尔值"

    from aegisgate.core.gateway_keys import (
        _is_forbidden_upstream_base_example,
        _normalize_input_upstream_base,
        upstream_base_error,
    )

    upstream_base = _normalize_input_upstream_base(raw.get("upstream_base"))
    if not upstream_base:
        return None, "upstream_base 为必填"
    if _is_forbidden_upstream_base_example(upstream_base):
        return None, "upstream_base 不能使用文档中的示例地址"
    format_error = upstream_base_error(upstream_base)
    if format_error is not None:
        return None, format_error

    note = raw.get("note", "")
    if note is None:
        note = ""
    if not isinstance(note, str):
        return None, "note 必须是字符串"

    expose = raw.get("expose", "internal")
    if expose not in _EXPOSE_VALUES:
        return None, "expose 必须是 public 或 internal"

    filters = raw.get("filters", {})
    if filters is None:
        filters = {}
    if not isinstance(filters, dict):
        return None, "filters 必须是对象"
    mode = filters.get("mode", "policy")
    if mode not in _FILTER_MODES:
        return None, "filters.mode 必须是 policy 或 custom"

    custom_raw = filters.get("custom", {})
    if custom_raw is None:
        custom_raw = {}
    if not isinstance(custom_raw, dict):
        return None, "filters.custom 必须是对象"
    allowed = _allowed_filter_names()
    unknown = sorted(str(key) for key in custom_raw if key not in allowed)
    if unknown:
        return None, f"未知的 filter 名: {', '.join(unknown)}"
    custom: dict[str, bool] = {}
    for name, value in custom_raw.items():
        if not isinstance(value, bool):
            return None, f"filters.custom.{name} 必须是布尔值"
        custom[name] = value
    if mode == "policy" and custom:
        return None, "filters.custom 仅在 mode=custom 时允许"

    rule = ForwardRule(
        host=host,
        upstream_base=upstream_base,
        note=note,
        expose=expose,
        enabled=enabled,
        filters_mode=mode,
        custom_filters=custom,
    )
    if (
        rule.baseline_off
        and rule.expose == "public"
        and not settings.forward_allow_public_baseline_off
    ):
        return (
            None,
            "public 规则关闭基线脱敏需要 AEGIS_FORWARD_ALLOW_PUBLIC_BASELINE_OFF=true 显式授权",
        )
    return rule, None


def _derive_tables(
    document: object,
) -> tuple[dict[str, ForwardRule], dict[str, dict[str, str]]]:
    """Build the live/denied tables from a raw document (no file or lock access)."""
    forwards: dict[str, ForwardRule] = {}
    denied: dict[str, dict[str, str]] = {}
    if not isinstance(document, dict):
        return forwards, denied
    raw_forwards = document.get(_DOCUMENT_KEY)
    if not isinstance(raw_forwards, dict):
        return forwards, denied
    for host_raw, entry in raw_forwards.items():
        rule, reason = validate_rule(host_raw, entry)
        if rule is None:
            host = _normalize_host(host_raw) or str(host_raw)
            denied[host] = {"reason": REASON_RULE_INVALID, "detail": reason or ""}
            logger.error(
                "gw_forwards entry invalid host=%s reason=%s", host, reason
            )
            continue
        if rule.host in forwards:
            # Two raw keys that normalize to the same host. The later one loses;
            # ignoring it silently would hide an operator typo.
            denied[rule.host] = {
                "reason": REASON_RULE_INVALID,
                "detail": "重复的网关域名（规范化后冲突）",
            }
            logger.error("gw_forwards duplicate host after normalization host=%s", rule.host)
            continue
        forwards[rule.host] = rule
    return forwards, denied


def _hmac_conflict() -> bool:
    return bool(settings.enable_gateway_forward and settings.enable_request_hmac_auth)


def _deny_all_current(reason: str, detail: str) -> None:
    """Move every currently live host into ``_denied`` and clear the live table."""
    denied = {
        host: {"reason": reason, "detail": detail} for host in _forwards
    }
    _forwards.clear()
    _denied.clear()
    _denied.update(denied)


def load(*, replace: bool = False) -> None:
    """Load ``config/gw_forwards.json`` into the derived tables.

    ``replace=False`` keeps the legacy-tolerant behaviour for a missing file (the
    in-memory table is left alone). ``replace=True`` is the hot-reload path:
    disk wins, including "the file was deleted".
    """
    path = _path()
    with _lock:
        if not path.is_file():
            if replace:
                _forwards.clear()
                _denied.clear()
                _document.clear()
                _document.update({"version": _VERSION, _DOCUMENT_KEY: {}})
                logger.info(
                    "gw_forwards file missing path=%s, cleared forward table", path
                )
            else:
                logger.debug("gw_forwards file not found path=%s, skip load", path)
            return

        if _hmac_conflict():
            # Refuse to load, but surface the hosts the operator configured so the
            # console shows *why* nothing is forwarding.
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, ValueError):
                data = None
            parsed, _ignored_denied = _derive_tables(data)
            _forwards.update(parsed)
            _deny_all_current(
                REASON_CONFIG_INVALID,
                "AEGIS_ENABLE_REQUEST_HMAC_AUTH=true 与网关转发互斥；转发表未加载",
            )
            logger.error(
                "gw_forwards not loaded: AEGIS_ENABLE_REQUEST_HMAC_AUTH=true is mutually "
                "exclusive with AEGIS_ENABLE_GATEWAY_FORWARD=true"
            )
            return

        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            _deny_all_current(REASON_CONFIG_INVALID, f"配置文件解析失败: {exc}")
            logger.error("gw_forwards load failed path=%s error=%s", path, exc)
            return

        if (
            not isinstance(data, dict)
            or data.get("version") != _VERSION
            or not isinstance(data.get(_DOCUMENT_KEY), dict)
        ):
            _deny_all_current(
                REASON_CONFIG_INVALID,
                f"顶层结构非法（需要 version={_VERSION} 与 forwards 对象）",
            )
            logger.error(
                "gw_forwards load failed path=%s error=invalid top-level structure", path
            )
            return

        forwards, denied = _derive_tables(data)
        _forwards.clear()
        _forwards.update(forwards)
        _denied.clear()
        _denied.update(denied)
        _document.clear()
        _document.update(copy.deepcopy(data))
        logger.info(
            "gw_forwards loaded path=%s count=%d denied=%d", path, len(_forwards), len(_denied)
        )
        _log_posture()


def _build_document() -> dict[str, Any]:
    return {
        "version": _VERSION,
        _DOCUMENT_KEY: {
            host: rule.to_payload() for host, rule in _forwards.items()
        },
    }


def _atomic_write(document: dict[str, Any]) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as tmp:
            tmp.write(json.dumps(document, ensure_ascii=False, indent=2))
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _save() -> None:
    """Atomically persist the editable document, mode 0600.

    The document is the source of truth the console mutates, so entries the
    operator has not fixed yet survive a write of an unrelated rule.
    """
    _atomic_write(copy.deepcopy(_document))


def upsert(rule: ForwardRule) -> None:
    """Insert or replace one rule and persist the document."""
    with _lock:
        document = copy.deepcopy(_document)
        raw_forwards = document.get(_DOCUMENT_KEY)
        if not isinstance(raw_forwards, dict):
            raw_forwards = {}
        raw_forwards[rule.host] = rule.to_payload()
        document["version"] = _VERSION
        document[_DOCUMENT_KEY] = raw_forwards
        _save_document_locked(document)


def delete(host: str) -> bool:
    """Remove one host from the editable document. Returns False when absent."""
    normalized = _normalize_host(host)
    with _lock:
        document = copy.deepcopy(_document)
        raw_forwards = document.get(_DOCUMENT_KEY)
        if not isinstance(raw_forwards, dict):
            return False
        if normalized in raw_forwards:
            del raw_forwards[normalized]
        else:
            # The raw key may differ in case / trailing dot.
            matches = [
                key for key in raw_forwards if _normalize_host(key) == normalized
            ]
            if not matches:
                return False
            for key in matches:
                del raw_forwards[key]
        _save_document_locked(document)
        return True


def _save_document_locked(document: dict[str, Any]) -> None:
    """Persist *document* and rebuild the derived tables. Caller holds ``_lock``."""
    _atomic_write(document)
    forwards, denied = _derive_tables(document)
    _document.clear()
    _document.update(copy.deepcopy(document))
    _forwards.clear()
    _forwards.update(forwards)
    _denied.clear()
    _denied.update(denied)
    _log_posture()


def get(host: str) -> ForwardRule | None:
    """Live rule for *host* (enabled or disabled), or None."""
    normalized = _normalize_host(host)
    with _lock:
        return _forwards.get(normalized)


def denied_reason(host: str) -> tuple[str, str] | None:
    """``(reason, detail)`` when *host* is in the deny table, else None."""
    normalized = _normalize_host(host)
    with _lock:
        item = _denied.get(normalized)
        if item is None:
            return None
        return item["reason"], item.get("detail", "")


def list_rules() -> list[ForwardRule]:
    with _lock:
        return list(_forwards.values())


def list_denied() -> dict[str, dict[str, str]]:
    with _lock:
        return copy.deepcopy(_denied)


def _whitelist_bypass_hosts(bases: list[tuple[str, str]]) -> set[str]:
    try:
        from aegisgate.adapters.openai_compat.upstream import _is_upstream_whitelisted
    except Exception:  # pragma: no cover - defensive, import must not break loading
        return set()
    affected: set[str] = set()
    for host, upstream_base in bases:
        try:
            if _is_upstream_whitelisted(upstream_base):
                affected.add(host)
        except Exception:  # pragma: no cover - defensive
            continue
    return affected


def whitelist_bypass_hosts() -> set[str]:
    """Hosts whose upstream base is on ``AEGIS_UPSTREAM_WHITELIST_URL_LIST``.

    Those upstreams skip both pipelines inside the V1 handler, so a rule's filter
    switches cannot take effect. Reported, never used to change behaviour.
    """
    with _lock:
        bases = [(host, rule.upstream_base) for host, rule in _forwards.items()]
    return _whitelist_bypass_hosts(bases)


def _log_posture() -> None:
    """Startup / hot-reload security-posture summary (§8.6). Caller holds ``_lock``."""
    rules = list(_forwards.values())
    public = [rule for rule in rules if rule.expose == "public"]
    baseline_off = [rule for rule in rules if rule.baseline_off]
    logger.info(
        "gw_forwards posture: rules=%d public=%d denied=%d",
        len(rules),
        len(public),
        len(_denied),
    )
    for rule in baseline_off:
        logger.warning(
            "gw_forwards baseline redaction disabled host=%s expose=%s — requests on this "
            "domain may reach the upstream unredacted",
            rule.host,
            rule.expose,
        )
    for rule in public:
        if rule.filters_mode == "custom" and rule.custom_filters and not any(
            rule.custom_filters.values()
        ):
            logger.warning(
                "gw_forwards public rule with every custom filter off host=%s", rule.host
            )
    affected = _whitelist_bypass_hosts([(rule.host, rule.upstream_base) for rule in rules])
    for host in sorted(affected):
        logger.warning(
            "gw_forwards rule upstream is on AEGIS_UPSTREAM_WHITELIST_URL_LIST and bypasses "
            "all filters host=%s — its filter switches have no effect",
            host,
        )
    for host, item in sorted(_denied.items()):
        logger.error(
            "gw_forwards denied host=%s reason=%s detail=%s",
            host,
            item.get("reason", ""),
            item.get("detail", ""),
        )
