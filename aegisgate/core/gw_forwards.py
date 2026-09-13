"""Host-based gateway forwarding table: ``config/gw_forwards.json``.

Each entry forwards a whole client-facing hostname (``Host`` becomes the routing
key instead of the ``/v1/__gw__/t/<token>`` path) to an operator-written upstream
base URL. The mapping is loaded at startup, watched for hot reload, and edited by
the console.

Security posture — the same one ``gw_tokens`` established:

* the file is fail-closed. A parse failure, an invalid ``version`` or a broken
  top-level structure clears the live table and parks every host the gateway
  knew about — live *and* already denied — in ``_denied`` so it answers 403
  rather than silently falling back to the default-upstream branch. A second
  broken save keeps them there. A single invalid entry only denies that host.
* ``expose: "public"`` rules that turn the baseline redaction filters off are
  refused unless the startup-pinned ``AEGIS_FORWARD_ALLOW_PUBLIC_BASELINE_OFF``
  authorises it. Weakening the public surface may not come from a hot-editable
  file, exactly like ``allow_public_passthrough_mode``.
* ``AEGIS_ENABLE_REQUEST_HMAC_AUTH`` and forwarding are mutually exclusive: HMAC
  forces signatures on every non-passthrough request, which a browser hitting a
  forwarded domain cannot provide. Enabling both refuses to load the table.
* console writes re-read the file under the lock and merge onto what is on
  disk, never onto an in-memory copy: a write can therefore neither resurrect a
  table the HMAC gate refused nor overwrite a file the operator is still fixing.
"""

from __future__ import annotations

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
_forwards: dict[str, "ForwardRule"] = {}
_denied: dict[str, dict[str, str]] = {}
_lock = threading.Lock()


class ForwardWriteRefused(RuntimeError):
    """A console write the current file state does not allow.

    Raised while the file cannot be parsed or the HMAC gate refuses the table:
    merging a change onto an unreadable file would throw the operator's pending
    edit away, and writing through the HMAC gate would load a table the gate
    exists to refuse.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class ForwardEtagMismatch(RuntimeError):
    """``If-Match`` named a version of the file that is no longer on disk."""

    def __init__(self, current_etag: str) -> None:
        super().__init__("etag_mismatch")
        self.current_etag = current_etag


class ForwardNotFound(LookupError):
    """The host to update is not in the file."""


class ForwardHostExists(ValueError):
    """The host to create (or rename to) is already in the file."""


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

    @property
    def llm_upstream_base(self) -> str:
        """The base the V1 pipeline branch forwards to.

        A rule stores the upstream *root* (the whole domain is forwarded, so the
        passthrough face appends the original path verbatim). The V1 forwarder
        instead strips the ``/v1`` gateway prefix from the request path before
        appending it (``_build_upstream_url``), so the prefix is put back here —
        otherwise ``/v1/chat/completions`` would reach the upstream as
        ``/chat/completions``.
        """
        from aegisgate.adapters.openai_compat.upstream import GATEWAY_PREFIX

        return f"{self.upstream_base}{GATEWAY_PREFIX}"

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


def route_host(raw_host: str) -> str:
    """Normalize a client-facing host to the routing key.

    Lowercased, trailing-dot stripped, port removed. IPv6 literals keep their
    inner address (brackets removed) so a ``[::1]:8080`` address cannot masquerade
    as a hostname rule. The deny table is keyed the same way, so an entry the
    operator wrote as ``api.ag.com:443`` still denies requests for ``api.ag.com``.
    """
    value = (raw_host or "").strip().lower()
    if not value:
        return ""
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            value = value[1:end]
    elif ":" in value:
        value = value.rsplit(":", 1)[0]
    return value.rstrip(".")


def _deny_key(host_raw: object) -> str:
    return route_host(str(host_raw)) or str(host_raw)


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

    # Type before membership: an unhashable value (a list, an object) would make
    # ``in frozenset`` raise and abort the whole load instead of denying one host.
    expose = raw.get("expose", "internal")
    if not isinstance(expose, str) or expose not in _EXPOSE_VALUES:
        return None, "expose 必须是 public 或 internal"

    filters = raw.get("filters", {})
    if filters is None:
        filters = {}
    if not isinstance(filters, dict):
        return None, "filters 必须是对象"
    mode = filters.get("mode", "policy")
    if not isinstance(mode, str) or mode not in _FILTER_MODES:
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


def _document_is_valid(document: object) -> bool:
    return (
        isinstance(document, dict)
        and document.get("version") == _VERSION
        and isinstance(document.get(_DOCUMENT_KEY), dict)
    )


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

    key_counts: dict[str, int] = {}
    for host_raw in raw_forwards:
        key = _deny_key(host_raw)
        key_counts[key] = key_counts.get(key, 0) + 1

    for host_raw, entry in raw_forwards.items():
        key = _deny_key(host_raw)
        if key_counts[key] > 1:
            # Two raw keys that route to the same host. Whichever JSON key came
            # first would otherwise win and the other's posture would silently
            # not apply, so neither is loaded.
            if key not in denied:
                logger.error("gw_forwards duplicate host after normalization host=%s", key)
            denied[key] = {
                "reason": REASON_RULE_INVALID,
                "detail": "重复的网关域名（规范化后冲突）",
            }
            continue
        try:
            rule, reason = validate_rule(host_raw, entry)
        except Exception as exc:  # defensive: one odd entry denies, never aborts the load
            rule, reason = None, f"规则校验异常: {type(exc).__name__}"
        if rule is None:
            denied[key] = {"reason": REASON_RULE_INVALID, "detail": reason or ""}
            logger.error(
                "gw_forwards entry invalid host=%s reason=%s", key, reason
            )
            continue
        forwards[rule.host] = rule
    return forwards, denied


def _hmac_conflict() -> bool:
    return bool(settings.enable_gateway_forward and settings.enable_request_hmac_auth)


def _deny_all_known(reason: str, detail: str, extra_hosts: set[str] | None = None) -> None:
    """Park every host the gateway knows about in ``_denied``. Caller holds ``_lock``.

    Known means live rules *and* hosts that were already denied: a failed load
    after a failed load (or after a load that denied one entry) must not release
    anything back to the default stack.
    """
    hosts = set(_forwards) | set(_denied) | set(extra_hosts or ())
    _forwards.clear()
    _denied.clear()
    _denied.update({host: {"reason": reason, "detail": detail} for host in hosts})


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
                logger.info(
                    "gw_forwards file missing path=%s, cleared forward table", path
                )
            else:
                logger.debug("gw_forwards file not found path=%s, skip load", path)
            return

        data: object = None
        parse_error: Exception | None = None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            parse_error = exc

        if _hmac_conflict():
            # Refuse to load, but surface the hosts the operator configured so the
            # console shows *why* nothing is forwarding.
            parsed, parsed_denied = _derive_tables(data if parse_error is None else None)
            _deny_all_known(
                REASON_CONFIG_INVALID,
                "AEGIS_ENABLE_REQUEST_HMAC_AUTH=true 与网关转发互斥；转发表未加载",
                extra_hosts=set(parsed) | set(parsed_denied),
            )
            logger.error(
                "gw_forwards not loaded: AEGIS_ENABLE_REQUEST_HMAC_AUTH=true is mutually "
                "exclusive with AEGIS_ENABLE_GATEWAY_FORWARD=true"
            )
            _log_posture()
            return

        if parse_error is not None:
            _deny_all_known(REASON_CONFIG_INVALID, f"配置文件解析失败: {parse_error}")
            logger.error("gw_forwards load failed path=%s error=%s", path, parse_error)
            _log_posture()
            return

        if not _document_is_valid(data):
            _deny_all_known(
                REASON_CONFIG_INVALID,
                f"顶层结构非法（需要 version={_VERSION} 与 forwards 对象）",
            )
            logger.error(
                "gw_forwards load failed path=%s error=invalid top-level structure", path
            )
            _log_posture()
            return

        forwards, denied = _derive_tables(data)
        _forwards.clear()
        _forwards.update(forwards)
        _denied.clear()
        _denied.update(denied)
        logger.info(
            "gw_forwards loaded path=%s count=%d denied=%d", path, len(_forwards), len(_denied)
        )
        _log_posture()


def _serialize(document: dict[str, Any]) -> bytes:
    return json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")


def _atomic_write(payload: bytes) -> None:
    """Temp file + fsync + replace, mode 0600 (the file holds internal addresses)."""
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
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


def _read_document_for_write(if_match: str | None) -> dict[str, Any]:
    """The on-disk document a console write merges onto. Caller holds ``_lock``.

    ``If-Match`` is checked here, against the bytes actually being replaced, so
    the check and the write cannot be separated by another request or by an
    operator's hand edit that the watcher has not picked up yet.
    """
    from aegisgate.core.ui_etag import ABSENT_ETAG, etag_for_bytes, if_match_is_stale

    if _hmac_conflict():
        raise ForwardWriteRefused(
            REASON_CONFIG_INVALID,
            "AEGIS_ENABLE_REQUEST_HMAC_AUTH=true 与网关转发互斥，转发表不能修改",
        )
    path = _path()
    try:
        payload: bytes | None = path.read_bytes()
    except FileNotFoundError:
        payload = None
    current_etag = ABSENT_ETAG if payload is None else etag_for_bytes(payload)
    if if_match_is_stale(if_match, current_etag):
        raise ForwardEtagMismatch(current_etag)
    if payload is None:
        return {"version": _VERSION, _DOCUMENT_KEY: {}}
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        document = None
    if not _document_is_valid(document):
        raise ForwardWriteRefused(
            REASON_CONFIG_INVALID,
            "规则文件无法解析或结构非法；请先修复或删除该文件，再通过控制台修改",
        )
    return document


def _raw_keys_for(raw_forwards: dict[str, Any], host: str) -> list[str]:
    return [key for key in raw_forwards if _deny_key(key) == host]


def _save_document_locked(document: dict[str, Any]) -> str:
    """Persist *document*, rebuild the derived tables, return the new ETag.

    Caller holds ``_lock``.
    """
    from aegisgate.core.ui_etag import etag_for_bytes

    payload = _serialize(document)
    _atomic_write(payload)
    forwards, denied = _derive_tables(document)
    _forwards.clear()
    _forwards.update(forwards)
    _denied.clear()
    _denied.update(denied)
    _log_posture()
    return etag_for_bytes(payload)


def upsert(rule: ForwardRule, *, if_match: str | None = None) -> str:
    """Insert or replace one rule and persist the file. Returns the new ETag.

    Any raw key that routes to the same host (different case, trailing dot, a
    port) is replaced in the same write, so a stale invalid entry cannot end up
    next to the new rule and deny both.
    """
    with _lock:
        document = _read_document_for_write(if_match)
        raw_forwards = document[_DOCUMENT_KEY]
        for key in _raw_keys_for(raw_forwards, rule.host):
            del raw_forwards[key]
        raw_forwards[rule.host] = rule.to_payload()
        return _save_document_locked(document)


def create(rule: ForwardRule, *, if_match: str | None = None) -> str:
    """Add a rule for a host that is not in the file yet. Returns the new ETag."""
    with _lock:
        document = _read_document_for_write(if_match)
        raw_forwards = document[_DOCUMENT_KEY]
        if _raw_keys_for(raw_forwards, rule.host):
            raise ForwardHostExists(rule.host)
        raw_forwards[rule.host] = rule.to_payload()
        return _save_document_locked(document)


def replace(old_host: str, rule: ForwardRule, *, if_match: str | None = None) -> str:
    """Replace the entry for *old_host* with *rule* (possibly renamed) in one write."""
    old = _deny_key(old_host)
    with _lock:
        document = _read_document_for_write(if_match)
        raw_forwards = document[_DOCUMENT_KEY]
        old_keys = _raw_keys_for(raw_forwards, old)
        if not old_keys:
            raise ForwardNotFound(old)
        if rule.host != old and _raw_keys_for(raw_forwards, rule.host):
            raise ForwardHostExists(rule.host)
        for key in old_keys:
            del raw_forwards[key]
        raw_forwards[rule.host] = rule.to_payload()
        return _save_document_locked(document)


def delete(host: str, *, if_match: str | None = None) -> bool:
    """Remove one host from the file. Returns False when absent."""
    normalized = _deny_key(host)
    with _lock:
        document = _read_document_for_write(if_match)
        raw_forwards = document[_DOCUMENT_KEY]
        keys = _raw_keys_for(raw_forwards, normalized)
        if not keys:
            return False
        for key in keys:
            del raw_forwards[key]
        _save_document_locked(document)
        return True


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
        return {host: dict(item) for host, item in _denied.items()}


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
    """Hosts whose V1 upstream base is on ``AEGIS_UPSTREAM_WHITELIST_URL_LIST``.

    Those upstreams skip both pipelines inside the V1 handler, so a rule's filter
    switches cannot take effect. Compared with the base the V1 branch actually
    uses (``llm_upstream_base``). Reported, never used to change behaviour.
    """
    with _lock:
        bases = [(host, rule.llm_upstream_base) for host, rule in _forwards.items()]
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
    affected = _whitelist_bypass_hosts(
        [(rule.host, rule.llm_upstream_base) for rule in rules]
    )
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
