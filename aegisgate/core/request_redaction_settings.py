"""Everything the request-redaction panel shows, computed server-side.

Request-side redaction is not "V1 vs V2". It is six execution surfaces, and the
``relaxed_pii_ids`` set governs four of them — including the V1 multipart
forward path, which is easy to miss because the *scoring* pass on those routes
uses the full pattern set while the pass that actually rewrites what leaves the
gateway uses the relaxed one. A console that derived any of this in the browser
would be a second implementation of the rule, free to drift from the first.

So the panel derives nothing. This module computes each rule's effective
surfaces, the master-switch overlay, and the two bypass mechanisms' real
preconditions from the same symbols the request path uses, and the browser
renders the answer.

Read-only: nothing here writes. The panel it feeds is read-only in this release.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegisgate.config.security_rules import (
    DEFAULT_RELAXED_PII_IDS,
    LOW_FALSE_POSITIVE_V1_ROUTES,
    configured_redaction_pattern_ids,
    load_security_rules,
    resolve_rules_file,
    rule_enabled,
    shadow_rules_file_candidates,
)
from aegisgate.config.settings import settings
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys

# The release that makes ``enabled: false`` actually skip compilation is the one
# that turns this on, in the same version as the switch that writes it. Shipping
# the runtime half first would leave a rule disabled with no way to bring it
# back; shipping the UI half first would grey out a row whose pattern still
# redacts traffic. Both compile sites and this panel read the same
# ``rule_enabled`` predicate, so they cannot disagree about a given entry.
ENABLED_SEMANTICS_ACTIVE = True

_RELAXED_ALL = "*"

# The four surfaces the relaxed set governs are E1, E3, E4 — plus nothing else.
# E2 and E5 always run the full set; E6 runs its own hard-coded set.
SURFACES: tuple[dict[str, Any], ...] = (
    {
        "id": "v1_pipeline_chat",
        "code": "E1",
        "label": "V1 管道层 · 对话路由",
        "pattern_set": "relaxed",
        "detail": f"{'、'.join(sorted(LOW_FALSE_POSITIVE_V1_ROUTES))}",
        "note": "打分与 {{AG_…}} 占位符替换；可还原",
        "master_switch": "enable_redaction",
    },
    {
        "id": "v1_pipeline_other",
        "code": "E2",
        "label": "V1 管道层 · 其他路由",
        "pattern_set": "full",
        "detail": "含 multipart、通用 JSON",
        "note": "使用全量集打分，不受 relaxed 集影响",
        "master_switch": "enable_redaction",
    },
    {
        "id": "v1_forward_chat",
        "code": "E3",
        "label": "V1 转发层 · 对话消息 / system / instructions / tools",
        "pattern_set": "relaxed",
        "detail": "按消息角色判定",
        "note": "常规角色 relaxed；非常规角色（如 legacy role: function）回退全量",
        "master_switch": None,
    },
    {
        "id": "v1_forward_multipart",
        "code": "E4",
        "label": "V1 转发层 · multipart 表单字段",
        "pattern_set": "relaxed",
        "detail": "/v1/files、/v1/images/edits、/v1/images/variations",
        "note": "硬编码 role=user，因此受 relaxed 集支配；与 E2 的全量集打分不同",
        "master_switch": None,
    },
    {
        "id": "v1_forward_generic",
        "code": "E5",
        "label": "V1 转发层 · 通用 /v1/<subpath> JSON",
        "pattern_set": "full",
        "detail": "按路由判定，非对话路由用全量集",
        "note": "不受 relaxed 集影响",
        "master_switch": None,
    },
    {
        "id": "v2_request",
        "code": "E6",
        "label": "V2 请求体",
        "pattern_set": "v2_fixed",
        "detail": "硬编码的 15 项集合",
        "note": "与 relaxed_pii_ids 完全解耦；修改 relaxed 集不改变任何 V2 行为",
        "master_switch": "v2_enable_request_redaction",
    },
)

# Surfaces the relaxed set governs, in the order they appear above.
RELAXED_GOVERNED_SURFACES = ("v1_pipeline_chat", "v1_forward_chat", "v1_forward_multipart")

# V1 transport-layer redaction has no off switch. Saying so explicitly is part of
# the panel's contract: it is a mandatory security baseline, not a missing toggle.
FORWARD_REDACTION_IS_MANDATORY = True


def _normalize_id(value: Any) -> str:
    return str(value or "").strip().upper()


def _relaxed_mode(rules: dict[str, Any]) -> tuple[str, list[str]]:
    """``(mode, explicit_members)`` exactly as the file spells them."""
    raw = rules.get("relaxed_pii_ids")
    if raw is None:
        return "default", []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple, set, frozenset)):
        # security_rules logs this once and falls back to the built-in default.
        return "invalid", []
    explicit = [str(item).strip() for item in raw if str(item).strip()]
    if any(_normalize_id(item) == _RELAXED_ALL for item in explicit):
        return "all", explicit
    return "custom", explicit


def _collisions(values: list[str], source: str) -> list[dict[str, Any]]:
    """Entries that differ only by case or surrounding whitespace."""
    grouped: dict[str, list[str]] = {}
    for value in values:
        grouped.setdefault(_normalize_id(value), []).append(value)
    return [
        {"normalized": key, "source": source, "raw": raw}
        for key, raw in sorted(grouped.items())
        if len(raw) > 1
    ]


def _pii_entries(rules: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """``(entries, malformed)`` for ``redaction.pii_patterns``."""
    entries: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    for index, item in enumerate(rules.get("pii_patterns") or [], start=1):
        if not isinstance(item, dict):
            # RedactionFilter calls ``item.get`` with no guard, so this entry
            # takes the V1 pipeline down. Surfacing it beats hiding it.
            malformed.append({"index": index, "value": str(item)[:80]})
            continue
        entries.append(item)
    return entries, malformed


def _regex_status(regex: Any) -> str:
    import re

    if not isinstance(regex, str) or not regex.strip():
        return "missing"
    try:
        re.compile(regex)
    except re.error:
        return "invalid"
    return "ok"


def _effective_surfaces(
    *, runtime_enabled: bool, relaxed_member: bool, relaxed_all: bool, pattern_id: str
) -> dict[str, bool]:
    from aegisgate.adapters.v2_proxy.router import V2_RELAXED_PII_IDS

    in_relaxed = relaxed_all or relaxed_member
    return {
        "v1_pipeline_chat": runtime_enabled and in_relaxed,
        "v1_pipeline_other": runtime_enabled,
        "v1_forward_chat": runtime_enabled and in_relaxed,
        "v1_forward_multipart": runtime_enabled and in_relaxed,
        "v1_forward_generic": runtime_enabled,
        "v2_request": runtime_enabled and _normalize_id(pattern_id) in V2_RELAXED_PII_IDS,
    }


def _master_switch_overlay() -> dict[str, dict[str, Any]]:
    """Which surfaces a master switch currently greys out, and which switch.

    ``enable_redaction`` governs only the V1 *pipeline*; the V1 forward path has
    no switch at all. The panel greys strictly what this says and nothing else.
    """
    values = _master_switches()
    overlay: dict[str, dict[str, Any]] = {}
    for surface in SURFACES:
        switch = surface["master_switch"]
        overlay[surface["id"]] = {
            "switch": switch,
            "active": True if switch is None else bool(values[switch]),
        }
    return overlay


def _master_switches() -> dict[str, bool]:
    return {
        "enable_redaction": bool(settings.enable_redaction),
        "enable_restoration": bool(settings.enable_restoration),
        "enable_exact_value_redaction": bool(settings.enable_exact_value_redaction),
        "v2_enable_request_redaction": bool(settings.v2_enable_request_redaction),
    }


MASTER_SWITCH_SCOPES: dict[str, str] = {
    "enable_redaction": (
        "只控制 V1 管道层的 RedactionFilter（{{AG_…}} 占位符、映射与风险报告）；"
        "**不控制** V1 转发期的 [REDACTED:ID] 脱敏"
    ),
    "enable_restoration": "只控制响应中 {{AG_…}} 的还原；对 [REDACTED:ID] 无效（后者本就不可还原）",
    "enable_exact_value_redaction": "控制精确值替换，但覆盖范围仍受各路由实现限制（见覆盖面表）",
    "v2_enable_request_redaction": "控制 V2 请求体的 PII 与精确值脱敏；关闭时二者都不执行",
}


def _field_section(rules: dict[str, Any]) -> dict[str, Any]:
    """Field rules, told as the three layers actually behave (v4 §2.5)."""
    raw = rules.get("field_value_patterns")
    items = raw if isinstance(raw, list) else []
    configured_min_len = rules.get("field_value_min_len", 12)
    try:
        parsed_min_len = int(configured_min_len)
    except (TypeError, ValueError):
        parsed_min_len = 12

    explicit: list[dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        if isinstance(item, dict):
            explicit.append({
                "index": index,
                "id": str(item.get("id", f"FIELD_SECRET_{index}")),
                "regex": str(item.get("regex", "")),
                "legacy_string": False,
            })
        elif isinstance(item, str):
            explicit.append({
                "index": index,
                "id": f"FIELD_SECRET_{index}",
                "regex": item,
                "legacy_string": True,
            })

    return {
        "mode": "explicit_yaml" if items else "code_default",
        "field_value_min_len_configured": configured_min_len,
        "editable": False,
        "explicit_rules": explicit,
        "explicit_disables_min_len": bool(items),
        "layers": [
            {
                "id": "v1_pipeline",
                "label": "V1 管道层",
                "floor": 8,
                "effective_min_len": max(8, parsed_min_len),
                "fallback_ids": ["FIELD_SECRET", "AUTH_BEARER"],
                "explicit_default_id": "FIELD_SECRET",
                "relaxed_filtered": False,
                "note": "field 规则无视路由恒跑，不受 relaxed 集过滤",
            },
            {
                "id": "v1_forward",
                "label": "V1 转发层",
                "floor": 8,
                "effective_min_len": max(8, parsed_min_len),
                "fallback_ids": ["FIELD_SECRET", "AUTH_BEARER"],
                "explicit_default_id": "FIELD_SECRET_{idx}",
                "relaxed_filtered": True,
                "note": "与 PII 规则合并后整体被 relaxed 过滤；默认 12 项不含这两个 ID，因此默认不生效",
            },
            {
                "id": "v2_request",
                "label": "V2 请求",
                "floor": 12,
                "effective_min_len": max(12, parsed_min_len),
                "fallback_ids": ["field_secret", "auth_bearer"],
                "explicit_default_id": "field_secret_{idx}",
                "relaxed_filtered": True,
                "note": "V2 的 15 项集合含 FIELD_SECRET 与 AUTH_BEARER，故两条 fallback 恒生效",
            },
        ],
    }


# v4 §2.6: which surfaces run exact-value redaction, what PII replacement looks
# like there, and whether it can be restored. The multipart *file content* row is
# the one that is easy to leave out and the most consequential.
COVERAGE_MATRIX: tuple[dict[str, Any], ...] = (
    {
        "surface": "V1 对话路由的扁平消息文本",
        "exact_value": "生效",
        "pii_form": "{{AG_…}}",
        "restorable": True,
    },
    {
        "surface": "V1 对话路由的结构化内容、instructions、工具定义",
        "exact_value": "不生效",
        "pii_form": "[REDACTED:ID]",
        "restorable": False,
    },
    {
        "surface": "V1 通用 /v1/<subpath> JSON",
        "exact_value": "不生效",
        "pii_form": "[REDACTED:ID]",
        "restorable": False,
    },
    {
        "surface": "V1 multipart 表单字段",
        "exact_value": "不生效",
        "pii_form": "[REDACTED:ID]",
        "restorable": False,
    },
    {
        "surface": "V1 multipart 文件内容",
        "exact_value": "不生效",
        "pii_form": "不脱敏、不扫描",
        "restorable": None,
        "emphasis": True,
        "note": "文件字节原样转发，分析文本里只放一个 [BINARY_CONTENT] 占位。"
                "/v1/files 是最容易夹带凭据的通道。",
    },
    {
        "surface": "V2 文本型请求体",
        "exact_value": "enable_exact_value_redaction 与 v2_enable_request_redaction 同时为 true 时生效",
        "pii_form": "[REDACTED:id]（小写）",
        "restorable": False,
    },
)


def _exemptions() -> dict[str, Any]:
    from aegisgate.adapters.openai_compat.router import WHITELIST_HEADER_DENYLIST
    from aegisgate.adapters.openai_compat.upstream import _parse_whitelist_bases
    from aegisgate.core.gw_tokens import list_tokens

    denylist = sorted(WHITELIST_HEADER_DENYLIST)
    tokens: list[dict[str, Any]] = []
    for token, meta in (list_tokens() or {}).items():
        keys: list[dict[str, Any]] = []
        for key in normalize_whitelist_keys(meta.get("whitelist_key") or []):
            hits = sorted({denied for denied in denylist if denied in key.lower()})
            keys.append({
                "key": key,
                # V1 re-filters the header through the denylist; V2 reads the
                # token scope directly and has no denylist at all. A key named
                # `access_token` is therefore dropped on V1 and honoured on V2.
                "v1_effective": not hits,
                "v2_effective": True,
                "denylist_hits": hits,
            })
        if not keys:
            continue
        tokens.append({
            "token_masked": f"{token[:6]}…{token[-4:]}" if len(token) > 12 else "…",
            "upstream_base": meta.get("upstream_base", ""),
            "keys": keys,
        })

    return {
        "field_whitelist": {
            "tokens": tokens,
            "denylist": denylist,
            "client_header_is_stripped": True,
            "note": "客户端自带的 x-aegis-redaction-whitelist 在 token 中间件与 _effective_gateway_headers "
                    "两处都会被剥离，V1/V2 的实际来源只有 token。",
        },
        "upstream_whitelist": {
            "configured_bases": sorted(_parse_whitelist_bases()),
            "allow_public_upstream_whitelist": bool(settings.allow_public_upstream_whitelist),
            "requires_internal_client": not bool(settings.allow_public_upstream_whitelist),
            "note": "allow_public_upstream_whitelist=false 且 client_is_internal 明确为 False 时，"
                    "上游白名单不再绕过过滤。",
        },
        "surface_matrix": [
            {
                "surface": "V1 对话路由 / 通用 JSON",
                "field_whitelist": "只保护指定 key/span，且 V1 侧会先过 denylist",
                "passthrough": "整请求跳过过滤",
                "upstream_whitelist": "整请求直接转发，有两个前置条件",
            },
            {
                "surface": "V1 multipart 表单字段",
                "field_whitelist": "只保护指定表单字段/span，同样过 denylist",
                "passthrough": "整请求跳过过滤",
                "upstream_whitelist": "不适用",
            },
            {
                "surface": "V1 multipart 文件内容",
                "field_whitelist": "不适用（本就不脱敏）",
                "passthrough": "不适用",
                "upstream_whitelist": "不适用",
            },
            {
                "surface": "V2",
                "field_whitelist": "只保护指定 key/span，不过 denylist",
                "passthrough": "不适用",
                "upstream_whitelist": "不适用",
            },
        ],
    }


def _resolver_report() -> dict[str, Any]:
    """Whether the historical resolvers would have agreed, and what they left behind."""
    active = resolve_rules_file()
    raw = Path(settings.security_rules_path)
    legacy_cwd = (raw if raw.is_absolute() else Path.cwd() / raw).resolve()
    shadows = [str(path) for path in shadow_rules_file_candidates()]
    return {
        "rules_file_path": str(active),
        "rules_file_exists": active.is_file(),
        "rules_file_resolver_consistent": legacy_cwd == active,
        "legacy_cwd_path": str(legacy_cwd),
        "shadow_rules_files": shadows,
    }


def build_settings_payload() -> dict[str, Any]:
    """The whole read-only panel, computed from the rules the runtime loaded."""
    from aegisgate.adapters.v2_proxy.router import V2_RELAXED_PII_IDS
    from aegisgate.core.gateway_ui_config import _ENV_PATH
    from aegisgate.core.rules_write import last_applied_write
    from aegisgate.core.ui_etag import etag_for_file

    rules = load_security_rules().get("redaction", {})
    if not isinstance(rules, dict):
        rules = {}

    mode, explicit = _relaxed_mode(rules)
    explicit_normalized = {_normalize_id(item) for item in explicit} - {_RELAXED_ALL}
    configured_ids = configured_redaction_pattern_ids(rules)

    entries, malformed = _pii_entries(rules)
    pii_ids = {_normalize_id(item.get("id", "PII")) for item in entries if item.get("regex")}
    field_ids = configured_ids - pii_ids

    if mode == "all":
        resolved: list[str] | None = None
    elif mode == "custom":
        resolved = sorted(explicit_normalized)
    else:
        resolved = sorted(DEFAULT_RELAXED_PII_IDS)
    resolved_set = set(resolved or ())

    collisions = _collisions(explicit, "relaxed_pii_ids") + _collisions(
        [str(item.get("id", "PII")) for item in entries], "pii_patterns"
    )

    relaxed_all = mode == "all"
    pii_rules: list[dict[str, Any]] = []
    pending_enabled_false: list[str] = []
    for item in entries:
        pattern_id = str(item.get("id", "PII"))
        normalized = _normalize_id(pattern_id)
        # The same predicate the compile sites use, so "disabled here" and
        # "not compiled there" can never come apart.
        enabled = rule_enabled(item)
        if not enabled and not ENABLED_SEMANTICS_ACTIVE:
            pending_enabled_false.append(pattern_id)
        relaxed_member = relaxed_all or normalized in resolved_set
        # What deleting or unlisting this rule would do to relaxed_pii_ids,
        # decided here rather than in the browser: the answer depends on the
        # relaxed *mode*, not just on membership, and a confirmation dialog that
        # describes the wrong consequence is worse than no dialog.
        if relaxed_all:
            reference = "all"
        elif mode == "custom" and normalized in explicit_normalized:
            reference = "custom_list"
        elif mode in {"default", "invalid"} and normalized in DEFAULT_RELAXED_PII_IDS:
            reference = "code_default"
        else:
            reference = "none"
        pii_rules.append({
            "id": pattern_id,
            "regex": str(item.get("regex", "")),
            "regex_status": _regex_status(item.get("regex")),
            "category": item.get("category") or None,
            "enabled": enabled,
            # Until F2 lands, the running code compiles the rule regardless of
            # ``enabled``; the surfaces below say what is happening, not what the
            # file asks for.
            "enabled_runtime": True if not ENABLED_SEMANTICS_ACTIVE else enabled,
            "relaxed_member": relaxed_member,
            "relaxed_editable": not relaxed_all,
            "relaxed_reference": reference,
            "relaxed_removal_empties_list": reference == "custom_list"
            and len(explicit_normalized) == 1,
            "effective_surfaces": _effective_surfaces(
                runtime_enabled=True if not ENABLED_SEMANTICS_ACTIVE else enabled,
                relaxed_member=relaxed_member,
                relaxed_all=relaxed_all,
                pattern_id=pattern_id,
            ),
        })

    return {
        **_resolver_report(),
        "relaxed_mode": mode,
        "relaxed_ids_explicit": explicit,
        "relaxed_ids_resolved": resolved,
        "default_relaxed_ids": sorted(DEFAULT_RELAXED_PII_IDS),
        "known_pii_ids": sorted(pii_ids),
        "known_field_ids": sorted(field_ids),
        "unresolved_ids": sorted(explicit_normalized - configured_ids),
        "normalized_collisions": collisions,
        "write_blocked": bool(collisions),
        "pii_rules": pii_rules,
        "malformed_pii_entries": malformed,
        "enabled_semantics_active": ENABLED_SEMANTICS_ACTIVE,
        "pending_enabled_false_ids": pending_enabled_false,
        "v2_effective_ids": sorted(V2_RELAXED_PII_IDS),
        "v2_field_ids_in_set": sorted(V2_RELAXED_PII_IDS & {"FIELD_SECRET", "AUTH_BEARER"}),
        "normalize_nfkc": bool(rules.get("normalize_nfkc", True)),
        "strip_invisible_chars": bool(rules.get("strip_invisible_chars", True)),
        "request_prefix_max_len": rules.get("request_prefix_max_len", 12),
        "field": _field_section(rules),
        "surfaces": [dict(surface) for surface in SURFACES],
        "relaxed_governed_surfaces": list(RELAXED_GOVERNED_SURFACES),
        "forward_redaction_is_mandatory": FORWARD_REDACTION_IS_MANDATORY,
        "master_switches": _master_switches(),
        "master_switch_scopes": dict(MASTER_SWITCH_SCOPES),
        "master_switch_overlay": _master_switch_overlay(),
        "coverage_matrix": [dict(row) for row in COVERAGE_MATRIX],
        "exemptions": _exemptions(),
        "last_applied_write": last_applied_write(),
        "env_etag": etag_for_file(_ENV_PATH),
    }


# ---------------------------------------------------------------------------
# Writes: strongly typed domain operations, never arbitrary key paths
# ---------------------------------------------------------------------------

RELAXED_PATH = ["redaction", "relaxed_pii_ids"]
REQUEST_PREFIX_MAX_LEN_BOUNDS = (1, 64)

_VALUE_FIELDS = ("normalize_nfkc", "strip_invisible_chars", "request_prefix_max_len")
_RELAXED_OPERATION_ARGS: dict[str, set[str]] = {
    "set_mode": {"mode"},
    "set_membership": {"id", "enabled", "confirm_empty", "confirm_materialize"},
    "materialize_custom": {"source", "confirm", "confirm_empty"},
    "remove_unresolved": {"id", "confirm", "confirm_empty"},
}


def _error(code: str, detail: str, status: int = 400, **extra: Any):
    from aegisgate.core.rules_write import RulesWriteError

    return RulesWriteError(code, detail, status=status, extra=extra or None)


def _require_no_unknown_keys(payload: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise _error("unknown_field", f"{where} 不支持字段：{'、'.join(unknown)}")


def _configured_pii_ids(redaction: dict[str, Any]) -> dict[str, str]:
    """``{normalized id: id as written}`` for every configured PII rule.

    Disabled rules are included: a disabled rule is still a configured one, and
    its relaxed membership must stay editable so re-enabling it has no hidden
    state (v4 §2.3).
    """
    entries, _ = _pii_entries(redaction)
    return {_normalize_id(item.get("id", "PII")): str(item.get("id", "PII")) for item in entries}


def _guard_collisions(redaction: dict[str, Any]) -> None:
    entries, _ = _pii_entries(redaction)
    collisions = _collisions(
        [str(item.get("id", "PII")) for item in entries], "pii_patterns"
    ) + _collisions([str(item) for item in _relaxed_mode(redaction)[1]], "relaxed_pii_ids")
    if collisions:
        raise _error(
            "id_normalization_conflict",
            "存在仅大小写或空白不同的重复 ID，必须先人工消除；工具不会替你选择保留哪一条："
            + "；".join(
                f"{item['source']} 中 {'、'.join(item['raw'])}" for item in collisions
            ),
            status=409,
            collisions=collisions,
        )


def _set_relaxed_list(redaction: dict[str, Any], members: list[str], confirm_empty: Any):
    from aegisgate.core.rules_editor import LeafOp

    if not members and confirm_empty is not True:
        raise _error(
            "confirm_empty_required",
            "该操作会把 relaxed 集清空，届时 V1 对话路由（管道 + 转发）与 multipart 转发上"
            "不再有任何 PII 规则生效。如确认，请带上 confirm_empty=true。",
            status=409,
        )
    redaction["relaxed_pii_ids"] = members
    return [LeafOp(list(RELAXED_PATH), "set", members)]


def _op_set_mode(payload: dict[str, Any], redaction: dict[str, Any], audit: dict[str, Any]):
    from aegisgate.core.rules_editor import LeafOp

    mode = payload.get("mode")
    if mode not in {"default", "all"}:
        raise _error(
            "invalid_mode",
            "mode 只能是 'default'（删除 key，恢复代码默认值）或 'all'（写入 [\"*\"]）；"
            "自定义列表请用 set_membership 或 materialize_custom",
        )
    audit["relaxed_mode_after"] = mode
    if mode == "default":
        # Writing today's default set back into the file would freeze it; the
        # point of "use the code default" is that it keeps tracking the code.
        redaction.pop("relaxed_pii_ids", None)
        return [LeafOp(list(RELAXED_PATH), "delete")]
    redaction["relaxed_pii_ids"] = [_RELAXED_ALL]
    return [LeafOp(list(RELAXED_PATH), "set", [_RELAXED_ALL])]


def _op_set_membership(payload: dict[str, Any], redaction: dict[str, Any], audit: dict[str, Any]):
    raw_id = payload.get("id")
    enabled = payload.get("enabled")
    if not isinstance(raw_id, str) or not raw_id.strip():
        raise _error("invalid_id", "id 必须是非空字符串")
    if not isinstance(enabled, bool):
        raise _error("invalid_type", "enabled 必须是 JSON 布尔值")

    _guard_collisions(redaction)
    normalized = _normalize_id(raw_id)
    configured = _configured_pii_ids(redaction)
    if normalized not in configured:
        raise _error(
            "unknown_pii_id",
            f"'{raw_id}' 不是当前已配置的 PII 规则 ID。新增未知 ID 会产生悬空引用，已拒绝。",
        )

    mode, explicit = _relaxed_mode(redaction)
    audit.update({"relaxed_id": configured[normalized], "relaxed_member_after": enabled})
    if mode == "all":
        raise _error(
            "relaxed_all_readonly",
            "当前 relaxed 集为 [\"*\"]，逐条成员不可编辑。先用 materialize_custom 展开为自定义列表。",
            status=409,
        )
    if mode in {"default", "invalid"}:
        if payload.get("confirm_materialize") is not True:
            raise _error(
                "materialize_required",
                "当前使用代码默认 relaxed 集（未写入文件）。逐条修改会把它固化成自定义列表，"
                "此后不再跟随代码默认值。如确认，请带上 confirm_materialize=true。",
                status=409,
                would_materialize=sorted(DEFAULT_RELAXED_PII_IDS),
            )
        baseline = sorted(DEFAULT_RELAXED_PII_IDS)
        audit["relaxed_materialized_from"] = mode
    else:
        baseline = list(explicit)

    # Incremental semantics: field ids and unresolved members this operation did
    # not name stay exactly as the file spells them.
    members = [item for item in baseline if _normalize_id(item) != normalized]
    if enabled:
        members.append(configured[normalized])
    audit["relaxed_mode_after"] = "custom"
    return _set_relaxed_list(redaction, members, payload.get("confirm_empty"))


def _op_materialize_custom(
    payload: dict[str, Any], redaction: dict[str, Any], audit: dict[str, Any]
):
    if payload.get("source", "current") != "current":
        raise _error("invalid_source", "source 只支持 'current'")
    if payload.get("confirm") is not True:
        raise _error("confirm_required", "展开为自定义列表需要 confirm=true", status=409)

    mode, _ = _relaxed_mode(redaction)
    if mode == "custom":
        raise _error("already_custom", "当前已经是自定义列表，无需展开", status=409)
    if mode == "all":
        members = sorted(configured_redaction_pattern_ids(redaction))
    else:
        members = sorted(DEFAULT_RELAXED_PII_IDS)
    audit.update({"relaxed_materialized_from": mode, "relaxed_mode_after": "custom"})
    return _set_relaxed_list(redaction, members, payload.get("confirm_empty"))


def _op_remove_unresolved(
    payload: dict[str, Any], redaction: dict[str, Any], audit: dict[str, Any]
):
    raw_id = payload.get("id")
    if not isinstance(raw_id, str) or not raw_id.strip():
        raise _error("invalid_id", "id 必须是非空字符串")
    if payload.get("confirm") is not True:
        raise _error("confirm_required", "清理悬空成员需要 confirm=true", status=409)

    mode, explicit = _relaxed_mode(redaction)
    if mode != "custom":
        raise _error(
            "not_a_custom_list",
            "只有自定义列表里才存在可清理的悬空成员",
            status=409,
        )
    normalized = _normalize_id(raw_id)
    configured = configured_redaction_pattern_ids(redaction)
    if normalized in configured:
        raise _error(
            "id_not_unresolved",
            f"'{raw_id}' 对应一条已配置的规则，请用 set_membership 移除它的 relaxed 归属",
        )
    if normalized not in {_normalize_id(item) for item in explicit}:
        raise _error("id_not_in_list", f"'{raw_id}' 不在当前 relaxed 列表中", status=404)

    audit.update({"relaxed_id": raw_id, "relaxed_unresolved_removed": True})
    members = [item for item in explicit if _normalize_id(item) != normalized]
    return _set_relaxed_list(redaction, members, payload.get("confirm_empty"))


_RELAXED_OPERATIONS = {
    "set_mode": _op_set_mode,
    "set_membership": _op_set_membership,
    "materialize_custom": _op_materialize_custom,
    "remove_unresolved": _op_remove_unresolved,
}


def _apply_values(values: Any, redaction: dict[str, Any], audit: dict[str, Any]):
    from aegisgate.core.rules_editor import LeafOp

    if not isinstance(values, dict) or not values:
        raise _error("invalid_values", "values 必须是非空对象")
    _require_no_unknown_keys(values, set(_VALUE_FIELDS), "values")
    low, high = REQUEST_PREFIX_MAX_LEN_BOUNDS
    ops = []
    for key in _VALUE_FIELDS:
        if key not in values:
            continue
        value = values[key]
        if key == "request_prefix_max_len":
            # A negative value silently truncates the prefix to "" rather than
            # erroring, so the bound is not cosmetic.
            if isinstance(value, bool) or not isinstance(value, int):
                raise _error("invalid_type", f"{key} 必须是整数")
            if not low <= value <= high:
                raise _error("out_of_range", f"{key} 必须在 {low}–{high} 之间")
        elif not isinstance(value, bool):
            raise _error("invalid_type", f"{key} 必须是 JSON 布尔值")
        redaction[key] = value
        ops.append(LeafOp(["redaction", key], "set", value))
    audit["values"] = sorted(key for key in _VALUE_FIELDS if key in values)
    return ops


def apply_settings_patch(body: Any, data: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    """Validate *body* against *data*, mutate *data*, and return ``(ops, audit)``.

    Only named domain operations are accepted — never an arbitrary key path. All
    of it runs inside the write transaction, against the document read under the
    lock, so "is this a known id?" is answered against the bytes being edited.
    """
    if not isinstance(body, dict) or not body:
        raise _error("empty_patch", "请求体不能为空")
    _require_no_unknown_keys(body, {"relaxed", "values"}, "请求体")

    redaction = data.setdefault("redaction", {})
    if not isinstance(redaction, dict):
        raise _error("invalid_redaction_section", "redaction 配置段必须是映射", status=500)

    audit: dict[str, Any] = {"relaxed_mode_before": _relaxed_mode(redaction)[0]}
    ops: list[Any] = []
    if "values" in body:
        ops.extend(_apply_values(body["values"], redaction, audit))
    if "relaxed" in body:
        payload = body["relaxed"]
        if not isinstance(payload, dict):
            raise _error("invalid_relaxed", "relaxed 必须是对象")
        operation = payload.get("operation")
        if operation not in _RELAXED_OPERATIONS:
            raise _error(
                "unknown_operation",
                f"relaxed.operation 只支持：{'、'.join(sorted(_RELAXED_OPERATIONS))}",
            )
        _require_no_unknown_keys(
            payload, {"operation"} | _RELAXED_OPERATION_ARGS[operation], f"relaxed.{operation}"
        )
        audit["relaxed_operation"] = operation
        ops.extend(_RELAXED_OPERATIONS[operation](payload, redaction, audit))
    return ops, audit


def relaxed_cleanup_for_deleted_rule(
    redaction: dict[str, Any], rule_id: str, *, confirm_referenced: bool, confirm_empty: bool
) -> tuple[list[Any], dict[str, Any]]:
    """What deleting *rule_id* should do to ``relaxed_pii_ids`` (v4 §3.B).

    Deliberately never a ``409 rule_referenced``: a dangling member changes no
    behaviour — the filter is a set intersection and simply skips it, warning
    once. Refusing the delete would force an admin through a relaxed-mode
    migration to fix something harmless, and that migration is exactly the
    "freeze the code default into the file" move this feature promises not to do.
    """
    mode, explicit = _relaxed_mode(redaction)
    normalized = _normalize_id(rule_id)

    if mode in {"default", "invalid"}:
        if normalized in {_normalize_id(item) for item in DEFAULT_RELAXED_PII_IDS}:
            return [], {
                "relaxed_dangling": True,
                "note": "该 ID 仍被代码默认 relaxed 集引用，删除后为无害悬空引用："
                        "集合过滤只会跳过它，并记录一次告警。未修改 relaxed 配置。",
            }
        return [], {}

    if mode == "all":
        return [], {}

    if normalized not in {_normalize_id(item) for item in explicit}:
        return [], {}

    if confirm_referenced:
        return [], {
            "relaxed_dangling": True,
            "note": "已按 confirm_referenced 保留 relaxed 列表中的悬空引用。",
        }

    members = [item for item in explicit if _normalize_id(item) != normalized]
    # An empty result still needs the same confirmation any other emptying does.
    ops = _set_relaxed_list(redaction, members, confirm_empty)
    return ops, {"relaxed_member_removed": True}
