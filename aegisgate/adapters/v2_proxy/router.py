"""v2 generic HTTP proxy with independent request/response safety chain."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
import re
from contextlib import AsyncExitStack
from functools import lru_cache
from typing import Any, AsyncGenerator, Mapping
from urllib.parse import urlparse

import ipaddress

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from aegisgate.config.security_rules import load_security_rules
from aegisgate.util.ip_safety import (
    is_blocked_ip as _is_blocked_ip,
    resolve_public_ips,
    bound_connect_url,
    request_host_header,
)
from aegisgate.config.redact_values import replace_exact_values
from aegisgate.config.settings import settings
from aegisgate.util.base64_detect import looks_like_base64_blob
from aegisgate.util.logger import logger
from aegisgate.util.masking import mask_for_log
from aegisgate.util.redaction_whitelist import (
    normalize_whitelist_keys,
    protected_spans_for_text,
    range_overlaps_protected,
)

router = APIRouter()

_ALL_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_V2_MAX_MATCH_IDS = 24
_DEBUG_REQUEST_BODY_MAX_CHARS = 32000
_STREAM_FLAG_DETECT_MAX_BYTES = 16_384
_V2_STREAM_PROBE_WINDOW_CHARS = 8_192
_SSE_DONE_RECOVERY_CHUNK = b"data: [DONE]\n\n"
_SSE_DONE_DETECT_TAIL_CHARS = 64
_REDACTION_WHITELIST_HEADER = "x-aegis-redaction-whitelist"
_DEBUG_HEADERS_REDACT = frozenset(
    {
        "authorization",
        "gateway-key",
        "x-aegis-signature",
        "x-aegis-timestamp",
        "x-aegis-nonce",
    }
)
_DEFAULT_FIELD_VALUE_MIN_LEN = 12
_DEFAULT_FIELD_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        "FIELD_SECRET",
        rf"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key|secret(?:_key)?)\b\s*[:=]\s*(?:bearer\s+)?[A-Za-z0-9._~+/=-]{{{_DEFAULT_FIELD_VALUE_MIN_LEN},}}",
    ),
    (
        "AUTH_BEARER",
        rf"(?i)\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{{{_DEFAULT_FIELD_VALUE_MIN_LEN},}}",
    ),
)
_V2_RELAXED_PII_IDS = frozenset(
    {
        "TOKEN",
        "JWT",
        "URL_TOKEN_QUERY",
        "COOKIE_SESSION",
        "PRIVATE_KEY_PEM",
        "AWS_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "EXCHANGE_API_SECRET",
        "CRYPTO_WIF_KEY",
        "CRYPTO_XPRV",
        "CRYPTO_SEED_PHRASE",
        "FIELD_SECRET",
        "AUTH_BEARER",
    }
)
_V2_NON_CONTENT_KEYS = frozenset({"id", "call_id", "type", "role", "name", "status"})
_V2_SKIP_REDACTION_FIELDS = frozenset(
    {
        # encryption/cipher blobs should be forwarded as-is to avoid breaking payload semantics
        "encrypted_content",
        "encrypted_payload",
        "encrypted_text",
        "ciphertext",
        "cipher",
        "iv",
        "nonce",
        "tag",
        "auth_tag",
        "mac",
        "hmac",
        "signature",
        "sig",
        "ephemeral_key",
        "ephemeral_public_key",
    }
)
_DEFAULT_DANGEROUS_COMMAND_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        "web_http_smuggling_cl_te",
        r"(?is)\bcontent-length\s*:\s*\d+\s*(?:\\r\\n|\r\n|\n)+\s*transfer-encoding\s*:\s*chunked\b",
    ),
    (
        "web_http_smuggling_te_cl",
        r"(?is)\btransfer-encoding\s*:\s*chunked\b\s*(?:\\r\\n|\r\n|\n)+\s*content-length\s*:\s*\d+",
    ),
    (
        "web_http_smuggling_te_te",
        r"(?is)\btransfer-encoding\s*:\s*(?:[^\r\n,]+,\s*)+chunked\b",
    ),
    (
        "web_http_response_splitting",
        r"(?is)(?:%0d%0a|\\r\\n|\r\n)\s*http/1\.[01]\s+\d{3}\b",
    ),
    (
        "web_http_obs_fold_header",
        r"(?is)(?:%0d%0a|\\r\\n|\r\n)[ \t]+(?:content-length|transfer-encoding|host|x-forwarded-[a-z-]+)\s*:",
    ),
)
_XSS_RULE_ID_HINTS = ("xss", "script_event")
_XSS_HIGH_CONFIDENCE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:%3c|\\x3c)\s*/?\s*script\b", re.IGNORECASE),
    re.compile(r"</\s*script\s*>\s*<\s*script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:\s*(?:alert|prompt|confirm)\s*\(", re.IGNORECASE),
    re.compile(
        r"on(?:error|load|mouseover)\s*=\s*['\"]?\s*(?:alert|prompt|confirm|document\.cookie)",
        re.IGNORECASE,
    ),
)
_V2_OBVIOUS_ONLY_BLOCK_RULE_IDS = frozenset(
    {
        # Prefer low-false-positive protocol/framing signatures only.
        "web_http_smuggling_cl_te",
        "web_http_smuggling_te_cl",
        "web_http_smuggling_te_te",
        "web_http_response_splitting",
        "web_http_obs_fold_header",
    }
)
_V2_HTTP_ATTACK_REASON_MAP: dict[str, str] = {
    "web_sqli_union_select": "检测到 SQL 注入特征（UNION SELECT）",
    "web_sqli_tautology": "检测到 SQL 注入特征（恒真条件）",
    "web_sqli_time_blind": "检测到 SQL 注入特征（时间盲注）",
    "web_xss": "检测到 XSS/脚本注入特征",
    "web_xss_script_event": "检测到 XSS/脚本注入特征",
    "web_command_injection_chain": "检测到命令注入链特征",
    "web_path_traversal": "检测到路径穿越特征",
    "web_xxe_external_entity": "检测到 XXE 外部实体注入特征",
    "web_ssti_or_log4shell": "检测到 SSTI/Log4Shell 注入特征",
    "web_ssrf_metadata": "检测到 SSRF 元数据访问特征",
    "web_crlf_header_injection": "检测到 CRLF 头注入特征",
    "web_http_smuggling_cl_te": "检测到响应正文中嵌入的 HTTP 走私特征（CL.TE）",
    "web_http_smuggling_te_cl": "检测到响应正文中嵌入的 HTTP 走私特征（TE.CL）",
    "web_http_smuggling_te_te": "检测到响应正文中嵌入的 HTTP 走私特征（TE.TE）",
    "web_http_response_splitting": "检测到响应正文中嵌入的 HTTP 响应拆分特征",
    "web_http_obs_fold_header": "检测到响应正文中嵌入的 HTTP 头折叠/混淆特征",
}
_V2_DANGER_FRAGMENT_NOTICE = "【AegisGate已处理危险疑似片段】"

_v2_async_client: httpx.AsyncClient | None = None
_v2_client_lock = asyncio.Lock()


@dataclass(frozen=True)
class _V2ValidatedTarget:
    original_url: str
    connect_urls: tuple[str, ...]
    request_host: str
    sni_hostname: str | None


def _parse_host_allowlist(raw: str) -> tuple[set[str], tuple[str, ...]]:
    exact: set[str] = set()
    suffixes: list[str] = []
    seen_suffixes: set[str] = set()
    for token in raw.split(","):
        value = token.strip().lower()
        if not value:
            continue
        if value.startswith("*."):
            value = value[2:]
        elif value.startswith("."):
            value = value[1:]
        if not value:
            continue
        if value.startswith("*"):
            value = value.lstrip("*").lstrip(".")
        if not value:
            continue
        if token.strip().startswith("*.") or token.strip().startswith("."):
            if value not in seen_suffixes:
                seen_suffixes.add(value)
                suffixes.append(value)
            continue
        exact.add(value)
    return exact, tuple(suffixes)


def _host_matches_allowlist(
    host: str, *, exact: set[str], suffixes: tuple[str, ...]
) -> bool:
    if host in exact:
        return True
    return any(host.endswith(f".{suffix}") for suffix in suffixes)


@lru_cache(maxsize=64)
def _response_filter_bypass_host_rules(raw: str) -> tuple[set[str], tuple[str, ...]]:
    return _parse_host_allowlist(raw)


@lru_cache(maxsize=64)
def _v2_target_allowlist_rules(raw: str) -> tuple[set[str], tuple[str, ...]]:
    return _parse_host_allowlist(raw)


def _target_host(target_url: str) -> str:
    try:
        return (urlparse(target_url).hostname or "").strip().lower()
    except (ValueError, AttributeError):
        return ""


def _should_bypass_v2_response_filter(target_url: str) -> bool:
    raw = (settings.v2_response_filter_bypass_hosts or "").strip()
    if not raw:
        return False
    host = _target_host(target_url)
    if not host:
        return False
    exact, suffixes = _response_filter_bypass_host_rules(raw)
    return _host_matches_allowlist(host, exact=exact, suffixes=suffixes)


def _is_v2_target_allowlisted(hostname: str) -> bool:
    raw = (settings.v2_target_allowlist or "").strip()
    # M-03: Empty allowlist = deny-all (fail-closed) rather than allow-all.
    # Operators must explicitly list permitted hostnames in AEGIS_V2_TARGET_ALLOWLIST.
    if not raw:
        return False
    host = (hostname or "").strip().lower()
    if not host:
        return False
    exact, suffixes = _v2_target_allowlist_rules(raw)
    return _host_matches_allowlist(host, exact=exact, suffixes=suffixes)


def _v2_http_limits() -> httpx.Limits:
    return httpx.Limits(
        max_connections=max(10, int(settings.upstream_max_connections)),
        max_keepalive_connections=max(
            5, int(settings.upstream_max_keepalive_connections)
        ),
    )


def _v2_http_timeout() -> httpx.Timeout:
    timeout = float(settings.upstream_timeout_seconds)
    # connect uses a capped value; read uses the full timeout for long-running requests
    connect = min(timeout, 30.0)
    # Under burst traffic allow longer pool wait than I/O timeout to reduce false
    # upstream_unreachable caused by short queueing contention.
    pool_timeout = max(timeout + 5.0, timeout * 2.0)
    return httpx.Timeout(
        connect=connect, read=timeout, write=timeout, pool=pool_timeout
    )


async def _get_v2_async_client() -> httpx.AsyncClient:
    global _v2_async_client
    if _v2_async_client is not None:
        return _v2_async_client
    async with _v2_client_lock:
        if _v2_async_client is None:
            _v2_async_client = httpx.AsyncClient(
                follow_redirects=False,
                http2=False,
                timeout=_v2_http_timeout(),
                limits=_v2_http_limits(),
            )
    return _v2_async_client


async def close_v2_async_client() -> None:
    global _v2_async_client
    if _v2_async_client is not None:
        await _v2_async_client.aclose()
        _v2_async_client = None


def _compile_patterns(
    items: list[dict[str, Any]] | None, fallback: tuple[tuple[str, str], ...]
) -> list[tuple[str, re.Pattern[str]]]:
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern_id, regex in fallback:
        try:
            compiled.append((pattern_id, re.compile(regex, re.IGNORECASE)))
        except re.error:
            continue
    for item in items or []:
        regex_value = item.get("regex")
        if not isinstance(regex_value, str) or not regex_value.strip():
            continue
        pattern_id = str(item.get("id") or "RULE").strip().lower() or "rule"
        try:
            compiled.append((pattern_id, re.compile(regex_value, re.IGNORECASE)))
        except re.error as exc:
            logger.warning("v2 pattern compile skipped id=%s error=%s", pattern_id, exc)
    return compiled


@lru_cache(maxsize=1)
def _v2_redaction_patterns() -> list[tuple[str, re.Pattern[str]]]:
    rules = load_security_rules().get("redaction", {})
    pii_patterns = rules.get("pii_patterns")
    compiled = _compile_patterns(
        pii_patterns if isinstance(pii_patterns, list) else None,
        fallback=(),
    )
    field_min_len = max(
        _DEFAULT_FIELD_VALUE_MIN_LEN,
        int(rules.get("field_value_min_len", _DEFAULT_FIELD_VALUE_MIN_LEN)),
    )
    field_patterns = rules.get("field_value_patterns")
    fallback_field_patterns = (
        (
            "field_secret",
            rf"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key|secret(?:_key)?)\b\s*[:=]\s*(?:bearer\s+)?[A-Za-z0-9._~+/=-]{{{field_min_len},}}",
        ),
        (
            "auth_bearer",
            rf"(?i)\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{{{field_min_len},}}",
        ),
    )
    compiled.extend(
        _compile_patterns(
            field_patterns if isinstance(field_patterns, list) else None,
            fallback=fallback_field_patterns,
        )
    )
    return compiled


def _normalize_pattern_id(pattern_id: str) -> str:
    return str(pattern_id or "").strip().upper()


@lru_cache(maxsize=1)
def _v2_relaxed_redaction_patterns() -> list[tuple[str, re.Pattern[str]]]:
    selected: list[tuple[str, re.Pattern[str]]] = []
    for pattern_id, pattern in _v2_redaction_patterns():
        if _normalize_pattern_id(pattern_id) in _V2_RELAXED_PII_IDS:
            selected.append((pattern_id, pattern))
    return selected


@lru_cache(maxsize=1)
def _v2_dangerous_command_patterns() -> list[tuple[str, re.Pattern[str]]]:
    sanitizer_rules = load_security_rules().get("sanitizer", {})
    command_rules = sanitizer_rules.get("command_patterns")
    return _compile_patterns(
        command_rules if isinstance(command_rules, list) else None,
        fallback=_DEFAULT_DANGEROUS_COMMAND_PATTERNS,
    )


def _v2_http_attack_reasons(matches: list[str]) -> list[str]:
    reasons: list[str] = []
    seen: set[str] = set()
    for match_id in matches:
        reason = _V2_HTTP_ATTACK_REASON_MAP.get(match_id, "检测到可疑注入攻击特征")
        key = f"{reason}|{match_id}"
        if key in seen:
            continue
        seen.add(key)
        reasons.append(f"{reason}（规则: {match_id}）")
    return reasons[:_V2_MAX_MATCH_IDS]


def _should_skip_v2_field_redaction(field: str) -> bool:
    normalized = str(field or "").strip().lower()
    if not normalized:
        return False
    if normalized in _V2_NON_CONTENT_KEYS:
        return True
    if normalized in _V2_SKIP_REDACTION_FIELDS:
        return True
    return normalized.endswith(
        (
            "_ciphertext",
            "_encrypted",
            "_encrypted_content",
            "_auth_tag",
            "_nonce",
            "_iv",
            "_mac",
            "_signature",
        )
    )


def _redact_text(
    text: str,
    *,
    field: str = "",
    whitelist_keys: set[str] | None = None,
) -> tuple[str, int, list[str], list[dict[str, str]]]:
    """Returns (redacted_text, replacement_count, hit_ids, markers).

    markers contains {kind, masked_value} for unique pattern hits (capped at _V2_MAX_MATCH_IDS).
    """
    if _should_skip_v2_field_redaction(field):
        return text, 0, [], []
    if looks_like_base64_blob(text):
        return text, 0, [], []
    value = text
    whitelist = set(normalize_whitelist_keys(whitelist_keys))
    normalized_field = str(field or "").strip().lower()
    if normalized_field and normalized_field in whitelist:
        return value, 0, [], []
    replacement_count = 0
    hit_ids: list[str] = []
    hit_set: set[str] = set()
    markers: list[dict[str, str]] = []
    for pattern_id, pattern in _v2_relaxed_redaction_patterns():
        replacement = f"[REDACTED:{pattern_id}]"
        protected_spans = protected_spans_for_text(value, whitelist)

        def _repl(m: re.Match[str], _pid: str = pattern_id) -> str:
            nonlocal replacement_count
            if protected_spans and range_overlaps_protected(
                protected_spans,
                start=m.start(),
                end=m.end(),
            ):
                return m.group(0)
            replacement_count += 1
            if _pid not in hit_set and len(hit_ids) < _V2_MAX_MATCH_IDS:
                hit_set.add(_pid)
                hit_ids.append(_pid)
                markers.append({"kind": _pid, "masked_value": mask_for_log(m.group(0))})
            return replacement

        value = pattern.sub(_repl, value)
    return value, replacement_count, hit_ids, markers


def _sanitize_json_value(
    value: Any,
    *,
    field: str = "",
    whitelist_keys: set[str] | None = None,
) -> tuple[Any, int, list[str], list[dict[str, str]]]:
    """Recursively sanitize a JSON-decoded value; returns (result, count, hit_ids, markers)."""
    if isinstance(value, str):
        return _redact_text(value, field=field, whitelist_keys=whitelist_keys)
    if isinstance(value, list):
        total = 0
        hit_ids: list[str] = []
        hit_set: set[str] = set()
        markers: list[dict[str, str]] = []
        out: list[Any] = []
        for item in value:
            next_item, next_count, next_hits, next_markers = _sanitize_json_value(
                item,
                field=field,
                whitelist_keys=whitelist_keys,
            )
            total += next_count
            out.append(next_item)
            for hit in next_hits:
                if hit not in hit_set and len(hit_ids) < _V2_MAX_MATCH_IDS:
                    hit_set.add(hit)
                    hit_ids.append(hit)
            markers.extend(next_markers)
        return out, total, hit_ids, markers
    if isinstance(value, dict):
        total = 0
        dict_hit_ids: list[str] = []
        dict_hit_set: set[str] = set()
        dict_markers: list[dict[str, str]] = []
        dict_out: dict[str, Any] = {}
        for key, item in value.items():
            next_item, next_count, next_hits, next_markers = _sanitize_json_value(
                item,
                field=str(key),
                whitelist_keys=whitelist_keys,
            )
            total += next_count
            dict_out[key] = next_item
            for hit in next_hits:
                if hit not in dict_hit_set and len(dict_hit_ids) < _V2_MAX_MATCH_IDS:
                    dict_hit_set.add(hit)
                    dict_hit_ids.append(hit)
            dict_markers.extend(next_markers)
        return dict_out, total, dict_hit_ids, dict_markers
    return value, 0, [], []


def _looks_textual_content_type(content_type: str) -> bool:
    lowered = content_type.lower()
    return (
        lowered.startswith("text/")
        or "json" in lowered
        or "xml" in lowered
        or "x-www-form-urlencoded" in lowered
        or "javascript" in lowered
        or "graphql" in lowered
    )


def _sanitize_request_body(
    body: bytes,
    content_type: str,
    *,
    whitelist_keys: set[str] | None = None,
) -> tuple[bytes, int, list[str], list[dict[str, str]]]:
    """Returns (sanitized_body, replacement_count, hit_ids, markers)."""
    if not body or not _looks_textual_content_type(content_type):
        return body, 0, [], []

    # Exact-value redaction runs first (highest priority).
    ev_count = 0
    if settings.enable_exact_value_redaction:
        text = body.decode("utf-8", errors="replace")
        replaced, ev_count = replace_exact_values(text)
        if ev_count > 0:
            body = replaced.encode("utf-8")

    if "json" in content_type.lower():
        try:
            raw = body.decode("utf-8")
            parsed = json.loads(raw)
            sanitized, count, hits, markers = _sanitize_json_value(
                parsed, whitelist_keys=whitelist_keys
            )
            total = ev_count + count
            if total <= 0:
                return body, 0, [], []
            out_body = (
                json.dumps(sanitized, ensure_ascii=False).encode("utf-8")
                if count > 0
                else body
            )
            return out_body, total, hits, markers
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            pass

    text = body.decode("utf-8", errors="replace")
    sanitized, count, hits, markers = _redact_text(text, whitelist_keys=whitelist_keys)
    total = ev_count + count
    if total <= 0:
        return body, 0, [], []
    out_body = sanitized.encode("utf-8") if count > 0 else body
    return out_body, total, hits, markers


def _detect_dangerous_commands(text: str) -> list[str]:
    return [
        pattern_id for pattern_id, _pattern in _matching_v2_dangerous_patterns(text)
    ]


def _matching_v2_dangerous_patterns(text: str) -> list[tuple[str, re.Pattern[str]]]:
    raw_matches: list[str] = []
    raw_patterns: list[tuple[str, re.Pattern[str]]] = []
    seen: set[str] = set()
    for pattern_id, pattern in _v2_dangerous_command_patterns():
        if pattern.search(text):
            if pattern_id not in seen:
                seen.add(pattern_id)
                raw_matches.append(pattern_id)
                raw_patterns.append((pattern_id, pattern))
            if len(raw_matches) >= _V2_MAX_MATCH_IDS:
                break
    if not raw_matches:
        return []

    xss_matches = [
        match_id
        for match_id in raw_matches
        if any(hint in match_id.lower() for hint in _XSS_RULE_ID_HINTS)
    ]
    if xss_matches:
        high_conf_xss = any(
            pattern.search(text) for pattern in _XSS_HIGH_CONFIDENCE_PATTERNS
        )
        if not high_conf_xss:
            # 普通网页经常包含 <script> 等标记；只有高置信载荷形态才作为注入拦截。
            raw_patterns = [
                (match_id, pattern)
                for match_id, pattern in raw_patterns
                if match_id not in xss_matches
            ]

    if not raw_patterns:
        return []

    if settings.v2_response_filter_obvious_only:
        # Strictly block only the most dangerous protocol-level signatures.
        raw_patterns = [
            (match_id, pattern)
            for match_id, pattern in raw_patterns
            if match_id in _V2_OBVIOUS_ONLY_BLOCK_RULE_IDS
        ]
        if not raw_patterns:
            return []

    return raw_patterns[:_V2_MAX_MATCH_IDS]


def _sanitize_v2_response_text(text: str) -> tuple[str, int, list[str]]:
    sanitized = text
    replacements = 0
    matched_rules: list[str] = []

    for pattern_id, pattern in _matching_v2_dangerous_patterns(text):
        rule_replacements = 0

        def _replace(_match: re.Match[str]) -> str:
            nonlocal replacements, rule_replacements
            replacements += 1
            rule_replacements += 1
            return _V2_DANGER_FRAGMENT_NOTICE

        sanitized = pattern.sub(_replace, sanitized)
        if rule_replacements > 0:
            matched_rules.append(pattern_id)

    return sanitized, replacements, matched_rules


def _sanitize_v2_response_json_value(value: Any) -> tuple[Any, int, list[str]]:
    if isinstance(value, str):
        sanitized, replacements, matched_rules = _sanitize_v2_response_text(value)
        return sanitized, replacements, matched_rules
    if isinstance(value, list):
        out_list: list[Any] = []
        total = 0
        list_matched_rules: list[str] = []
        list_seen_rules: set[str] = set()
        for item in value:
            next_value, next_count, next_rules = _sanitize_v2_response_json_value(item)
            out_list.append(next_value)
            total += next_count
            for rule in next_rules:
                if rule not in list_seen_rules:
                    list_seen_rules.add(rule)
                    list_matched_rules.append(rule)
        return out_list, total, list_matched_rules
    if isinstance(value, dict):
        out_dict: dict[str, Any] = {}
        total = 0
        dict_matched_rules: list[str] = []
        dict_seen_rules: set[str] = set()
        for key, item in value.items():
            next_value, next_count, next_rules = _sanitize_v2_response_json_value(item)
            out_dict[key] = next_value
            total += next_count
            for rule in next_rules:
                if rule not in dict_seen_rules:
                    dict_seen_rules.add(rule)
                    dict_matched_rules.append(rule)
        return out_dict, total, dict_matched_rules
    return value, 0, []


def _sanitize_v2_response_body(
    body: bytes,
    content_type: str,
) -> tuple[bytes, int, list[str]]:
    if not body or not _looks_textual_content_type(content_type):
        return body, 0, []

    lowered = content_type.lower()
    if "json" in lowered:
        try:
            parsed = json.loads(body.decode("utf-8"))
            sanitized, replacements, matched_rules = _sanitize_v2_response_json_value(
                parsed
            )
            if replacements <= 0:
                return body, 0, []
            return (
                json.dumps(sanitized, ensure_ascii=False).encode("utf-8"),
                replacements,
                matched_rules,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            pass

    text = body.decode("utf-8", errors="replace")
    sanitized_text, replacements, matched_rules = _sanitize_v2_response_text(text)
    if replacements <= 0:
        return body, 0, []
    return sanitized_text.encode("utf-8"), replacements, matched_rules


def _apply_v2_response_sanitize_headers(
    response_headers: dict[str, str],
    *,
    replacements: int,
    matched_rules: list[str],
) -> None:
    if replacements <= 0:
        return
    response_headers["x-aegis-v2-response-sanitized"] = "true"
    response_headers["x-aegis-v2-response-sanitized-count"] = str(replacements)
    response_headers["x-aegis-v2-response-rule-count"] = str(len(matched_rules))
    if matched_rules:
        response_headers["x-aegis-v2-response-rule-ids"] = ",".join(
            matched_rules[:_V2_MAX_MATCH_IDS]
        )


def _extend_stream_probe_window(
    probe_window: str,
    piece: str,
    *,
    inspected_chars: int,
    max_chars: int,
    max_window_chars: int,
) -> tuple[str, int, list[str]]:
    """Incrementally scan a bounded tail window instead of rescanning the full probe text."""
    if not piece or inspected_chars >= max_chars:
        return probe_window, inspected_chars, []

    remain = max_chars - inspected_chars
    if remain <= 0:
        return probe_window, inspected_chars, []

    capped_piece = piece[:remain]
    if not capped_piece:
        return probe_window, inspected_chars, []

    inspected_chars += len(capped_piece)
    probe_window = f"{probe_window}{capped_piece}"
    if len(probe_window) > max_window_chars:
        probe_window = probe_window[-max_window_chars:]

    return probe_window, inspected_chars, _detect_dangerous_commands(probe_window)


_V2_TARGET_URL_HEADER = "x-target-url"


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


async def _resolve_public_target_ips(
    hostname: str,
) -> tuple[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...], str | None]:
    """Resolve target hostname via shared async DNS with SSRF protection."""
    return await resolve_public_ips(hostname)


async def _extract_target_url(
    request: Request,
) -> tuple[_V2ValidatedTarget | None, str | None]:
    value = request.headers.get(_V2_TARGET_URL_HEADER, "").strip()
    if not value:
        return None, f"missing required header: {_V2_TARGET_URL_HEADER}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return (
            None,
            f"invalid target url in header {_V2_TARGET_URL_HEADER}: scheme must be http/https",
        )
    hostname = (parsed.hostname or "").strip().lower()
    if not _is_v2_target_allowlisted(hostname):
        return None, "target url host is not in v2 target allowlist"
    connect_urls = (value,)
    sni_hostname: str | None = None
    if settings.v2_block_internal_targets:
        resolved, error = await _resolve_public_target_ips(hostname)
        if error is not None:
            return None, error
        if resolved and not _is_ip_literal(hostname):
            connect_urls = tuple(bound_connect_url(parsed, addr) for addr in resolved)
            if parsed.scheme == "https":
                sni_hostname = hostname
    return (
        _V2ValidatedTarget(
            original_url=value,
            connect_urls=connect_urls,
            request_host=request_host_header(parsed),
            sni_hostname=sni_hostname,
        ),
        None,
    )


def _bound_request_headers(
    headers: Mapping[str, str],
    *,
    request_host: str,
) -> dict[str, str]:
    bound_headers = dict(headers)
    if request_host:
        bound_headers["Host"] = request_host
    return bound_headers


def _bound_request_extensions(
    *,
    sni_hostname: str | None,
) -> dict[str, str] | None:
    if not sni_hostname:
        return None
    return {"sni_hostname": sni_hostname}


async def _request_v2_upstream(
    *,
    client: httpx.AsyncClient,
    method: str,
    target: _V2ValidatedTarget,
    headers: Mapping[str, str],
    content: bytes,
) -> httpx.Response:
    last_error: httpx.HTTPError | None = None
    bound_headers = _bound_request_headers(headers, request_host=target.request_host)
    extensions = _bound_request_extensions(sni_hostname=target.sni_hostname)
    for connect_url in target.connect_urls:
        try:
            return await client.request(
                method=method,
                url=connect_url,
                headers=bound_headers,
                content=content,
                extensions=extensions,
            )
        except httpx.HTTPError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


async def _open_v2_stream(
    *,
    client: httpx.AsyncClient,
    method: str,
    target: _V2ValidatedTarget,
    headers: Mapping[str, str],
    content: bytes,
) -> tuple[AsyncExitStack, httpx.Response]:
    last_error: httpx.HTTPError | None = None
    bound_headers = _bound_request_headers(headers, request_host=target.request_host)
    extensions = _bound_request_extensions(sni_hostname=target.sni_hostname)
    for connect_url in target.connect_urls:
        exit_stack = AsyncExitStack()
        try:
            response = await exit_stack.enter_async_context(
                client.stream(
                    method,
                    connect_url,
                    headers=bound_headers,
                    content=content,
                    extensions=extensions,
                )
            )
            return exit_stack, response
        except httpx.HTTPError as exc:
            last_error = exc
            await exit_stack.aclose()
    assert last_error is not None
    raise last_error


def _connection_scoped_headers(headers: Mapping[str, str]) -> set[str]:
    scoped: set[str] = set()
    for key, value in headers.items():
        if key.lower() != "connection":
            continue
        for token in value.split(","):
            name = token.strip().lower()
            if name:
                scoped.add(name)
    return scoped


def _build_forward_headers(request: Request) -> dict[str, str]:
    connection_scoped = _connection_scoped_headers(request.headers)
    excluded = {
        "host",
        "content-length",
        _V2_TARGET_URL_HEADER,
        settings.upstream_base_header.lower(),
        settings.upstream_base_header.replace("-", "_").lower(),
        settings.gateway_key_header.lower(),
        settings.gateway_key_header.replace("-", "_").lower(),
        *_HOP_BY_HOP_HEADERS,
    }
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        lowered = key.lower()
        if lowered in excluded:
            continue
        if lowered in connection_scoped:
            continue
        if lowered.startswith("x-aegis-") or lowered.startswith("x_aegis_"):
            continue
        headers[key] = value
    return headers


def _build_client_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    connection_scoped = _connection_scoped_headers(headers)
    excluded = {
        "content-length",
        "content-encoding",
        "set-cookie",
        "set-cookie2",
        *_HOP_BY_HOP_HEADERS,
    }
    out: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in excluded:
            continue
        if lowered in connection_scoped:
            continue
        out[key] = value
    return out


def _extract_redaction_whitelist_keys(request: Request) -> set[str]:
    # Security default: only allow whitelist keys injected by the gateway token middleware.
    # Ignore any client-supplied x-aegis-redaction-whitelist header.
    keys = normalize_whitelist_keys(request.scope.get("aegis_redaction_whitelist_keys"))
    return set(keys)


def _request_prefers_streaming(
    request: Request, body: bytes, content_type: str
) -> bool:
    accept = (request.headers.get("accept") or "").lower()
    if "text/event-stream" in accept:
        return True
    if "json" not in content_type.lower():
        return False
    sample = body[:_STREAM_FLAG_DETECT_MAX_BYTES]
    return bool(re.search(rb'"stream"\s*:\s*true\b', sample, re.IGNORECASE))


def _sse_done_seen_from_chunk(chunk: bytes, *, tail: str) -> tuple[bool, str]:
    text = tail + chunk.decode("utf-8", errors="ignore")
    done_seen = "data: [DONE]" in text or "data:[DONE]" in text
    new_tail = text[-_SSE_DONE_DETECT_TAIL_CHARS:] if text else ""
    return done_seen, new_tail


async def _proxy_v2_streaming(
    *,
    request: Request,
    client: httpx.AsyncClient,
    target: _V2ValidatedTarget,
    forward_headers: dict[str, str],
    outbound_body: bytes,
    redaction_count: int,
) -> Response:
    try:
        exit_stack, upstream_response = await _open_v2_stream(
            client=client,
            method=request.method,
            target=target,
            headers=forward_headers,
            content=outbound_body,
        )
    except httpx.HTTPError as exc:
        detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
        logger.warning(
            "v2 upstream unreachable target=%s error=%s",
            target.original_url,
            detail,
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": f"upstream_unreachable: {detail}",
                    "type": "aegisgate_v2_error",
                    "code": "upstream_unreachable",
                }
            },
        )

    response_headers = _build_client_response_headers(upstream_response.headers)
    if redaction_count > 0:
        response_headers["x-aegis-v2-request-redacted"] = "true"
        response_headers["x-aegis-v2-redaction-count"] = str(redaction_count)

    response_content_type = upstream_response.headers.get("content-type", "")
    is_textual = _looks_textual_content_type(response_content_type)
    is_sse = "text/event-stream" in response_content_type.lower()
    response_filter_bypassed = _should_bypass_v2_response_filter(target.original_url)
    if response_filter_bypassed:
        logger.info(
            "v2 response filter bypass method=%s path=%s target=%s host=%s",
            request.method,
            request.url.path,
            target.original_url,
            _target_host(target.original_url),
        )

    buffered_chunks: list[bytes] = []
    upstream_exhausted = False
    sanitized_stream_matches: list[str] = []
    upstream_iter = upstream_response.aiter_bytes()
    if (
        settings.v2_enable_response_command_filter
        and not response_filter_bypassed
        and is_textual
    ):
        max_chars = max(1_000, int(settings.v2_response_filter_max_chars))
        if is_sse:
            max_chars = max(
                256,
                max_chars,
                int(settings.v2_sse_filter_probe_max_chars),
            )
        probe_window = ""
        max_window_chars = max(1_024, min(max_chars, _V2_STREAM_PROBE_WINDOW_CHARS))
        inspected_chars = 0
        matches: list[str] = []
        async for chunk in upstream_iter:
            if chunk:
                buffered_chunks.append(chunk)
                if inspected_chars < max_chars:
                    piece = chunk.decode("utf-8", errors="replace")
                    probe_window, inspected_chars, matches = (
                        _extend_stream_probe_window(
                            probe_window,
                            piece,
                            inspected_chars=inspected_chars,
                            max_chars=max_chars,
                            max_window_chars=max_window_chars,
                        )
                    )
                    if matches:
                        break
            if inspected_chars >= max_chars:
                break
        else:
            upstream_exhausted = True

        if matches:
            buffered_body = b"".join(buffered_chunks)
            sanitized_body, replacements, sanitized_stream_matches = (
                _sanitize_v2_response_body(buffered_body, response_content_type)
            )
            if replacements > 0:
                buffered_chunks = [sanitized_body]
                _apply_v2_response_sanitize_headers(
                    response_headers,
                    replacements=replacements,
                    matched_rules=sanitized_stream_matches,
                )
                logger.warning(
                    "v2 response sanitized stream method=%s path=%s target=%s status=%s replacements=%s matches=%s",
                    request.method,
                    request.url.path,
                    target.original_url,
                    upstream_response.status_code,
                    replacements,
                    sanitized_stream_matches,
                )
            else:
                sanitized_stream_matches = matches
            logger.warning(
                "v2 response stream probe matched method=%s path=%s target=%s status=%s matches=%s passthrough_after_sanitize=%s",
                request.method,
                request.url.path,
                target.original_url,
                upstream_response.status_code,
                matches,
                bool(replacements > 0),
            )

    async def _iter_body() -> AsyncGenerator[bytes, None]:
        saw_done = False
        sse_tail = ""
        inject_done = False
        try:
            for chunk in buffered_chunks:
                if not chunk:
                    continue
                if is_sse:
                    detected, sse_tail = _sse_done_seen_from_chunk(chunk, tail=sse_tail)
                    saw_done = saw_done or detected
                if settings.enable_exact_value_redaction:
                    chunk_text = chunk.decode("utf-8", errors="replace")
                    replaced, ev_count = replace_exact_values(chunk_text)
                    if ev_count > 0:
                        chunk = replaced.encode("utf-8")
                yield chunk
            if not upstream_exhausted:
                async for chunk in upstream_iter:
                    if not chunk:
                        continue
                    if is_sse:
                        detected, sse_tail = _sse_done_seen_from_chunk(
                            chunk, tail=sse_tail
                        )
                        saw_done = saw_done or detected
                    if settings.enable_exact_value_redaction:
                        chunk_text = chunk.decode("utf-8", errors="replace")
                        replaced, ev_count = replace_exact_values(chunk_text)
                        if ev_count > 0:
                            chunk = replaced.encode("utf-8")
                    yield chunk
        except httpx.HTTPError as exc:
            detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
            logger.warning(
                "v2 upstream stream interrupted target=%s error=%s",
                target.original_url,
                detail,
            )
        finally:
            if is_sse and not saw_done:
                inject_done = True
            await exit_stack.aclose()
        if inject_done:
            logger.warning(
                "v2 sse upstream closed without DONE method=%s path=%s target=%s inject_done=true",
                request.method,
                request.url.path,
                target.original_url,
            )
            yield _SSE_DONE_RECOVERY_CHUNK

    return StreamingResponse(
        _iter_body(),
        status_code=upstream_response.status_code,
        headers=response_headers,
    )


def _log_v2_request_if_debug(request: Request, body: bytes) -> None:
    if not logger.isEnabledFor(logging.DEBUG):
        return

    headers_safe: dict[str, str] = {}
    for key, value in request.headers.items():
        key_lower = key.lower()
        if (
            key_lower in _DEBUG_HEADERS_REDACT
            or "key" in key_lower
            or "secret" in key_lower
            or "token" in key_lower
        ):
            headers_safe[key] = "***"
        else:
            headers_safe[key] = value

    content_type = request.headers.get("content-type", "")
    body_size = len(body)
    logger.debug(
        "incoming v2 request method=%s path=%s headers=%s body_size=%d content_type=%s",
        request.method,
        request.url.path,
        headers_safe,
        body_size,
        content_type,
    )
    if not settings.log_full_request_body:
        return

    body_text: str
    if _looks_textual_content_type(content_type):
        body_text = body.decode("utf-8", errors="replace")
        if "json" in content_type.lower():
            try:
                parsed = json.loads(body_text)
                body_text = json.dumps(parsed, ensure_ascii=False, indent=2)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
    else:
        body_text = f"<non-text body len={body_size}>"

    total_len = len(body_text)
    if total_len <= _DEBUG_REQUEST_BODY_MAX_CHARS:
        logger.debug("incoming v2 request body (%d chars):\n%s", total_len, body_text)
        return

    offset = 0
    segment = 0
    while offset < total_len:
        chunk = body_text[offset : offset + _DEBUG_REQUEST_BODY_MAX_CHARS]
        segment += 1
        logger.debug(
            "incoming v2 request body segment %d (chars %d-%d of %d):\n%s",
            segment,
            offset + 1,
            min(offset + _DEBUG_REQUEST_BODY_MAX_CHARS, total_len),
            total_len,
            chunk,
        )
        offset += _DEBUG_REQUEST_BODY_MAX_CHARS


@router.api_route("/v2", methods=list(_ALL_METHODS))
@router.api_route("/v2/{proxy_path:path}", methods=list(_ALL_METHODS))
async def proxy_v2(request: Request, proxy_path: str = "") -> Response:
    del proxy_path

    target, err = await _extract_target_url(request)
    if err:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": err,
                    "type": "aegisgate_v2_error",
                    "code": "missing_target_url_header",
                }
            },
        )
    assert target is not None

    request_body = await request.body()
    _log_v2_request_if_debug(request, request_body)
    original_content_type = request.headers.get("content-type", "")
    redaction_hits: list[str] = []
    redaction_count = 0
    outbound_body = request_body
    whitelist_keys = _extract_redaction_whitelist_keys(request)
    if settings.v2_enable_request_redaction:
        outbound_body, redaction_count, redaction_hits, redaction_markers = (
            _sanitize_request_body(
                request_body,
                original_content_type,
                whitelist_keys=whitelist_keys,
            )
        )
        if redaction_count > 0:
            client_ip = (request.client.host if request.client else None) or "-"
            user_agent = request.headers.get("user-agent", "-")
            # WARNING 级别：含敏感字段的请求属于安全审计事件
            logger.warning(
                "v2 redaction method=%s path=%s target=%s client_ip=%s user_agent=%s replacements=%d hit_ids=%s markers=%s",
                request.method,
                request.url.path,
                target.original_url,
                client_ip,
                user_agent,
                redaction_count,
                redaction_hits,
                redaction_markers,
            )

    forward_headers = _build_forward_headers(request)
    client = await _get_v2_async_client()
    if _request_prefers_streaming(request, outbound_body, original_content_type):
        return await _proxy_v2_streaming(
            request=request,
            client=client,
            target=target,
            forward_headers=forward_headers,
            outbound_body=outbound_body,
            redaction_count=redaction_count,
        )

    try:
        upstream_response = await _request_v2_upstream(
            client=client,
            method=request.method,
            target=target,
            headers=forward_headers,
            content=outbound_body,
        )
    except httpx.HTTPError as exc:
        detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
        logger.warning(
            "v2 upstream unreachable target=%s error=%s",
            target.original_url,
            detail,
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": f"upstream_unreachable: {detail}",
                    "type": "aegisgate_v2_error",
                    "code": "upstream_unreachable",
                }
            },
        )

    response_headers = _build_client_response_headers(upstream_response.headers)
    response_body = upstream_response.content
    response_content_type = upstream_response.headers.get("content-type", "")

    # Exact-value redaction on non-streaming response body.
    if (
        settings.enable_exact_value_redaction
        and response_body
        and _looks_textual_content_type(response_content_type)
    ):
        text = response_body.decode("utf-8", errors="replace")
        replaced, ev_count = replace_exact_values(text)
        if ev_count > 0:
            response_body = replaced.encode("utf-8")

    response_filter_bypassed = _should_bypass_v2_response_filter(target.original_url)
    if response_filter_bypassed:
        logger.info(
            "v2 response filter bypass method=%s path=%s target=%s host=%s",
            request.method,
            request.url.path,
            target.original_url,
            _target_host(target.original_url),
        )
    if (
        settings.v2_enable_response_command_filter
        and not response_filter_bypassed
        and response_body
        and _looks_textual_content_type(response_content_type)
    ):
        max_chars = max(1_000, int(settings.v2_response_filter_max_chars))
        probe_body = response_body[: max_chars * 4]
        sanitized_body, replacements, matches = _sanitize_v2_response_body(
            probe_body if len(probe_body) == len(response_body) else response_body,
            response_content_type,
        )
        if replacements > 0:
            response_body = sanitized_body
            _apply_v2_response_sanitize_headers(
                response_headers,
                replacements=replacements,
                matched_rules=matches,
            )
            logger.warning(
                "v2 response sanitized method=%s path=%s target=%s status=%s replacements=%s matches=%s",
                request.method,
                request.url.path,
                target.original_url,
                upstream_response.status_code,
                replacements,
                matches,
            )

    if redaction_count > 0:
        response_headers["x-aegis-v2-request-redacted"] = "true"
        response_headers["x-aegis-v2-redaction-count"] = str(redaction_count)
    return Response(
        content=response_body,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )
