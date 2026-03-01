"""v2 generic HTTP proxy with independent request/response safety chain."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from functools import lru_cache
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from aegisgate.config.security_rules import load_security_rules
from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

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
_DEBUG_HEADERS_REDACT = frozenset(
    {"authorization", "gateway-key", "x-aegis-signature", "x-aegis-timestamp", "x-aegis-nonce"}
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
_DEFAULT_DANGEROUS_COMMAND_PATTERNS: tuple[tuple[str, str], ...] = (
    ("web_sqli_union_select", r"\bunion\s+select\b"),
    ("web_sqli_tautology", r"\b(?:or|and)\s+1\s*=\s*1\b"),
    ("web_sqli_time_blind", r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d+\s*\)"),
    ("web_xss_script_event", r"(?:<\s*script\b|on(?:error|load|mouseover)\s*=|javascript:\s*)"),
    ("web_command_injection_chain", r"(?:;|\|\||&&|\|)\s*(?:curl|wget|bash|sh|nc|python3?|perl|powershell|cmd(?:\.exe)?)\b"),
    ("web_path_traversal", r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e%252f|/etc/passwd\b|/proc/self/environ\b|win\.ini\b)"),
    ("web_xxe_external_entity", r"(?:<!DOCTYPE[^>]*\[[\s\S]{0,200}?<!ENTITY|<!ENTITY\s+%?\w+\s+SYSTEM\s+(?:file|https?)://)"),
    ("web_ssti_or_log4shell", r"(?:\{\{\s*7\s*\*\s*7\s*\}\}|\$\{jndi:(?:ldap|rmi|dns|iiop)://)"),
    ("web_ssrf_metadata", r"(?:https?://)?(?:169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal)(?::\d+)?(?:/|\b)"),
    ("web_crlf_header_injection", r"(?:%0d%0a|\r\n)\s*(?:set-cookie:|location:|x-forwarded-)"),
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
        r"on(?:error|load|mouseover)\s*=\s*['\"]?\s*(?:alert|prompt|confirm|document\.cookie|fetch\s*\(|xmlhttprequest)",
        re.IGNORECASE,
    ),
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
    "web_http_smuggling_cl_te": "检测到 HTTP 请求走私特征（CL.TE）",
    "web_http_smuggling_te_cl": "检测到 HTTP 请求走私特征（TE.CL）",
    "web_http_smuggling_te_te": "检测到 HTTP 请求走私特征（TE.TE）",
    "web_http_response_splitting": "检测到 HTTP 响应拆分特征",
    "web_http_obs_fold_header": "检测到 HTTP 头折叠/混淆特征",
    "request_framing_cl_te_conflict": "检测到请求报文边界冲突（CL+TE）",
    "request_framing_multiple_content_length": "检测到请求存在重复 Content-Length",
    "request_framing_multiple_transfer_encoding": "检测到请求存在重复 Transfer-Encoding",
    "request_framing_invalid_content_length": "检测到请求 Content-Length 非法",
    "request_framing_te_ambiguous_value": "检测到请求 Transfer-Encoding 值可疑",
    "request_framing_header_control_chars": "检测到请求头包含控制字符",
    "response_framing_cl_te_conflict": "检测到上游响应报文边界冲突（CL+TE）",
    "response_framing_multiple_content_length": "检测到上游响应存在重复 Content-Length",
    "response_framing_multiple_transfer_encoding": "检测到上游响应存在重复 Transfer-Encoding",
    "response_framing_invalid_content_length": "检测到上游响应 Content-Length 非法",
    "response_framing_te_ambiguous_value": "检测到上游响应 Transfer-Encoding 值可疑",
    "response_framing_header_control_chars": "检测到上游响应头包含控制字符",
}

_v2_async_client: httpx.AsyncClient | None = None
_v2_client_lock: asyncio.Lock | None = None


def _v2_http_limits() -> httpx.Limits:
    return httpx.Limits(
        max_connections=max(10, int(settings.upstream_max_connections)),
        max_keepalive_connections=max(5, int(settings.upstream_max_keepalive_connections)),
    )


def _v2_http_timeout() -> httpx.Timeout:
    timeout = float(settings.upstream_timeout_seconds)
    return httpx.Timeout(connect=timeout, read=timeout, write=timeout, pool=timeout)


async def _get_v2_async_client() -> httpx.AsyncClient:
    global _v2_async_client, _v2_client_lock
    if _v2_async_client is not None:
        return _v2_async_client
    if _v2_client_lock is None:
        _v2_client_lock = asyncio.Lock()
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


def _compile_patterns(items: list[dict[str, Any]] | None, fallback: tuple[tuple[str, str], ...]) -> list[tuple[str, re.Pattern[str]]]:
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern_id, regex in fallback:
        try:
            compiled.append((pattern_id, re.compile(regex, re.IGNORECASE)))
        except re.error:
            continue
    for item in items or []:
        regex = item.get("regex")
        if not isinstance(regex, str) or not regex.strip():
            continue
        pattern_id = str(item.get("id") or "RULE").strip().lower() or "rule"
        try:
            compiled.append((pattern_id, re.compile(regex, re.IGNORECASE)))
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
    field_min_len = max(_DEFAULT_FIELD_VALUE_MIN_LEN, int(rules.get("field_value_min_len", _DEFAULT_FIELD_VALUE_MIN_LEN)))
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
        _compile_patterns(field_patterns if isinstance(field_patterns, list) else None, fallback=fallback_field_patterns)
    )
    return compiled


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


def _redact_text(text: str) -> tuple[str, int, list[str]]:
    value = text
    replacement_count = 0
    hit_ids: list[str] = []
    hit_set: set[str] = set()
    for pattern_id, pattern in _v2_redaction_patterns():
        replacement = f"[REDACTED:{pattern_id}]"

        def _repl(_: re.Match[str]) -> str:
            nonlocal replacement_count
            replacement_count += 1
            if pattern_id not in hit_set and len(hit_ids) < _V2_MAX_MATCH_IDS:
                hit_set.add(pattern_id)
                hit_ids.append(pattern_id)
            return replacement

        value = pattern.sub(_repl, value)
    return value, replacement_count, hit_ids


def _sanitize_json_value(value: Any) -> tuple[Any, int, list[str]]:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        total = 0
        hit_ids: list[str] = []
        hit_set: set[str] = set()
        out: list[Any] = []
        for item in value:
            next_item, next_count, next_hits = _sanitize_json_value(item)
            total += next_count
            out.append(next_item)
            for hit in next_hits:
                if hit not in hit_set and len(hit_ids) < _V2_MAX_MATCH_IDS:
                    hit_set.add(hit)
                    hit_ids.append(hit)
        return out, total, hit_ids
    if isinstance(value, dict):
        total = 0
        hit_ids = []
        hit_set: set[str] = set()
        out: dict[str, Any] = {}
        for key, item in value.items():
            next_item, next_count, next_hits = _sanitize_json_value(item)
            total += next_count
            out[key] = next_item
            for hit in next_hits:
                if hit not in hit_set and len(hit_ids) < _V2_MAX_MATCH_IDS:
                    hit_set.add(hit)
                    hit_ids.append(hit)
        return out, total, hit_ids
    return value, 0, []


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


def _sanitize_request_body(body: bytes, content_type: str) -> tuple[bytes, int, list[str]]:
    if not body or not _looks_textual_content_type(content_type):
        return body, 0, []

    if "json" in content_type.lower():
        try:
            raw = body.decode("utf-8")
            parsed = json.loads(raw)
            sanitized, count, hits = _sanitize_json_value(parsed)
            if count <= 0:
                return body, 0, []
            return json.dumps(sanitized, ensure_ascii=False).encode("utf-8"), count, hits
        except Exception:
            pass

    text = body.decode("utf-8", errors="replace")
    sanitized, count, hits = _redact_text(text)
    if count <= 0:
        return body, 0, []
    return sanitized.encode("utf-8"), count, hits


def _raw_header_values(request: Request, header_name: str) -> list[str]:
    name = header_name.lower().encode("latin-1")
    values: list[str] = []
    for raw_key, raw_value in request.scope.get("headers", []):
        if raw_key.lower() != name:
            continue
        values.append(raw_value.decode("latin-1", errors="ignore"))
    return values


def _header_values(headers: Mapping[str, str], header_name: str) -> list[str]:
    values: list[str] = []
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        for value in get_list(header_name):
            values.append(str(value))
    else:
        value = headers.get(header_name, "")
        if value:
            values.append(str(value))
    return values


def _has_header_control_chars(values: list[str]) -> bool:
    for value in values:
        if any(ch in value for ch in ("\r", "\n", "\x00")):
            return True
    return False


def _collect_framing_anomalies(
    *,
    content_length_values: list[str],
    transfer_encoding_values: list[str],
    prefix: str,
) -> list[str]:
    issues: list[str] = []
    cl_values = [value.strip() for value in content_length_values if value is not None]
    te_values = [value.strip().lower() for value in transfer_encoding_values if value is not None]

    if len(cl_values) > 1:
        issues.append(f"{prefix}_multiple_content_length")
    if len(te_values) > 1:
        issues.append(f"{prefix}_multiple_transfer_encoding")
    if cl_values and te_values:
        issues.append(f"{prefix}_cl_te_conflict")
    if any(not re.fullmatch(r"\d+", value) for value in cl_values if value):
        issues.append(f"{prefix}_invalid_content_length")
    if any("chunked" in value and "," in value for value in te_values):
        issues.append(f"{prefix}_te_ambiguous_value")
    if _has_header_control_chars(cl_values) or _has_header_control_chars(te_values):
        issues.append(f"{prefix}_header_control_chars")

    deduped: list[str] = []
    for issue in issues:
        if issue not in deduped:
            deduped.append(issue)
    return deduped


def _detect_request_framing_anomalies(request: Request) -> list[str]:
    return _collect_framing_anomalies(
        content_length_values=_raw_header_values(request, "content-length"),
        transfer_encoding_values=_raw_header_values(request, "transfer-encoding"),
        prefix="request_framing",
    )


def _detect_response_framing_anomalies(headers: Mapping[str, str]) -> list[str]:
    return _collect_framing_anomalies(
        content_length_values=_header_values(headers, "content-length"),
        transfer_encoding_values=_header_values(headers, "transfer-encoding"),
        prefix="response_framing",
    )


def _detect_dangerous_commands(text: str) -> list[str]:
    raw_matches: list[str] = []
    seen: set[str] = set()
    for pattern_id, pattern in _v2_dangerous_command_patterns():
        if pattern.search(text):
            if pattern_id not in seen:
                seen.add(pattern_id)
                raw_matches.append(pattern_id)
            if len(raw_matches) >= _V2_MAX_MATCH_IDS:
                break
    if not raw_matches:
        return []

    xss_matches = [match_id for match_id in raw_matches if any(hint in match_id.lower() for hint in _XSS_RULE_ID_HINTS)]
    if xss_matches:
        high_conf_xss = any(pattern.search(text) for pattern in _XSS_HIGH_CONFIDENCE_PATTERNS)
        if not high_conf_xss:
            # 普通网页经常包含 <script> 等标记；只有高置信载荷形态才作为注入拦截。
            raw_matches = [match_id for match_id in raw_matches if match_id not in xss_matches]

    return raw_matches[:_V2_MAX_MATCH_IDS]


def _target_url_header_candidates() -> list[str]:
    configured = (settings.v2_original_url_header or "").strip()
    candidates: list[str] = []
    if configured:
        candidates.append(configured)
    for alias in ("x-target-url", "x-original-url"):
        if not configured or alias.lower() != configured.lower():
            candidates.append(alias)
    return candidates


def _extract_target_url(request: Request) -> tuple[str | None, str | None]:
    value = ""
    matched_header = ""
    for header_name in _target_url_header_candidates():
        candidate = request.headers.get(header_name, "").strip()
        if candidate:
            value = candidate
            matched_header = header_name
            break
    if not value:
        accepted = ", ".join(_target_url_header_candidates())
        return None, f"missing required target-url header (accepted: {accepted})"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None, f"invalid target url in header: {matched_header or settings.v2_original_url_header}"
    return value, None


def _build_forward_headers(request: Request) -> dict[str, str]:
    excluded = {
        "host",
        "content-length",
        settings.upstream_base_header.lower(),
        settings.gateway_key_header.lower(),
        settings.gateway_key_header.replace("-", "_").lower(),
        *_HOP_BY_HOP_HEADERS,
    }
    for header_name in _target_url_header_candidates():
        excluded.add(header_name.lower())
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        lowered = key.lower()
        if lowered in excluded:
            continue
        if lowered.startswith("x-aegis-"):
            continue
        headers[key] = value
    return headers


def _build_client_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    excluded = {"content-length", "content-encoding", *_HOP_BY_HOP_HEADERS}
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in excluded:
            continue
        out[key] = value
    return out


def _log_v2_request_if_debug(request: Request, body: bytes) -> None:
    if not logger.isEnabledFor(logging.DEBUG):
        return

    headers_safe: dict[str, str] = {}
    for key, value in request.headers.items():
        key_lower = key.lower()
        if key_lower in _DEBUG_HEADERS_REDACT or "key" in key_lower or "secret" in key_lower or "token" in key_lower:
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
            except Exception:
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

    request_framing_issues = _detect_request_framing_anomalies(request)
    if request_framing_issues:
        logger.warning(
            "v2 request blocked method=%s path=%s reason=request_framing_ambiguous issues=%s",
            request.method,
            request.url.path,
            request_framing_issues,
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": "该请求已被安全网关拦截，检测到可疑 HTTP 报文边界特征。",
                    "type": "aegisgate_v2_security_block",
                    "code": "v2_request_http_framing_blocked",
                    "details": _v2_http_attack_reasons(request_framing_issues),
                },
                "aegisgate_v2": {
                    "request_redaction_enabled": settings.v2_enable_request_redaction,
                    "response_command_filter_enabled": settings.v2_enable_response_command_filter,
                    "matched_rules": request_framing_issues,
                },
            },
        )

    target_url, err = _extract_target_url(request)
    if err:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": err,
                    "type": "aegisgate_v2_error",
                    "code": "invalid_original_url_header",
                }
            },
        )
    assert target_url is not None

    request_body = await request.body()
    _log_v2_request_if_debug(request, request_body)
    original_content_type = request.headers.get("content-type", "")
    redaction_hits: list[str] = []
    redaction_count = 0
    outbound_body = request_body
    if settings.v2_enable_request_redaction:
        outbound_body, redaction_count, redaction_hits = _sanitize_request_body(request_body, original_content_type)
        if redaction_count > 0:
            logger.info(
                "v2 request redacted method=%s path=%s target=%s replacements=%s hit_ids=%s",
                request.method,
                request.url.path,
                target_url,
                redaction_count,
                redaction_hits,
            )

    forward_headers = _build_forward_headers(request)
    client = await _get_v2_async_client()
    try:
        upstream_response = await client.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            content=outbound_body,
        )
    except httpx.HTTPError as exc:
        detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
        logger.warning("v2 upstream unreachable target=%s error=%s", target_url, detail)
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

    response_framing_issues = _detect_response_framing_anomalies(upstream_response.headers)
    if settings.v2_enable_response_command_filter and response_framing_issues:
        logger.warning(
            "v2 response blocked method=%s path=%s target=%s status=%s reason=response_framing_ambiguous issues=%s",
            request.method,
            request.url.path,
            target_url,
            upstream_response.status_code,
            response_framing_issues,
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": "上游响应存在可疑 HTTP 报文边界特征，已被安全网关拦截。",
                    "type": "aegisgate_v2_security_block",
                    "code": "v2_upstream_response_framing_blocked",
                    "details": _v2_http_attack_reasons(response_framing_issues),
                },
                "aegisgate_v2": {
                    "request_redaction_enabled": settings.v2_enable_request_redaction,
                    "response_command_filter_enabled": settings.v2_enable_response_command_filter,
                    "matched_rules": response_framing_issues,
                },
            },
        )

    response_headers = _build_client_response_headers(upstream_response.headers)
    response_body = upstream_response.content
    response_content_type = upstream_response.headers.get("content-type", "")
    if settings.v2_enable_response_command_filter and response_body and _looks_textual_content_type(response_content_type):
        text = response_body.decode("utf-8", errors="replace")
        max_chars = max(1_000, int(settings.v2_response_filter_max_chars))
        matches = _detect_dangerous_commands(text[:max_chars])
        if matches:
            logger.warning(
                "v2 response blocked method=%s path=%s target=%s status=%s matches=%s",
                request.method,
                request.url.path,
                target_url,
                upstream_response.status_code,
                matches,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "该请求已被安全网关拦截，可能携带注入攻击。",
                        "type": "aegisgate_v2_security_block",
                        "code": "v2_response_http_attack_blocked",
                        "details": _v2_http_attack_reasons(matches),
                    },
                    "aegisgate_v2": {
                        "request_redaction_enabled": settings.v2_enable_request_redaction,
                        "response_command_filter_enabled": settings.v2_enable_response_command_filter,
                        "matched_rules": matches,
                    },
                },
            )

    if redaction_count > 0:
        response_headers["x-aegis-v2-request-redacted"] = "true"
        response_headers["x-aegis-v2-redaction-count"] = str(redaction_count)
    return Response(
        content=response_body,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )
