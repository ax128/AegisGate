"""UI configuration field definitions, docs catalog, and env file helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ENV_PATH = (Path.cwd() / "config" / ".env").resolve()

_EXCLUDED_ROOT_DOCS: frozenset[str] = frozenset(
    {
        "AGENTS.md",
        "CHANGELOG.md",
        "PRODUCTION_READINESS_TEST_REPORT.md",
        "OPEN_SOURCE_CHECKLIST.md",
        "PR_DESCRIPTION_2026-02-26-security-hardening.md",
    }
)

_DOC_FRIENDLY_TITLES: dict[str, str] = {
    "README.md": "README",
    "WEBUI-QUICKSTART.md": "Web UI 快速上手",
    "CLIPROXY-QUICKSTART.md": "CLI Proxy 快速上手",
    "SUB2API-QUICKSTART.md": "Sub2API 快速上手",
    "AICLIENT2API-QUICKSTART.md": "AI Client→API 快速上手",
    "OTHER_TERMINAL_CLIENTS_USAGE.md": "其他终端客户端用法",
    "OPENCLAW_INJECT_PROXY_FETCH.md": "OpenClaw 注入代理",
    "SKILL.md": "Skill 功能说明",
}

_DOC_ORDER: tuple[str, ...] = (
    "README.md",
    "WEBUI-QUICKSTART.md",
    "CLIPROXY-QUICKSTART.md",
    "SUB2API-QUICKSTART.md",
    "AICLIENT2API-QUICKSTART.md",
    "OTHER_TERMINAL_CLIENTS_USAGE.md",
    "OPENCLAW_INJECT_PROXY_FETCH.md",
    "SKILL.md",
)


def _docs_catalog() -> list[dict[str, str]]:
    """返回 UI 文档目录：按 _DOC_ORDER 排序，仅包含实际存在的文件。"""
    available: set[str] = {
        p.name for p in _PROJECT_ROOT.glob("*.md")
        if p.name not in _EXCLUDED_ROOT_DOCS
    }
    docs: list[dict[str, str]] = []
    seen: set[str] = set()
    for name in _DOC_ORDER:
        if name in available:
            docs.append({
                "id": name,
                "title": _DOC_FRIENDLY_TITLES.get(name, name.replace("-", " ").replace("_", " ").rstrip(".md")),
                "path": name,
            })
            seen.add(name)
    for name in sorted(available - seen):
        docs.append({
            "id": name,
            "title": _DOC_FRIENDLY_TITLES.get(name, name.replace("-", " ").replace("_", " ")),
            "path": name,
        })
    return docs


def _resolve_doc_path(doc_id: str) -> Path | None:
    safe_id = Path(doc_id).name
    if safe_id != doc_id:
        return None
    if safe_id in _EXCLUDED_ROOT_DOCS:
        return None
    candidate = (_PROJECT_ROOT / safe_id).resolve()
    if candidate.is_file() and candidate.suffix == ".md" and candidate.parent == _PROJECT_ROOT:
        return candidate
    return None


# ---------------------------------------------------------------------------
# UI config field metadata
# ---------------------------------------------------------------------------
_UI_CONFIG_FIELDS: tuple[dict[str, object], ...] = (
    # ---- general ----
    {"env": "AEGIS_HOST", "field": "host", "label": "监听 Host", "type": "string", "section": "general"},
    {"env": "AEGIS_PORT", "field": "port", "label": "监听端口", "type": "int", "section": "general"},
    {"env": "AEGIS_UPSTREAM_BASE_URL", "field": "upstream_base_url", "label": "直连上游地址", "type": "string", "section": "general"},
    {"env": "AEGIS_LOG_LEVEL", "field": "log_level", "label": "日志级别", "type": "enum", "section": "general", "options": ["debug", "info", "warning", "error"]},
    {"env": "AEGIS_LOG_FULL_REQUEST_BODY", "field": "log_full_request_body", "label": "打印完整请求体", "type": "bool", "section": "general"},
    {"env": "AEGIS_STORAGE_BACKEND", "field": "storage_backend", "label": "存储后端", "type": "enum", "section": "general", "options": ["sqlite", "redis", "postgres"]},
    {"env": "AEGIS_SQLITE_DB_PATH", "field": "sqlite_db_path", "label": "SQLite 路径", "type": "string", "section": "general"},
    {"env": "AEGIS_REDIS_URL", "field": "redis_url", "label": "Redis URL", "type": "string", "section": "general"},
    {"env": "AEGIS_UPSTREAM_TIMEOUT_SECONDS", "field": "upstream_timeout_seconds", "label": "上游超时（秒）", "type": "int", "section": "general"},
    {"env": "AEGIS_UPSTREAM_MAX_CONNECTIONS", "field": "upstream_max_connections", "label": "最大并发连接数", "type": "int", "section": "general"},
    {"env": "AEGIS_UPSTREAM_MAX_KEEPALIVE_CONNECTIONS", "field": "upstream_max_keepalive_connections", "label": "Keepalive 连接池", "type": "int", "section": "general"},
    {"env": "AEGIS_ENABLE_THREAD_OFFLOAD", "field": "enable_thread_offload", "label": "线程池卸载", "type": "bool", "section": "general"},
    {"env": "AEGIS_FILTER_PIPELINE_TIMEOUT_S", "field": "filter_pipeline_timeout_s", "label": "过滤管道超时（秒）", "type": "int", "section": "general"},
    {"env": "AEGIS_MAX_REQUEST_BODY_BYTES", "field": "max_request_body_bytes", "label": "最大请求体（字节）", "type": "int", "section": "general"},
    {"env": "AEGIS_MAX_MESSAGES_COUNT", "field": "max_messages_count", "label": "最大消息条数", "type": "int", "section": "general"},
    {"env": "AEGIS_MAX_CONTENT_LENGTH_PER_MESSAGE", "field": "max_content_length_per_message", "label": "单条消息最大字符", "type": "int", "section": "general"},
    {"env": "AEGIS_MAX_PENDING_PAYLOAD_BYTES", "field": "max_pending_payload_bytes", "label": "Pending 最大字节", "type": "int", "section": "general"},
    {"env": "AEGIS_MAX_RESPONSE_LENGTH", "field": "max_response_length", "label": "最大响应字符", "type": "int", "section": "general"},
    {"env": "AEGIS_AUDIT_LOG_PATH", "field": "audit_log_path", "label": "审计日志路径", "type": "string", "section": "general"},
    {"env": "AEGIS_ENABLE_DANGEROUS_RESPONSE_LOG", "field": "enable_dangerous_response_log", "label": "保存危险响应样本", "type": "bool", "section": "general"},
    {"env": "AEGIS_DANGEROUS_RESPONSE_LOG_PATH", "field": "dangerous_response_log_path", "label": "危险响应样本日志路径", "type": "string", "section": "general"},
    {"env": "AEGIS_TRUSTED_PROXY_IPS", "field": "trusted_proxy_ips", "label": "信任代理 IP（逗号分隔）", "type": "string", "section": "general"},
    {"env": "AEGIS_ENABLE_LOCAL_PORT_ROUTING", "field": "enable_local_port_routing", "label": "本地端口自动路由", "type": "bool", "section": "general"},
    {"env": "AEGIS_LOCAL_PORT_ROUTING_HOST", "field": "local_port_routing_host", "label": "端口路由目标 Host", "type": "string", "section": "general"},
    {"env": "AEGIS_ENABLE_RELAY_ENDPOINT", "field": "enable_relay_endpoint", "label": "Relay 兼容端点", "type": "bool", "section": "general"},
    # ---- security ----
    {"env": "AEGIS_SECURITY_LEVEL", "field": "security_level", "label": "安全档位", "type": "enum", "section": "security", "options": ["low", "medium", "high"]},
    {"env": "AEGIS_DEFAULT_POLICY", "field": "default_policy", "label": "默认策略", "type": "enum", "section": "security", "options": ["default", "permissive", "strict"]},
    {"env": "AEGIS_STRICT_COMMAND_BLOCK_ENABLED", "field": "strict_command_block_enabled", "label": "强制命令拦截", "type": "bool", "section": "security"},
    {"env": "AEGIS_RISK_SCORE_THRESHOLD", "field": "risk_score_threshold", "label": "风险评分阈值（0-1）", "type": "string", "section": "security"},
    {"env": "AEGIS_REQUEST_PIPELINE_TIMEOUT_ACTION", "field": "request_pipeline_timeout_action", "label": "请求管道超时动作", "type": "enum", "section": "security", "options": ["block", "pass"]},
    {"env": "AEGIS_ADMIN_RATE_LIMIT_PER_MINUTE", "field": "admin_rate_limit_per_minute", "label": "管理接口限流（次/分）", "type": "int", "section": "security"},
    {"env": "AEGIS_ENFORCE_LOOPBACK_ONLY", "field": "enforce_loopback_only", "label": "仅环回地址", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_SEMANTIC_MODULE", "field": "enable_semantic_module", "label": "语义模块", "type": "bool", "section": "security"},
    {"env": "AEGIS_SEMANTIC_GRAY_LOW", "field": "semantic_gray_low", "label": "语义低风险阈值", "type": "string", "section": "security"},
    {"env": "AEGIS_SEMANTIC_GRAY_HIGH", "field": "semantic_gray_high", "label": "语义高风险阈值", "type": "string", "section": "security"},
    {"env": "AEGIS_SEMANTIC_TIMEOUT_MS", "field": "semantic_timeout_ms", "label": "语义超时（ms）", "type": "int", "section": "security"},
    {"env": "AEGIS_SEMANTIC_CACHE_TTL_SECONDS", "field": "semantic_cache_ttl_seconds", "label": "语义缓存 TTL（秒）", "type": "int", "section": "security"},
    {"env": "AEGIS_SEMANTIC_SERVICE_URL", "field": "semantic_service_url", "label": "语义服务外部 URL", "type": "string", "section": "security"},
    {"env": "AEGIS_ENABLE_EXACT_VALUE_REDACTION", "field": "enable_exact_value_redaction", "label": "精确值脱敏", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_REDACTION", "field": "enable_redaction", "label": "PII 脱敏", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_RESTORATION", "field": "enable_restoration", "label": "脱敏还原", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_INJECTION_DETECTOR", "field": "enable_injection_detector", "label": "注入检测", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_PRIVILEGE_GUARD", "field": "enable_privilege_guard", "label": "权限提升防护", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_ANOMALY_DETECTOR", "field": "enable_anomaly_detector", "label": "异常检测", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_REQUEST_SANITIZER", "field": "enable_request_sanitizer", "label": "请求净化", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_OUTPUT_SANITIZER", "field": "enable_output_sanitizer", "label": "输出净化", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_POST_RESTORE_GUARD", "field": "enable_post_restore_guard", "label": "还原后检测", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_UNTRUSTED_CONTENT_GUARD", "field": "enable_untrusted_content_guard", "label": "不可信内容防护", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_TOOL_CALL_GUARD", "field": "enable_tool_call_guard", "label": "工具调用防护", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_RAG_POISON_GUARD", "field": "enable_rag_poison_guard", "label": "RAG 投毒防护", "type": "bool", "section": "security"},
    {"env": "AEGIS_ENABLE_SYSTEM_PROMPT_GUARD", "field": "enable_system_prompt_guard", "label": "系统提示词防护", "type": "bool", "section": "security"},
    # ---- v2 proxy ----
    {"env": "AEGIS_ENABLE_V2_PROXY", "field": "enable_v2_proxy", "label": "启用 v2 代理", "type": "bool", "section": "v2"},
    {"env": "AEGIS_V2_ENABLE_REQUEST_REDACTION", "field": "v2_enable_request_redaction", "label": "v2 请求脱敏", "type": "bool", "section": "v2"},
    {"env": "AEGIS_V2_ENABLE_RESPONSE_COMMAND_FILTER", "field": "v2_enable_response_command_filter", "label": "v2 响应指令过滤", "type": "bool", "section": "v2"},
    {"env": "AEGIS_V2_RESPONSE_FILTER_OBVIOUS_ONLY", "field": "v2_response_filter_obvious_only", "label": "v2 最小误拦模式", "type": "bool", "section": "v2"},
    {"env": "AEGIS_V2_BLOCK_INTERNAL_TARGETS", "field": "v2_block_internal_targets", "label": "v2 SSRF 防护", "type": "bool", "section": "v2"},
    {"env": "AEGIS_V2_RESPONSE_FILTER_BYPASS_HOSTS", "field": "v2_response_filter_bypass_hosts", "label": "v2 过滤豁免域名", "type": "string", "section": "v2"},
    {"env": "AEGIS_V2_RESPONSE_FILTER_MAX_CHARS", "field": "v2_response_filter_max_chars", "label": "v2 响应最大扫描字符", "type": "int", "section": "v2"},
)


def _ui_config_field_map() -> dict[str, dict[str, object]]:
    return {str(item["field"]): dict(item) for item in _UI_CONFIG_FIELDS}


def _field_default(field_name: str) -> object:
    field_info = settings.__class__.model_fields[field_name]
    return field_info.default


def _serialize_env_value(kind: str, value: object) -> str:
    if kind == "bool":
        return "true" if bool(value) else "false"
    return str(value)


def _parse_bool_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def _coerce_config_value(meta: dict[str, object], raw_value: object) -> object:
    kind = str(meta["type"])
    if kind == "bool":
        return _parse_bool_value(raw_value)
    if kind == "int":
        try:
            return int(str(raw_value).strip())
        except ValueError as exc:
            raise ValueError(f"invalid integer for {meta['field']}") from exc
    value = str(raw_value or "").strip()
    if kind == "enum":
        raw_options = meta.get("options")
        options = {str(item) for item in raw_options} if isinstance(raw_options, list) else set()
        if value not in options:
            raise ValueError(f"invalid option for {meta['field']}")
    return value


def _read_env_lines() -> list[str]:
    if not _ENV_PATH.exists():
        return []
    return _ENV_PATH.read_text(encoding="utf-8").splitlines()


def _write_env_updates(updates: dict[str, str]) -> None:
    existing_lines = _read_env_lines()
    consumed: set[str] = set()
    new_lines: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue
        key, _, _value = line.partition("=")
        key = key.strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            consumed.add(key)
        else:
            new_lines.append(line)
    if new_lines and new_lines[-1].strip():
        new_lines.append("")
    for key in updates:
        if key not in consumed:
            new_lines.append(f"{key}={updates[key]}")
    try:
        _ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(_ENV_PATH.parent)) as tmp:
            tmp.write("\n".join(new_lines).rstrip() + "\n")
            tmp_path = Path(tmp.name)
        tmp_path.replace(_ENV_PATH)
    except OSError as exc:
        logger.error("config env write failed path=%s error=%s", _ENV_PATH, exc)
        raise RuntimeError(f"无法写入 {_ENV_PATH}: {exc}") from exc


def _ui_config_payload() -> dict[str, object]:
    items: list[dict[str, object]] = []
    for meta in _UI_CONFIG_FIELDS:
        field_name = str(meta["field"])
        current_value = getattr(settings, field_name)
        default_value = _field_default(field_name)
        items.append({**meta, "value": current_value, "default": default_value})
    return {"items": items}
