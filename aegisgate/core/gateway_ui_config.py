"""UI configuration field definitions, docs catalog, and env file helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ENV_PATH = (Path.cwd() / "config" / ".env").resolve()

# The operator guides the console may serve, in the order it lists them. This is
# an allow-list, not a deny-list: it used to serve every root *.md except a few
# named exclusions, so any Markdown that landed in the app root was published to
# anyone with a console session. That included the local/internal reports
# .gitignore keeps out of the repo — OPTIMIZATION_PLAN.md, task_plan.md,
# notes.md, FINAL_REPORT.md were never on the exclusion list, and the deny-list
# could only ever name files someone had already thought of.
#
# CHANGELOG.md and ROADMAP.md stay off deliberately: maintainer-facing history
# and plans, not operator guides. Adding a doc here is the one step needed to
# surface it, and test_doc_alignment pins this list against the repo root.
_UI_DOCS: tuple[tuple[str, str], ...] = (
    ("README.md", "README"),
    ("README_zh.md", "README（中文）"),
    ("WEBUI-QUICKSTART.md", "Web UI 快速上手"),
    ("UPSTREAM-QUICKSTART.md", "上游接入快速上手"),
    ("OTHER_TERMINAL_CLIENTS_USAGE.md", "其他终端客户端用法"),
    ("SKILL.md", "Skill 功能说明"),
)

_DOC_FRIENDLY_TITLES: dict[str, str] = dict(_UI_DOCS)
_DOC_ORDER: tuple[str, ...] = tuple(name for name, _ in _UI_DOCS)


def _doc_title(name: str) -> str:
    """Friendly title for *name*. Every allow-listed doc has one by construction."""
    return _DOC_FRIENDLY_TITLES.get(name, name.removesuffix(".md"))


def _docs_catalog() -> list[dict[str, str]]:
    """The UI document catalogue: the allow-listed docs that exist, in order."""
    return [
        {"id": name, "title": _doc_title(name), "path": name}
        for name in _DOC_ORDER
        if (_PROJECT_ROOT / name).is_file()
    ]


def _resolve_doc_path(doc_id: str) -> Path | None:
    if doc_id not in _DOC_FRIENDLY_TITLES:
        return None
    raw = _PROJECT_ROOT / doc_id
    if raw.is_symlink():
        logger.warning("ignoring symlinked doc path=%s", raw)
        return None
    candidate = raw.resolve()
    if candidate.is_file() and candidate.parent == _PROJECT_ROOT:
        return candidate
    return None


# ---------------------------------------------------------------------------
# UI config field metadata
# ---------------------------------------------------------------------------
# Sections are rendered as one panel each, in the order declared here. Adding a
# section or a field needs no front-end change: the console builds its panels
# and nav entries from this table.
_UI_CONFIG_SECTIONS: tuple[dict[str, str], ...] = (
    {
        "id": "general",
        "label": "基础设置",
        "desc": "监听地址、日志与运行时路径",
        "icon": "sliders",
    },
    {
        "id": "storage",
        "label": "存储与保留",
        "desc": "映射表后端、连接串与清理策略",
        "icon": "database",
    },
    {
        "id": "limits",
        "label": "限额与超时",
        "desc": "上游连接池、请求体大小与管道超时",
        "icon": "gauge",
    },
    {
        "id": "security",
        "label": "安全策略",
        "desc": "安全等级、过滤器开关、风险评分与语义复核",
        "icon": "shield",
    },
    {
        "id": "access",
        "label": "访问控制",
        "desc": "网络边界、公网闸门与请求签名",
        "icon": "lock",
    },
    {
        "id": "compat",
        "label": "协议转换与路由",
        "desc": "端口路由、Docker 上游与 compat 模型映射",
        "icon": "shuffle",
    },
    {
        "id": "v2",
        "label": "v2 代理",
        "desc": "通用 HTTP 代理的过滤、限额与 SSRF 防护",
        "icon": "layers",
    },
    {
        "id": "console",
        "label": "控制台",
        "desc": "Web 控制台自身的会话、Cookie 与限流",
        "icon": "monitor",
    },
)


def _f(
    env: str,
    field: str,
    label: str,
    kind: str,
    section: str,
    group: str,
    help_text: str = "",
    **extra: object,
) -> dict[str, object]:
    """Build one UI config field descriptor.

    The tuple below is a data table; this constructor keeps it to one readable
    line per field instead of a seven-line dict literal.
    """
    item: dict[str, object] = {
        "env": env,
        "field": field,
        "label": label,
        "type": kind,
        "section": section,
        "group": group,
    }
    if help_text:
        item["help"] = help_text
    item.update(extra)
    return item


# Fields deliberately NOT exposed here:
#   app_name                            cosmetic, no operational effect
#   gateway_key                         managed by the key-management panel
#   require_confirmation_on_block       deprecated, behaviour is pinned to False
#   internal_forwarding_kernel_rollout  private internal rollout gate
_UI_CONFIG_FIELDS: tuple[dict[str, object], ...] = (
    # ---- general ----
    _f("AEGIS_HOST", "host", "监听 Host", "string", "general", "服务"),
    _f("AEGIS_PORT", "port", "监听端口", "int", "general", "服务", min=1, max=65535),
    _f("AEGIS_ENV", "env", "运行环境标识", "string", "general", "服务", "仅用于日志与标识，不改变行为"),
    _f("AEGIS_UPSTREAM_BASE_URL", "upstream_base_url", "直连上游地址", "string", "general", "上游",
       "设置后 /v1/... 可不带 token 直接调用"),
    _f("AEGIS_UPSTREAM_BASE_HEADER", "upstream_base_header", "上游地址请求头名", "string", "general", "上游"),
    _f("AEGIS_ENABLE_RELAY_ENDPOINT", "enable_relay_endpoint", "Relay 兼容端点", "bool", "general", "上游"),
    _f("AEGIS_LOG_LEVEL", "log_level", "日志级别", "enum", "general", "日志",
       options=["debug", "info", "warning", "error"]),
    _f("AEGIS_LOG_FULL_REQUEST_BODY", "log_full_request_body", "打印完整请求体", "bool", "general", "日志",
       "仅调试用；开启后请求正文会进入日志"),
    _f("AEGIS_LOG_JSON", "log_json", "JSON 结构化日志", "bool", "general", "日志",
       "每行输出一个 JSON 对象；OTel span 活跃时带 trace_id / span_id"),
    _f("AEGIS_AUDIT_LOG_PATH", "audit_log_path", "审计日志路径", "string", "general", "日志",
       "留空则关闭审计文件"),
    _f("AEGIS_ENABLE_DANGEROUS_RESPONSE_LOG", "enable_dangerous_response_log", "保存危险响应样本", "bool",
       "general", "日志"),
    _f("AEGIS_DANGEROUS_RESPONSE_LOG_PATH", "dangerous_response_log_path", "危险响应样本日志路径", "string",
       "general", "日志"),
    _f("AEGIS_DANGEROUS_RESPONSE_LOG_INCLUDE_RAW", "dangerous_response_log_include_raw",
       "危险响应样本保留原文", "bool", "general", "日志",
       "开启后样本文件里保留原始响应文本；关闭只留结构化证据。注意原文可能含敏感内容"),
    _f("AEGIS_SECURITY_RULES_PATH", "security_rules_path", "安全规则 YAML 路径", "string", "general", "路径"),
    _f("AEGIS_GW_TOKENS_PATH", "gw_tokens_path", "Token 映射表路径", "string", "general", "路径"),
    _f("AEGIS_COMPOSE_DIR", "compose_dir", "Compose 文件目录", "string", "general", "路径",
       "留空则使用 config/compose/"),

    # ---- storage ----
    _f("AEGIS_STORAGE_BACKEND", "storage_backend", "存储后端", "enum", "storage", "后端",
       options=["sqlite", "redis", "postgres"]),
    _f("AEGIS_STORAGE_FAILURE_ACTION", "storage_failure_action", "存储故障处置", "enum", "storage", "后端",
       "block=拒绝请求（安全默认），forward=仅跳过持久化", options=["block", "forward"]),
    _f("AEGIS_SQLITE_DB_PATH", "sqlite_db_path", "SQLite 路径", "string", "storage", "SQLite",
       depends_on={"storage_backend": "sqlite"}),
    _f("AEGIS_REDIS_URL", "redis_url", "Redis URL", "string", "storage", "Redis",
       depends_on={"storage_backend": "redis"}),
    _f("AEGIS_REDIS_KEY_PREFIX", "redis_key_prefix", "Redis Key 前缀", "string", "storage", "Redis",
       depends_on={"storage_backend": "redis"}),
    _f("AEGIS_POSTGRES_DSN", "postgres_dsn", "PostgreSQL DSN", "string", "storage", "PostgreSQL",
       "postgresql://user:pass@host:5432/db", sensitive=True,
       depends_on={"storage_backend": "postgres"}),
    _f("AEGIS_POSTGRES_SCHEMA", "postgres_schema", "PostgreSQL Schema", "string", "storage", "PostgreSQL",
       depends_on={"storage_backend": "postgres"}),
    _f("AEGIS_PENDING_DATA_TTL_SECONDS", "pending_data_ttl_seconds", "脱敏映射保留（秒）", "int",
       "storage", "保留策略", min=0),
    _f("AEGIS_ENABLE_MAPPING_PRUNE_TASK", "enable_mapping_prune_task", "定期清理过期映射", "bool",
       "storage", "保留策略"),
    _f("AEGIS_MAPPING_PRUNE_INTERVAL_SECONDS", "mapping_prune_interval_seconds", "清理间隔（秒）", "int",
       "storage", "保留策略", min=1),

    # ---- limits ----
    _f("AEGIS_UPSTREAM_TIMEOUT_SECONDS", "upstream_timeout_seconds", "上游超时（秒）", "float",
       "limits", "上游连接", min=0),
    _f("AEGIS_UPSTREAM_MAX_CONNECTIONS", "upstream_max_connections", "最大并发连接数", "int",
       "limits", "上游连接", min=1),
    _f("AEGIS_UPSTREAM_MAX_KEEPALIVE_CONNECTIONS", "upstream_max_keepalive_connections", "Keepalive 连接池",
       "int", "limits", "上游连接", min=0),
    _f("AEGIS_STREAM_BOOTSTRAP_RETRIES", "stream_bootstrap_retries", "流式首字节前重试次数", "int",
       "limits", "上游连接", "0 关闭；建议不超过 2，避免放大失败流量", min=0, max=5),
    _f("AEGIS_FILTER_PIPELINE_TIMEOUT_S", "filter_pipeline_timeout_s", "过滤管道超时（秒）", "float",
       "limits", "过滤管道", "0 表示不限制（生产不建议）", min=0),
    _f("AEGIS_MAX_REQUEST_BODY_BYTES", "max_request_body_bytes", "最大请求体（字节）", "int",
       "limits", "请求体", min=1),
    _f("AEGIS_MAX_MULTIPART_BODY_BYTES", "max_multipart_body_bytes", "multipart 最大请求体（字节）", "int",
       "limits", "请求体", min=1),
    _f("AEGIS_MAX_MESSAGES_COUNT", "max_messages_count", "最大消息条数", "int", "limits", "消息", min=1),
    _f("AEGIS_MAX_CONTENT_LENGTH_PER_MESSAGE", "max_content_length_per_message", "单条消息最大字符", "int",
       "limits", "消息", min=1),
    _f("AEGIS_MAX_RESPONSE_LENGTH", "max_response_length", "最大响应字符", "int", "limits", "消息", min=1),

    # ---- security ----
    _f("AEGIS_SECURITY_LEVEL", "security_level", "安全等级", "enum", "security", "等级",
       options=["low", "medium", "high"]),
    _f("AEGIS_DEFAULT_POLICY", "default_policy", "默认策略", "enum", "security", "等级",
       options=["default", "strict", "permissive"]),
    _f("AEGIS_RISK_SCORE_THRESHOLD", "risk_score_threshold", "风险分阈值", "float", "security", "风险评分",
       "0–1，超过即触发拦截动作", min=0, max=1),
    _f("AEGIS_REQUEST_PIPELINE_TIMEOUT_ACTION", "request_pipeline_timeout_action", "请求管道超时处置",
       "enum", "security", "风险评分", options=["block", "pass"]),
    _f("AEGIS_STRICT_COMMAND_BLOCK_ENABLED", "strict_command_block_enabled", "强制命令拦截", "bool",
       "security", "命令拦截", "命中强拦截规则时直接阻断，不看风险分"),
    _f("AEGIS_CONFIRMATION_SHOW_HIT_PREVIEW", "confirmation_show_hit_preview", "展示命中片段预览", "bool",
       "security", "命令拦截"),
    _f("AEGIS_ENABLE_REDACTION", "enable_redaction", "PII 脱敏", "bool", "security", "过滤器开关"),
    _f("AEGIS_ENABLE_EXACT_VALUE_REDACTION", "enable_exact_value_redaction", "精确值脱敏", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_RESTORATION", "enable_restoration", "占位符还原", "bool", "security", "过滤器开关"),
    _f("AEGIS_ENABLE_INJECTION_DETECTOR", "enable_injection_detector", "注入检测", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_PRIVILEGE_GUARD", "enable_privilege_guard", "越权防护", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_ANOMALY_DETECTOR", "enable_anomaly_detector", "异常检测", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_REQUEST_SANITIZER", "enable_request_sanitizer", "请求净化", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_OUTPUT_SANITIZER", "enable_output_sanitizer", "输出净化", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_POST_RESTORE_GUARD", "enable_post_restore_guard", "还原后二次检查", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_UNTRUSTED_CONTENT_GUARD", "enable_untrusted_content_guard", "不可信内容防护", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_TOOL_CALL_GUARD", "enable_tool_call_guard", "工具调用防护", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_RAG_POISON_GUARD", "enable_rag_poison_guard", "RAG 投毒防护", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_SYSTEM_PROMPT_GUARD", "enable_system_prompt_guard", "系统提示词防护", "bool",
       "security", "过滤器开关"),
    _f("AEGIS_ENABLE_SEMANTIC_MODULE", "enable_semantic_module", "启用语义复核", "bool",
       "security", "语义复核"),
    _f("AEGIS_SEMANTIC_SERVICE_URL", "semantic_service_url", "语义服务地址", "string",
       "security", "语义复核", "留空则只记录降级，不抬升风险"),
    _f("AEGIS_SEMANTIC_GRAY_LOW", "semantic_gray_low", "灰区下界", "float", "security", "语义复核",
       min=0, max=1),
    _f("AEGIS_SEMANTIC_GRAY_HIGH", "semantic_gray_high", "灰区上界", "float", "security", "语义复核",
       min=0, max=1),
    _f("AEGIS_SEMANTIC_TIMEOUT_MS", "semantic_timeout_ms", "语义调用超时（毫秒）", "int",
       "security", "语义复核", min=1),
    _f("AEGIS_SEMANTIC_CACHE_TTL_SECONDS", "semantic_cache_ttl_seconds", "语义缓存 TTL（秒）", "int",
       "security", "语义复核", min=0),
    _f("AEGIS_SEMANTIC_CACHE_MAX_ENTRIES", "semantic_cache_max_entries", "语义缓存条数上限", "int",
       "security", "语义复核", min=1),
    _f("AEGIS_SEMANTIC_CIRCUIT_FAILURE_THRESHOLD", "semantic_circuit_failure_threshold", "熔断失败阈值",
       "int", "security", "语义复核", min=1),
    _f("AEGIS_SEMANTIC_CIRCUIT_OPEN_SECONDS", "semantic_circuit_open_seconds", "熔断打开时长（秒）", "int",
       "security", "语义复核", min=1),

    # ---- access ----
    _f("AEGIS_ENFORCE_LOOPBACK_ONLY", "enforce_loopback_only", "仅允许回环访问", "bool",
       "access", "网络边界"),
    _f("AEGIS_TRUSTED_PROXY_IPS", "trusted_proxy_ips", "信任代理 IP（逗号分隔）", "string",
       "access", "网络边界", "留空表示只信任直连对端 IP"),
    _f("AEGIS_XFF_STRICT_INTERNAL", "xff_strict_internal", "严格校验 X-Forwarded-For", "bool",
       "access", "网络边界", "开启后非信任来源携带 XFF 一律视为公网客户端"),
    _f("AEGIS_UPSTREAM_WHITELIST_URL_LIST", "upstream_whitelist_url_list", "上游过滤豁免地址", "string",
       "access", "网络边界", "命中的上游将跳过全部过滤，谨慎使用"),
    _f("AEGIS_ALLOW_PUBLIC_NUMERIC_TOKENS", "allow_public_numeric_tokens", "允许公网使用数字 Token", "bool",
       "access", "公网闸门", "数字 token 可预测，公网开放有风险"),
    _f("AEGIS_ALLOW_PUBLIC_PASSTHROUGH_MODE", "allow_public_passthrough_mode", "允许公网使用直通模式", "bool",
       "access", "公网闸门", "直通模式会关闭全部安全过滤"),
    _f("AEGIS_ALLOW_PUBLIC_UPSTREAM_WHITELIST", "allow_public_upstream_whitelist", "允许公网走上游白名单",
       "bool", "access", "公网闸门"),
    _f("AEGIS_GATEWAY_KEY_HEADER", "gateway_key_header", "网关密钥请求头名", "string", "access", "请求头"),
    _f("AEGIS_ENABLE_REQUEST_HMAC_AUTH", "enable_request_hmac_auth", "启用请求 HMAC 签名", "bool",
       "access", "请求签名"),
    _f("AEGIS_REQUEST_HMAC_SECRET", "request_hmac_secret", "HMAC 密钥", "string", "access", "请求签名",
       "留空提交表示保持当前值不变", sensitive=True),
    _f("AEGIS_REQUEST_SIGNATURE_HEADER", "request_signature_header", "签名请求头名", "string",
       "access", "请求签名"),
    _f("AEGIS_REQUEST_TIMESTAMP_HEADER", "request_timestamp_header", "时间戳请求头名", "string",
       "access", "请求签名"),
    _f("AEGIS_REQUEST_NONCE_HEADER", "request_nonce_header", "Nonce 请求头名", "string",
       "access", "请求签名"),
    _f("AEGIS_REQUEST_REPLAY_WINDOW_SECONDS", "request_replay_window_seconds", "重放窗口（秒）", "int",
       "access", "请求签名", min=1),
    _f("AEGIS_REQUEST_NONCE_CACHE_SIZE", "request_nonce_cache_size", "Nonce 缓存条数", "int",
       "access", "请求签名", min=1),
    _f("AEGIS_NONCE_CACHE_BACKEND", "nonce_cache_backend", "Nonce 缓存后端", "enum",
       "access", "请求签名", options=["memory", "redis"]),

    # ---- compat ----
    _f("AEGIS_ENABLE_LOCAL_PORT_ROUTING", "enable_local_port_routing", "本地端口自动路由", "bool",
       "compat", "端口路由"),
    _f("AEGIS_LOCAL_PORT_ROUTING_HOST", "local_port_routing_host", "端口路由目标 Host", "string",
       "compat", "端口路由", "裸机用 127.0.0.1，Docker 用 host.docker.internal"),
    _f("AEGIS_COMPAT_ALLOWED_PORTS", "compat_allowed_ports", "允许的端口白名单", "string",
       "compat", "端口路由", "逗号分隔；留空表示禁止全部端口路由"),
    _f("AEGIS_DOCKER_UPSTREAMS", "docker_upstreams", "Docker 上游自动注册", "string",
       "compat", "Docker 上游", "格式 token:service[:port]，逗号分隔"),
    _f("AEGIS_ENABLE_BUILTIN_COMPAT_TOKENS", "enable_builtin_compat_tokens", "注入内置 compat Token", "bool",
       "compat", "模型映射", "内置 token 可预测，生产不建议开启"),
    _f("AEGIS_COMPAT_MODEL_MAP_PATH", "compat_model_map_path", "模型映射文件路径", "string",
       "compat", "模型映射"),

    # ---- v2 proxy ----
    _f("AEGIS_ENABLE_V2_PROXY", "enable_v2_proxy", "启用 v2 代理", "bool", "v2", "开关"),
    _f("AEGIS_V2_ENABLE_REQUEST_REDACTION", "v2_enable_request_redaction", "v2 请求脱敏", "bool", "v2", "过滤"),
    _f("AEGIS_V2_ENABLE_RESPONSE_COMMAND_FILTER", "v2_enable_response_command_filter", "v2 响应风险替换",
       "bool", "v2", "过滤"),
    _f("AEGIS_V2_RESPONSE_FILTER_OBVIOUS_ONLY", "v2_response_filter_obvious_only", "v2 最小误拦模式",
       "bool", "v2", "过滤"),
    _f("AEGIS_V2_RESPONSE_FILTER_BYPASS_HOSTS", "v2_response_filter_bypass_hosts", "v2 过滤豁免域名",
       "string", "v2", "过滤"),
    _f("AEGIS_V2_BLOCK_INTERNAL_TARGETS", "v2_block_internal_targets", "v2 SSRF 防护", "bool", "v2", "安全"),
    _f("AEGIS_V2_TARGET_ALLOWLIST", "v2_target_allowlist", "v2 目标域名白名单", "string", "v2", "安全"),
    _f("AEGIS_V2_MAX_REQUEST_BODY_BYTES", "v2_max_request_body_bytes", "v2 最大请求体（字节）", "int",
       "v2", "限额", min=1),
    _f("AEGIS_V2_RESPONSE_FILTER_MAX_CHARS", "v2_response_filter_max_chars", "v2 响应最大扫描字符", "int",
       "v2", "限额", min=0),
    _f("AEGIS_V2_SSE_FILTER_PROBE_MAX_CHARS", "v2_sse_filter_probe_max_chars", "v2 SSE 探测字符上限", "int",
       "v2", "限额", min=0),

    # ---- console ----
    _f("AEGIS_LOCAL_UI_SESSION_TTL_SECONDS", "local_ui_session_ttl_seconds", "会话有效期（秒）", "int",
       "console", "会话", min=60),
    _f("AEGIS_LOCAL_UI_LOGIN_RATE_LIMIT_PER_MINUTE", "local_ui_login_rate_limit_per_minute",
       "登录限流（次/分钟）", "int", "console", "会话", min=1),
    _f("AEGIS_LOCAL_UI_SECURE_COOKIE", "local_ui_secure_cookie", "Cookie 仅 HTTPS", "bool",
       "console", "会话", "通过 HTTP 访问控制台时需要关闭，否则无法登录"),
    _f("AEGIS_LOCAL_UI_ALLOW_INTERNAL_NETWORK", "local_ui_allow_internal_network", "允许内网访问控制台",
       "bool", "console", "会话"),
    _f("AEGIS_ADMIN_RATE_LIMIT_PER_MINUTE", "admin_rate_limit_per_minute", "管理接口限流（次/分钟）", "int",
       "console", "限流", min=1),
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


def _check_range(meta: dict[str, object], value: float) -> None:
    """Enforce the optional ``min``/``max`` bounds declared on *meta*."""
    minimum = meta.get("min")
    maximum = meta.get("max")
    if minimum is not None and value < float(minimum):  # type: ignore[arg-type]
        raise ValueError(f"{meta['field']} must be >= {minimum}")
    if maximum is not None and value > float(maximum):  # type: ignore[arg-type]
        raise ValueError(f"{meta['field']} must be <= {maximum}")


def _coerce_config_value(meta: dict[str, object], raw_value: object) -> object:
    kind = str(meta["type"])
    if kind == "bool":
        return _parse_bool_value(raw_value)
    if kind == "int":
        try:
            # Accept "600.0" as 600 so a float-looking round-trip from the UI
            # does not fail; a genuine fraction is still rejected.
            parsed = float(str(raw_value).strip())
        except ValueError as exc:
            raise ValueError(f"invalid integer for {meta['field']}") from exc
        if parsed != int(parsed):
            raise ValueError(f"invalid integer for {meta['field']}")
        _check_range(meta, parsed)
        return int(parsed)
    if kind == "float":
        try:
            parsed = float(str(raw_value).strip())
        except ValueError as exc:
            raise ValueError(f"invalid number for {meta['field']}") from exc
        _check_range(meta, parsed)
        return parsed
    value = str(raw_value or "").strip()
    if kind == "enum":
        raw_options = meta.get("options")
        options = (
            {str(item) for item in raw_options}
            if isinstance(raw_options, list)
            else set()
        )
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
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=str(_ENV_PATH.parent)
        ) as tmp:
            tmp.write("\n".join(new_lines).rstrip() + "\n")
            tmp_path = Path(tmp.name)
        tmp_path.replace(_ENV_PATH)
    except OSError as exc:
        logger.error("config env write failed path=%s error=%s", _ENV_PATH, exc)
        raise RuntimeError(f"无法写入 {_ENV_PATH}: {exc}") from exc


def _restart_required_fields() -> frozenset[str]:
    """Fields the running process pins at startup and hot-reload will not apply.

    Read straight from ``hot_reload._IMMUTABLE_FIELDS`` so the console can never
    drift out of sync with the reload rules it is describing.
    """
    try:
        from aegisgate.core.hot_reload import _IMMUTABLE_FIELDS

        return frozenset(_IMMUTABLE_FIELDS)
    except Exception:  # pragma: no cover - defensive, hot_reload is always importable
        logger.warning("could not read _IMMUTABLE_FIELDS; assuming all fields hot-reloadable")
        return frozenset()


def _read_env_values() -> dict[str, str]:
    """Parse ``config/.env`` into a plain ``KEY -> value`` mapping."""
    values: dict[str, str] = {}
    for raw_line in _read_env_lines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}***{value[-3:]}"


def _ui_config_payload() -> dict[str, object]:
    """Build the console config payload.

    Two things the naive ``getattr(settings, ...)`` version got wrong:

    * ``_IMMUTABLE_FIELDS`` are pinned at startup, so for those the in-memory
      value is stale the moment the user saves. We report the value actually
      written to ``config/.env`` as ``pending_value`` and flag the field, so the
      form stops silently reverting the user's edit.
    * secrets must not be echoed back to the browser; they are masked and the
      client submits an empty string to mean "leave unchanged".
    """
    restart_fields = _restart_required_fields()
    env_values = _read_env_values()
    items: list[dict[str, object]] = []
    for meta in _UI_CONFIG_FIELDS:
        field_name = str(meta["field"])
        current_value = getattr(settings, field_name)
        default_value = _field_default(field_name)
        item: dict[str, object] = {
            **meta,
            "value": current_value,
            "default": default_value,
            "requires_restart": field_name in restart_fields,
        }
        if meta.get("sensitive"):
            raw = str(current_value or "")
            item["value"] = ""
            item["has_value"] = bool(raw)
            item["masked"] = _mask_secret(raw)
            item["default"] = ""
        if item["requires_restart"]:
            raw_env = env_values.get(str(meta["env"]))
            if raw_env is not None:
                try:
                    pending = _coerce_config_value(meta, raw_env)
                except ValueError:
                    pending = raw_env
                if pending != current_value and not meta.get("sensitive"):
                    # Written to .env but not applied to the running process.
                    item["pending_value"] = pending
                    item["value"] = pending
        items.append(item)
    return {"items": items, "sections": [dict(s) for s in _UI_CONFIG_SECTIONS]}
