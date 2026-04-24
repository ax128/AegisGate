"""Runtime settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        extra="ignore",
        env_file="config/.env",
        env_file_encoding="utf-8",
    )

    app_name: str = "AegisGate"
    env: str = "dev"
    log_level: str = "info"
    # DEBUG 下是否打印完整请求正文；False 时只打 method/path/route/headers + body_size，不打正文
    log_full_request_body: bool = False
    host: str = "127.0.0.1"
    port: int = 18080
    enable_relay_endpoint: bool = False

    upstream_timeout_seconds: float = 600.0
    upstream_max_connections: int = 300
    upstream_max_keepalive_connections: int = 100
    # 流式请求在尚未向客户端发送任何字节前，遇到可重试上游错误时的最大重试次数。
    # 0 表示禁用；建议按需显式开启并保持小值（1~2）以避免放大失败流量。
    stream_bootstrap_retries: int = 0
    # 默认关闭线程池卸载：当前 Python 3.13 运行环境下，asyncio.to_thread 会让
    # 事件循环在关闭阶段卡住，导致 pytest/短生命周期脚本无法正常退出。
    # 生产如确认运行时无该问题，可通过环境变量显式开启。
    enable_thread_offload: bool = False
    # 过滤管道（request/response pipeline）最大允许执行时间（秒）。
    # 超时后该请求被拒绝（response: block，request: pass-through），event loop 不再被阻塞。
    # 设为 0 表示不限制（不推荐生产使用）。
    filter_pipeline_timeout_s: float = 90.0
    upstream_base_header: str = "x-upstream-base"
    # 默认上游（可选）：设置后可直接请求 /v1/...，无需走端口路由或 token 注册（如 http://localhost:8317/v1）
    upstream_base_url: str = ""
    upstream_whitelist_url_list: str = ""
    # 编辑器读写 docker-compose 文件的目录。空字符串 = 默认使用 config/compose/
    compose_dir: str = ""
    storage_backend: str = "sqlite"  # sqlite | redis | postgres
    # 存储后端故障时的行为：block = 拒绝请求（默认）, forward = 降级转发（无审计/脱敏持久化）
    storage_failure_action: str = "block"
    sqlite_db_path: str = (
        "logs/aegisgate.db"  # Docker 下若 logs 不可写可设为 /tmp/aegisgate.db
    )
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_key_prefix: str = "aegisgate"
    redis_pending_scan_batch_size: int = 200
    redis_pending_scan_max_entries: int = (
        0  # <=0 表示不限制扫描数量，避免高并发会话漏检较早 pending
    )
    postgres_dsn: str = ""
    postgres_schema: str = "public"
    max_request_body_bytes: int = 12_000_000
    # Multipart/form-data requests (for example image edits / file upload) may be larger.
    # OpenAI image edit masks require the image+mask to be <50MB; keep a small safety buffer.
    max_multipart_body_bytes: int = 60_000_000
    max_messages_count: int = 500
    max_content_length_per_message: int = 250_000
    max_pending_payload_bytes: int = 1_200_000
    max_response_length: int = 2_000_000
    gateway_key_header: str = "gateway-key"
    gateway_key: str = ""  # Loaded from config/aegis_gateway.key at startup
    tenant_id_header: str = "x-tenant-id"
    confirmation_ttl_seconds: int = 600
    confirmation_executing_timeout_seconds: int = 120
    pending_data_ttl_seconds: int = 86400
    # 是否在确认文案中展示「命中片段（安全变形）」预览，默认开启
    confirmation_show_hit_preview: bool = True
    # [DEPRECATED] require_confirmation_on_block — 此字段已废弃，保留仅为配置兼容。
    # 无论该值设为 True 或 False，行为均等同 False：拦截时直接将危险片段
    # 变形后返回结果，不再支持 yes/no 放行指令。
    # UI (.env.example, config/README.md) 已标注废弃；未来版本可能移除此字段。
    require_confirmation_on_block: bool = False
    # 开启后：命中「强制拦截命令」规则即直接拦截（不依赖 security_level/risk 阈值）
    strict_command_block_enabled: bool = False
    # high: 全量检测 | medium（默认）: 宽松，仅高危+脱敏 | low: 极宽松，基本只脱敏+极端危险拦截
    security_level: str = "medium"
    # 语义复核（响应侧、灰区门控）。
    # 仅当 risk_score 落在 (semantic_gray_low, semantic_gray_high) 时才触发；
    # 通过 semantic_service_url 指向的语义服务执行。URL 为空时仅记录降级，不做风险抬升。
    enable_semantic_module: bool = True
    semantic_gray_low: float = 0.25
    semantic_gray_high: float = 0.75
    semantic_timeout_ms: int = 150
    semantic_cache_ttl_seconds: int = 300
    semantic_cache_max_entries: int = 5000
    semantic_service_url: str = ""
    semantic_circuit_failure_threshold: int = 3
    semantic_circuit_open_seconds: int = 30
    default_policy: str = "default"
    security_rules_path: str = "aegisgate/policies/rules/security_filters.yaml"
    # token 映射表路径（config/gw_tokens.json），启动时加载，注册/删除时写入
    gw_tokens_path: str = "config/gw_tokens.json"
    # 本地端口自动路由：token 为纯数字端口（1024-65535）时自动转发到 host.docker.internal:{port}/v1
    # 开启后 /v1/__gw__/t/8080/chat/completions → http://host.docker.internal:8080/v1/chat/completions
    # 全局模型映射配置（config/model_map.json），compat 转换时使用
    compat_model_map_path: str = "config/model_map.json"
    # Private, internal-only rollout gate for forwarding-kernel cutover.
    # Comma-separated route/mode keys such as "responses.once,chat.stream".
    # Empty string keeps all forwarding-kernel rollout paths disabled.
    internal_forwarding_kernel_rollout: str = ""
    # 是否自动注入内置 compat token（例如 "claude-to-gpt"）。
    # 安全默认：关闭。生产环境不建议开启（避免可预测 token 被滥用）。
    enable_builtin_compat_tokens: bool = False
    enable_local_port_routing: bool = False
    # Allow numeric tokens (1024-65535) to be used from public/non-internal clients.
    # Default: False (internal-only) to prevent exposing predictable port tokens on public ingress.
    allow_public_numeric_tokens: bool = False
    # Allow `token__passthrough` mode from public/non-internal clients.
    # Default: False (internal-only) because passthrough disables all security filters.
    allow_public_passthrough_mode: bool = False
    # 自定义 host（Docker 环境默认 host.docker.internal，裸机可改为 127.0.0.1）
    local_port_routing_host: str = "host.docker.internal"
    # H-08: Comma-separated allowlist of ports permitted for compat port routing.
    # Empty string = deny all compat port routing (safe default).
    # Example: "8317,8080,3000"
    compat_allowed_ports: str = ""
    # Docker 上游自动注入：启动时自动注册 token → Docker 服务名映射，无需手动编辑 gw_tokens.json。
    # 格式：逗号分隔，每项为 token:service_name[:port]，port 省略时默认等于 token。
    # 示例：8317:cli-proxy-api,8080:sub2api,3000:aiclient2api
    # 生成映射：token=8317 → upstream_base=http://cli-proxy-api:8317/v1
    docker_upstreams: str = ""
    enforce_loopback_only: bool = True
    # Trusted reverse-proxy IPs (comma-separated); only these may set X-Forwarded-For.
    # Empty = trust direct client IP only (safest default).
    trusted_proxy_ips: str = ""
    local_ui_session_ttl_seconds: int = 43_200
    local_ui_login_rate_limit_per_minute: int = 10
    local_ui_secure_cookie: bool = True
    local_ui_allow_internal_network: bool = False
    # Block internal/private IPs as v2 target URL (SSRF protection)
    v2_block_internal_targets: bool = True

    enable_request_hmac_auth: bool = False
    request_hmac_secret: str = ""
    request_signature_header: str = "x-aegis-signature"
    request_timestamp_header: str = "x-aegis-timestamp"
    request_nonce_header: str = "x-aegis-nonce"
    request_replay_window_seconds: int = 300
    request_nonce_cache_size: int = 50000
    nonce_cache_backend: str = "memory"  # memory | redis

    # v2 generic HTTP proxy (independent from v1 OpenAI-compatible filter chain)
    enable_v2_proxy: bool = True
    v2_enable_request_redaction: bool = True
    v2_enable_response_command_filter: bool = True
    v2_response_filter_obvious_only: bool = True
    v2_target_allowlist: str = ""
    v2_response_filter_bypass_hosts: str = ""
    v2_response_filter_max_chars: int = 200_000
    v2_sse_filter_probe_max_chars: int = 4_000

    enable_pending_prune_task: bool = True
    pending_prune_interval_seconds: int = 60
    # SQLite mapping_store 定期清理间隔（秒）。用于删除超出 pending_data_ttl_seconds 的旧映射，
    # 防止长时间运行导致磁盘膨胀。
    mapping_prune_interval_seconds: int = 3600
    clear_pending_on_startup: bool = False
    audit_log_path: str = (
        "logs/audit.jsonl"  # 空串表示不写审计文件；Docker 下可设为 /tmp/audit.jsonl
    )
    enable_dangerous_response_log: bool = (
        False  # 保存响应侧危险样本，按日期切分并自动清理 10 天前旧文件
    )
    dangerous_response_log_path: str = "logs/dangerous_response_samples.jsonl"  # 危险响应样本日志基路径；Docker 下可设为 /tmp/aegisgate/dangerous_response_samples.jsonl

    enable_redaction: bool = True
    enable_restoration: bool = True
    enable_injection_detector: bool = True
    enable_privilege_guard: bool = True
    enable_anomaly_detector: bool = True
    enable_request_sanitizer: bool = True
    enable_output_sanitizer: bool = True
    enable_post_restore_guard: bool = True
    enable_system_prompt_guard: bool = False
    enable_untrusted_content_guard: bool = True
    enable_tool_call_guard: bool = True
    enable_rag_poison_guard: bool = True
    enable_exact_value_redaction: bool = True

    risk_score_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    # Request pipeline timeout action: "block" (safe default) or "pass" (legacy)
    request_pipeline_timeout_action: str = "block"
    # Admin endpoint rate limit: max requests per minute per client IP
    admin_rate_limit_per_minute: int = 30


settings = Settings()
