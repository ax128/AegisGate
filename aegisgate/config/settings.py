"""Runtime settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", extra="ignore")

    app_name: str = "AegisGate"
    env: str = "dev"
    log_level: str = "info"
    # DEBUG 下是否打印完整请求正文；False 时只打 method/path/route/headers + body_size，不打正文
    log_full_request_body: bool = False
    host: str = "127.0.0.1"
    port: int = 18080
    enable_relay_endpoint: bool = False

    upstream_base_url: str = "https://your-upstream.example.com/v1"
    upstream_timeout_seconds: float = 60.0
    upstream_max_connections: int = 100
    upstream_max_keepalive_connections: int = 20
    enable_thread_offload: bool = False
    upstream_base_header: str = "x-upstream-base"
    upstream_whitelist_url_list: str = ""
    storage_backend: str = "sqlite"  # sqlite | redis | postgres
    sqlite_db_path: str = "logs/aegisgate.db"  # Docker 下若 logs 不可写可设为 /tmp/aegisgate.db
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_key_prefix: str = "aegisgate"
    redis_pending_scan_batch_size: int = 200
    redis_pending_scan_max_entries: int = 0  # <=0 表示不限制扫描数量，避免高并发会话漏检较早 pending
    postgres_dsn: str = "postgresql://postgres:postgres@127.0.0.1:5432/aegisgate"
    postgres_schema: str = "public"
    max_request_body_bytes: int = 2_000_000
    max_messages_count: int = 100
    max_content_length_per_message: int = 50_000
    max_pending_payload_bytes: int = 100_000
    max_response_length: int = 500_000
    gateway_key_header: str = "gateway-key"
    gateway_key: str = "agent"
    tenant_id_header: str = "x-tenant-id"
    confirmation_ttl_seconds: int = 300
    confirmation_executing_timeout_seconds: int = 120
    pending_data_ttl_seconds: int = 86400
    # 是否在确认文案中展示「命中片段（安全变形）」预览，默认开启
    confirmation_show_hit_preview: bool = True
    # 开启后：命中「强制拦截命令」规则即直接拦截（不依赖 security_level/risk 阈值）
    strict_command_block_enabled: bool = False
    # high|medium|low 三档均已整体放宽，medium 为默认
    security_level: str = "medium"
    enable_semantic_module: bool = False  # 默认关闭；仅在具备 1G 1vCPU 可用的语义模型或接受内置正则占位时设为 True
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
    enforce_loopback_only: bool = True

    enable_request_hmac_auth: bool = False
    request_hmac_secret: str = ""
    request_signature_header: str = "x-aegis-signature"
    request_timestamp_header: str = "x-aegis-timestamp"
    request_nonce_header: str = "x-aegis-nonce"
    request_replay_window_seconds: int = 300
    request_nonce_cache_size: int = 50000
    nonce_cache_backend: str = "memory"  # memory | redis

    enable_pending_prune_task: bool = True
    pending_prune_interval_seconds: int = 60
    clear_pending_on_startup: bool = False
    audit_log_path: str = "logs/audit.jsonl"  # 空串表示不写审计文件；Docker 下可设为 /tmp/audit.jsonl

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
    enable_tool_call_guard: bool = False
    enable_rag_poison_guard: bool = True

    risk_score_threshold: float = Field(default=0.7, ge=0.0, le=1.0)


settings = Settings()
