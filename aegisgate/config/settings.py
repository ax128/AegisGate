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
    # Whether DEBUG logs the full request body; False logs only method/path/route/headers + body_size.
    log_full_request_body: bool = False
    host: str = "127.0.0.1"
    port: int = 18080
    enable_relay_endpoint: bool = False

    upstream_timeout_seconds: float = 600.0
    upstream_max_connections: int = 300
    upstream_max_keepalive_connections: int = 100
    # Max retries for a streaming request that hits a retryable upstream error before any byte
    # has been sent to the client.
    # 0 disables it; enable explicitly and keep it small (1-2) so failing traffic is not amplified.
    stream_bootstrap_retries: int = 0
    # Maximum run time (seconds) allowed for the filter pipeline (request/response pipeline).
    # On timeout the request is rejected (response: block, request: pass-through) and the event
    # loop is no longer blocked.
    # 0 means unlimited (not recommended in production).
    filter_pipeline_timeout_s: float = 90.0
    upstream_base_header: str = "x-upstream-base"
    # Default upstream (optional): once set, /v1/... can be called directly without port routing
    # or token registration (e.g. http://localhost:8317/v1).
    upstream_base_url: str = ""
    upstream_whitelist_url_list: str = ""
    # Directory the editor reads/writes docker-compose files in. Empty string = use config/compose/.
    compose_dir: str = ""
    storage_backend: str = "sqlite"  # sqlite | redis | postgres
    # Behaviour when the storage backend fails: block = reject the request (default),
    # forward = skip persisting mapping/audit records only. It does not change
    # filter verdicts or response-side block behaviour, and unregistered request
    # filters still fail closed.
    storage_failure_action: str = "block"
    sqlite_db_path: str = (
        "logs/aegisgate.db"  # Under Docker, set to /tmp/aegisgate.db if logs is not writable
    )
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_key_prefix: str = "aegisgate"
    postgres_dsn: str = ""
    postgres_schema: str = "public"
    max_request_body_bytes: int = 12_000_000
    # Multipart/form-data requests (for example image edits / file upload) may be larger.
    # OpenAI image edit masks require the image+mask to be <50MB; keep a small safety buffer.
    max_multipart_body_bytes: int = 60_000_000
    # Token-routed generic-proxy requests (CLIProxyAPI etc.) may carry large
    # multimodal payloads (inline image/video) above the 12MB text JSON limit.
    v2_max_request_body_bytes: int = 64_000_000
    max_messages_count: int = 500
    max_content_length_per_message: int = 250_000
    max_response_length: int = 2_000_000
    gateway_key_header: str = "gateway-key"
    gateway_key: str = ""  # Loaded from config/aegis_gateway.key at startup
    # Retention for redaction mappings; also drives the periodic mapping-store sweep.
    pending_data_ttl_seconds: int = 86400
    # Whether the confirmation text shows the "matched fragment (safely transformed)" preview; on by default.
    confirmation_show_hit_preview: bool = True
    # [DEPRECATED] require_confirmation_on_block — kept only for config compatibility.
    # Whether it is True or False, the behaviour matches False: on a block the dangerous fragment
    # is transformed and returned directly, and the yes/no approval commands are gone.
    # config/.env.example and config/README.md mark it deprecated; a future release may remove it.
    require_confirmation_on_block: bool = False
    # When on, matching a "force-block command" rule blocks outright (independent of
    # security_level and the risk threshold).
    strict_command_block_enabled: bool = False
    # high: full detection | medium (default): relaxed, high-risk hits + redaction only
    # | low: very relaxed, essentially redaction plus blocking of extreme risks
    security_level: str = "medium"
    # Semantic re-check (response side, gray-zone gate).
    # Triggers only when risk_score falls inside (semantic_gray_low, semantic_gray_high) and runs
    # against the semantic service at semantic_service_url. With an empty URL it only records the
    # degradation and does not raise the risk.
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
    # Path to the token mapping table (config/gw_tokens.json); loaded at startup, written on
    # register/delete.
    gw_tokens_path: str = "config/gw_tokens.json"
    # Automatic local-port routing: a purely numeric token (1024-65535) is forwarded to
    # host.docker.internal:{port}/v1.
    # Once on, /v1/__gw__/t/8080/chat/completions → http://host.docker.internal:8080/v1/chat/completions
    # Global model-mapping config (config/model_map.json), used during compat conversion.
    compat_model_map_path: str = "config/model_map.json"
    # Private, internal-only rollout gate for forwarding-kernel cutover.
    # Comma-separated route/mode keys such as "responses.once,chat.stream".
    # Empty string keeps all forwarding-kernel rollout paths disabled.
    internal_forwarding_kernel_rollout: str = ""
    # Whether to auto-inject the built-in compat tokens (e.g. "claude-to-gpt").
    # Safe default: off. Enabling it in production is discouraged, since predictable tokens
    # invite abuse.
    enable_builtin_compat_tokens: bool = False
    enable_local_port_routing: bool = False
    # Allow numeric tokens (1024-65535) to be used from public/non-internal clients.
    # Default: False (internal-only) to prevent exposing predictable port tokens on public ingress.
    allow_public_numeric_tokens: bool = False
    # Allow `token__passthrough` mode from public/non-internal clients.
    # Default: False (internal-only) because passthrough disables all security filters.
    allow_public_passthrough_mode: bool = False
    # Allow ``AEGIS_UPSTREAM_WHITELIST_URL_LIST`` bypass from public/non-internal
    # clients. Default False: whitelist still skips both pipelines (including PII
    # redaction) for internal clients, but public clients fall back to the normal
    # filter path unless this is explicitly enabled.
    allow_public_upstream_whitelist: bool = False
    # Custom host (defaults to host.docker.internal under Docker; use 127.0.0.1 on bare metal).
    local_port_routing_host: str = "host.docker.internal"
    # H-08: Comma-separated allowlist of ports permitted for compat port routing.
    # Empty string = deny all compat port routing (safe default).
    # Example: "8317,8080,3000"
    compat_allowed_ports: str = ""
    # Automatic Docker upstream injection: registers token → Docker service name at startup, so
    # gw_tokens.json needs no manual editing.
    # Format: comma-separated, each item token:service_name[:port]; port defaults to token.
    # Example: 8317:cli-proxy-api,8080:sub2api,3000:aiclient2api
    # Resulting mapping: token=8317 → upstream_base=http://cli-proxy-api:8317/v1
    docker_upstreams: str = ""
    enforce_loopback_only: bool = True
    # Trusted reverse-proxy IPs (comma-separated); only these may set X-Forwarded-For.
    # Empty = trust direct client IP only (safest default).
    trusted_proxy_ips: str = ""
    # When True (default), X-Forwarded-For from a direct peer that is not in
    # trusted_proxy_ips is treated as a public client even if the resolved IP
    # looks internal. Set false to restore the pre-A3 admin / default-/v1 / UI
    # checks while rolling out AEGIS_TRUSTED_PROXY_IPS. Restart required.
    xff_strict_internal: bool = True
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

    # Periodic mapping_store cleanup: deletes mappings older than pending_data_ttl_seconds so
    # long-running instances do not grow the database forever.
    # (Renamed from enable_pending_prune_task, which also drove the removed pending-confirmation
    # sweep; pending_prune_interval_seconds and clear_pending_on_startup are gone with it.)
    enable_mapping_prune_task: bool = True
    mapping_prune_interval_seconds: int = 3600
    audit_log_path: str = (
        "logs/audit.jsonl"  # Empty string disables the audit file; under Docker use /tmp/audit.jsonl
    )
    enable_dangerous_response_log: bool = (
        False  # Store dangerous response samples, split by date, auto-pruning files older than 10 days
    )
    dangerous_response_log_path: str = "logs/dangerous_response_samples.jsonl"  # Base path for the dangerous-response sample log; under Docker use /tmp/aegisgate/dangerous_response_samples.jsonl
    # Keep the matched text in those samples instead of only a sha256 + length. Off by default
    # and only consulted when enable_dangerous_response_log is already on, so turning the log on
    # never silently starts storing secrets. Turn this on when you intend to calibrate rules
    # against recorded traffic (scripts/replay_calibrate.py) — with it off the corpus is all
    # digests and nothing can be replayed against it.
    dangerous_response_log_include_raw: bool = False

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
