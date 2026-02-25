"""Feature flags used by filters and policy engine."""

from dataclasses import dataclass

from aegisgate.config.settings import settings


@dataclass(slots=True)
class FeatureFlags:
    redaction: bool = settings.enable_redaction
    restoration: bool = settings.enable_restoration
    injection_detector: bool = settings.enable_injection_detector
    privilege_guard: bool = settings.enable_privilege_guard
    anomaly_detector: bool = settings.enable_anomaly_detector
    request_sanitizer: bool = settings.enable_request_sanitizer
    output_sanitizer: bool = settings.enable_output_sanitizer
    post_restore_guard: bool = settings.enable_post_restore_guard
    system_prompt_guard: bool = settings.enable_system_prompt_guard
    untrusted_content_guard: bool = settings.enable_untrusted_content_guard
    tool_call_guard: bool = settings.enable_tool_call_guard


feature_flags = FeatureFlags()
