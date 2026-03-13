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
    rag_poison_guard: bool = settings.enable_rag_poison_guard
    exact_value_redaction: bool = settings.enable_exact_value_redaction


feature_flags = FeatureFlags()


def refresh_feature_flags() -> None:
    feature_flags.redaction = settings.enable_redaction
    feature_flags.restoration = settings.enable_restoration
    feature_flags.injection_detector = settings.enable_injection_detector
    feature_flags.privilege_guard = settings.enable_privilege_guard
    feature_flags.anomaly_detector = settings.enable_anomaly_detector
    feature_flags.request_sanitizer = settings.enable_request_sanitizer
    feature_flags.output_sanitizer = settings.enable_output_sanitizer
    feature_flags.post_restore_guard = settings.enable_post_restore_guard
    feature_flags.system_prompt_guard = settings.enable_system_prompt_guard
    feature_flags.untrusted_content_guard = settings.enable_untrusted_content_guard
    feature_flags.tool_call_guard = settings.enable_tool_call_guard
    feature_flags.rag_poison_guard = settings.enable_rag_poison_guard
    feature_flags.exact_value_redaction = settings.enable_exact_value_redaction
