"""Feature flags used by filters and policy engine."""

from dataclasses import dataclass

from aegisgate.config.settings import settings


@dataclass(frozen=True, slots=True)
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
    # Atomically swap the snapshot reference so concurrent readers always
    # observe a consistent set of flags.
    new = FeatureFlags(
        redaction=settings.enable_redaction,
        restoration=settings.enable_restoration,
        injection_detector=settings.enable_injection_detector,
        privilege_guard=settings.enable_privilege_guard,
        anomaly_detector=settings.enable_anomaly_detector,
        request_sanitizer=settings.enable_request_sanitizer,
        output_sanitizer=settings.enable_output_sanitizer,
        post_restore_guard=settings.enable_post_restore_guard,
        system_prompt_guard=settings.enable_system_prompt_guard,
        untrusted_content_guard=settings.enable_untrusted_content_guard,
        tool_call_guard=settings.enable_tool_call_guard,
        rag_poison_guard=settings.enable_rag_poison_guard,
        exact_value_redaction=settings.enable_exact_value_redaction,
    )
    global feature_flags
    feature_flags = new
