"""Feature flags used by filters and policy engine."""

from dataclasses import dataclass

from aegisgate.config.settings import settings

_SECURITY_CRITICAL_FLAGS = (
    "injection_detector",
    "request_sanitizer",
    "privilege_guard",
    "tool_call_guard",
    "output_sanitizer",
)


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


def _check_disabled_filters(flags: FeatureFlags) -> None:
    from aegisgate.util.logger import logger

    disabled = [name for name in _SECURITY_CRITICAL_FLAGS if not getattr(flags, name)]
    if len(disabled) == len(_SECURITY_CRITICAL_FLAGS):
        logger.error(
            "SECURITY CRITICAL: ALL security-critical filters are disabled (%s). "
            "The gateway provides NO security protection. "
            "Set at least one AEGIS_ENABLE_* flag to true.",
            ", ".join(disabled),
        )
    elif disabled:
        logger.warning(
            "Security filters disabled: %s. "
            "Review AEGIS_ENABLE_* settings to ensure this is intentional.",
            ", ".join(disabled),
        )


feature_flags = FeatureFlags()
_check_disabled_filters(feature_flags)


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
    _check_disabled_filters(new)
    global feature_flags
    feature_flags = new
