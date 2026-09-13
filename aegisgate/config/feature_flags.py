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


def _forward_override_counts() -> tuple[dict[str, int], dict[str, int]]:
    """How many enabled forward rules turn each critical filter on / off.

    Reported alongside the global state because with rule-level switches a
    globally-all-off configuration can still be fully protected on the forwarded
    hosts (and the opposite: globally on but switched off per rule).
    """
    turned_on: dict[str, int] = {}
    turned_off: dict[str, int] = {}
    if not settings.enable_gateway_forward:
        # Rules on disk do nothing while forwarding is off; counting them would
        # report protection (or exposure) that is not there.
        return turned_on, turned_off
    try:
        from aegisgate.core import gw_forwards

        rules = gw_forwards.list_rules()
    except Exception:  # pragma: no cover - defensive, must not break flag checks
        return turned_on, turned_off
    for rule in rules:
        if not rule.enabled:
            continue
        for name, value in rule.resolved_filter_overrides().items():
            if name not in _SECURITY_CRITICAL_FLAGS:
                continue
            bucket = turned_on if value else turned_off
            bucket[name] = bucket.get(name, 0) + 1
    return turned_on, turned_off


def _override_note(
    names: tuple[str, ...],
    turned_on: dict[str, int],
    turned_off: dict[str, int],
) -> str:
    parts = []
    for name in names:
        on = turned_on.get(name, 0)
        off = turned_off.get(name, 0)
        if on or off:
            parts.append(f"{name}(on:{on}/off:{off})")
    if not parts:
        return ""
    return "; forward-rule overrides: " + ", ".join(parts)


def _check_disabled_filters(
    flags: FeatureFlags, *, count_forward_overrides: bool = True
) -> None:
    from aegisgate.util.logger import logger

    disabled = [name for name in _SECURITY_CRITICAL_FLAGS if not getattr(flags, name)]
    if count_forward_overrides:
        turned_on, turned_off = _forward_override_counts()
    else:
        turned_on, turned_off = {}, {}
    note = _override_note(_SECURITY_CRITICAL_FLAGS, turned_on, turned_off)
    if len(disabled) == len(_SECURITY_CRITICAL_FLAGS):
        logger.error(
            "SECURITY CRITICAL: ALL security-critical filters are disabled (%s). "
            "The gateway provides NO security protection. "
            "Set at least one AEGIS_ENABLE_* flag to true.%s",
            ", ".join(disabled),
            note,
        )
    elif disabled:
        logger.warning(
            "Security filters disabled: %s. "
            "Review AEGIS_ENABLE_* settings to ensure this is intentional.%s",
            ", ".join(disabled),
            note,
        )
    elif any(turned_off.get(name) for name in _SECURITY_CRITICAL_FLAGS):
        logger.warning(
            "Security filters are globally on but turned off by forward rules.%s", note
        )


feature_flags = FeatureFlags()
# Import time is too early to count forward rules, and reading them here is not
# safe either: gw_forwards imports this module for the first time from inside its
# locked load (validate_rule → _allowed_filter_names), so calling back into
# gw_forwards.list_rules() would wait on that same lock forever. The startup
# lifespan re-runs the report with the counts once the table has loaded.
_check_disabled_filters(feature_flags, count_forward_overrides=False)


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


def recheck_disabled_filters() -> None:
    """Re-emit the disabled-filter report against the current flags and forward rules.

    Called once the forward table has loaded at startup and after every
    gw_forwards hot reload: the global flags did not move, but the per-rule
    overrides counted in the message did.
    """
    _check_disabled_filters(feature_flags)
