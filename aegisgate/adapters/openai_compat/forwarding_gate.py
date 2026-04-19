from __future__ import annotations


_KNOWN_FORWARDING_KERNEL_ROLLOUT_KEYS = frozenset(
    {
        "chat.once",
        "chat.stream",
        "responses.once",
        "responses.stream",
        "messages.once",
        "messages.stream",
        "messages.compat",
    }
)


def is_forwarding_kernel_rollout_enabled(raw_setting: str, route_key: str) -> bool:
    normalized_key = route_key.strip()
    if normalized_key not in _KNOWN_FORWARDING_KERNEL_ROLLOUT_KEYS:
        return False

    enabled = {
        token.strip()
        for token in raw_setting.split(",")
        if token.strip() in _KNOWN_FORWARDING_KERNEL_ROLLOUT_KEYS
    }
    return normalized_key in enabled
