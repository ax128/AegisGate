"""Policy-driven filter activation."""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any

import yaml

from aegisgate.config.security_level import apply_threshold, normalize_security_level
from aegisgate.config.feature_flags import feature_flags
from aegisgate.core.context import RequestContext
from aegisgate.core.errors import PolicyResolutionError
from aegisgate.util.logger import logger


# 当策略文件不存在（如 config 挂载为空）时使用的内置默认，与 default.yaml 一致
_BUILTIN_DEFAULT_POLICY: dict[str, Any] = {
    "enabled_filters": [
        "redaction",
        "request_sanitizer",
        "anomaly_detector",
        "injection_detector",
        "privilege_guard",
        "restoration",
        "post_restore_guard",
        "output_sanitizer",
    ],
    "risk_threshold": 0.85,
}


class PolicyEngine:
    def __init__(self, rules_dir: str = "aegisgate/policies/rules") -> None:
        self.rules_dir = Path(rules_dir)
        self._cache_lock = Lock()
        self._cache: dict[str, tuple[int, dict[str, Any]]] = {}

    def _load_policy(self, policy_name: str) -> dict[str, Any]:
        rule_path = self.rules_dir / f"{policy_name}.yaml"
        if not rule_path.exists():
            if policy_name == "default":
                logger.warning(
                    "policy file not found, using built-in default policy path=%s",
                    rule_path,
                )
                return dict(_BUILTIN_DEFAULT_POLICY)
            raise PolicyResolutionError(f"policy not found: {policy_name}")

        mtime_ns = rule_path.stat().st_mtime_ns
        with self._cache_lock:
            cached = self._cache.get(policy_name)
            if cached and cached[0] == mtime_ns:
                return cached[1]

            loaded = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise PolicyResolutionError(f"invalid policy format: {rule_path}")
            self._cache[policy_name] = (mtime_ns, loaded)
            return loaded

    def resolve(self, ctx: RequestContext, policy_name: str = "default") -> dict[str, Any]:
        data = self._load_policy(policy_name)
        configured = set(data.get("enabled_filters", []))

        global_flags = {
            "redaction": feature_flags.redaction,
            "restoration": feature_flags.restoration,
            "injection_detector": feature_flags.injection_detector,
            "privilege_guard": feature_flags.privilege_guard,
            "anomaly_detector": feature_flags.anomaly_detector,
            "request_sanitizer": feature_flags.request_sanitizer,
            "output_sanitizer": feature_flags.output_sanitizer,
            "post_restore_guard": feature_flags.post_restore_guard,
            "system_prompt_guard": feature_flags.system_prompt_guard,
            "untrusted_content_guard": feature_flags.untrusted_content_guard,
            "tool_call_guard": feature_flags.tool_call_guard,
        }
        enabled = {item for item in configured if global_flags.get(item, False)}
        # Redaction is mandatory baseline protection and is not downgraded by security level.
        if feature_flags.redaction:
            enabled.add("redaction")
        raw_threshold = float(data.get("risk_threshold", 0.85))
        security_level = normalize_security_level()
        threshold = apply_threshold(raw_threshold, level=security_level)
        ctx.enabled_filters = enabled
        ctx.risk_threshold = float(threshold)

        logger.info(
            "policy resolved: request_id=%s policy=%s security_level=%s filters=%s threshold=%s raw_threshold=%s",
            ctx.request_id,
            policy_name,
            security_level,
            sorted(enabled),
            threshold,
            raw_threshold,
        )
        return {"enabled_filters": enabled, "threshold": threshold}
