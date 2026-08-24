"""Policy-driven filter activation."""

from __future__ import annotations

import os
import time
from pathlib import Path
from threading import Lock
from typing import Any

import yaml

from aegisgate.config.settings import settings
from aegisgate.config.security_level import apply_threshold, normalize_security_level
import aegisgate.config.feature_flags as feature_flags_module
from aegisgate.core.context import RequestContext
from aegisgate.core.errors import PolicyResolutionError
from aegisgate.util.logger import logger


# Built-in default used when the policy file is missing (e.g. an empty config mount); matches
# default.yaml. It declares risk_threshold on purpose rather than letting resolve() fall back to
# AEGIS_RISK_SCORE_THRESHOLD: a missing policy file must not quietly move the threshold too. That
# makes the number below a hand-maintained copy, so test_doc_alignment pins it to default.yaml.
_BUILTIN_DEFAULT_POLICY: dict[str, Any] = {
    "enabled_filters": [
        "exact_value_redaction",
        "redaction",
        "request_sanitizer",
        "rag_poison_guard",
        "anomaly_detector",
        "injection_detector",
        "privilege_guard",
        "tool_call_guard",
        "restoration",
        "post_restore_guard",
        "output_sanitizer",
    ],
    "risk_threshold": 0.85,
}

# Policy names already warned about with "policy file not found"; warn once per process
_builtin_policy_warned: set[str] = set()
_builtin_policy_warned_lock = Lock()
_POLICY_STAT_TTL_SECONDS = 1.0


def _resolve_rules_dir(rules_dir: str | None) -> Path:
    raw = rules_dir or str(Path(settings.security_rules_path).parent)
    candidate = Path(raw)
    if not candidate.is_absolute():
        app_root = Path(__file__).resolve().parents[2]
        candidates = [Path.cwd() / candidate, app_root / candidate]
        for item in candidates:
            if item.exists():
                candidate = item.resolve()
                break
        else:
            candidate = candidates[-1].resolve()
    if candidate.exists() and (candidate / "default.yaml").is_file():
        return candidate
    bootstrap = os.environ.get("AEGIS_BOOTSTRAP_RULES_DIR", "").strip()
    if bootstrap:
        fallback = Path(bootstrap)
        if (fallback / "default.yaml").is_file():
            return fallback.resolve()
    return candidate


class PolicyEngine:
    def __init__(self, rules_dir: str | None = None) -> None:
        self.rules_dir = _resolve_rules_dir(rules_dir)
        self._cache_lock = Lock()
        self._cache: dict[str, tuple[int, float, dict[str, Any]]] = {}

    def _load_policy(self, policy_name: str) -> dict[str, Any]:
        rule_path = self.rules_dir / f"{policy_name}.yaml"
        if not rule_path.exists():
            if policy_name == "default":
                with _builtin_policy_warned_lock:
                    already_warned = policy_name in _builtin_policy_warned
                    _builtin_policy_warned.add(policy_name)
                if not already_warned:
                    logger.warning(
                        "policy file not found, using built-in default policy path=%s (will not warn again this run)",
                        rule_path,
                    )
                return dict(_BUILTIN_DEFAULT_POLICY)
            raise PolicyResolutionError(f"policy not found: {policy_name}")

        mtime_ns = rule_path.stat().st_mtime_ns
        now = time.monotonic()
        with self._cache_lock:
            cached = self._cache.get(policy_name)
            if cached:
                cached_mtime_ns, next_stat_at, cached_data = cached
                if now < next_stat_at:
                    return cached_data
                if cached_mtime_ns == mtime_ns:
                    self._cache[policy_name] = (
                        cached_mtime_ns,
                        now + _POLICY_STAT_TTL_SECONDS,
                        cached_data,
                    )
                    return cached_data

            loaded = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise PolicyResolutionError(f"invalid policy format: {rule_path}")
            self._cache[policy_name] = (
                mtime_ns,
                now + _POLICY_STAT_TTL_SECONDS,
                loaded,
            )
            return loaded

    def declared_risk_threshold(self, policy_name: str = "default") -> float:
        """The policy's own ``risk_threshold``, before the security level scales it.

        Same fallback order ``resolve`` uses. Exists so a health probe can ask what
        the threshold *would* be without building a RequestContext to get it.
        """
        data = self._load_policy(policy_name)
        return float(data.get("risk_threshold", settings.risk_score_threshold))

    def resolve(
        self, ctx: RequestContext, policy_name: str = "default"
    ) -> dict[str, Any]:
        data = self._load_policy(policy_name)
        configured = set(data.get("enabled_filters", []))

        flags = feature_flags_module.feature_flags
        global_flags = {
            "redaction": flags.redaction,
            "restoration": flags.restoration,
            "injection_detector": flags.injection_detector,
            "privilege_guard": flags.privilege_guard,
            "anomaly_detector": flags.anomaly_detector,
            "request_sanitizer": flags.request_sanitizer,
            "output_sanitizer": flags.output_sanitizer,
            "post_restore_guard": flags.post_restore_guard,
            "system_prompt_guard": flags.system_prompt_guard,
            "untrusted_content_guard": flags.untrusted_content_guard,
            "tool_call_guard": flags.tool_call_guard,
            "rag_poison_guard": flags.rag_poison_guard,
            "exact_value_redaction": flags.exact_value_redaction,
        }
        enabled = {item for item in configured if global_flags.get(item, False)}
        # Redaction is mandatory baseline protection and is not downgraded by security level.
        if flags.redaction:
            enabled.add("redaction")
        if flags.exact_value_redaction:
            enabled.add("exact_value_redaction")
        # AEGIS_RISK_SCORE_THRESHOLD is the global floor; a policy YAML that
        # declares risk_threshold overrides it per policy. It used to fall back to a
        # hardcoded 0.85, which left the documented global setting with no consumer.
        raw_threshold = float(
            data.get("risk_threshold", settings.risk_score_threshold)
        )
        security_level = normalize_security_level()
        threshold = apply_threshold(raw_threshold, level=security_level)
        ctx.enabled_filters = enabled
        ctx.risk_threshold = float(threshold)

        logger.debug(
            "policy resolved: request_id=%s policy=%s security_level=%s threshold=%.4f filter_count=%d",
            ctx.request_id,
            policy_name,
            security_level,
            threshold,
            len(enabled),
        )
        return {"enabled_filters": enabled, "threshold": threshold}
