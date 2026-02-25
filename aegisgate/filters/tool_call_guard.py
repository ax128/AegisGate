"""Tool-call security guard with externalized policy."""

from __future__ import annotations

import json
import re

from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger


class ToolCallGuard(BaseFilter):
    name = "tool_call_guard"

    def __init__(self) -> None:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "violations": [],
        }

        rules = load_security_rules()
        guard_rules = rules.get(self.name, {})
        action_map = rules.get("action_map", {}).get(self.name, {})

        self._tool_whitelist = {str(item) for item in guard_rules.get("tool_whitelist", [])}
        self._default_action = str(guard_rules.get("default_action", "block"))
        self._action_map = {str(key): str(value) for key, value in action_map.items()}

        self._param_rules: dict[tuple[str, str], re.Pattern[str]] = {}
        for item in guard_rules.get("parameter_rules", []):
            tool = str(item.get("tool", ""))
            param = str(item.get("param", ""))
            regex = item.get("regex")
            if not tool or not param or not regex:
                continue
            self._param_rules[(tool, param)] = re.compile(regex)

        self._dangerous_param_patterns = [
            re.compile(item.get("regex"), re.IGNORECASE)
            for item in guard_rules.get("dangerous_param_patterns", [])
            if item.get("regex")
        ]
        self._semantic_patterns = [
            re.compile(item.get("regex"), re.IGNORECASE)
            for item in guard_rules.get("semantic_approval_patterns", [])
            if item.get("regex")
        ]

    def _apply_action(self, ctx: RequestContext, key: str) -> str:
        action = self._action_map.get(key, self._default_action)
        ctx.enforcement_actions.append(f"{self.name}:{key}:{action}")

        if action == "block":
            ctx.risk_score = max(ctx.risk_score, 0.96)
            ctx.requires_human_review = True
        elif action == "review":
            ctx.risk_score = max(ctx.risk_score, 0.86)
            ctx.requires_human_review = True

        return action

    @staticmethod
    def _as_text(value: object) -> str:
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    def process_response(self, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "violations": [],
        }

        tool_calls = resp.metadata.get("tool_calls")
        if not isinstance(tool_calls, list):
            return resp

        violations: list[str] = []
        blocked = False

        for tool_call in tool_calls:
            if not isinstance(tool_call, dict):
                continue

            tool_name = str(tool_call.get("name", "")).strip()
            args = tool_call.get("arguments", {})
            args_text = self._as_text(args)

            if self._tool_whitelist and tool_name and tool_name not in self._tool_whitelist:
                violations.append(f"disallowed_tool:{tool_name}")
                action = self._apply_action(ctx, "disallowed_tool")
                blocked = blocked or action == "block"

            for pattern in self._dangerous_param_patterns:
                if pattern.search(args_text):
                    violations.append(f"dangerous_param:{tool_name or 'unknown'}")
                    action = self._apply_action(ctx, "dangerous_param")
                    blocked = blocked or action == "block"
                    break

            if isinstance(args, dict):
                for (rule_tool, rule_param), rule_pattern in self._param_rules.items():
                    if rule_tool != tool_name:
                        continue
                    if rule_param not in args:
                        continue
                    value = str(args.get(rule_param, ""))
                    if not rule_pattern.match(value):
                        violations.append(f"invalid_param:{tool_name}.{rule_param}")
                        action = self._apply_action(ctx, "invalid_param")
                        blocked = blocked or action == "block"

            semantic_input = f"{tool_name} {args_text}"
            for pattern in self._semantic_patterns:
                if pattern.search(semantic_input):
                    violations.append(f"semantic_review:{tool_name or 'unknown'}")
                    action = self._apply_action(ctx, "semantic_review")
                    blocked = blocked or action == "block"
                    break

        if violations:
            ctx.security_tags.add("tool_call_violation")
            self._report = {
                "filter": self.name,
                "hit": True,
                "risk_score": ctx.risk_score,
                "violations": sorted(set(violations)),
                "blocked": blocked,
            }
            logger.info(
                "tool call violations request_id=%s blocked=%s violations=%s",
                ctx.request_id,
                blocked,
                sorted(set(violations)),
            )

            if blocked:
                resp.output_text = "[AegisGate] tool call blocked by policy."

        return resp

    def report(self) -> dict:
        return self._report
