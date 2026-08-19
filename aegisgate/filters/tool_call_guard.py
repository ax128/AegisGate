"""Tool-call security guard with externalized policy."""

from __future__ import annotations

import json
import re

from aegisgate.config.security_rules import load_security_rules
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger
from aegisgate.util.text_normalize import (
    build_haystacks,
    normalize_for_match,
    pattern_hits_in,
)


# H-10: Unconditionally blocked tool names regardless of whitelist configuration.
# These represent system-execution tools that a language model must never invoke
# unless explicitly whitelisted by the operator.
_DANGEROUS_TOOL_NAMES: frozenset[str] = frozenset({
    "bash", "shell", "sh", "zsh", "fish",
    "eval", "exec", "execute",
    "system", "popen", "subprocess",
    "python", "ruby", "node", "perl",
    "powershell", "cmd",
    "curl", "wget",
    "nc", "netcat",
    "rm", "del", "rmdir",
    "sudo", "su",
})


_READ_ONLY_CONTENT_TOOLS = frozenset(
    {
        # read-only file operations
        "read",
        "read_file",
        "glob",
        "grep",
        # read-only search/browsing
        "web_search",
        "webfetch",
        "web_fetch",
        "browser",
        "search",
        # general agent tools (non-executing)
        "todowrite",
        "task",
        "submit",
        "multi_tool_use.parallel",
        # Notebook (read-only viewing)
        "notebook_edit",
        "notebookedit",
    }
)

# File-writing tools: their content is code or documentation, which may reference a sensitive path
# without being an actual attack. For these tools only the injection-chain patterns (shell_injection
# and friends) are checked; the path-reference patterns (sensitive_file_access, ssh_key_access,
# path_traversal) are skipped to avoid false blocks.
_FILE_WRITE_CONTENT_TOOLS = frozenset(
    {
        "write",
        "edit",
        "apply_patch",
        "patch",
        "str_replace_editor",
        "file_editor",
        "create_file",
        "replace_in_file",
        "insert_code_block",
        "write_file",
        "delete_file",
    }
)

# Path-reference rule IDs — a hotspot for false positives in file-writing tool arguments
_PATH_REFERENCE_PATTERN_IDS = frozenset(
    {"sensitive_file_access", "path_traversal", "ssh_key_access"}
)


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

        self._tool_whitelist = {
            str(item) for item in guard_rules.get("tool_whitelist", [])
        }
        if not self._tool_whitelist:
            logger.warning(
                "tool_call_guard: no tool_whitelist configured — "
                "dangerous tool names will be blocked by built-in blacklist (%d entries)",
                len(_DANGEROUS_TOOL_NAMES),
            )
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

        self._dangerous_param_patterns: list[tuple[str, re.Pattern[str]]] = []
        self._dangerous_param_patterns_exec_only: list[tuple[str, re.Pattern[str]]] = []
        for item in guard_rules.get("dangerous_param_patterns", []):
            regex = item.get("regex")
            if not regex:
                continue
            rule_id = str(item.get("id", ""))
            compiled = re.compile(regex, re.IGNORECASE)
            self._dangerous_param_patterns.append((rule_id, compiled))
            if rule_id not in _PATH_REFERENCE_PATTERN_IDS:
                self._dangerous_param_patterns_exec_only.append((rule_id, compiled))
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
        except (TypeError, ValueError, OverflowError):
            return str(value)

    @staticmethod
    def _normalize_tool_call(tool_call: object) -> dict[str, object] | None:
        if not isinstance(tool_call, dict):
            return None

        tool_name = str(tool_call.get("name", "")).strip()
        arguments = tool_call.get("arguments", {})

        function = tool_call.get("function")
        if isinstance(function, dict):
            tool_name = str(function.get("name", tool_name)).strip()
            arguments = function.get("arguments", arguments)

        item_type = str(tool_call.get("type", "")).strip().lower()
        if item_type == "function_call":
            tool_name = str(tool_call.get("name", tool_name)).strip()
            arguments = tool_call.get("arguments", arguments)
        elif item_type in {
            "bash",
            "computer_call",
            "shell",
            "terminal",
            "run_command",
            "execute",
        }:
            tool_name = tool_name or item_type
            arguments = (
                tool_call.get("action")
                or tool_call.get("command")
                or tool_call.get("arguments")
                or arguments
            )

        if isinstance(arguments, str):
            stripped = arguments.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    arguments = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    arguments = stripped

        if not tool_name and arguments in ({}, "", None):
            return None
        return {"name": tool_name, "arguments": arguments}

    def _extract_tool_calls(self, resp: InternalResponse) -> list[dict[str, object]]:
        raw_tool_calls = resp.metadata.get("tool_calls")
        if isinstance(raw_tool_calls, list):
            normalized = [
                item
                for item in (self._normalize_tool_call(tc) for tc in raw_tool_calls)
                if item
            ]
            if normalized:
                return normalized

        raw = resp.raw if isinstance(resp.raw, dict) else {}

        choices = raw.get("choices")
        if isinstance(choices, list):
            extracted: list[dict[str, object]] = []
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message")
                if not isinstance(message, dict):
                    continue
                tool_calls = message.get("tool_calls")
                if not isinstance(tool_calls, list):
                    continue
                extracted.extend(
                    item
                    for item in (self._normalize_tool_call(tc) for tc in tool_calls)
                    if item
                )
            if extracted:
                return extracted

        output = raw.get("output")
        if isinstance(output, list):
            extracted = [
                item
                for item in (self._normalize_tool_call(tc) for tc in output)
                if item
            ]
            if extracted:
                return extracted

        return []

    def process_response(
        self, resp: InternalResponse, ctx: RequestContext
    ) -> InternalResponse:
        self._report = {
            "filter": self.name,
            "hit": False,
            "risk_score": 0.0,
            "violations": [],
        }

        tool_calls = self._extract_tool_calls(resp)
        if not tool_calls:
            return resp

        violations: list[str] = []
        blocked = False

        for tool_call in tool_calls:
            if not isinstance(tool_call, dict):
                continue

            tool_name = str(tool_call.get("name", "")).strip()
            args = tool_call.get("arguments", {})
            args_text = self._as_text(args)
            args_norm = normalize_for_match(args_text)
            tool_norm = normalize_for_match(tool_name)

            if (
                self._tool_whitelist
                and tool_name
                and tool_name not in self._tool_whitelist
            ):
                violations.append(f"disallowed_tool:{tool_name}")
                action = self._apply_action(ctx, "disallowed_tool")
                blocked = blocked or action == "block"
                logger.debug(
                    "disallowed_tool hit request_id=%s tool=%s action=%s",
                    ctx.request_id,
                    tool_name,
                    action,
                )

            # H-10: Blacklist check — applies even when no whitelist is configured.
            lowered_name = tool_name.lower()
            if lowered_name and (
                lowered_name in _DANGEROUS_TOOL_NAMES or tool_norm in _DANGEROUS_TOOL_NAMES
            ):
                if not self._tool_whitelist or tool_name not in self._tool_whitelist:
                    violations.append(f"dangerous_tool_name:{tool_name}")
                    action = self._apply_action(ctx, "disallowed_tool")
                    blocked = blocked or action == "block"
                    logger.warning(
                        "dangerous_tool_name blocked request_id=%s tool=%s action=%s",
                        ctx.request_id,
                        tool_name,
                        action,
                    )
            if lowered_name not in _READ_ONLY_CONTENT_TOOLS and tool_norm not in _READ_ONLY_CONTENT_TOOLS:
                # File-writing tools check only injection-chain rules and skip path-reference
                # rules, which lowers false blocks
                patterns = (
                    self._dangerous_param_patterns_exec_only
                    if lowered_name in _FILE_WRITE_CONTENT_TOOLS
                    or tool_norm in _FILE_WRITE_CONTENT_TOOLS
                    else self._dangerous_param_patterns
                )
                args_haystacks = build_haystacks(args_text)
                for _rule_id, pattern in patterns:
                    if not pattern_hits_in(pattern, args_haystacks):
                        continue
                    match = pattern.search(args_text) or pattern.search(args_norm)
                    matched_text = (match.group(0) if match else args_norm)[:120]
                    violations.append(f"dangerous_param:{tool_name or 'unknown'}")
                    action = self._apply_action(ctx, "dangerous_param")
                    blocked = blocked or action == "block"
                    logger.debug(
                        "dangerous_param hit request_id=%s tool=%s pattern=%s matched=%s",
                        ctx.request_id,
                        tool_name,
                        pattern.pattern[:60],
                        matched_text,
                    )
                    break

            if isinstance(args, dict):
                for (rule_tool, rule_param), rule_pattern in self._param_rules.items():
                    if rule_tool != tool_name:
                        continue
                    if rule_param not in args:
                        continue
                    value = str(args.get(rule_param, ""))
                    if not rule_pattern.match(value) and not rule_pattern.match(
                        normalize_for_match(value)
                    ):
                        violations.append(f"invalid_param:{tool_name}.{rule_param}")
                        action = self._apply_action(ctx, "invalid_param")
                        blocked = blocked or action == "block"

            semantic_input = f"{tool_name} {args_text}"
            semantic_norm = normalize_for_match(semantic_input)
            for pattern in self._semantic_patterns:
                match = pattern.search(semantic_input) or pattern.search(semantic_norm)
                if match:
                    matched_text = match.group(0)[:120]
                    violations.append(f"semantic_review:{tool_name or 'unknown'}")
                    action = self._apply_action(ctx, "semantic_review")
                    blocked = blocked or action == "block"
                    logger.debug(
                        "semantic_review hit request_id=%s tool=%s pattern=%s matched=%s",
                        ctx.request_id,
                        tool_name,
                        pattern.pattern[:60],
                        matched_text,
                    )
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

        return resp

    def report(self) -> dict:
        return self._report
