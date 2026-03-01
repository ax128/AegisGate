"""External security rule loader with mtime-based cache."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from threading import Lock
from typing import Any

import yaml

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger


_DEFAULT_RULES: dict[str, Any] = {
    "redaction": {
        "request_prefix_max_len": 12,
        "normalize_nfkc": True,
        "strip_invisible_chars": True,
        "field_value_min_len": 12,
        "pii_patterns": [
            {"id": "EMAIL", "regex": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"},
            {"id": "TOKEN", "regex": r"\\b(?:sk|rk|pk)-[A-Za-z0-9\\-_]{10,}\\b"},
            {"id": "PHONE", "regex": r"\b(?:\+?1[-.\s]?)?(?:[(]?\d{3}[)]?[-.\s]?)\d{3}[-.\s]?\d{4}\b"},
            {"id": "SSN", "regex": r"\\b\\d{3}-\\d{2}-\\d{4}\\b"},
            {"id": "CARD", "regex": r"\\b(?:\\d[ -]*?){13,16}\\b"},
            {"id": "CN_MOBILE", "regex": r"(?<!\\d)1[3-9]\\d{9}(?!\\d)"},
            {"id": "CN_ID", "regex": r"(?<!\\d)\\d{17}[\\dXx](?!\\d)"},
            {"id": "AWS_ACCESS_KEY", "regex": r"\\bAKIA[0-9A-Z]{16}\\b"},
            {"id": "GITHUB_TOKEN", "regex": r"\\bghp_[A-Za-z0-9]{20,}\\b"},
            {"id": "SLACK_TOKEN", "regex": r"\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b"},
            {"id": "IBAN", "regex": r"\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\\b"},
        ],
    },
    "restoration": {
        "placeholder_regex": r"\\{\\{AG_[A-Z0-9]+_[A-Z_]+_\\d+\\}\\}",
        "suspicious_context_patterns": [
            {
                "id": "exfiltration_en",
                "regex": r"(reveal|show|dump|leak|print|secret|password|token|api\\s*key|system\\s+prompt)",
            },
            {
                "id": "exfiltration_zh",
                "regex": r"(泄露|暴露|显示|输出|打印|给我|提供).*(密钥|口令|密码|令牌|token|api\\s*key|系统提示词|系统提示)",
            },
        ],
        "restore_policy": {
            "max_placeholders_per_response": 20,
            "restore_ttl_seconds": 1800,
            "allow_partial_restore": False,
        },
    },
    "untrusted_content_guard": {
        "untrusted_sources": ["external", "retrieval", "web", "tool", "plugin", "document"],
        "source_trust_matrix": {
            "system": {"trusted": True, "risk_multiplier": 0.2},
            "user": {"trusted": True, "risk_multiplier": 0.5},
            "retrieval": {"trusted": False, "risk_multiplier": 1.0},
            "web": {"trusted": False, "risk_multiplier": 1.1},
            "tool": {"trusted": False, "risk_multiplier": 1.1},
            "external": {"trusted": False, "risk_multiplier": 1.2},
            "partner_feed": {"trusted": False, "risk_multiplier": 1.2},
        },
        "boundary_start": "[UNTRUSTED_CONTENT_START]",
        "boundary_end": "[UNTRUSTED_CONTENT_END]",
        "risk_score": 0.88,
        "instructional_patterns": [
            {
                "id": "instructional_en",
                "regex": r"(ignore\\s+.*instructions?|bypass\\s+.*(policy|safety)|reveal\\s+.*(system\\s+prompt|developer\\s+message)|run\\s+command|execute\\s+shell)",
            },
            {
                "id": "instructional_zh",
                "regex": r"(忽略|无视).*(指令|规则|说明)|(绕过|关闭).*(安全|策略|限制)|(泄露|显示).*(系统提示词|开发者消息)",
            },
        ],
    },
    "injection_detector": {
        "base64_candidate_regex": r"[A-Za-z0-9+/]{24,}={0,2}",
        "hex_candidate_regex": r"\\b[0-9a-fA-F]{32,}\\b",
        "word_regex": r"\\b[a-z]{4,}\\b",
        "base64_max_candidates": 8,
        "hex_max_candidates": 8,
        "multi_stage_decode": {
            "enabled": True,
            "max_decode_depth": 2,
            "url_decode_enabled": True,
        },
        "unicode_confusable_map": {
            "а": "a",
            "е": "e",
            "о": "o",
            "р": "p",
            "с": "c",
            "у": "y",
            "х": "x",
            "і": "i",
            "ѕ": "s",
            "ο": "o",
            "ρ": "p",
            "ν": "v",
            "ｍ": "m",
        },
        "unicode_invisible_chars": ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"],
        "unicode_bidi_chars": ["\u202a", "\u202b", "\u202d", "\u202e", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069"],
        "direct_patterns": [
            {"id": "ignore_previous_en", "regex": r"ignore\\s+(all\\s+)?(previous|prior)\\s+instructions?"},
            {"id": "override_safety_en", "regex": r"(bypass|override)\\s+.*(safety|guardrails?|policy)"},
            {"id": "developer_mode_en", "regex": r"(you\\s+are\\s+now|act\\s+as)\\s+.*(developer|root|admin)"},
            {
                "id": "reveal_hidden_en",
                "regex": r"(reveal|show|print|dump|leak)\\s+.*(system\\s+prompt|developer\\s+message|hidden\\s+instructions?)",
            },
            {"id": "repeat_prompt_en", "regex": r"(repeat|quote|verbatim)\\s+.*(prompt|instructions?)"},
            {"id": "ignore_previous_zh", "regex": r"(忽略|无视).*(之前|以上|先前).*(指令|说明|规则)"},
            {"id": "override_safety_zh", "regex": r"(绕过|关闭).*(安全|防护|策略|限制)"},
            {"id": "reveal_hidden_zh", "regex": r"(泄露|显示|输出|打印).*(系统提示词|开发者消息|隐藏指令)"},
            {"id": "repeat_prompt_zh", "regex": r"(逐字|原样|完整).*(复述|输出).*(提示词|指令)"},
        ],
        "system_exfil_patterns": [
            {"id": "system_prompt_request_en", "regex": r"(what|show|reveal)\\s+.*system\\s+prompt"},
            {"id": "developer_message_request_en", "regex": r"(show|reveal|print)\\s+.*developer\\s+message"},
            {"id": "delimiter_breakout_en", "regex": r"(ignore|forget)\\s+.*(system|developer)\\s+instructions"},
            {"id": "system_prompt_request_zh", "regex": r"(显示|告诉|输出|泄露).*(系统提示词|系统提示)"},
            {"id": "developer_message_request_zh", "regex": r"(显示|输出|泄露).*(开发者消息|开发提示)"},
        ],
        "html_markdown_patterns": [
            {"id": "script_tag", "regex": r"<\\s*script\\b"},
            {"id": "img_tag", "regex": r"<\\s*img\\b"},
            {"id": "javascript_uri", "regex": r"javascript:\\s*"},
            {"id": "data_uri", "regex": r"data:\\s*text/html"},
        ],
        "remote_content_patterns": [
            {"id": "markdown_link_instruction_en", "regex": r"\[[^\]]+\]\(https?://[^)]+\).*(follow|execute|instructions?)"},
            {"id": "url_instruction_en", "regex": r"https?://\S+.*(follow|execute|instructions?)"},
            {"id": "markdown_link_instruction_zh", "regex": r"\[[^\]]+\]\(https?://[^)]+\).*(按|执行|遵循).*(指令|说明)"},
            {"id": "url_instruction_zh", "regex": r"https?://\S+.*(按|执行|遵循).*(指令|说明)"},
        ],
        "indirect_injection_patterns": [
            {"id": "retrieved_override_en", "regex": r"(retrieved|document|knowledge\s*base|web\s*page).*(ignore|override|bypass).*(instructions|policy|guardrails?)"},
            {"id": "context_priority_hijack_en", "regex": r"(treat|use).*(this|retrieved|external).*(as|with).*(highest|top).*(priority|authority)"},
            {"id": "retrieved_override_zh", "regex": r"(检索|文档|知识库|网页).*(忽略|覆盖|绕过).*(指令|规则|策略|安全)"},
            {"id": "context_priority_hijack_zh", "regex": r"(将|把).*(检索内容|外部内容|文档).*(作为|设为).*(最高|最高级).*(优先级|权威)"},
        ],
        "remote_content_instruction_patterns": [
            {"id": "copy_paste_terminal_en", "regex": r"(copy|paste).*(terminal|shell|powershell|cmd)|(run|execute).*(from|in).*(url|link|document)"},
            {"id": "remote_tool_invocation_en", "regex": r"(follow|execute).*(tool|function|api).*(from|in).*(link|url|document)"},
            {"id": "copy_paste_terminal_zh", "regex": r"(复制|粘贴).*(终端|shell|powershell|cmd)|(按|执行).*(链接|网页|文档).*(命令|脚本)"},
            {"id": "remote_tool_invocation_zh", "regex": r"(根据|按照).*(链接|文档|网页).*(调用|执行).*(工具|函数|接口)"},
        ],
        "typoglycemia_targets": ["ignore", "bypass", "override", "reveal", "system", "prompt", "instructions"],
        "decoded_keywords": [
            "ignore previous instructions",
            "reveal system prompt",
            "developer message",
            "bypass safety",
            "override policy",
            "忽略之前所有指令",
            "忽略以上所有指令",
            "泄露系统提示词",
            "显示开发者消息",
        ],
        "obfuscated_markers": [
            "ignoreallpreviousinstructions",
            "忽略之前所有指令",
            "忽略以上所有指令",
        ],
        "scoring_model": {
            "nonlinear_k": 2.2,
            "thresholds": {
                "allow": 0.35,
                "review": 0.7,
            },
            "weights": {
                "intent": 0.45,
                "payload": 0.25,
                "hijack": 0.2,
                "anomaly": 0.1,
            },
            "signal_profiles": {
                "direct": {"bucket": "intent", "severity": 9},
                "system_exfil": {"bucket": "intent", "severity": 10},
                "obfuscated": {"bucket": "payload", "severity": 9},
                "html_markdown": {"bucket": "payload", "severity": 6},
                "remote_content": {"bucket": "hijack", "severity": 8},
                "remote_content_instruction": {"bucket": "hijack", "severity": 9},
                "indirect_injection": {"bucket": "hijack", "severity": 9},
                "typoglycemia": {"bucket": "hijack", "severity": 7},
                "unicode_invisible": {"bucket": "anomaly", "severity": 6},
                "unicode_bidi": {"bucket": "anomaly", "severity": 10},
            },
        },
        "false_positive_mitigation": {
            "enabled": True,
            "max_risk_reduction": 0.35,
            "non_reducible_categories": ["system_exfil", "obfuscated", "unicode_bidi"],
            "discussion_patterns": [
                r"(用于|用于研究|安全研究|教学|示例|样例|引用|分析|解释|检测|防护|OWASP|论文)",
                r"(for\s+research|for\s+analysis|for\s+education|for\s+teaching|for\s+example|quoted|citation|security\s+testing|owasp|case\s+study)",
            ],
            "quoted_instruction_patterns": [
                r"""["'`].{0,120}(ignore|bypass|override|忽略|绕过).{0,120}["'`]""",
                r"```[\s\S]{0,200}(ignore|bypass|override|忽略|绕过)[\s\S]{0,200}```",
            ],
        },
    },
    "privilege_guard": {
        "request_risk_floor": 0.9,
        "response_risk_floor": 0.85,
        "blocked_patterns": [
            {"id": "read_etc_passwd_en", "regex": r"(cat|type|more)\s+/etc/passwd"},
            {"id": "read_ssh_en", "regex": r"(read|cat|show)\s+~/.ssh"},
            {"id": "dump_secret_en", "regex": r"(dump|show|reveal|print).*(secret|token|password|api\s*key)"},
            {"id": "execute_shell_en", "regex": r"(run|execute).*(shell|bash|powershell|cmd)"},
            {"id": "read_local_zh", "regex": r"(读取|打开|导出).*(本地文件|系统文件|配置文件|日志|数据库)"},
            {"id": "leak_secret_zh", "regex": r"(输出|泄露|显示|打印).*(密钥|口令|密码|token|api\s*key)"},
            {"id": "run_cmd_zh", "regex": r"(执行|运行).*(命令|shell|脚本|powershell|终端)"},
        ],
    },
    "anomaly_detector": {
        "repetition": {
            "repetition_ratio_threshold": 0.35,
            "max_run_length_threshold": 40,
            "repeated_line_threshold": 20,
        },
        "encoded_payload": {
            "base64_min_length": 200,
            "hex_min_length": 300,
            "url_encoded_min_count": 12,
        },
        "unicode": {
            "invisible_chars": ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"],
            "bidi_chars": ["\u202a", "\u202b", "\u202d", "\u202e", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069"],
            "invisible_char_threshold": 6,
        },
        "command_patterns": [
            {"id": "sqli_union_select", "regex": r"\bunion\s+select\b"},
            {"id": "sqli_tautology", "regex": r"\b(?:or|and)\s+1\s*=\s*1\b"},
            {"id": "sqli_time_blind", "regex": r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d+\s*\)"},
            {"id": "xss_script_event", "regex": r"(?:<\s*script\b|on(?:error|load|mouseover)\s*=|javascript:\s*)"},
            {"id": "command_injection_chain", "regex": r"(?:;|\|\||&&|\|)\s*(?:curl|wget|bash|sh|nc|python3?|perl|powershell|cmd(?:\.exe)?)\b"},
            {"id": "path_traversal", "regex": r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e%252f|/etc/passwd\b|/proc/self/environ\b|win\.ini\b)"},
            {"id": "xxe_external_entity", "regex": r"(?:<!DOCTYPE[^>]*\[[\s\S]{0,200}?<!ENTITY|<!ENTITY\s+%?\w+\s+SYSTEM\s+(?:file|https?)://)"},
            {"id": "ssti_or_log4shell", "regex": r"(?:\{\{\s*7\s*\*\s*7\s*\}\}|\$\{jndi:(?:ldap|rmi|dns|iiop)://)"},
            {"id": "ssrf_metadata", "regex": r"(?:https?://)?(?:169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal)(?::\d+)?(?:/|\b)"},
            {"id": "crlf_header_injection", "regex": r"(?:%0d%0a|\r\n)\s*(?:set-cookie:|location:|x-forwarded-)"},
        ],
        "points": {
            "repetition_ratio": 0.25,
            "max_run_length": 0.2,
            "repeated_line": 0.2,
            "base64_payload": 0.35,
            "hex_payload": 0.3,
            "url_encoded_payload": 0.2,
            "invisible_chars": 0.25,
            "bidi_control": 0.4,
            "high_risk_command": 0.4,
        },
        "point_buckets": {
            "repetition_ratio": "anomaly",
            "max_run_length": "anomaly",
            "repeated_line": "anomaly",
            "base64_payload": "payload",
            "hex_payload": "payload",
            "url_encoded_payload": "payload",
            "invisible_chars": "anomaly",
            "bidi_control": "anomaly",
            "high_risk_command": "payload",
        },
        "scoring_model": {
            "nonlinear_k": 2.2,
            "weights": {"payload": 0.7, "anomaly": 0.3},
            "points_max": {"payload": 1.45, "anomaly": 1.3},
            "thresholds": {"allow": 0.35, "review": 0.7},
        },
    },
    "request_sanitizer": {
        "thresholds": {"sanitize": 0.35, "block": 0.7},
        "discussion_context_patterns": [
            r"(用于|用于研究|安全研究|教学|示例|样例|引用|分析|解释|检测|防护|OWASP|论文)",
            r"(for\s+research|for\s+analysis|for\s+education|for\s+teaching|for\s+example|quoted|citation|security\s+testing|owasp|case\s+study)",
        ],
        "command_patterns": [
            {"id": "web_sqli", "regex": r"(\bunion\s+select\b|\b(?:or|and)\s+1\s*=\s*1\b|\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d+\s*\))"},
            {"id": "web_xss", "regex": r"(?:<\s*script\b|on(?:error|load|mouseover)\s*=|javascript:\s*)"},
            {"id": "web_path_traversal", "regex": r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e%252f|/etc/passwd\b|/proc/self/environ\b|win\.ini\b)"},
            {"id": "web_command_injection", "regex": r"(?:;|\|\||&&|\|)\s*(?:curl|wget|bash|sh|nc|python3?|perl|powershell|cmd(?:\.exe)?)\b"},
            {"id": "web_xxe_ssti", "regex": r"(?:<!DOCTYPE[^>]*\[[\s\S]{0,200}?<!ENTITY|<!ENTITY\s+%?\w+\s+SYSTEM\s+(?:file|https?)://|\{\{\s*7\s*\*\s*7\s*\}\}|\$\{jndi:(?:ldap|rmi|dns|iiop)://)"},
            {"id": "web_ssrf_crlf", "regex": r"((?:https?://)?(?:169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal)(?::\d+)?(?:/|\b)|(?:%0d%0a|\r\n)\s*(?:set-cookie:|location:|x-forwarded-))"},
        ],
        "secret_exfil_patterns": [
            {
                "id": "secret_en",
                "regex": r"(reveal|dump|show|print|leak).*(api\s*key|token|cookie|password|system\s+prompt|developer\s+message)",
            },
            {
                "id": "secret_zh",
                "regex": r"(泄露|显示|输出|打印|提供).*(密钥|令牌|token|cookie|密码|系统提示词|开发者消息)",
            },
        ],
        "encoded_payload_patterns": [
            {"id": "base64_long", "regex": r"[A-Za-z0-9+/]{200,}={0,2}"},
            {"id": "hex_long", "regex": r"\b[0-9a-fA-F]{300,}\b"},
            {"id": "url_encoded_dense", "regex": r"(%[0-9A-Fa-f]{2}){12,}"},
        ],
        "redactions": {
            "command": "[REDACTED:command]",
            "exfiltration": "[REDACTED:secret-exfiltration]",
            "payload": "[REDACTED:encoded-payload]",
        },
        "block_message": "[AegisGate] request blocked by security policy.",
    },
    "sanitizer": {
        "thresholds": {"sanitize": 0.35, "block": 0.7},
        "discussion_context_patterns": [
            r"(用于|用于研究|安全研究|教学|示例|样例|引用|分析|解释|检测|防护|OWASP|论文)",
            r"(for\s+research|for\s+analysis|for\s+education|for\s+teaching|for\s+example|quoted|citation|security\s+testing|owasp|case\s+study)",
        ],
        "command_patterns": [
            {
                "id": "web_http_smuggling_cl_te",
                "regex": r"(?is)\bcontent-length\s*:\s*\d+\s*(?:\\r\\n|\r\n|\n)+\s*transfer-encoding\s*:\s*chunked\b",
            },
            {
                "id": "web_http_smuggling_te_cl",
                "regex": r"(?is)\btransfer-encoding\s*:\s*chunked\b\s*(?:\\r\\n|\r\n|\n)+\s*content-length\s*:\s*\d+",
            },
            {
                "id": "web_http_smuggling_te_te",
                "regex": r"(?is)\btransfer-encoding\s*:\s*(?:[^\r\n,]+,\s*)+chunked\b",
            },
            {
                "id": "web_http_response_splitting",
                "regex": r"(?is)(?:%0d%0a|\\r\\n|\r\n)\s*http/1\.[01]\s+\d{3}\b",
            },
            {
                "id": "web_http_obs_fold_header",
                "regex": r"(?is)(?:%0d%0a|\\r\\n|\r\n)[ \t]+(?:content-length|transfer-encoding|host|x-forwarded-[a-z-]+)\s*:",
            },
        ],
        "force_block_command_patterns": [
            {"id": "docker_compose_down", "regex": r"(?:^|\s)(?:/)?(?:docker\s+compose|docker-compose)\s+down\b"},
            {"id": "docker_compose_logs", "regex": r"(?:^|\s)(?:/)?(?:docker\s+compose|docker-compose)\s+logs\b"},
            {"id": "docker_images", "regex": r"(?:^|\s)(?:/)?docker\s+images\b"},
            {"id": "docker_ps", "regex": r"(?:^|\s)(?:/)?docker\s+ps\b"},
            {"id": "docker_stop", "regex": r"(?:^|\s)(?:/)?docker\s+stop\b"},
            {"id": "docker_restart", "regex": r"(?:^|\s)(?:/)?docker\s+restart\b"},
            {
                "id": "docker_exec_interactive",
                "regex": r"(?:^|\s)(?:/)?docker\s+exec\b[^\n]*(?:\s-(?:it|ti)\b|\s--interactive\b|\s--tty\b)",
            },
            {
                "id": "web_http_smuggling_cl_te",
                "regex": r"(?is)\bcontent-length\s*:\s*\d+\s*(?:\\r\\n|\r\n|\n)+\s*transfer-encoding\s*:\s*chunked\b",
            },
            {
                "id": "web_http_smuggling_te_cl",
                "regex": r"(?is)\btransfer-encoding\s*:\s*chunked\b\s*(?:\\r\\n|\r\n|\n)+\s*content-length\s*:\s*\d+",
            },
            {
                "id": "web_http_smuggling_te_te",
                "regex": r"(?is)\btransfer-encoding\s*:\s*(?:[^\r\n,]+,\s*)+chunked\b",
            },
            {
                "id": "web_http_response_splitting",
                "regex": r"(?is)(?:%0d%0a|\\r\\n|\r\n)\s*http/1\.[01]\s+\d{3}\b",
            },
            {
                "id": "web_http_obs_fold_header",
                "regex": r"(?is)(?:%0d%0a|\\r\\n|\r\n)[ \t]+(?:content-length|transfer-encoding|host|x-forwarded-[a-z-]+)\s*:",
            },
        ],
        "encoded_payload_patterns": [
            {"id": "base64_long", "regex": r"[A-Za-z0-9+/]{200,}={0,2}"},
            {"id": "hex_long", "regex": r"\b[0-9a-fA-F]{300,}\b"},
            {"id": "url_encoded_dense", "regex": r"(%[0-9A-Fa-f]{2}){12,}"},
        ],
        "redactions": {
            "command": "[REDACTED:command]",
            "payload": "[REDACTED:encoded-payload]",
            "uri": "[unsafe-uri-removed]",
            "markup": "[unsafe-tag-removed]",
        },
        "block_message": "[AegisGate] response blocked by security policy.",
        "sanitize_prefix": "[AegisGate] content sanitized: ",
        "system_leak_patterns": [
            {"id": "system_leak_en", "regex": r"(system\\s+prompt|developer\\s+message|hidden\\s+instructions?)"},
            {"id": "system_leak_zh", "regex": r"(系统提示词|开发者消息|隐藏指令)"},
        ],
        "unsafe_markup_patterns": [
            {"id": "script", "regex": r"<\\s*(script|img|iframe)\\b"},
        ],
        "unsafe_uri_patterns": [
            {"id": "unsafe_uri", "regex": r"(javascript:|data:text/html)"},
        ],
    },
    "tool_call_guard": {
        "tool_whitelist": ["search", "calculator", "weather"],
        "parameter_rules": [
            {"tool": "search", "param": "q", "regex": r"^.{1,500}$"},
            {"tool": "weather", "param": "location", "regex": r"^.{1,120}$"},
        ],
        "dangerous_param_patterns": [
            {"id": "shell", "regex": r"(;|\|\||&&|`|\$\(|/etc/passwd|rm\\s+-rf)"},
            {"id": "path_traversal", "regex": r"(\.\./|~/.ssh|/var/run/secrets)"},
            {"id": "zh_sensitive", "regex": r"(删除|提权|读取本地|密钥|口令)"},
        ],
        "semantic_approval_patterns": [
            {"id": "approval_en", "regex": r"(delete|drop|shutdown|exfiltrate|leak)"},
            {"id": "approval_zh", "regex": r"(删除|清空|泄露|导出敏感)"},
        ],
        "default_action": "block",
    },
    "rag_poison_guard": {
        "ingestion_risk_score": 0.9,
        "retrieval_risk_score": 0.86,
        "propagation_risk_score": 0.88,
        "traceback_excerpt_max_chars": 180,
        "ingestion_poison_patterns": [
            {"id": "ingestion_override_en", "regex": r"(ignore|override|bypass).*(instructions|policy|guardrails?)"},
            {"id": "ingestion_exfil_en", "regex": r"(reveal|dump|print|show).*(system\s+prompt|developer\s+message|api\s*key|token|password)"},
            {"id": "ingestion_override_zh", "regex": r"(忽略|覆盖|绕过).*(指令|规则|策略|安全)"},
            {"id": "ingestion_exfil_zh", "regex": r"(泄露|显示|输出|打印).*(系统提示词|开发者消息|密钥|令牌|token|密码)"},
            {"id": "hidden_markup_payload", "regex": r"(<!--[\s\S]{0,300}(ignore|override|bypass)|BEGIN[_\s-]?PROMPT[_\s-]?INJECTION|data:\s*text/html|javascript:)"},
        ],
        "retrieval_poison_patterns": [
            {"id": "retrieval_instruction_en", "regex": r"(retrieved|document|web|link).*(follow|execute|run|copy|paste).*(instruction|command|script|shell)"},
            {"id": "retrieval_tool_en", "regex": r"(call|invoke|use).*(tool|function|api).*(from|according to).*(retrieved|document|web|link)"},
            {"id": "retrieval_instruction_zh", "regex": r"(检索|文档|网页|链接).*(按|执行|运行|复制|粘贴).*(指令|命令|脚本|shell)"},
            {"id": "retrieval_tool_zh", "regex": r"(调用|使用|执行).*(工具|函数|接口).*(根据|按照).*(检索|文档|网页|链接)"},
        ],
        "propagation_patterns": [
            {"id": "propagation_cmd_en", "regex": r"(run|execute|copy|paste).*(shell|powershell|cmd|bash)|curl\s+[^|]+\|\s*(sh|bash)"},
            {"id": "propagation_exfil_en", "regex": r"(reveal|dump|print|show).*(system\s+prompt|developer\s+message|api\s*key|token|password)"},
            {"id": "propagation_cmd_zh", "regex": r"(执行|运行|复制|粘贴).*(命令|脚本|终端|shell)"},
            {"id": "propagation_exfil_zh", "regex": r"(泄露|显示|输出|打印).*(系统提示词|开发者消息|密钥|令牌|token|密码)"},
        ],
    },
        "action_map": {
            "injection_detector": {
                "system_exfil": "block",
                "obfuscated": "block",
                "unicode_bidi": "block",
                "unicode_invisible": "review",
                "remote_content": "review",
                "remote_content_instruction": "review",
                "indirect_injection": "review",
                "direct": "downgrade",
                "typoglycemia": "review",
                "html_markdown": "sanitize",
            },
        "untrusted_content_guard": {
            "suspicious_untrusted": "review",
        },
        "restoration": {
            "exfiltration": "block",
            "too_many_placeholders": "block",
            "stale_mapping": "block",
            "partial_restore": "review",
        },
        "tool_call_guard": {
            "disallowed_tool": "block",
            "dangerous_param": "block",
            "invalid_param": "review",
            "semantic_review": "review",
        },
        "sanitizer": {
            "system_leak": "block",
        },
        "request_sanitizer": {
            "secret_exfiltration": "review",
            "privilege_escalation": "review",
            "rule_bypass": "block",
            "leak_check": "block",
            "shape_anomaly": "sanitize",
        },
        "rag_poison_guard": {
            "ingestion_poison": "block",
            "retrieval_poison": "review",
            "poison_propagation": "block",
        },
    },
}

_CACHE_LOCK = Lock()
_CACHE_PATH = ""
_CACHE_MTIME_NS = -1
_CACHE_RULES: dict[str, Any] | None = None


def _resolve_rules_file(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    app_root = Path(__file__).resolve().parents[2]
    candidates = [Path.cwd() / candidate, app_root / candidate]
    for item in candidates:
        if item.exists():
            return item.resolve()
    return candidates[-1].resolve()


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            base[key] = _deep_merge(dict(base[key]), value)
        else:
            base[key] = value
    return base


def load_security_rules(path: str | None = None) -> dict[str, Any]:
    global _CACHE_PATH, _CACHE_MTIME_NS, _CACHE_RULES

    rules_path = _resolve_rules_file(path or settings.security_rules_path)
    path_key = str(rules_path.resolve())
    mtime_ns = rules_path.stat().st_mtime_ns if rules_path.exists() else -1

    with _CACHE_LOCK:
        if _CACHE_RULES is not None and _CACHE_PATH == path_key and _CACHE_MTIME_NS == mtime_ns:
            return deepcopy(_CACHE_RULES)

        rules = deepcopy(_DEFAULT_RULES)
        if rules_path.exists():
            raw = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
            if not isinstance(raw, dict):
                raise ValueError(f"security rules file must be a mapping: {rules_path}")
            rules = _deep_merge(rules, raw)
            logger.info("security rules loaded path=%s", rules_path)
        else:
            logger.info("security rules file not found, using defaults path=%s", rules_path)

        _CACHE_PATH = path_key
        _CACHE_MTIME_NS = mtime_ns
        _CACHE_RULES = rules
        return deepcopy(rules)
