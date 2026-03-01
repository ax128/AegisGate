from aegisgate.adapters.openai_compat import router as openai_router


def test_sanitize_payload_for_log_drops_parameters_recursively():
    payload = {
        "model": "gpt-test",
        "tools": [
            {
                "type": "function",
                "name": "write",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                },
                "metadata": {
                    "nested": {
                        "parameters": {
                            "will": "be removed",
                        }
                    }
                },
            }
        ],
        "config": {
            "parameters": {
                "should": "remove",
            },
            "keep": "ok",
        },
        "input": [{"role": "user", "content": "hello"}],
    }

    sanitized = openai_router._sanitize_payload_for_log(payload)

    # input payload should not be mutated
    assert "parameters" in payload["tools"][0]

    # tools field is preserved but values are omitted
    assert sanitized["tools"] == []
    assert "parameters" not in sanitized["config"]
    assert sanitized["config"]["keep"] == "ok"
    assert sanitized["model"] == "gpt-test"


def test_sanitize_payload_for_log_keeps_function_call_output_body():
    payload = {
        "input": [
            {
                "type": "function_call_output",
                "call_id": "call_1",
                "output": "root ssh:notty 31.220.196.235 token=sk-abcdefghijklmnop",
            }
        ]
    }

    sanitized = openai_router._sanitize_payload_for_log(payload)
    output_text = sanitized["input"][0]["output"]

    assert "31.220.196.235" in output_text
    assert "sk-abcdefghijklmnop" in output_text


def test_sanitize_responses_input_for_upstream_redacts_function_call_output_sensitive_text():
    payload = [
        {
            "type": "function_call_output",
            "call_id": "call_2",
            "output": "root ssh:notty 31.220.196.235 token=sk-abcdefghijklmnop",
        }
    ]

    sanitized = openai_router._sanitize_responses_input_for_upstream(payload)
    output = sanitized[0]["output"]

    assert sanitized[0]["call_id"] == "call_2"
    assert "[REDACTED:TOKEN]" in output
    # Tool output uses relaxed redaction rules to reduce false positives.
    assert "31.220.196.235" in output
    assert "sk-abcdefghijklmnop" not in output


def test_sanitize_responses_input_for_upstream_relaxes_redaction_for_developer_role():
    payload = [
        {
            "role": "developer",
            "content": "联系邮箱 admin@example.com，不要输出 token=sk-abcdefghijklmnop",
        }
    ]

    sanitized = openai_router._sanitize_responses_input_for_upstream(payload)
    content = sanitized[0]["content"]

    assert "admin@example.com" in content
    assert "[REDACTED:TOKEN]" in content
    assert "sk-abcdefghijklmnop" not in content


def test_sanitize_responses_input_for_upstream_relaxes_user_role():
    payload = [
        {
            "role": "user",
            "content": "联系邮箱 admin@example.com，不要输出 token=sk-abcdefghijklmnop",
        }
    ]

    sanitized = openai_router._sanitize_responses_input_for_upstream(payload)
    content = sanitized[0]["content"]

    assert "admin@example.com" in content
    assert "[REDACTED:TOKEN]" in content
    assert "sk-abcdefghijklmnop" not in content


def test_sanitize_responses_input_for_upstream_records_hit_positions_and_is_idempotent():
    payload = [
        {
            "role": "user",
            "content": "ssh from 31.220.196.235 token=sk-abcdefghijklmnop",
        },
        {
            "type": "function_call_output",
            "call_id": "call_3",
            "output": "root ssh:notty 157.66.144.16",
        },
    ]

    first_sanitized, first_hits = openai_router._sanitize_responses_input_for_upstream_with_hits(payload)
    second_sanitized, second_hits = openai_router._sanitize_responses_input_for_upstream_with_hits(first_sanitized)

    assert first_hits
    assert any(item["path"] == "input[0].content" for item in first_hits)
    assert not any(item["path"] == "input[1].output" for item in first_hits)
    assert second_sanitized == first_sanitized
    assert second_hits == []
