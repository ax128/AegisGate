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
