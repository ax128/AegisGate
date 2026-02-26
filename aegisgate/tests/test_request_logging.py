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
        "input": [{"role": "user", "content": "hello"}],
    }

    sanitized = openai_router._sanitize_payload_for_log(payload)

    # input payload should not be mutated
    assert "parameters" in payload["tools"][0]

    tool0 = sanitized["tools"][0]
    assert "parameters" not in tool0
    assert "parameters" not in tool0["metadata"]["nested"]
    assert tool0["name"] == "write"
    assert sanitized["model"] == "gpt-test"
