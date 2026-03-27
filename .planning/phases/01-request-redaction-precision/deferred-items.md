# Deferred Items

## 2026-03-27

- Out of scope: `pytest -q aegisgate/tests/test_passthrough_filter_mode.py -x` times out on `test_chat_endpoint_redirects_responses_stream_back_to_chat_chunks` after the first three tests. The same timeout blocks the plan's broader focused-suite command, but it is unrelated to request redaction precision and reproduces without this plan's code paths.
