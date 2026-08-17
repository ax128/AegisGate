"""Request-side redaction coverage guards.

Each test here pins a path that previously forwarded sensitive request content
verbatim: base64-looking credentials, the Responses ``instructions`` field, tool
definitions, and generic ``/v1/<subpath>`` provider payloads.
"""

from __future__ import annotations

import base64
import os

import pytest

from aegisgate.adapters.openai_compat.router import (
    _build_chat_upstream_payload,
    _build_generic_upstream_payload,
    _build_messages_upstream_payload,
    _build_responses_upstream_payload,
)
from aegisgate.adapters.openai_compat.sanitize import (
    _preserves_json_shape,
    _sanitize_text_for_upstream_with_hits,
)
from aegisgate.config import settings as settings_module
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.core.pipeline import _SECURITY_CRITICAL_FILTER_NAMES, Pipeline
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.base64_detect import (
    contains_high_confidence_credential,
    looks_like_base64_blob,
)


_PEM_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join(["MIIEowIBAAKCAQEAvJ8p1Kq3Zx8Q7Yb2Nn5Rr9Tt1Uu3Vv5Ww7Xx9Yy1Zz3Aa5Bb7C"] * 8)
    + "\n-----END RSA PRIVATE KEY-----"
)
_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "A" * 400 + "." + "B" * 43
_SK_TOKEN = "sk-live1234567890abcdefghij"
_GH_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz012345"


class _MemoryKVStore(KVStore):
    def __init__(self) -> None:
        self.mappings: dict[tuple[str, str], dict[str, str]] = {}

    def set_mapping(
        self, session_id: str, request_id: str, mapping: dict[str, str]
    ) -> None:
        self.mappings[(session_id, request_id)] = dict(mapping)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return dict(self.mappings.get((session_id, request_id), {}))

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return dict(self.mappings.pop((session_id, request_id), {}))

    def prune_pending_confirmations(self, now_ts: int) -> int:
        return 0

    def clear_all_pending_confirmations(self) -> int:
        return 0


class _FailingKVStore(_MemoryKVStore):
    def set_mapping(
        self, session_id: str, request_id: str, mapping: dict[str, str]
    ) -> None:
        raise RuntimeError("storage down")


class TestBlobHeuristicDoesNotHideCredentials:
    def test_pem_private_key_is_not_treated_as_blob(self) -> None:
        assert looks_like_base64_blob(_PEM_KEY) is False
        assert contains_high_confidence_credential(_PEM_KEY) is True

    def test_long_jwt_is_not_treated_as_blob(self) -> None:
        assert looks_like_base64_blob(_JWT) is False
        assert looks_like_base64_blob(f"Authorization: Bearer {_JWT}") is False

    def test_openssh_and_pgp_headers_covered(self) -> None:
        for header in (
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        ):
            assert looks_like_base64_blob(f"{header}\n" + "A" * 400) is False

    def test_media_payloads_are_still_skipped(self) -> None:
        image = "data:image/png;base64," + base64.b64encode(os.urandom(2048)).decode()
        raw_blob = base64.b64encode(os.urandom(2048)).decode()
        assert looks_like_base64_blob(image) is True
        assert looks_like_base64_blob(raw_blob) is True

    def test_credential_is_redacted_end_to_end(self) -> None:
        for value, marker in ((_PEM_KEY, "PRIVATE_KEY_PEM"), (_JWT, "JWT")):
            cleaned, hits = _sanitize_text_for_upstream_with_hits(
                value, role="user", path="messages[0].content", field="content"
            )
            assert f"[REDACTED:{marker}]" in cleaned
            assert [hit["pattern"] for hit in hits] == [marker]

    def test_pem_key_body_is_redacted_not_just_the_header(self) -> None:
        cleaned, _ = _sanitize_text_for_upstream_with_hits(
            f"here you go:\n{_PEM_KEY}\nthanks",
            role="user",
            path="messages[0].content",
            field="content",
        )
        assert cleaned == "here you go:\n[REDACTED:PRIVATE_KEY_PEM]\nthanks"

    def test_truncated_pem_header_still_redacted(self) -> None:
        cleaned, _ = _sanitize_text_for_upstream_with_hits(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * 400,
            role="user",
            path="messages[0].content",
            field="content",
        )
        assert cleaned.startswith("[REDACTED:PRIVATE_KEY_PEM]")


class TestInstructionsAndToolRedaction:
    def _responses_payload(self) -> dict:
        return {
            "model": "gpt-5.4",
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "hi"}]}
            ],
            "instructions": f"You are a helper. Deploy key: {_SK_TOKEN}",
            "tools": [
                {
                    "type": "function",
                    "name": "deploy",
                    "description": f"Deploy using token {_GH_TOKEN}",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "default": _SK_TOKEN}
                        },
                    },
                }
            ],
        }

    def test_responses_instructions_and_tools_are_redacted(self) -> None:
        payload = self._responses_payload()
        upstream = _build_responses_upstream_payload(
            payload,
            [InternalMessage(role="user", content="hi")],
            request_id="req-1",
            session_id="sess-1",
            route="/v1/responses",
        )
        assert _SK_TOKEN not in upstream["instructions"]
        assert "[REDACTED:TOKEN]" in upstream["instructions"]

        tool = upstream["tools"][0]
        assert _GH_TOKEN not in tool["description"]
        assert "[REDACTED:GITHUB_TOKEN]" in tool["description"]
        assert _SK_TOKEN not in tool["parameters"]["properties"]["target"]["default"]
        # Tool linkage fields must survive verbatim.
        assert tool["name"] == "deploy"
        assert tool["type"] == "function"
        assert _preserves_json_shape(payload["tools"], upstream["tools"])

    def test_responses_payload_without_instructions_is_unchanged(self) -> None:
        payload = {"model": "gpt-5.4", "input": "hello"}
        upstream = _build_responses_upstream_payload(
            payload,
            [InternalMessage(role="user", content="hello")],
            request_id="req-2",
            session_id="sess-2",
            route="/v1/responses",
        )
        assert "instructions" not in upstream

    def test_chat_tools_are_redacted(self) -> None:
        payload = {
            "model": "gpt-5.4",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "deploy",
                        "description": f"token {_GH_TOKEN}",
                    },
                }
            ],
        }
        upstream = _build_chat_upstream_payload(
            payload,
            [InternalMessage(role="user", content="hi")],
            request_id="req-3",
            session_id="sess-3",
            route="/v1/chat/completions",
        )
        function = upstream["tools"][0]["function"]
        assert _GH_TOKEN not in function["description"]
        assert function["name"] == "deploy"

    def test_messages_tools_are_redacted(self) -> None:
        payload = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {
                    "name": "deploy",
                    "description": f"token {_GH_TOKEN}",
                    "input_schema": {"type": "object", "properties": {}},
                }
            ],
        }
        upstream = _build_messages_upstream_payload(
            payload,
            [InternalMessage(role="user", content="hi")],
            request_id="req-4",
            session_id="sess-4",
            route="/v1/messages",
        )
        assert _GH_TOKEN not in upstream["tools"][0]["description"]
        assert upstream["tools"][0]["name"] == "deploy"


class TestGenericProxyPayloadRedaction:
    def test_embeddings_payload_is_redacted_and_shape_preserved(self) -> None:
        payload = {
            "model": "text-embedding-3-large",
            "input": [f"deploy key {_SK_TOKEN}", "plain text"],
            "dimensions": 1024,
            "user": "analyst-7",
        }
        upstream = _build_generic_upstream_payload(
            payload,
            request_id="req-5",
            session_id="sess-5",
            route="/v1/embeddings",
        )
        assert _SK_TOKEN not in upstream["input"][0]
        assert "[REDACTED:TOKEN]" in upstream["input"][0]
        assert upstream["input"][1] == "plain text"
        assert upstream["dimensions"] == 1024
        assert _preserves_json_shape(payload, upstream)
        # The caller's payload must not be mutated in place.
        assert _SK_TOKEN in payload["input"][0]

    def test_structural_keys_are_preserved(self) -> None:
        payload = {
            "model": "provider-native",
            "id": _SK_TOKEN,
            "items": [{"type": "text", "name": _SK_TOKEN, "value": _SK_TOKEN}],
        }
        upstream = _build_generic_upstream_payload(payload, route="/v1/rerank")
        assert upstream["id"] == _SK_TOKEN
        assert upstream["items"][0]["name"] == _SK_TOKEN
        assert _SK_TOKEN not in upstream["items"][0]["value"]

    def test_whitelisted_key_is_not_redacted(self) -> None:
        payload = {"model": "m", "query": f"bn_key={_SK_TOKEN}"}
        upstream = _build_generic_upstream_payload(
            payload, route="/v1/rerank", whitelist_keys={"bn_key"}
        )
        assert upstream["query"] == f"bn_key={_SK_TOKEN}"


class _ExplodingFilter:
    """Duck-typed stand-in for the redaction filter.

    Deliberately not a BaseFilter subclass: test_doc_alignment counts concrete
    BaseFilter subclasses to guard the documented filter count.
    """

    name = "redaction"

    def enabled(self, ctx: RequestContext) -> bool:  # noqa: ARG002
        return True

    def process_request(
        self, req: InternalRequest, ctx: RequestContext
    ) -> InternalRequest:
        raise RuntimeError("boom")

    def report(self) -> dict:
        return {"filter": self.name, "hit": False, "risk_score": 0.0}


class TestRedactionFailureIsFailClosed:
    def test_redaction_filters_are_security_critical(self) -> None:
        assert "redaction" in _SECURITY_CRITICAL_FILTER_NAMES
        assert "exact_value_redaction" in _SECURITY_CRITICAL_FILTER_NAMES

    def test_filter_error_blocks_even_when_forwarding_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            settings_module.settings, "storage_failure_action", "forward"
        )
        ctx = RequestContext(
            request_id="req-6", session_id="sess-6", route="/v1/chat/completions"
        )
        req = InternalRequest(
            request_id="req-6",
            session_id="sess-6",
            route="/v1/chat/completions",
            model="m",
            messages=[InternalMessage(role="user", content=f"key {_SK_TOKEN}")],
        )
        Pipeline(request_filters=[_ExplodingFilter()], response_filters=[]).run_request(
            req, ctx
        )
        assert ctx.request_disposition == "block"
        assert "request_pipeline:error:redaction" in ctx.enforcement_actions

    def test_mapping_persist_failure_raises_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings_module.settings, "storage_failure_action", "block")
        ctx = RequestContext(
            request_id="req-7", session_id="sess-7", route="/v1/chat/completions"
        )
        req = InternalRequest(
            request_id="req-7",
            session_id="sess-7",
            route="/v1/chat/completions",
            model="m",
            messages=[InternalMessage(role="user", content=f"key {_SK_TOKEN}")],
        )
        with pytest.raises(RuntimeError):
            RedactionFilter(_FailingKVStore()).process_request(req, ctx)

    def test_mapping_persist_failure_degrades_when_forwarding_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            settings_module.settings, "storage_failure_action", "forward"
        )
        ctx = RequestContext(
            request_id="req-8", session_id="sess-8", route="/v1/chat/completions"
        )
        req = InternalRequest(
            request_id="req-8",
            session_id="sess-8",
            route="/v1/chat/completions",
            model="m",
            messages=[InternalMessage(role="user", content=f"key {_SK_TOKEN}")],
        )
        result = RedactionFilter(_FailingKVStore()).process_request(req, ctx)
        # Content is redacted regardless; only the restoration mapping is lost.
        assert _SK_TOKEN not in result.messages[0].content
        assert "redaction_mapping_persist_failed" in ctx.security_tags
        assert "redaction:mapping_persist_failed:degraded" in ctx.enforcement_actions
