"""P2 acceptance: the fourth filter-switch layer (per forward rule)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from aegisgate.adapters.openai_compat import router as router_module
from aegisgate.adapters.openai_compat import upstream as upstream_module
from aegisgate.config import settings as settings_module
from aegisgate.config import feature_flags as feature_flags_module
from aegisgate.core import gw_forwards
from aegisgate.core.context import RequestContext
from aegisgate.filters.exact_value_redaction import ExactValueRedactionFilter


class _LogRecorder:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str, *args: Any) -> None:
        self.errors.append(message % args if args else message)

    def warning(self, message: str, *args: Any) -> None:
        self.warnings.append(message % args if args else message)

    def info(self, message: str, *args: Any) -> None:  # pragma: no cover - unused
        pass

    def debug(self, message: str, *args: Any) -> None:  # pragma: no cover - unused
        pass


def _ctx() -> RequestContext:
    return RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions")


def _entry(**overrides) -> dict:
    entry = {
        "enabled": True,
        "upstream_base": "https://api.xxx.com",
        "expose": "internal",
        "filters": {"mode": "policy"},
    }
    entry.update(overrides)
    return entry


@pytest.fixture()
def rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "gw_forwards.json"
    monkeypatch.setattr(settings_module.settings, "gw_forwards_path", str(path), raising=False)
    monkeypatch.setattr(settings_module.settings, "enable_gateway_forward", True, raising=False)
    monkeypatch.setattr(
        settings_module.settings, "forward_allow_public_baseline_off", False, raising=False
    )
    monkeypatch.setattr(
        settings_module.settings, "enable_request_hmac_auth", False, raising=False
    )

    def _load(forwards: dict) -> None:
        path.write_text(json.dumps({"version": 1, "forwards": forwards}), encoding="utf-8")
        gw_forwards.load(replace=True)

    gw_forwards.load(replace=True)
    yield _load
    monkeypatch.setattr(
        settings_module.settings, "enable_gateway_forward", False, raising=False
    )
    gw_forwards.load(replace=True)


class TestNoRuleBaseline:
    def test_no_forward_header_is_a_no_op(self, rules) -> None:
        ctx = _ctx()
        ctx.enabled_filters = {"redaction", "restoration"}
        before = set(ctx.enabled_filters)
        mode = router_module._apply_filter_mode(ctx, {})
        assert mode is None
        assert ctx.enabled_filters == before
        assert ctx.forward_filter_overrides == {}
        assert ctx.security_tags == set()

    def test_exact_value_filter_still_follows_global_without_override(
        self, rules, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", False, raising=False
        )
        ctx = _ctx()
        assert ExactValueRedactionFilter().enabled(ctx) is False
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", True, raising=False
        )
        assert ExactValueRedactionFilter().enabled(ctx) is True


class TestOverrides:
    def test_rule_can_open_a_globally_off_filter(self, rules, monkeypatch) -> None:
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"injection_detector": True}}
                )
            }
        )
        monkeypatch.setattr(
            settings_module.settings, "enable_injection_detector", False, raising=False
        )
        ctx = _ctx()
        ctx.enabled_filters = set()
        mode = router_module._apply_filter_mode(ctx, {"x-aegis-forward-host": "api.ag.com"})
        assert mode is None
        assert ctx.forward_filter_overrides == {"injection_detector": True}
        assert "injection_detector" in ctx.enabled_filters
        # The pipeline is built unconditionally, so the object is already there.
        from aegisgate.adapters.openai_compat.pipeline_runtime import _build_pipeline

        pipeline = _build_pipeline()
        names = {filter_.name for filter_ in pipeline.request_filters} | {
            filter_.name for filter_ in pipeline.response_filters
        }
        assert "injection_detector" in names

    def test_rule_can_close_baseline_and_tags_it(self, rules) -> None:
        rules(
            {
                "api.ag.com": _entry(
                    filters={
                        "mode": "custom",
                        "custom": {"redaction": False, "exact_value_redaction": False},
                    }
                )
            }
        )
        ctx = _ctx()
        ctx.enabled_filters = {"redaction", "exact_value_redaction", "restoration"}
        router_module._apply_filter_mode(ctx, {"x-aegis-forward-host": "api.ag.com"})
        assert "redaction" not in ctx.enabled_filters
        assert "exact_value_redaction" not in ctx.enabled_filters
        assert "restoration" in ctx.enabled_filters
        assert ctx.forward_filter_overrides == {
            "redaction": False,
            "exact_value_redaction": False,
        }
        assert "forward_rule:api.ag.com:baseline_off" in ctx.security_tags

    def test_override_actually_executes_exact_value_redaction(
        self, rules, monkeypatch
    ) -> None:
        from aegisgate.core.models import InternalMessage, InternalRequest

        rules(
            {
                "api.ag.com": _entry(
                    filters={
                        "mode": "custom",
                        "custom": {"exact_value_redaction": True},
                    }
                )
            }
        )
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", False, raising=False
        )
        monkeypatch.setattr(
            "aegisgate.filters.exact_value_redaction.replace_exact_values",
            lambda text: (text.replace("SECRET", "[REDACTED:EXACT_VALUE]"), 1),
        )
        ctx = _ctx()
        router_module._apply_filter_mode(ctx, {"x-aegis-forward-host": "api.ag.com"})
        request = InternalRequest(
            request_id="r1",
            session_id="s1",
            route="/v1/chat/completions",
            model="m",
            messages=[InternalMessage(role="user", content="say SECRET")],
        )
        result = ExactValueRedactionFilter().process_request(request, ctx)
        assert "SECRET" not in result.messages[0].content

    def test_missing_key_falls_back_to_policy_result(self, rules) -> None:
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"redaction": True}}
                )
            }
        )
        ctx = _ctx()
        ctx.enabled_filters = {"restoration"}
        router_module._apply_filter_mode(ctx, {"x-aegis-forward-host": "api.ag.com"})
        assert "restoration" in ctx.enabled_filters
        assert ctx.forward_filter_overrides == {"redaction": True}

    def test_hot_reload_removal_yields_empty_override(self, rules) -> None:
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"redaction": False}}
                )
            }
        )
        first = _ctx()
        first.enabled_filters = {"redaction"}
        router_module._apply_filter_mode(first, {"x-aegis-forward-host": "api.ag.com"})
        assert first.forward_filter_overrides == {"redaction": False}

        rules({})
        second = _ctx()
        second.enabled_filters = {"redaction"}
        router_module._apply_filter_mode(second, {"x-aegis-forward-host": "api.ag.com"})
        assert second.forward_filter_overrides == {}
        assert "redaction" in second.enabled_filters


class TestHeaderTransport:
    def _request(self, headers: dict[str, str], rule=None) -> Request:
        raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/chat/completions",
            "raw_path": b"/v1/chat/completions",
            "root_path": "",
            "query_string": b"",
            "headers": raw,
            "client": ("127.0.0.1", 5000),
            "server": ("127.0.0.1", 18080),
        }
        if rule is not None:
            scope["aegis_forward_rule"] = rule
        return Request(scope)

    def test_client_supplied_forward_header_is_stripped(self) -> None:
        headers = upstream_module._effective_gateway_headers(
            self._request({"x-aegis-forward-host": "attacker.example"})
        )
        assert "x-aegis-forward-host" not in headers

    def test_scope_rule_injects_forward_host(self, rules) -> None:
        rules({"api.ag.com": _entry()})
        rule = gw_forwards.get("api.ag.com")
        headers = upstream_module._effective_gateway_headers(self._request({}, rule=rule))
        assert headers["x-aegis-forward-host"] == "api.ag.com"


class TestDisabledFilterReport:
    def test_report_counts_forward_overrides(
        self, rules, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _LogRecorder()
        monkeypatch.setattr("aegisgate.util.logger.logger", recorder)
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"injection_detector": True}}
                )
            }
        )
        flags = feature_flags_module.FeatureFlags(
            injection_detector=False,
            request_sanitizer=False,
            privilege_guard=False,
            tool_call_guard=False,
            output_sanitizer=False,
        )
        feature_flags_module._check_disabled_filters(flags)
        assert recorder.errors
        assert "injection_detector(on:1/off:0)" in recorder.errors[0]

    def test_recheck_recomputes_after_reload(
        self, rules, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _LogRecorder()
        monkeypatch.setattr("aegisgate.util.logger.logger", recorder)
        flags = feature_flags_module.FeatureFlags(
            injection_detector=False,
            request_sanitizer=False,
            privilege_guard=False,
            tool_call_guard=False,
            output_sanitizer=False,
        )
        feature_flags_module._check_disabled_filters(flags)
        assert "on:1" not in recorder.errors[0]

        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"injection_detector": True}}
                )
            }
        )
        monkeypatch.setattr(feature_flags_module, "feature_flags", flags)
        feature_flags_module.recheck_disabled_filters()
        assert "injection_detector(on:1/off:0)" in recorder.errors[-1]


class TestCopyConsistencyGuard:
    def test_resolve_and_apply_mode_appear_equally_often(self) -> None:
        # The spec text is "count ``policy_engine.resolve(`` == ``_apply_filter_mode(ctx``".
        # The bare text match does not hold even on main: the function *definition*
        # also contains ``_apply_filter_mode(ctx``. Compare call sites instead.
        source = Path(router_module.__file__).read_text(encoding="utf-8")
        call_sites = source.count("_apply_filter_mode(ctx") - source.count(
            "def _apply_filter_mode(ctx"
        )
        assert source.count("policy_engine.resolve(") == call_sites == 9
