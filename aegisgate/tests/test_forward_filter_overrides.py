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
from aegisgate.config import redact_values as redact_values_module
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


@pytest.fixture(autouse=True)
def _isolated_exact_value_override():
    # _apply_filter_mode pins the switch in the current context; tests share one.
    token = redact_values_module._exact_value_override.set(None)
    yield
    redact_values_module._exact_value_override.reset(token)


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


class TestTransportLayerExactValues:
    """The V1 transport layer resolves values without a ctx; the rule must reach it."""

    def _load_values(self, monkeypatch) -> None:
        monkeypatch.setattr(
            redact_values_module, "load_redact_values", lambda: ["SECRET-VALUE-123"]
        )

    def test_rule_on_reaches_transport_layer_when_global_off(
        self, rules, monkeypatch
    ) -> None:
        self._load_values(monkeypatch)
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", False, raising=False
        )
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"exact_value_redaction": True}}
                )
            }
        )
        assert redact_values_module.active_exact_values() == ()
        router_module._apply_filter_mode(_ctx(), {"x-aegis-forward-host": "api.ag.com"})
        assert redact_values_module.active_exact_values() == ("SECRET-VALUE-123",)

    def test_rule_off_reaches_transport_layer_when_global_on(
        self, rules, monkeypatch
    ) -> None:
        self._load_values(monkeypatch)
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", True, raising=False
        )
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"exact_value_redaction": False}}
                )
            }
        )
        router_module._apply_filter_mode(_ctx(), {"x-aegis-forward-host": "api.ag.com"})
        assert redact_values_module.active_exact_values() == ()

    def test_request_without_rule_resets_to_global(self, rules, monkeypatch) -> None:
        self._load_values(monkeypatch)
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", True, raising=False
        )
        redact_values_module.set_exact_value_override(False)
        router_module._apply_filter_mode(_ctx(), {})
        assert redact_values_module.active_exact_values() == ("SECRET-VALUE-123",)


class TestOverridesThroughTheApp:
    """HostForward → header injection → _execute_* → what the upstream receives."""

    SECRET = "SECRET-VALUE-123"

    @pytest.fixture()
    def upstream(self, rules, monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
        captured: dict[str, list] = {"payloads": []}

        async def fake_forward_json(*, url, payload, headers, connect_urls, host_header):
            captured["payloads"].append(payload)
            return 200, {
                "id": "chat-1",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

        async def fake_iter_stream(*, url, payload, headers, connect_urls, host_header):
            captured["payloads"].append(payload)
            yield b'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"}}]}\n\n'
            yield b"data: [DONE]\n\n"

        async def passthrough_pipeline(_pipeline, item, _ctx):
            return item

        async def no_semantic(*_args, **_kwargs):
            return None

        monkeypatch.setattr(router_module, "_forward_json_with_pinning", fake_forward_json)
        monkeypatch.setattr(router_module, "_iter_forward_stream_with_pinning", fake_iter_stream)
        monkeypatch.setattr(router_module, "_run_request_pipeline", passthrough_pipeline)
        monkeypatch.setattr(router_module, "_run_response_pipeline", passthrough_pipeline)
        monkeypatch.setattr(router_module, "_apply_semantic_review", no_semantic)
        monkeypatch.setattr(router_module, "_write_audit_event", lambda *a, **k: None)
        monkeypatch.setattr(router_module, "debug_log_original", lambda *a, **k: None)
        monkeypatch.setattr(redact_values_module, "load_redact_values", lambda: [self.SECRET])
        return captured

    def _message(self) -> dict[str, Any]:
        return {
            "role": "user",
            "content": [{"type": "text", "text": f"my key is {self.SECRET}"}],
        }

    def _post(self, *, stream: bool) -> int:
        from fastapi.testclient import TestClient

        from aegisgate.core.gateway import app

        # Structured content: plain-string content reaches the upstream through the
        # filter pipeline (stubbed here, covered above), structured parts through
        # the transport-layer walk that only the context switch can reach.
        body = {
            "model": "m",
            "stream": stream,
            "messages": [self._message()],
        }
        with TestClient(app, client=("127.0.0.1", 50000)) as client:
            response = client.post(
                "/v1/chat/completions", headers={"host": "api.ag.com"}, json=body
            )
            response.read()
        return response.status_code

    @pytest.mark.parametrize("stream", [False, True])
    def test_rule_on_redacts_what_the_upstream_receives_when_global_is_off(
        self, rules, upstream, monkeypatch: pytest.MonkeyPatch, stream: bool
    ) -> None:
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", False, raising=False
        )
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"exact_value_redaction": True}}
                )
            }
        )
        assert self._post(stream=stream) == 200
        assert upstream["payloads"], "the request never reached the upstream"
        assert self.SECRET not in json.dumps(upstream["payloads"][-1])

    @pytest.mark.parametrize("stream", [False, True])
    def test_rule_off_lets_the_value_through_when_global_is_on(
        self, rules, upstream, monkeypatch: pytest.MonkeyPatch, stream: bool
    ) -> None:
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", True, raising=False
        )
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"exact_value_redaction": False}}
                )
            }
        )
        assert self._post(stream=stream) == 200
        assert self.SECRET in json.dumps(upstream["payloads"][-1])

    def test_request_without_a_rule_keeps_the_global_switch(
        self, rules, upstream, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            settings_module.settings, "enable_exact_value_redaction", True, raising=False
        )
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"exact_value_redaction": False}}
                )
            }
        )
        from fastapi.testclient import TestClient

        from aegisgate.core.gateway import app

        monkeypatch.setattr(
            settings_module.settings, "upstream_base_url", "http://127.0.0.1:9/v1", raising=False
        )
        with TestClient(app, client=("127.0.0.1", 50000)) as client:
            # Same process, a host without a rule: the other request's "off" must not stick.
            response = client.post(
                "/v1/chat/completions",
                headers={"host": "other.test"},
                json={"model": "m", "messages": [self._message()]},
            )
        assert response.status_code == 200
        assert self.SECRET not in json.dumps(upstream["payloads"][-1])


class TestReloadReport:
    def test_reload_skips_the_report_while_forwarding_is_off(
        self, rules, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aegisgate.core import hot_reload

        calls: list[bool] = []
        monkeypatch.setattr(
            feature_flags_module, "recheck_disabled_filters", lambda: calls.append(True)
        )
        monkeypatch.setattr(
            settings_module.settings, "enable_gateway_forward", False, raising=False
        )
        hot_reload.reload_gw_forwards()
        assert calls == []
        monkeypatch.setattr(
            settings_module.settings, "enable_gateway_forward", True, raising=False
        )
        hot_reload.reload_gw_forwards()
        assert calls == [True]


class TestAdmittedRuleSnapshot:
    def test_rule_edited_mid_flight_keeps_the_admitted_switches(self, rules) -> None:
        # Admitted under a rule that keeps redaction on …
        rules({"api.ag.com": _entry(filters={"mode": "custom", "custom": {"redaction": True}})})
        admitted = gw_forwards.get("api.ag.com")
        snapshot = upstream_module.encode_forward_overrides(admitted.resolved_filter_overrides())
        # … then the rule is rewritten to switch it off before the pipeline runs.
        rules({"api.ag.com": _entry(filters={"mode": "custom", "custom": {"redaction": False}})})
        ctx = _ctx()
        ctx.enabled_filters = {"redaction"}
        router_module._apply_filter_mode(
            ctx,
            {"x-aegis-forward-host": "api.ag.com", "x-aegis-forward-overrides": snapshot},
        )
        assert "redaction" in ctx.enabled_filters
        assert "forward_rule:api.ag.com:baseline_off" not in ctx.security_tags

    def test_deleted_rule_still_means_no_override(self, rules) -> None:
        rules({"api.ag.com": _entry(filters={"mode": "custom", "custom": {"redaction": False}})})
        snapshot = upstream_module.encode_forward_overrides({"redaction": False})
        rules({})
        ctx = _ctx()
        ctx.enabled_filters = {"redaction"}
        router_module._apply_filter_mode(
            ctx,
            {"x-aegis-forward-host": "api.ag.com", "x-aegis-forward-overrides": snapshot},
        )
        assert ctx.forward_filter_overrides == {}
        assert "redaction" in ctx.enabled_filters

    @pytest.mark.parametrize(
        "overrides", [{}, {"redaction": False, "injection_detector": True}]
    )
    def test_encoding_round_trips(self, overrides: dict) -> None:
        encoded = upstream_module.encode_forward_overrides(overrides)
        assert upstream_module.decode_forward_overrides(encoded) == overrides
        assert upstream_module.decode_forward_overrides("") is None


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
            self._request(
                {
                    "x-aegis-forward-host": "attacker.example",
                    "x-aegis-upstream-source": "scope",
                }
            )
        )
        assert "x-aegis-forward-host" not in headers
        # A client cannot claim the scope upstream source either.
        assert headers.get("x-aegis-upstream-source") != "scope"

    def test_scope_rule_injects_forward_host(self, rules) -> None:
        rules({"api.ag.com": _entry()})
        rule = gw_forwards.get("api.ag.com")
        headers = upstream_module._effective_gateway_headers(self._request({}, rule=rule))
        assert headers["x-aegis-forward-host"] == "api.ag.com"
        assert headers["x-aegis-forward-overrides"] == "-"

    def test_client_supplied_override_snapshot_is_replaced(self, rules) -> None:
        rules({"api.ag.com": _entry()})
        rule = gw_forwards.get("api.ag.com")
        headers = upstream_module._effective_gateway_headers(
            self._request({"x-aegis-forward-overrides": "redaction=0"}, rule=rule)
        )
        assert headers["x-aegis-forward-overrides"] == "-"
        plain = upstream_module._effective_gateway_headers(
            self._request({"x-aegis-forward-overrides": "redaction=0"})
        )
        assert "x-aegis-forward-overrides" not in plain


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


class TestStartupReport:
    def test_counts_are_skipped_while_forwarding_is_off(
        self, rules, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rules(
            {
                "api.ag.com": _entry(
                    filters={"mode": "custom", "custom": {"injection_detector": True}}
                )
            }
        )
        monkeypatch.setattr(
            settings_module.settings, "enable_gateway_forward", False, raising=False
        )
        assert feature_flags_module._forward_override_counts() == ({}, {})

    def test_lifespan_rechecks_after_loading_the_table(self) -> None:
        source = Path(__import__("aegisgate.core.gateway", fromlist=["x"]).__file__).read_text(
            encoding="utf-8"
        )
        load_at = source.index("gw_forwards_load()")
        assert source.index("recheck_disabled_filters()", load_at) > load_at

    def test_loading_before_feature_flags_import_does_not_deadlock(
        self, tmp_path: Path
    ) -> None:
        import subprocess
        import sys

        path = tmp_path / "gw_forwards.json"
        path.write_text(
            json.dumps({"version": 1, "forwards": {"api.ag.com": _entry()}}),
            encoding="utf-8",
        )
        script = (
            "import sys\n"
            "from aegisgate.config.settings import settings\n"
            f"settings.gw_forwards_path = {str(path)!r}\n"
            "settings.enable_gateway_forward = True\n"
            "from aegisgate.core import gw_forwards\n"
            "assert 'aegisgate.config.feature_flags' not in sys.modules\n"
            "gw_forwards.load(replace=True)\n"
            "assert gw_forwards.get('api.ag.com') is not None\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(Path(__file__).resolve().parents[2]),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr[-2000:]


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

    def test_every_resolve_is_followed_by_apply_mode_before_the_next(self) -> None:
        source = Path(router_module.__file__).read_text(encoding="utf-8")
        body = source.split("def _apply_filter_mode(ctx", 1)[1]
        resolves = [i for i in range(len(body)) if body.startswith("policy_engine.resolve(", i)]
        applies = [i for i in range(len(body)) if body.startswith("_apply_filter_mode(ctx", i)]
        assert len(resolves) == len(applies) == 9
        for index, resolve_at in enumerate(resolves):
            next_resolve = resolves[index + 1] if index + 1 < len(resolves) else len(body)
            assert any(resolve_at < apply_at < next_resolve for apply_at in applies)
