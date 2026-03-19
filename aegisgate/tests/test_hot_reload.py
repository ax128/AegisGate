from __future__ import annotations

from types import SimpleNamespace

from aegisgate.config import settings as settings_module
from aegisgate.config import feature_flags
from aegisgate.core import hot_reload
from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.adapters.openai_compat import pipeline_runtime
from aegisgate import init_config
from aegisgate.util import logger as logger_module


def test_reload_settings_reconfigures_semantic_runtime(monkeypatch):
    class FakeSettings:
        model_fields = {
            "log_level": object(),
            "semantic_service_url": object(),
            "semantic_cache_ttl_seconds": object(),
            "semantic_cache_max_entries": object(),
            "semantic_circuit_failure_threshold": object(),
            "semantic_circuit_open_seconds": object(),
        }

        def __init__(self) -> None:
            self.log_level = "debug"
            self.semantic_service_url = "https://semantic.example.com/analyze"
            self.semantic_cache_ttl_seconds = 123
            self.semantic_cache_max_entries = 456
            self.semantic_circuit_failure_threshold = 7
            self.semantic_circuit_open_seconds = 89

    calls: list[object] = []
    fake_runtime_settings = SimpleNamespace()

    monkeypatch.setattr(settings_module, "Settings", FakeSettings)
    monkeypatch.setattr(settings_module, "settings", fake_runtime_settings)
    monkeypatch.setattr(feature_flags, "refresh_feature_flags", lambda: calls.append("flags"))
    monkeypatch.setattr(init_config, "ensure_runtime_storage_paths", lambda: calls.append("paths"))
    monkeypatch.setattr(logger_module, "apply_log_level", lambda level: calls.append(("log", level)))
    monkeypatch.setattr(pipeline_runtime, "reload_runtime_dependencies", lambda: calls.append("runtime"))
    monkeypatch.setattr(openai_router, "reload_semantic_client_settings", lambda: calls.append("semantic"))

    hot_reload.reload_settings()

    assert fake_runtime_settings.log_level == "debug"
    assert fake_runtime_settings.semantic_service_url == "https://semantic.example.com/analyze"
    assert fake_runtime_settings.semantic_cache_ttl_seconds == 123
    assert fake_runtime_settings.semantic_cache_max_entries == 456
    assert fake_runtime_settings.semantic_circuit_failure_threshold == 7
    assert fake_runtime_settings.semantic_circuit_open_seconds == 89
    assert calls == ["flags", "paths", ("log", "debug"), "runtime", "semantic"]


def test_build_watcher_tracks_env_candidates_even_when_missing(monkeypatch, tmp_path):
    rules_dir = tmp_path / "aegisgate" / "policies" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "security_filters.yaml").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        settings_module,
        "settings",
        SimpleNamespace(
            security_rules_path="aegisgate/policies/rules/security_filters.yaml",
            gw_tokens_path="config/gw_tokens.json",
        ),
    )

    watcher = hot_reload.build_watcher()
    labels = [watched.label for watched, _ in watcher._watches]

    assert "env:.env" in labels
    assert "env:config/.env" in labels
