import pytest

from aegisgate import init_config


def test_ensure_config_dir_bootstraps_required_rule_files(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir(parents=True, exist_ok=True)
    for name in ("default.yaml", "security_filters.yaml", "permissive.yaml", "strict.yaml"):
        (bootstrap / name).write_text(f"# {name}\n", encoding="utf-8")

    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(rules_dir))
    monkeypatch.setenv("AEGIS_BOOTSTRAP_RULES_DIR", str(bootstrap))

    init_config.ensure_config_dir()
    missing = init_config.missing_required_rules(rules_dir)
    assert missing == []
    init_config.assert_security_bootstrap_ready(rules_dir)


def test_assert_security_bootstrap_ready_raises_when_missing(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "default.yaml").write_text("enabled_filters: []\n", encoding="utf-8")

    missing = init_config.missing_required_rules(rules_dir)
    assert "security_filters.yaml" in missing

    with pytest.raises(RuntimeError):
        init_config.assert_security_bootstrap_ready(rules_dir)
