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


def test_assert_security_bootstrap_ready_raises_when_missing(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "default.yaml").write_text("enabled_filters: []\n", encoding="utf-8")
    # 无可用 bootstrap 源时（如无 env 且包内不可用），缺少策略文件应抛错
    monkeypatch.setattr(init_config, "_rules_source_dir", lambda: None)

    missing = init_config.missing_required_rules(rules_dir)
    assert "security_filters.yaml" in missing

    with pytest.raises(RuntimeError):
        init_config.assert_security_bootstrap_ready(rules_dir)


def test_assert_security_bootstrap_ready_passes_when_rules_dir_is_empty(tmp_path, monkeypatch):
    """挂载目录完全为空时，允许使用 bootstrap 目录兜底。"""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir(parents=True, exist_ok=True)
    for name in ("default.yaml", "security_filters.yaml", "permissive.yaml", "strict.yaml"):
        (bootstrap / name).write_text(f"# {name}\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(rules_dir))
    monkeypatch.setenv("AEGIS_BOOTSTRAP_RULES_DIR", str(bootstrap))

    init_config.assert_security_bootstrap_ready(rules_dir)


def test_assert_security_bootstrap_ready_passes_when_only_security_rules_exist(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "security_filters.yaml").write_text("redaction: {}\n", encoding="utf-8")
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir(parents=True, exist_ok=True)
    for name in ("default.yaml", "security_filters.yaml", "permissive.yaml", "strict.yaml"):
        (bootstrap / name).write_text(f"# {name}\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(rules_dir))
    monkeypatch.setenv("AEGIS_BOOTSTRAP_RULES_DIR", str(bootstrap))

    init_config.assert_security_bootstrap_ready(rules_dir)


def test_assert_security_bootstrap_ready_raises_when_rules_dir_partially_populated(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "default.yaml").write_text("enabled_filters: []\n", encoding="utf-8")
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir(parents=True, exist_ok=True)
    for name in ("default.yaml", "security_filters.yaml", "permissive.yaml", "strict.yaml"):
        (bootstrap / name).write_text(f"# {name}\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(rules_dir))
    monkeypatch.setenv("AEGIS_BOOTSTRAP_RULES_DIR", str(bootstrap))

    with pytest.raises(RuntimeError):
        init_config.assert_security_bootstrap_ready(rules_dir)
