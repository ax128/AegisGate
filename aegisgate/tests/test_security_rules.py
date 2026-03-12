from aegisgate.config import security_rules


def test_load_security_rules_uses_bootstrap_file_when_primary_path_missing(tmp_path, monkeypatch):
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir(parents=True, exist_ok=True)
    (bootstrap / "security_filters.yaml").write_text(
        "redaction:\n  request_prefix_max_len: 7\n",
        encoding="utf-8",
    )
    missing = tmp_path / "rules" / "security_filters.yaml"
    monkeypatch.setenv("AEGIS_BOOTSTRAP_RULES_DIR", str(bootstrap))
    monkeypatch.setattr(security_rules, "_CACHE_PATH", "")
    monkeypatch.setattr(security_rules, "_CACHE_MTIME_NS", -1)
    monkeypatch.setattr(security_rules, "_CACHE_RULES", None)

    rules = security_rules.load_security_rules(str(missing))

    assert rules["redaction"]["request_prefix_max_len"] == 7
