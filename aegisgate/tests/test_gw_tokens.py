from aegisgate.core import gw_tokens


def test_register_generates_10_char_token_and_reuses_pair(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()

    token, existed = gw_tokens.register(
        "https://upstream.example.com/v1",
        "agent",
        ["bn_key", "ak_secret", "bn_key"],
    )
    assert existed is False
    assert len(token) == 10
    assert gw_tokens.get(token)["whitelist_key"] == ["bn_key", "ak_secret"]

    token2, existed2 = gw_tokens.register(
        "https://upstream.example.com/v1",
        "agent",
        ["bn_key", "new_key"],
    )
    assert existed2 is True
    assert token2 == token
    assert gw_tokens.get(token)["whitelist_key"] == ["bn_key", "new_key"]


def test_load_legacy_tokens_without_whitelist_key(monkeypatch, tmp_path):
    path = tmp_path / "gw_tokens.json"
    path.write_text(
        '{"tokens":{"tok123":{"upstream_base":"https://upstream.example.com/v1","gateway_key":"agent"}}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(path))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()

    gw_tokens.load()
    mapping = gw_tokens.get("tok123")
    assert mapping is not None
    assert mapping["upstream_base"] == "https://upstream.example.com/v1"
    assert mapping["gateway_key"] == "agent"
    assert mapping["whitelist_key"] == []


def test_update_rewrites_upstream_and_whitelist(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    token, _ = gw_tokens.register("https://upstream.example.com/v1", "agent", ["bn_key"])

    updated = gw_tokens.update(
        token,
        upstream_base="https://new-upstream.example.com/v1/",
        gateway_key="agent",
        whitelist_key=["okx_key"],
    )
    assert updated is True
    mapping = gw_tokens.get(token)
    assert mapping is not None
    assert mapping["upstream_base"] == "https://new-upstream.example.com/v1"
    assert mapping["gateway_key"] == "agent"
    assert mapping["whitelist_key"] == ["okx_key"]


def test_register_without_whitelist_does_not_reset_existing(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    token, existed = gw_tokens.register("https://upstream.example.com/v1", "agent", ["bn_key"])
    assert existed is False

    token2, existed2 = gw_tokens.register("https://upstream.example.com/v1", "agent")
    assert existed2 is True
    assert token2 == token
    assert gw_tokens.get(token)["whitelist_key"] == ["bn_key"]


def test_get_returns_mapping_copy(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    token, _ = gw_tokens.register("https://upstream.example.com/v1", "agent", ["bn_key"])

    mapping = gw_tokens.get(token)
    assert mapping is not None
    mapping["gateway_key"] = "tampered"
    mapping["whitelist_key"].append("okx_key")

    latest = gw_tokens.get(token)
    assert latest is not None
    assert latest["gateway_key"] == "agent"
    assert latest["whitelist_key"] == ["bn_key"]


def test_list_tokens_returns_deep_copy(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    token, _ = gw_tokens.register("https://upstream.example.com/v1", "agent", ["bn_key"])

    listed = gw_tokens.list_tokens()
    listed[token]["gateway_key"] = "tampered"
    listed[token]["whitelist_key"].append("okx_key")

    latest = gw_tokens.get(token)
    assert latest is not None
    assert latest["gateway_key"] == "agent"
    assert latest["whitelist_key"] == ["bn_key"]
