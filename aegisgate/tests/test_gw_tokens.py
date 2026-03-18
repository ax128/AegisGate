from aegisgate.core import gw_tokens


def test_register_generates_token_and_reuses_pair(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()

    token, existed = gw_tokens.register(
        "https://upstream.example.com/v1",
        ["bn_key", "ak_secret", "bn_key"],
    )
    assert existed is False
    assert len(token) == gw_tokens._TOKEN_LEN
    assert gw_tokens.get(token)["whitelist_key"] == ["bn_key", "ak_secret"]

    token2, existed2 = gw_tokens.register(
        "https://upstream.example.com/v1",
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
    assert mapping["whitelist_key"] == []


def test_update_rewrites_upstream_and_whitelist(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    token, _ = gw_tokens.register("https://upstream.example.com/v1", "agent", ["bn_key"])

    updated = gw_tokens.update(
        token,
        upstream_base="https://new-upstream.example.com/v1/",
        whitelist_key=["okx_key"],
    )
    assert updated is True
    mapping = gw_tokens.get(token)
    assert mapping is not None
    assert mapping["upstream_base"] == "https://new-upstream.example.com/v1"
    assert mapping["whitelist_key"] == ["okx_key"]


def test_register_without_whitelist_does_not_reset_existing(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    token, existed = gw_tokens.register("https://upstream.example.com/v1", ["bn_key"])
    assert existed is False

    token2, existed2 = gw_tokens.register("https://upstream.example.com/v1")
    assert existed2 is True
    assert token2 == token
    assert gw_tokens.get(token)["whitelist_key"] == ["bn_key"]


def test_get_returns_mapping_copy(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    token, _ = gw_tokens.register("https://upstream.example.com/v1", ["bn_key"])

    mapping = gw_tokens.get(token)
    assert mapping is not None
    mapping["whitelist_key"].append("okx_key")

    latest = gw_tokens.get(token)
    assert latest is not None
    assert latest["whitelist_key"] == ["bn_key"]


def test_list_tokens_returns_deep_copy(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
    token, _ = gw_tokens.register("https://upstream.example.com/v1", ["bn_key"])

    listed = gw_tokens.list_tokens()
    listed[token]["whitelist_key"].append("okx_key")

    latest = gw_tokens.get(token)
    assert latest is not None
    assert latest["whitelist_key"] == ["bn_key"]


def test_inject_docker_upstreams(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    monkeypatch.setattr(gw_tokens.settings, "docker_upstreams", "8317:cli-proxy-api,8080:sub2api,3000:aiclient2api:3000")
    with gw_tokens._lock:
        gw_tokens._tokens.clear()

    count = gw_tokens.inject_docker_upstreams()
    assert count == 3

    m1 = gw_tokens.get("8317")
    assert m1 is not None
    assert m1["upstream_base"] == "http://cli-proxy-api:8317/v1"

    m2 = gw_tokens.get("8080")
    assert m2 is not None
    assert m2["upstream_base"] == "http://sub2api:8080/v1"

    m3 = gw_tokens.get("3000")
    assert m3 is not None
    assert m3["upstream_base"] == "http://aiclient2api:3000/v1"

    # Verify persisted to file
    assert (tmp_path / "gw_tokens.json").is_file()


def test_inject_docker_upstreams_custom_port(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    monkeypatch.setattr(gw_tokens.settings, "docker_upstreams", "8317:my-proxy:9000")
    with gw_tokens._lock:
        gw_tokens._tokens.clear()

    count = gw_tokens.inject_docker_upstreams()
    assert count == 1

    m = gw_tokens.get("8317")
    assert m is not None
    assert m["upstream_base"] == "http://my-proxy:9000/v1"


def test_inject_docker_upstreams_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    monkeypatch.setattr(gw_tokens.settings, "docker_upstreams", "")
    with gw_tokens._lock:
        gw_tokens._tokens.clear()

    count = gw_tokens.inject_docker_upstreams()
    assert count == 0


def test_inject_docker_upstreams_overrides_existing(monkeypatch, tmp_path):
    monkeypatch.setattr(gw_tokens.settings, "gw_tokens_path", str(tmp_path / "gw_tokens.json"))
    with gw_tokens._lock:
        gw_tokens._tokens.clear()
        gw_tokens._tokens["8317"] = {
            "upstream_base": "http://old-host:8317/v1",
            "whitelist_key": ["keep_me"],
        }

    monkeypatch.setattr(gw_tokens.settings, "docker_upstreams", "8317:new-proxy")
    gw_tokens.inject_docker_upstreams()

    m = gw_tokens.get("8317")
    assert m["upstream_base"] == "http://new-proxy:8317/v1"
    assert m["whitelist_key"] == []
