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
