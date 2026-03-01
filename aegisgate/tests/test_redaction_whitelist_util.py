from aegisgate.util.redaction_whitelist import (
    normalize_whitelist_keys,
    protected_spans_for_text,
    range_overlaps_protected,
)


def test_normalize_whitelist_keys_accepts_string_list_and_dict():
    assert normalize_whitelist_keys("bn_key, okx_key  bn_key") == ["bn_key", "okx_key"]
    assert normalize_whitelist_keys(["bn_key", "okx_key", "bn_key"]) == ["bn_key", "okx_key"]
    assert normalize_whitelist_keys({"bn_key": True, "okx_key": 1, "skip": 0}) == ["bn_key", "okx_key"]


def test_protected_spans_cover_key_value_and_query_forms():
    text = 'bn_key=sk-abc "bn_key":{} https://x.test?a=1&bn_key=sk-zzz'
    spans = protected_spans_for_text(text, ["bn_key"])
    assert spans

    kv_idx = text.index("sk-abc")
    assert range_overlaps_protected(spans, start=kv_idx, end=kv_idx + 6)

    obj_idx = text.index('"bn_key":{}')
    assert range_overlaps_protected(spans, start=obj_idx, end=obj_idx + len('"bn_key":{}'))

    q_idx = text.index("bn_key=sk-zzz")
    assert range_overlaps_protected(spans, start=q_idx, end=q_idx + len("bn_key=sk-zzz"))
