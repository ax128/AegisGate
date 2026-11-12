"""Guards for linear-time rule regexes.

Differential samples follow the appendix B walker: YAML rules, code defaults,
and the v2 dangerous-command table. Hit/miss and ``match.start()`` must agree
with the original regex. Match ends are the earliest chain completion, which
the fixed ``finditer`` / ``sub`` example pins down.
"""

from __future__ import annotations

import random
import re
import signal
import time
import types
from pathlib import Path

import pytest
import yaml

from aegisgate.adapters.v2_proxy.router import _DEFAULT_DANGEROUS_COMMAND_PATTERNS
from aegisgate.config.security_rules import _DEFAULT_RULES
from aegisgate.storage.kv import KVStore
from aegisgate.util.rule_regex import GapGuardedPattern, compile_rule_regex

_REPO_ROOT = Path(__file__).resolve().parents[2]
_YAML_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"
_WORD = re.compile(r"[A-Za-z]{2,}|[\u4e00-\u9fff]+")
_FILLER = [
    "the",
    "x",
    " ",
    "\n",
    ".",
    ",",
    "|",
    "curl",
    "sh",
    "-",
    "-it",
    "/etc/",
    "~/.ssh",
    "api key",
    "，",
    "docker",
    "exec",
    "\r\n",
]
_SEED = 7
_SAMPLES_PER_FLAG = 300
_BUDGET_SECONDS = 0.1
_DENSE_CHARS = 16 * 1024
_RUNTIME_FLAGS = re.IGNORECASE | re.DOTALL


def _walk(obj: object, path: str = "") -> list[tuple[str, str]]:
    """Same shape as the appendix B collector."""
    found: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        regex = obj.get("regex")
        if isinstance(regex, str):
            found.append((f"{path}:{obj.get('id')}", regex))
        for key, value in obj.items():
            if key == "regex":
                continue
            child = f"{path}.{key}" if path else str(key)
            found.extend(_walk(value, child))
    elif isinstance(obj, list):
        for value in obj:
            if isinstance(value, str) and path.endswith("patterns"):
                found.append((f"{path}:<str>", value))
            else:
                found.extend(_walk(value, path))
    return found


def _all_rule_patterns() -> list[tuple[str, str]]:
    loaded = yaml.safe_load(_YAML_RULES.read_text(encoding="utf-8"))
    collected = (
        [("yaml." + label, pattern) for label, pattern in _walk(loaded)]
        + [("code." + label, pattern) for label, pattern in _walk(_DEFAULT_RULES)]
        + [("v2." + pattern_id, pattern) for pattern_id, pattern in _DEFAULT_DANGEROUS_COMMAND_PATTERNS]
    )
    return list(dict.fromkeys(collected))


def _vocab(pattern: str) -> list[str]:
    return list(dict.fromkeys(_WORD.findall(pattern))) or ["a"]


def _dense_texts(pattern: str, size: int = _DENSE_CHARS) -> list[str]:
    vocab = _vocab(pattern)
    texts: list[str] = []
    for unit in (
        " ".join(vocab[: max(1, len(vocab) - 2)]) + " ",
        vocab[0] + " ",
        vocab[0] + "\n",
    ):
        texts.append((unit * (size // len(unit) + 1))[:size])
    return texts


class _SearchTimeout(Exception):
    pass


def _alarm(_signum: int, _frame: object) -> None:
    raise _SearchTimeout()


@pytest.mark.timeout(180, method="thread")
def test_wrapped_rules_agree_on_hit_and_start() -> None:
    """300 samples per wrapped rule per flag set; start() matches re.compile."""
    rng = random.Random(_SEED)
    mismatches: list[str] = []
    wrapped = 0
    for flags in (re.I, re.I | re.S):
        for label, pattern in _all_rule_patterns():
            guarded = compile_rule_regex(pattern, flags)
            if not isinstance(guarded, GapGuardedPattern):
                continue
            wrapped += 1
            original = re.compile(pattern, flags)
            vocab = _vocab(pattern) or ["x"]
            for _ in range(_SAMPLES_PER_FLAG):
                tokens = [
                    rng.choice(vocab) if rng.random() < 0.6 else rng.choice(_FILLER)
                    for _ in range(rng.randint(1, 30))
                ]
                sample = rng.choice([" ", "", "\n"]).join(tokens)
                raw = original.search(sample)
                got = guarded.search(sample)
                if bool(raw) != bool(got) or (raw is not None and raw.start() != got.start()):
                    mismatches.append(
                        f"{label} flags={flags} sample={sample[:120]!r} "
                        f"raw={bool(raw)} guarded={bool(got)} "
                        f"starts={(None if raw is None else raw.start(), None if got is None else got.start())}"
                    )
                    if len(mismatches) >= 5:
                        break
            if len(mismatches) >= 5:
                break
        if len(mismatches) >= 5:
            break
    assert wrapped > 0, "no rule was wrapped; the guard is not engaged"
    assert mismatches == [], mismatches


@pytest.mark.timeout(180, method="thread")
def test_keyword_dense_rules_stay_within_budget() -> None:
    """16 KB keyword-dense search + finditer must finish in 100 ms."""
    previous = signal.signal(signal.SIGALRM, _alarm)
    try:
        for label, pattern in _all_rule_patterns():
            guarded = compile_rule_regex(pattern, _RUNTIME_FLAGS)
            for text in _dense_texts(pattern):
                signal.alarm(2)
                started = time.perf_counter()
                try:
                    guarded.search(text)
                    list(guarded.finditer(text))
                    elapsed = time.perf_counter() - started
                except _SearchTimeout:
                    pytest.fail(f"{label} exceeded 2s on a {len(text)} char keyword-dense input")
                finally:
                    signal.alarm(0)
                assert elapsed < _BUDGET_SECONDS, (
                    f"{label} took {elapsed * 1000:.0f} ms on {len(text)} chars"
                )
    finally:
        signal.signal(signal.SIGALRM, previous)


def test_dot_star_without_dotall_does_not_cross_a_newline() -> None:
    assert compile_rule_regex(r"a.*b", 0).search("a\nb") is None


def test_segment_may_cross_the_newline_that_ends_its_gap() -> None:
    matched = compile_rule_regex(r"dump.*api\s*key", 0).search("dump x api\n key")
    assert matched is not None
    assert matched.start() == 0


def test_plus_gap_requires_one_character() -> None:
    guarded = compile_rule_regex(r"a.+b", 0)
    assert guarded.search("ab") is None
    assert guarded.search("a\nb") is None
    matched = guarded.search("axb")
    assert matched is not None
    assert matched.span() == (0, 3)


def test_outer_group_is_unwrapped_before_the_split() -> None:
    pattern = r"(a.*b|c.*d)"
    guarded = compile_rule_regex(pattern, 0)
    assert isinstance(guarded, GapGuardedPattern)
    text = "c yy d and a xx b"
    matched = guarded.search(text)
    raw = re.compile(pattern).search(text)
    assert matched is not None and raw is not None
    assert matched.start() == raw.start() == 0
    assert matched.span() == (0, 6)


def test_top_level_alternation_picks_the_leftmost_branch() -> None:
    text = "c yy d and a xx b"
    matched = compile_rule_regex(r"a.*b|c.*d", 0).search(text)
    assert matched is not None
    assert matched.start() == 0
    assert matched.span() == (0, 6)


def test_lookaround_stays_a_native_pattern() -> None:
    compiled = compile_rule_regex(r"a(?=b).*c", 0)
    assert isinstance(compiled, re.Pattern)
    assert not isinstance(compiled, GapGuardedPattern)


def test_finditer_sub_and_subn_end_at_the_earliest_chain() -> None:
    text = "a X b a Y b a Z b"
    guarded = compile_rule_regex(r"a.*b", 0)
    spans = [match.span() for match in guarded.finditer(text)]
    assert spans == [(0, 5), (6, 11), (12, 17)]
    assert [match.span() for match in re.compile(r"a.*b").finditer(text)] == [(0, 17)]
    assert guarded.sub("M", text) == "M M M"
    assert guarded.subn(lambda match: str(match.span()), text) == (
        "(0, 5) (6, 11) (12, 17)",
        3,
    )


def test_probe_child_runs_a_guarded_pattern() -> None:
    from aegisgate.core.regex_probe import probe

    result = probe(r"a.*b", ["a X b a Y b"])
    assert result.get("error") is None
    assert result["timed_out"] is False
    assert result["results"][0]["spans"] == [[0, 5], [6, 11]]


class _MemoryKVStore(KVStore):
    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        return None

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return {}

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return {}


def _default_pipeline_filters() -> list[object]:
    from aegisgate.filters.anomaly_detector import AnomalyDetector
    from aegisgate.filters.exact_value_redaction import ExactValueRedactionFilter
    from aegisgate.filters.injection_detector import PromptInjectionDetector
    from aegisgate.filters.post_restore_guard import PostRestoreGuard
    from aegisgate.filters.privilege_guard import PrivilegeGuard
    from aegisgate.filters.rag_poison_guard import RagPoisonGuard
    from aegisgate.filters.redaction import RedactionFilter
    from aegisgate.filters.request_sanitizer import RequestSanitizer
    from aegisgate.filters.restoration import RestorationFilter
    from aegisgate.filters.sanitizer import OutputSanitizer
    from aegisgate.filters.system_prompt_guard import SystemPromptGuard
    from aegisgate.filters.tool_call_guard import ToolCallGuard
    from aegisgate.filters.untrusted_content_guard import UntrustedContentGuard

    store = _MemoryKVStore()
    return [
        ExactValueRedactionFilter(),
        RedactionFilter(store),
        SystemPromptGuard(),
        UntrustedContentGuard(),
        RequestSanitizer(),
        RagPoisonGuard(),
        AnomalyDetector(),
        PromptInjectionDetector(),
        PrivilegeGuard(),
        ToolCallGuard(),
        RestorationFilter(store),
        PostRestoreGuard(),
        OutputSanitizer(),
    ]


def _assert_raw_patterns_have_no_top_level_gap(obj: object, trail: str, seen: list[object]) -> None:
    if obj is None or isinstance(obj, (str, bytes, bytearray, int, float, bool, complex)):
        return
    if isinstance(obj, (types.ModuleType, types.FunctionType, types.MethodType, type)):
        return
    for previous in seen:
        if previous is obj:
            return
    seen.append(obj)
    if isinstance(obj, GapGuardedPattern):
        return
    if isinstance(obj, re.Pattern):
        guarded = compile_rule_regex(obj.pattern, obj.flags)
        assert not isinstance(guarded, GapGuardedPattern), (
            f"unwrapped gap pattern at {trail}: {obj.pattern!r}"
        )
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            label = f"{trail}:{key}" if isinstance(key, str) else f"{trail}[{key!r}]"
            _assert_raw_patterns_have_no_top_level_gap(value, label, seen)
        return
    if isinstance(obj, tuple) and len(obj) == 2 and isinstance(obj[0], str) and isinstance(
        obj[1], (re.Pattern, GapGuardedPattern)
    ):
        _assert_raw_patterns_have_no_top_level_gap(obj[1], f"{trail}:{obj[0]}", seen)
        return
    if isinstance(obj, (list, tuple, set, frozenset)):
        for index, value in enumerate(obj):
            _assert_raw_patterns_have_no_top_level_gap(value, f"{trail}[{index}]", seen)
        return
    attrs = getattr(obj, "__dict__", None)
    if not isinstance(attrs, dict):
        return
    for name, value in attrs.items():
        if name.startswith("__"):
            continue
        _assert_raw_patterns_have_no_top_level_gap(value, f"{trail}.{name}", seen)


def test_default_filters_do_not_keep_unwrapped_gap_patterns() -> None:
    for filt in _default_pipeline_filters():
        _assert_raw_patterns_have_no_top_level_gap(filt, type(filt).__name__, [])
