"""CI static ReDoS guards for every compiled security regex.

Runtime loading must not time patterns (that would jitter the request path).
These tests walk YAML + code defaults + v2_proxy hardcoded patterns instead.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
import yaml

from aegisgate.adapters.v2_proxy.router import _DEFAULT_DANGEROUS_COMMAND_PATTERNS
from aegisgate.config.security_rules import _DEFAULT_RULES
from aegisgate.init_config import migrate_http_smuggling_regex

_REPO_ROOT = Path(__file__).resolve().parents[2]
_YAML_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"
_SEARCH_SUFFIXES = {".py", ".yaml", ".yml"}
_SKIP_DIR_NAMES = {
    ".git",
    ".worktrees",
    "__pycache__",
    ".pytest_cache",
    "htmlcov",
    "node_modules",
    ".venv",
    "venv",
}
_BUDGET_SECONDS = 0.1
# Hundreds of chars is enough to catch exponential backtracking (the old te_te
# shape already blew up at ~160 bytes). Keep this modest so linear PII patterns
# such as EMAIL stay under the 100ms CI budget on CPython.
_LARGE_INPUT = ("a" * 768) + (", " * 64) + ("\r\n" * 24)
_OLD_TE_TE_NEEDLE = "(?:" + r"[^\r\n,]+,\s*" + ")+"
_N24_TE_TE = "Transfer-Encoding: " + ("gzip, " * 24) + "identity"
_N24_CL_TE = "Content-Length: 13" + (" \t\r\n" * 24) + "Host: example"
_N24_TE_CL = "Transfer-Encoding: chunked" + (" \t\r\n" * 24) + "Host: example"

_CL_TE_SAMPLES = (
    "Content-Length: 13 \r\nTransfer-Encoding: chunked",
    "Content-Length: 13\r\n Transfer-Encoding: chunked",
    "Content-Length: 13" + ("\r\n" * 5) + "Transfer-Encoding: chunked",
    "Content-Length: 13\\r\\nTransfer-Encoding: chunked",
)
_TE_CL_SAMPLES = (
    "Transfer-Encoding: chunked \r\nContent-Length: 13",
    "Transfer-Encoding: chunked\r\n Content-Length: 13",
    "Transfer-Encoding: chunked" + ("\r\n" * 5) + "Content-Length: 13",
    "Transfer-Encoding: chunked\\r\\nContent-Length: 13",
)
_TE_TE_SAMPLES = (
    "Transfer-Encoding: gzip, chunked",
    "Transfer-Encoding: gzip,chunked",
    "Transfer-Encoding: gzip, deflate, chunked",
)


def _walk_regexes(obj: object, path: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        regex = obj.get("regex")
        if isinstance(regex, str) and regex:
            ident = str(obj.get("id") or path or "anonymous")
            found.append((ident, regex))
        for key, value in obj.items():
            if key == "regex":
                continue
            found.extend(_walk_regexes(value, f"{path}.{key}" if path else str(key)))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            found.extend(_walk_regexes(value, f"{path}[{index}]"))
    elif isinstance(obj, str) and path.endswith("discussion_context_patterns"):
        found.append((path, obj))
    return found


def _yaml_rules() -> dict:
    loaded = yaml.safe_load(_YAML_RULES.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _all_named_regexes() -> list[tuple[str, str]]:
    collected: list[tuple[str, str]] = []
    collected.extend((f"yaml:{ident}", regex) for ident, regex in _walk_regexes(_yaml_rules()))
    collected.extend(
        (f"code_default:{ident}", regex) for ident, regex in _walk_regexes(_DEFAULT_RULES)
    )
    collected.extend(
        (f"v2_proxy:{ident}", regex) for ident, regex in _DEFAULT_DANGEROUS_COMMAND_PATTERNS
    )
    # Keep order stable and drop exact duplicates of the same source+pattern.
    unique: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in collected:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _smuggling_regexes() -> list[tuple[str, str]]:
    wanted = ("http_smuggling_cl_te", "http_smuggling_te_cl", "http_smuggling_te_te")
    wanted_web = (
        "web_http_smuggling_cl_te",
        "web_http_smuggling_te_cl",
        "web_http_smuggling_te_te",
    )
    found: list[tuple[str, str]] = []
    yaml_rules = _yaml_rules()
    sections = (
        ("yaml.anomaly", yaml_rules.get("anomaly_detector", {}).get("command_patterns")),
        ("yaml.sanitizer", yaml_rules.get("sanitizer", {}).get("command_patterns")),
        (
            "yaml.force_block",
            yaml_rules.get("sanitizer", {}).get("force_block_command_patterns"),
        ),
        (
            "code.anomaly",
            _DEFAULT_RULES.get("anomaly_detector", {}).get("command_patterns"),
        ),
        ("code.sanitizer", _DEFAULT_RULES.get("sanitizer", {}).get("command_patterns")),
        (
            "code.force_block",
            _DEFAULT_RULES.get("sanitizer", {}).get("force_block_command_patterns"),
        ),
    )
    for label, items in sections:
        assert isinstance(items, list), label
        by_id = {
            str(item.get("id")): str(item.get("regex"))
            for item in items
            if isinstance(item, dict) and item.get("id") and item.get("regex")
        }
        ids = wanted if label.endswith("anomaly") else wanted_web
        for pattern_id in ids:
            assert pattern_id in by_id, f"{label} missing {pattern_id}"
            found.append((f"{label}:{pattern_id}", by_id[pattern_id]))
    for pattern_id, regex in _DEFAULT_DANGEROUS_COMMAND_PATTERNS[:3]:
        found.append((f"v2_proxy:{pattern_id}", regex))
    assert len(found) == 21, found  # 6 YAML/code sections * 3 + 3 v2_proxy
    return found


def _assert_search_budget(pattern: str, text: str) -> None:
    compiled = re.compile(pattern)
    started = time.perf_counter()
    compiled.search(text)
    elapsed = time.perf_counter() - started
    assert elapsed < _BUDGET_SECONDS, f"regex exceeded {_BUDGET_SECONDS}s ({elapsed:.3f}s): {pattern}"


@pytest.mark.parametrize("label,pattern", _all_named_regexes())
def test_every_security_regex_returns_within_budget(label: str, pattern: str) -> None:
    del label
    _assert_search_budget(pattern, _LARGE_INPUT)


@pytest.mark.parametrize("label,pattern", _smuggling_regexes())
def test_smuggling_regexes_are_linear_on_n24_amplification(label: str, pattern: str) -> None:
    payload = _N24_TE_TE
    if "cl_te" in label:
        payload = _N24_CL_TE
    elif "te_cl" in label:
        payload = _N24_TE_CL
    _assert_search_budget(pattern, payload)


@pytest.mark.parametrize("label,pattern", _smuggling_regexes())
def test_smuggling_regexes_still_match_obfuscated_payloads(label: str, pattern: str) -> None:
    compiled = re.compile(pattern)
    if "cl_te" in label:
        samples = _CL_TE_SAMPLES
    elif "te_cl" in label:
        samples = _TE_CL_SAMPLES
    else:
        samples = _TE_TE_SAMPLES
    for sample in samples:
        assert compiled.search(sample), f"{label} missed {sample!r}"


def _walk_source_files(root: Path):
    """Yield files under *root*, pruning skipped directories as we descend.

    ``rglob("*")`` would stat every entry inside .git and .worktrees before the
    per-path skip check discards them. On a checkout with git worktrees that is
    ~4900 stats for the same 121 files, which runs into pytest's 30s per-test
    timeout; pruning keeps it under a second.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _SKIP_DIR_NAMES:
                    stack.append(entry)
            else:
                yield entry


def test_repo_has_no_quantifier_ambiguous_te_te_shape() -> None:
    offenders: list[str] = []
    for path in _walk_source_files(_REPO_ROOT):
        if path.suffix not in _SEARCH_SUFFIXES:
            continue
        if path.name == "test_redos_guard.py":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _OLD_TE_TE_NEEDLE in text:
            offenders.append(str(path.relative_to(_REPO_ROOT)))
    assert offenders == []


def test_migrate_http_smuggling_regex_updates_ids_and_keeps_custom_rules(
    tmp_path: Path,
) -> None:
    old_te_te = r"(?is)\btransfer-encoding\s*:\s*(?:[^\r\n,]+,\s*)+chunked\b"
    old_cl_te = (
        r"(?is)\bcontent-length\s*:\s*\d+\s*(?:\\r\\n|\r\n|\n)+\s*"
        r"transfer-encoding\s*:\s*chunked\b"
    )
    runtime = {
        "version": 2,
        "anomaly_detector": {
            "command_patterns": [
                {"id": "http_smuggling_cl_te", "regex": old_cl_te},
                {"id": "http_smuggling_te_te", "regex": old_te_te},
                {"id": "custom_anomaly", "regex": "user-custom-anomaly"},
            ]
        },
        "sanitizer": {
            "command_patterns": [
                {"id": "web_http_smuggling_te_te", "regex": old_te_te},
                {"id": "custom_sanitizer", "regex": "keep-sanitizer"},
            ],
            "force_block_command_patterns": [
                {"id": "web_http_smuggling_te_te", "regex": old_te_te},
                {"id": "custom_force_block", "regex": "keep-force-block"},
            ],
        },
    }
    dest = tmp_path / "security_filters.yaml"
    dest.write_text(yaml.dump(runtime, sort_keys=False), encoding="utf-8")

    changed = migrate_http_smuggling_regex(tmp_path)
    assert changed
    assert any(item.endswith("web_http_smuggling_te_te") for item in changed)
    updated = yaml.safe_load(dest.read_text(encoding="utf-8"))
    package = _yaml_rules()
    package_te_te = next(
        item["regex"]
        for item in package["sanitizer"]["command_patterns"]
        if item["id"] == "web_http_smuggling_te_te"
    )
    package_cl_te = next(
        item["regex"]
        for item in package["anomaly_detector"]["command_patterns"]
        if item["id"] == "http_smuggling_cl_te"
    )
    assert updated["sanitizer"]["command_patterns"][0]["regex"] == package_te_te
    assert updated["sanitizer"]["force_block_command_patterns"][0]["regex"] == package_te_te
    assert updated["anomaly_detector"]["command_patterns"][0]["regex"] == package_cl_te
    assert updated["anomaly_detector"]["command_patterns"][2]["regex"] == "user-custom-anomaly"
    assert updated["sanitizer"]["command_patterns"][1]["regex"] == "keep-sanitizer"
    assert updated["sanitizer"]["force_block_command_patterns"][1]["regex"] == "keep-force-block"
    backups = list(tmp_path.glob("security_filters.yaml.bak-*"))
    assert len(backups) == 1


def test_migrate_skips_package_rules_file() -> None:
    package_dir = _REPO_ROOT / "aegisgate" / "policies" / "rules"
    assert migrate_http_smuggling_regex(package_dir) == []
