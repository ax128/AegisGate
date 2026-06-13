"""Doc-code alignment regression guards.

These tests pin a handful of facts that the user-facing docs rely on, so that
documentation drift (filter count, compat model whitelist, default action_map
disposition) is caught by CI instead of by a manual audit.

If one of these fails, either the code changed on purpose — in which case update
the cited docs and the expected value here — or a doc/code mismatch slipped in.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

import yaml

import aegisgate.filters
from aegisgate.adapters.openai_compat.mapper import COMPAT_ALLOWED_MODELS
from aegisgate.filters.base import BaseFilter

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"

# Number of concrete BaseFilter subclasses. README pipeline section and
# docs/prompts/audit_general.md both cite this count — update all three together.
_EXPECTED_FILTER_CLASS_COUNT = 13


def _import_all_filter_modules() -> None:
    for mod in pkgutil.iter_modules(aegisgate.filters.__path__):
        importlib.import_module(f"aegisgate.filters.{mod.name}")


def test_filter_class_count_matches_docs() -> None:
    _import_all_filter_modules()
    concrete = {cls.__name__ for cls in BaseFilter.__subclasses__()}
    assert len(concrete) == _EXPECTED_FILTER_CLASS_COUNT, (
        f"BaseFilter concrete subclasses are now {len(concrete)} "
        f"({sorted(concrete)}); update _EXPECTED_FILTER_CLASS_COUNT and the "
        f"filter-count claims in README.md / README_zh.md / "
        f"docs/prompts/audit_general.md."
    )


def test_compat_allowed_models_documented() -> None:
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    readme_zh = (_REPO_ROOT / "README_zh.md").read_text(encoding="utf-8")
    for model in COMPAT_ALLOWED_MODELS:
        assert model in readme, f"{model} missing from README.md allowed-models list"
        assert model in readme_zh, (
            f"{model} missing from README_zh.md allowed-models list"
        )


def test_tool_call_injection_default_action_is_review() -> None:
    rules = yaml.safe_load(_RULES.read_text(encoding="utf-8"))
    injection = rules.get("action_map", {}).get("injection_detector", {})
    assert injection.get("tool_call_injection") == "review", (
        "action_map.injection_detector.tool_call_injection changed; docs that "
        "describe its disposition (README_zh §5.2) must be updated to match — "
        "it is NOT an unconditional force-block by default."
    )
