#!/usr/bin/env python3
"""Report how many shipped rules a linear-time regex engine could compile.

ROADMAP R3.3 lists "linear-time regex engine" as an option. Its feasibility
hinges on one number nobody had measured: how many of the rules in
security_filters.yaml use a construct RE2 does not support. RE2 has no
lookaround and no backreferences, and this repo uses both — ``(?<!\\d)`` guards
CN_MOBILE and CN_ID, and the exfil-chain rules use ``(?=...)`` prefilters.

That matters more than a performance number, because of how such a migration
usually lands: **if an incompatible pattern is handled by skipping the rule,
a performance change silently turns off CN mobile redaction.** This script
exists so that decision is made against the real proportion rather than a guess.

Read-only. It compiles nothing, changes nothing, writes no files, and reports
to stdout.

    python scripts/regex_engine_survey.py
    python scripts/regex_engine_survey.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Constructs RE2 rejects. Each is (label, detector).
#
# Detected by pattern text rather than by asking RE2, because google-re2 is not
# a dependency of this repo and the point of the survey is to decide whether it
# should ever become one. The text checks are deliberately conservative: they
# describe the syntax RE2 documents as unsupported.
#
# Conservative here means the incompatible count is an **upper bound**, not an
# exact figure: `[*+?}]\+` also fires on a quantifier followed by an escaped
# literal plus, and `\\[1-9]` cannot tell a backreference from an escape that
# happens to start with a digit. Over-reporting is the safe direction for the
# decision this feeds — it can only make a migration look harder than it is —
# but the headline percentage should be read as "at least this compatible".
_UNSUPPORTED = (
    ("lookbehind", re.compile(r"\(\?<[=!]")),
    ("lookahead", re.compile(r"\(\?[=!]")),
    ("backreference", re.compile(r"\\[1-9]")),
    ("atomic_group", re.compile(r"\(\?>")),
    ("conditional", re.compile(r"\(\?\(")),
    ("possessive_quantifier", re.compile(r"[*+?}]\+")),
    ("recursion", re.compile(r"\(\?R\)|\(\?&")),
)


def _iter_rules(node: Any, path: str = "") -> Any:
    """Yield (section_path, rule_id, regex) for every regex-bearing entry."""
    if isinstance(node, dict):
        regex = node.get("regex")
        if isinstance(regex, str):
            yield path, str(node.get("id") or "?"), regex
        for key, value in node.items():
            if key == "regex":
                continue
            yield from _iter_rules(value, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for item in node:
            yield from _iter_rules(item, path)
    elif isinstance(node, str) and path.endswith(("patterns", "regexes")):
        # The legacy bare-string rule form.
        yield path, "?", node


def survey() -> dict[str, Any]:
    from aegisgate.config.security_rules import load_security_rules

    rules = load_security_rules()
    total = 0
    incompatible: list[dict[str, str]] = []
    reasons: Counter[str] = Counter()
    by_section: Counter[str] = Counter()

    for section, rule_id, regex in _iter_rules(rules):
        total += 1
        hits = [label for label, detector in _UNSUPPORTED if detector.search(regex)]
        if hits:
            reasons.update(hits)
            by_section[section] += 1
            incompatible.append(
                {
                    "section": section,
                    "id": rule_id,
                    "reasons": ",".join(hits),
                    "regex": regex if len(regex) <= 120 else regex[:117] + "...",
                }
            )

    return {
        "total_rules": total,
        "incompatible": len(incompatible),
        "compatible": total - len(incompatible),
        "compatible_pct": round(100.0 * (total - len(incompatible)) / total, 1) if total else 0.0,
        "reasons": dict(reasons.most_common()),
        "by_section": dict(by_section.most_common()),
        "details": incompatible,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    report = survey()
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    print(
        f"{report['compatible']}/{report['total_rules']} rules "
        f"({report['compatible_pct']}%) use only RE2-supported syntax"
    )
    print(f"{report['incompatible']} would fail to compile, by construct:")
    for reason, count in report["reasons"].items():
        print(f"  {reason:24s} {count}")
    print("\nby rule group:")
    for section, count in report["by_section"].items():
        print(f"  {section:48s} {count}")
    print("\nincompatible rules:")
    for item in report["details"]:
        print(f"  [{item['reasons']}] {item['section']} :: {item['id']}")
    print(
        "\nNOTE: a migration that 'skips rules it cannot compile' would turn "
        "these off. Read this list as the set of detections at risk, not as a "
        "porting checklist."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
