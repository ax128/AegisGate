#!/usr/bin/env python3
"""Replay captured dangerous-response samples against the current rule file.

Answers the one question you have before turning a new rule on: *on traffic this
deployment actually saw, what would it have hit?* Rules are cheap to write and
expensive to be wrong about, and the only honest calibration input is recorded
traffic rather than invented examples.

**Why not the audit log.** ``logs/audit.jsonl`` carries request_id / route / risk /
tags / reasons / enforcement_actions / report and **no request or response body**,
so there is nothing in it for a regex to match. The corpus is
``logs/dangerous_response_samples.jsonl``, written by
``core/dangerous_response_log``, which is off by default
(``AEGIS_ENABLE_DANGEROUS_RESPONSE_LOG``) precisely because it does hold text.

That switch is also why a run can come back with nothing to replay: samples are
only written when a response already tripped the sanitizer, and only while the
log is enabled.

**Two switches, not one.** ``content``/``dangerous_fragments`` are reduced to a
sha256 + length unless ``AEGIS_DANGEROUS_RESPONSE_LOG_INCLUDE_RAW`` is also on,
which is what actually makes a corpus replayable. That default is deliberate —
turning the sample log on must not by itself begin persisting credential paths
and URLs with keys in them — so calibration is an explicit, bounded window you
open and close, not a side effect. A corpus that is all digests replays as zero
matchable text, which this reports rather than silently scoring 0%.

Usage:
    python scripts/replay_calibrate.py
    python scripts/replay_calibrate.py --samples logs/dangerous_response_samples.jsonl
    python scripts/replay_calibrate.py --prefix exfil_        # only the new family
    python scripts/replay_calibrate.py --json                 # machine-readable

Reads only. Nothing is written, and no sample text is printed — the report is
counts and rule ids, so it can be pasted into a review without leaking the corpus.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from aegisgate.config.security_rules import load_security_rules  # noqa: E402
from aegisgate.config.settings import settings  # noqa: E402

# The groups that decide an exfiltration disposition. Ordered the way the pipeline
# reaches them, so the report reads in execution order.
REPLAY_GROUPS = (
    "tool_call_guard.dangerous_param_patterns",
    "sanitizer.command_patterns",
    "sanitizer.force_block_command_patterns",
    "anomaly_detector.command_patterns",
    "privilege_guard.blocked_patterns",
)


def _group(rules: dict[str, Any], dotted: str) -> list[dict[str, Any]]:
    node: Any = rules
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return []
        node = node.get(part)
    return node if isinstance(node, list) else []


def compile_rules(prefix: str = "") -> list[tuple[str, str, re.Pattern[str]]]:
    """(group, rule_id, pattern) for every replayable rule, filtered by *prefix*."""
    rules = load_security_rules()
    compiled: list[tuple[str, str, re.Pattern[str]]] = []
    for dotted in REPLAY_GROUPS:
        for item in _group(rules, dotted):
            if not isinstance(item, dict):
                continue
            regex = item.get("regex")
            rule_id = str(item.get("id", ""))
            if not regex or not rule_id.startswith(prefix):
                continue
            try:
                compiled.append((dotted, rule_id, re.compile(str(regex), re.IGNORECASE)))
            except re.error as exc:
                print(f"  ! skipped {dotted}/{rule_id}: uncompilable ({exc})", file=sys.stderr)
    return compiled


def iter_samples(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                print(f"  ! {path.name}:{line_no} is not JSON, skipped", file=sys.stderr)
                continue
            if isinstance(payload, dict):
                yield payload


def sample_text(sample: dict[str, Any]) -> str:
    """The matchable text in a sample, or ``""`` when it was captured redacted."""
    parts: list[str] = []
    content = sample.get("content")
    if isinstance(content, str):
        parts.append(content)
    fragments = sample.get("dangerous_fragments")
    if isinstance(fragments, list):
        parts.extend(str(item) for item in fragments if item)
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", default="", help="sample log path (default: the configured one)")
    parser.add_argument("--prefix", default="", help="only replay rule ids with this prefix")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = parser.parse_args()

    path = Path(args.samples or settings.dangerous_response_log_path)
    if not path.is_file():
        print(
            f"no sample log at {path}. It is written only while "
            f"AEGIS_ENABLE_DANGEROUS_RESPONSE_LOG=true (currently "
            f"{str(settings.enable_dangerous_response_log).lower()}), and only for responses "
            f"the sanitizer already flagged. Replayable text additionally needs "
            f"AEGIS_DANGEROUS_RESPONSE_LOG_INCLUDE_RAW=true (currently "
            f"{str(settings.dangerous_response_log_include_raw).lower()}); without it every "
            f"sample is a digest.",
            file=sys.stderr,
        )
        return 2

    compiled = compile_rules(args.prefix)
    if not compiled:
        print(f"no rules to replay (prefix={args.prefix!r})", file=sys.stderr)
        return 2

    hits: Counter[str] = Counter()
    total = 0
    replayable = 0
    matched_samples = 0
    for sample in iter_samples(path):
        total += 1
        text = sample_text(sample)
        if not text:
            continue
        replayable += 1
        fired = {rule_id for _group_name, rule_id, pattern in compiled if pattern.search(text)}
        if fired:
            matched_samples += 1
        hits.update(fired)

    summary = {
        "samples_path": str(path),
        "samples_total": total,
        "samples_replayable": replayable,
        "samples_redacted": total - replayable,
        "samples_matched": matched_samples,
        # By id, not by (group, id): the same rule is deliberately listed in more
        # than one group, and counting it twice would overstate the corpus.
        "rules_replayed": len({rule_id for _g, rule_id, _p in compiled}),
        "hits_by_rule": dict(hits.most_common()),
        "rules_never_hit": sorted(
            {rule_id for _g, rule_id, _p in compiled} - set(hits)
        ),
    }

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    print(f"corpus   {path}")
    print(f"samples  {total} total, {replayable} with matchable text, {total - replayable} redacted to a digest")
    if total and not replayable:
        print(
            "         (every sample is a digest — set "
            "AEGIS_DANGEROUS_RESPONSE_LOG_INCLUDE_RAW=true for a calibration window, "
            f"currently {str(settings.dangerous_response_log_include_raw).lower()})"
        )
    print(f"rules    {summary['rules_replayed']} replayed" + (f" (prefix {args.prefix!r})" if args.prefix else ""))
    print(f"matched  {matched_samples} of {replayable} replayable samples")
    print()
    if hits:
        width = max(len(rule_id) for rule_id in hits)
        print("hits by rule")
        for rule_id, count in hits.most_common():
            share = f"{count / replayable:.0%}" if replayable else "-"
            print(f"  {rule_id:<{width}}  {count:>5}  {share:>5}")
    else:
        print("hits by rule: none")
    never = summary["rules_never_hit"]
    if never:
        print()
        print(f"never hit ({len(never)}): {', '.join(never)}")
        print("  A rule that never fires on real traffic is either well-targeted or dead;")
        print("  this corpus cannot tell you which. It only rules out the noisy case.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
