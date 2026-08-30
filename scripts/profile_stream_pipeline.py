#!/usr/bin/env python3
"""Answer where a long streamed answer actually spends its time.

The claim this exists to test: "the streaming path re-scans the whole window
every N chunks, so re-scanning dominates streaming cost." That was derived from
reading the code. Before paying for an incremental-scan redesign — which needs a
static overlap estimator, and underestimating that overlap by one character is a
silently missed cross-chunk detection — the claim gets measured.

Three questions, all answered from one cProfile run with no resident
instrumentation and therefore no observer effect:

  1. what share of the run is inside _run_stream_response_probe?
  2. inside a probe, how does the whole-text statistics work (AnomalyDetector's
     repetition ratio and run length) compare with the regex work?
  3. what does one probe cost in absolute milliseconds?

Question 2 is the one that decides the shape of any fix. The response pipeline
holds two kinds of judgement and they differ in whether they can be made
incremental at all:

  - stateless regex (injection detector, sanitizer, exfil chain) -- incremental
    is possible, with a delta plus an overlap;
  - whole-text statistics (AnomalyDetector._repetition_ratio / _max_run_length,
    the script-diversity check) -- not incremental by definition, since they are
    ratios and extrema over the entire text.

Read-only: it profiles scripts/bench_gateway.py's stream_long scenario and
prints a report. It changes no behaviour and writes no files unless asked.

    python scripts/profile_stream_pipeline.py
    python scripts/profile_stream_pipeline.py --save /tmp/stream.prof
    python scripts/profile_stream_pipeline.py --load /tmp/stream.prof
"""

from __future__ import annotations

import argparse
import cProfile
import pstats
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Function-name fragments, grouped by the question they answer, matched against
# pstats' "file:line(name)" key. A rename therefore shows up as a zero rather
# than as a wrong number silently folded into another bucket.
#
# Never include the line number from that key. It looked tempting for precision
# and it is the opposite: pstats records where a function is *defined*, so one
# added import above _run_phase moves the key and the bucket matches nothing —
# and a bucket that matches nothing reports 0.0%, which is a wrong answer that
# looks like a finished one. Match the file and the parenthesised name only.
#
# Buckets are scored on *self* time (tottime), not cumulative. The response
# pipeline runs on a worker thread (run_filter_pipeline_offloop), so the
# coroutine that starts a probe returns long before the work it triggered has
# finished: its cumulative time excludes almost everything it costs. Self time
# is additive across threads and does not have that problem.
_BUCKETS: dict[str, tuple[str, ...]] = {
    # The whole response pipeline, which is what a probe actually runs.
    "pipeline": ("core/pipeline.py:", "(_run_phase)"),
    # Stateless matching: incrementable in principle, with a delta + overlap.
    "regex": (
        "<method 'search' of 're.Pattern' objects>",
        "<method 'sub' of 're.Pattern' objects>",
        "<method 'findall' of 're.Pattern' objects>",
        "<method 'finditer' of 're.Pattern' objects>",
        "<method 'match' of 're.Pattern' objects>",
        "<method 'fullmatch' of 're.Pattern' objects>",
    ),
    # Whole-text judgements: not incrementable by definition. Ratios, extrema
    # and per-character scans over the entire window.
    "whole_text": (
        "_repetition_ratio",
        "_max_run_length",
        "_collect_points",
        "_detect_message_script_diversity",
        "_detect_script_mixing",
        "_is_typoglycemia_variant",
        "<method 'isalpha' of 'str' objects>",
    ),
}

_PROBE = "_run_stream_response_probe"


def _sum_bucket(stats: pstats.Stats, fragments: tuple[str, ...]) -> tuple[float, int]:
    """(self seconds, call count) over every profiled function matching a fragment."""
    seen: set[Any] = set()
    seconds = 0.0
    calls = 0
    for func, entry in stats.stats.items():  # type: ignore[attr-defined]
        label = f"{func[0]}:{func[1]}({func[2]})"
        if not any(fragment in label for fragment in fragments):
            continue
        if func in seen:
            continue
        seen.add(func)
        calls += entry[1]  # ncalls
        seconds += entry[2]  # tottime
    return seconds, calls


def report(stats: pstats.Stats) -> int:
    wall = stats.total_tt  # type: ignore[attr-defined]
    total_self = sum(entry[2] for entry in stats.stats.values())  # type: ignore[attr-defined]

    pipeline_cum = 0.0
    pipeline_runs = 0
    probe_frames = 0
    matched_pipeline = False
    for func, entry in stats.stats.items():  # type: ignore[attr-defined]
        label = f"{func[0]}:{func[1]}({func[2]})"
        if all(fragment in label for fragment in _BUCKETS["pipeline"]):
            pipeline_cum = entry[3]
            pipeline_runs = entry[1]
            matched_pipeline = True
        if _PROBE in label:
            probe_frames = entry[1]
    if not matched_pipeline:
        # Loud, because every number below Q1 is derived from this one and each
        # of them would otherwise print a plausible-looking zero.
        print(
            "ERROR: no profiled function matched "
            f"{_BUCKETS['pipeline']!r} — the response pipeline was either never "
            "entered or _run_phase has moved. Every figure below would be zero.",
            file=sys.stderr,
        )
        return 1
    # The probe is a coroutine, and cProfile counts a frame entry per
    # resumption, so its call count is roughly twice the number of probes. Cost
    # per probe is therefore divided by the pipeline-run count, which is one per
    # probe and not subject to that doubling.
    probes = pipeline_runs

    regex_s, regex_calls = _sum_bucket(stats, _BUCKETS["regex"])
    whole_s, whole_calls = _sum_bucket(stats, _BUCKETS["whole_text"])

    print(f"profiled wall time              {wall:9.3f} s")
    print(f"summed self time (all threads)  {total_self:9.3f} s")
    print(f"pipeline runs (~= probes)       {probes:9d}"
          f"   [probe coroutine frames: {probe_frames}, ~2 per probe]")
    print()
    print("Q1  how much of the run is the response pipeline the probe drives?")
    print(f"    pipeline._run_phase cumulative  {pipeline_cum:9.3f} s"
          f"   {100.0 * pipeline_cum / wall if wall else 0:5.1f}% of wall")
    print()
    print("Q2  inside it: stateless regex vs whole-text judgements")
    print(f"    regex        {regex_s:9.3f} s self"
          f"   {100.0 * regex_s / pipeline_cum if pipeline_cum else 0:5.1f}% of pipeline"
          f"   ({regex_calls} calls)")
    print(f"    whole-text   {whole_s:9.3f} s self"
          f"   {100.0 * whole_s / pipeline_cum if pipeline_cum else 0:5.1f}% of pipeline"
          f"   ({whole_calls} calls)")
    if whole_s:
        print(f"    regex : whole-text ratio  {regex_s / whole_s:9.2f}")
    print()
    print("Q3  absolute cost of one probe")
    if probes:
        print(f"    {1000.0 * pipeline_cum / probes:9.3f} ms per probe"
              f"  (mean, inflated by profiler overhead)")
    print()
    print("top 20 by self time — where a fix would have to land")
    stats.sort_stats("tottime").print_stats(20)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Profile the stream_long scenario.")
    parser.add_argument("--save", help="write the raw pstats file here as well")
    parser.add_argument("--load", help="report on an existing pstats file instead of profiling")
    args = parser.parse_args(argv)

    if args.load:
        return report(pstats.Stats(args.load))

    import bench_gateway  # noqa: PLC0415 - imported for its side-effect-free scenario

    profiler = cProfile.Profile()
    profiler.enable()
    try:
        bench_gateway.main(["--scenario", "stream_long"])
    finally:
        profiler.disable()
    if args.save:
        profiler.dump_stats(args.save)
    return report(pstats.Stats(profiler))


if __name__ == "__main__":
    raise SystemExit(main())
