"""Linear-time guard for rule regexes shaped like ``A.*B.*C``.

CPython's backtracking engine is polynomial on these shapes whenever the anchors
repeat without completing the chain (O(n^2) per gap level). This wrapper finds
the earliest chain with one bounded ``search`` per segment, then hands the
original regex only that window, so callers still receive a real ``re.Match``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

_FLAG_LETTERS = {"a": re.A, "i": re.I, "L": re.L, "m": re.M, "s": re.S, "u": re.U, "x": re.X}
_LEADING_FLAGS_RE = re.compile(r"^\(\?([aiLmsux]+)\)")
# Backreferences and lookarounds can tie segments together; leave those alone.
_UNSPLITTABLE_RE = re.compile(r"\\[1-9]|\(\?P=|\(\?<?[=!]")
_ANY_CLASSES = ("[\\s\\S]", "[\\S\\s]", "[\\d\\D]", "[\\w\\W]")
_LINE_CLASSES = ("[^\\n]", "[^\\r\\n]", "[^\\n\\r]")
# How far a segment match may run past the newline that ends its gap. Segments
# are keyword-shaped; whitespace-padding evasion is covered by the folded haystack.
_SEGMENT_SLACK = 256


@dataclass(frozen=True)
class _Gap:
    min_chars: int
    crosses_newline: bool


@dataclass(frozen=True)
class _Branch:
    segments: tuple[re.Pattern[str], ...]
    gaps: tuple[_Gap, ...]


def _read_gap(pattern: str, i: int, dotall: bool) -> tuple[_Gap, int] | None:
    """Recognise an unbounded gap token starting at ``pattern[i]``."""
    if pattern.startswith(".", i):
        body_end, crosses = i + 1, dotall
    else:
        for cls, cls_crosses in [(c, True) for c in _ANY_CLASSES] + [(c, False) for c in _LINE_CLASSES]:
            if pattern.startswith(cls, i):
                body_end, crosses = i + len(cls), cls_crosses
                break
        else:
            return None
    if body_end >= len(pattern) or pattern[body_end] not in "*+":
        return None
    min_chars = 1 if pattern[body_end] == "+" else 0
    end = body_end + 1
    if end < len(pattern) and pattern[end] == "?":
        end += 1
    return _Gap(min_chars, crosses), end


def _unwrap_outer_group(pattern: str) -> str:
    """``(A.*B|C.*D)`` -> ``A.*B|C.*D`` when one group spans the whole pattern."""
    while pattern.startswith("(") and pattern.endswith(")"):
        inner_start = 3 if pattern.startswith("(?:") else 1
        if pattern.startswith("(?") and inner_start == 1:
            return pattern  # named group / flags group: leave alone
        depth, i = 0, 0
        while i < len(pattern):
            ch = pattern[i]
            if ch == "\\":
                i += 2
                continue
            if ch == "[":
                j = i + 1
                if j < len(pattern) and pattern[j] == "^":
                    j += 1
                if j < len(pattern) and pattern[j] == "]":
                    j += 1
                while j < len(pattern) and pattern[j] != "]":
                    j += 2 if pattern[j] == "\\" else 1
                i = j + 1
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(pattern) - 1:
                    return pattern  # first group closes early: not an outer wrapper
            i += 1
        pattern = pattern[inner_start:-1]
    return pattern


def _split(pattern: str, dotall: bool) -> list[tuple[list[str], list[_Gap]]] | None:
    pattern = _unwrap_outer_group(pattern)
    branches: list[tuple[list[str], list[_Gap]]] = []
    segments: list[str] = []
    gaps: list[_Gap] = []
    buf: list[str] = []
    depth, i, n = 0, 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            buf.append(pattern[i : i + 2])
            i += 2
            continue
        if depth == 0:
            gap = _read_gap(pattern, i, dotall)
            if gap is not None:
                segments.append("".join(buf))
                buf = []
                gaps.append(gap[0])
                i = gap[1]
                continue
        if ch == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            buf.append(pattern[i : j + 1])
            i = j + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return None
        elif ch == "|" and depth == 0:
            segments.append("".join(buf))
            branches.append((segments, gaps))
            segments, gaps, buf = [], [], []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if depth != 0:
        return None
    segments.append("".join(buf))
    branches.append((segments, gaps))
    return branches


class GapGuardedPattern:
    """``re.Pattern``-compatible subset (search/finditer/sub/subn) with linear search.

    Match *start* equals the original regex's leftmost match. Match *end* is the
    earliest point the chain completes, not the greedy furthest one — callers
    that rewrite a span replace ``A..C`` instead of ``A..<last C in the text>``.
    """

    def __init__(self, compiled: re.Pattern[str], branches: tuple[_Branch, ...]) -> None:
        self._compiled = compiled
        self._branches = branches
        self.pattern = compiled.pattern
        self.flags = compiled.flags

    def _branch_window(self, branch: _Branch, text: str, pos: int, endpos: int) -> tuple[int, int] | None:
        head = branch.segments[0]
        first_gap = branch.gaps[0] if branch.gaps else None
        # A later head whose match ends no earlier than a failed head's, and is
        # still cut off by the same newline, has strictly less room: skip it
        # without re-running the chain. This is what keeps the loop linear.
        dominated_from, dominated_to = -1, -1
        while pos <= endpos:
            first = head.search(text, pos, endpos)
            if first is None:
                return None
            if dominated_from <= first.end() <= dominated_to:
                pos = first.start() + 1
                continue
            cur, ok = first.end(), True
            for gap, seg in zip(branch.gaps, branch.segments[1:]):
                limit, newline = endpos, -1
                if not gap.crosses_newline:
                    newline = text.find("\n", cur, endpos)
                    if newline != -1:
                        # The gap may not contain a newline, but the next segment
                        # may itself span one (``api\s*key``): bound its start,
                        # and give its body a little room past the line end.
                        limit = min(endpos, newline + _SEGMENT_SLACK)
                lo = cur + gap.min_chars
                found = seg.search(text, lo, limit) if lo <= limit else None
                if found is not None and newline != -1 and found.start() > newline:
                    found = None
                if found is None:
                    ok = False
                    break
                cur = found.end()
            if ok:
                return first.start(), cur
            dominated_from = first.end()
            if first_gap is None or first_gap.crosses_newline:
                dominated_to = endpos
            else:
                newline = text.find("\n", first.end(), endpos)
                dominated_to = endpos if newline == -1 else newline
            pos = first.start() + 1
        return None

    def _search(
        self, text: str, pos: int, end: int, cache: list[tuple[int, int] | None | bool]
    ) -> re.Match[str] | None:
        # cache[i]: False = not computed; None = branch has no window at or after
        # an earlier pos (so none later either); (s, e) = earliest window found.
        best: tuple[int, int] | None = None
        for index, branch in enumerate(self._branches):
            cached = cache[index]
            if cached is None:
                continue
            # ``True`` is not stored. ``isinstance`` drops it so ``<`` is a pair of windows.
            if cached is False or (isinstance(cached, tuple) and cached[0] < pos):
                cached = self._branch_window(branch, text, pos, end)
                cache[index] = cached
            if isinstance(cached, tuple) and (best is None or cached < best):
                best = cached
        if best is None:
            return None
        return self._compiled.search(text, best[0], best[1])

    def match(self, text: str, pos: int = 0, endpos: int | None = None) -> re.Match[str] | None:
        """Anchored match on the original regex.

        Param rules call ``match`` for a full-value check. That stays the
        unwrapped engine: the linear window is for ``search`` / ``finditer`` /
        ``sub``, and a gapped rule used here must not raise ``AttributeError``.
        """
        end = len(text) if endpos is None else endpos
        return self._compiled.match(text, pos, end)

    def search(self, text: str, pos: int = 0, endpos: int | None = None) -> re.Match[str] | None:
        end = len(text) if endpos is None else min(endpos, len(text))
        return self._search(text, pos, end, [False] * len(self._branches))

    def finditer(self, text: str, pos: int = 0, endpos: int | None = None) -> Iterator[re.Match[str]]:
        end = len(text) if endpos is None else min(endpos, len(text))
        cache: list[tuple[int, int] | None | bool] = [False] * len(self._branches)
        while pos <= end:
            match = self._search(text, pos, end, cache)
            if match is None:
                return
            yield match
            pos = match.end() if match.end() > match.start() else match.end() + 1

    def subn(self, repl: str | Callable[[re.Match[str]], str], text: str, count: int = 0) -> tuple[str, int]:
        out: list[str] = []
        last = done = 0
        for match in self.finditer(text):
            if count and done >= count:
                break
            out.append(text[last : match.start()])
            out.append(repl(match) if callable(repl) else match.expand(repl))
            last = match.end()
            done += 1
        out.append(text[last:])
        return "".join(out), done

    def sub(self, repl: str | Callable[[re.Match[str]], str], text: str, count: int = 0) -> str:
        return self.subn(repl, text, count)[0]


# Container type for a rule regex. Patterns with no top-level unbounded gap stay
# a real ``re.Pattern``; the others are the linear wrapper above.
RulePattern = re.Pattern[str] | GapGuardedPattern


def compile_rule_regex(regex: str, flags: int = 0) -> re.Pattern[str] | GapGuardedPattern:
    """Compile a rule regex; wrap it when it has top-level unbounded gaps."""
    compiled = re.compile(regex, flags)
    if _UNSPLITTABLE_RE.search(regex):
        return compiled
    body, seg_flags = regex, flags
    leading = _LEADING_FLAGS_RE.match(regex)
    if leading:
        body = regex[leading.end() :]
        for letter in leading.group(1):
            seg_flags |= _FLAG_LETTERS[letter]
    split = _split(body, dotall=bool(seg_flags & re.S))
    if split is None or not any(gaps for _, gaps in split):
        return compiled
    try:
        branches = tuple(
            _Branch(tuple(re.compile(s, seg_flags) for s in segs), tuple(gaps)) for segs, gaps in split
        )
    except re.error:
        return compiled
    return GapGuardedPattern(compiled, branches)
