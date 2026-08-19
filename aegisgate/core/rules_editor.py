"""Comment-preserving edits to ``security_filters.yaml``.

Saving a rule from the console used to run ``yaml.safe_load`` → ``yaml.dump``.
PyYAML drops every comment and re-flows indentation and quoting, so editing one
regex rewrote the whole file: 80 comment lines gone, ~1250 lines of diff churn.
Those comments are the security policy's documentation ("pattern ids that stay
active on the low-false-positive surfaces", the ReDoS notes on individual
patterns) and losing them silently is real information loss.

So a rule edit is applied as a **line-level patch** to the original text: only
the lines belonging to the affected rule change, everything else stays byte for
byte. Text surgery on YAML is fragile, so the result is never trusted blindly —
it is re-parsed and compared against the structure the caller intended. Only an
exact match is written; anything else falls back to the old dump path, loudly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

from aegisgate.util.logger import logger

_KEY_RE = re.compile(r"^(\s*)([^\s#\-][^:]*):\s*(.*?)\s*$")
_ITEM_RE = re.compile(r"^(\s*)-\s")
# `id: FOO` whether it sits on the dash line or a continuation line.
_ID_RE = re.compile(r"(?:^|\s)id:\s*(.+?)\s*$")


@dataclass
class RuleEdit:
    """One console edit, described well enough to patch the text directly."""

    path: list[str]
    op: str  # "add" | "update" | "delete"
    rule_id: str
    fields: dict[str, Any] | None = None


def _is_skippable(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _block_end(lines: list[str], start: int, parent_indent: int) -> int:
    """First index at or after *start* that dedents out of the parent block."""
    for index in range(start, len(lines)):
        if _is_skippable(lines[index]):
            continue
        if _indent_of(lines[index]) <= parent_indent:
            return index
    return len(lines)


def _find_key(lines: list[str], start: int, end: int, key: str) -> tuple[int, int] | None:
    """Locate ``key:`` in [start, end), returning ``(line_index, indent)``.

    Only the shallowest indentation level inside the range is searched, so a key
    nested deeper cannot be mistaken for a sibling.
    """
    level: int | None = None
    for index in range(start, end):
        line = lines[index]
        if _is_skippable(line):
            continue
        indent = _indent_of(line)
        if level is None:
            level = indent
        if indent != level:
            continue
        match = _KEY_RE.match(line)
        if match and match.group(2).strip() == key:
            return index, indent
    return None


def _locate_list(lines: list[str], path: list[str]) -> tuple[int, int, int] | None:
    """Resolve *path* to its list block: ``(first_item, end, item_indent)``."""
    start, end, parent_indent = 0, len(lines), -1
    key_index = -1
    for key in path:
        found = _find_key(lines, start, end, key)
        if found is None:
            return None
        key_index, key_indent = found
        if _KEY_RE.match(lines[key_index]).group(3):  # type: ignore[union-attr]
            return None  # key has an inline value, so it is not a block list
        start = key_index + 1
        end = _block_end(lines, start, key_indent)
        parent_indent = key_indent

    for index in range(start, end):
        if _is_skippable(lines[index]):
            continue
        match = _ITEM_RE.match(lines[index])
        if not match:
            return None  # first payload line is not a list item
        return index, end, len(match.group(1))
    # An empty list block: items would go directly under the key.
    return start, end, parent_indent + 2


def _entry_ranges(lines: list[str], start: int, end: int, item_indent: int) -> list[tuple[int, int]]:
    """Line ranges of each list entry, trailing comments included in the entry."""
    starts = [
        index
        for index in range(start, end)
        if not _is_skippable(lines[index])
        and _ITEM_RE.match(lines[index])
        and _indent_of(lines[index]) == item_indent
    ]
    ranges: list[tuple[int, int]] = []
    for position, first in enumerate(starts):
        last = starts[position + 1] if position + 1 < len(starts) else end
        ranges.append((first, last))
    return ranges


def _entry_id(lines: list[str], first: int, last: int) -> str | None:
    for index in range(first, last):
        if _is_skippable(lines[index]):
            continue
        match = _ID_RE.search(lines[index])
        if match:
            return match.group(1).strip().strip("'\"")
    return None


# Fields whose values are always single-quoted, matching the file's convention
# and keeping a pattern that opens with a YAML indicator (`*`, `>`, `%`…) safe.
_ALWAYS_QUOTED_FIELDS = frozenset({"regex"})


def _emit_scalar(value: Any, *, quoted: bool = False) -> str | None:
    """Render *value* as a single-line YAML scalar, or ``None`` if it needs a block."""
    dumped = yaml.safe_dump(
        value,
        allow_unicode=True,
        default_flow_style=True,
        width=10**9,
        default_style="'" if (quoted and isinstance(value, str)) else None,
    )
    # safe_dump of a bare scalar appends a "..." document-end marker.
    parts = [line for line in dumped.splitlines() if line.strip() and line.strip() != "..."]
    if len(parts) != 1:
        return None
    return parts[0].strip()


def _continuation_indent(lines: list[str], first: int, last: int, item_indent: int) -> int:
    for index in range(first + 1, last):
        if not _is_skippable(lines[index]):
            return _indent_of(lines[index])
    return item_indent + 2


def _set_field(
    lines: list[str], first: int, last: int, item_indent: int, key: str, value: Any
) -> bool:
    """Set ``key`` inside one entry, in place. False if the shape is unsupported."""
    rendered = _emit_scalar(value, quoted=key in _ALWAYS_QUOTED_FIELDS)
    if rendered is None:
        return False
    pattern = re.compile(rf"^(\s*(?:-\s+)?){re.escape(key)}:\s*(.*)$")
    for index in range(first, last):
        if _is_skippable(lines[index]):
            continue
        match = pattern.match(lines[index])
        if not match:
            continue
        existing = match.group(2).strip()
        # A block scalar (| or >) spans lines we are not going to rewrite safely.
        if existing.startswith("|") or existing.startswith(">") or not existing:
            return False
        lines[index] = f"{match.group(1)}{key}: {rendered}"
        return True

    indent = " " * _continuation_indent(lines, first, last, item_indent)
    insert_at = last
    while insert_at > first and _is_skippable(lines[insert_at - 1]):
        insert_at -= 1
    lines.insert(insert_at, f"{indent}{key}: {rendered}")
    return True


def _render_entry(rule_id: str, fields: dict[str, Any], item_indent: int, cont_indent: int) -> list[str] | None:
    ordered: list[tuple[str, Any]] = [("id", rule_id)]
    ordered.extend((key, value) for key, value in fields.items() if key != "id")
    rendered_lines: list[str] = []
    for position, (key, value) in enumerate(ordered):
        rendered = _emit_scalar(value, quoted=key in _ALWAYS_QUOTED_FIELDS)
        if rendered is None:
            return None
        prefix = " " * item_indent + "- " if position == 0 else " " * cont_indent
        rendered_lines.append(f"{prefix}{key}: {rendered}")
    return rendered_lines


def apply_edit(text: str, edit: RuleEdit) -> str | None:
    """Patch *text* for *edit*, or ``None`` when the file shape is not supported."""
    lines = text.splitlines()
    located = _locate_list(lines, edit.path)
    if located is None:
        return None
    list_start, list_end, item_indent = located
    ranges = _entry_ranges(lines, list_start, list_end, item_indent)

    if edit.op == "add":
        if any(_entry_id(lines, first, last) == edit.rule_id for first, last in ranges):
            return None  # duplicate; the caller rejects this before reaching here
        cont_indent = (
            _continuation_indent(lines, ranges[-1][0], ranges[-1][1], item_indent)
            if ranges
            else item_indent + 2
        )
        entry = _render_entry(edit.rule_id, edit.fields or {}, item_indent, cont_indent)
        if entry is None:
            return None
        insert_at = ranges[-1][1] if ranges else list_end
        while insert_at > list_start and _is_skippable(lines[insert_at - 1]):
            insert_at -= 1
        lines[insert_at:insert_at] = entry
        return "\n".join(lines) + "\n"

    target = next(
        ((first, last) for first, last in ranges if _entry_id(lines, first, last) == edit.rule_id),
        None,
    )
    if target is None:
        return None
    first, last = target

    if edit.op == "delete":
        # Trailing blank lines and comments after the entry are ambiguous — they
        # may separate the block from what follows, or document the next rule.
        # Keep them: this whole module exists so the console stops destroying
        # things it did not mean to touch.
        stop = last
        while stop > first + 1 and _is_skippable(lines[stop - 1]):
            stop -= 1
        del lines[first:stop]
        return "\n".join(lines) + "\n"

    if edit.op == "update":
        for key, value in (edit.fields or {}).items():
            if key == "id":
                continue
            if not _set_field(lines, first, last, item_indent, key, value):
                return None
            # _set_field may have inserted a line; recompute the entry window.
            ranges = _entry_ranges(lines, list_start, _block_end(lines, list_start, item_indent - 1), item_indent)
            target = next(
                ((s, e) for s, e in ranges if _entry_id(lines, s, e) == edit.rule_id), None
            )
            if target is None:
                return None
            first, last = target
        return "\n".join(lines) + "\n"

    return None


def render_rules_yaml(text: str, expected: dict, edit: RuleEdit) -> str:
    """YAML text for *expected*, keeping comments when the patch verifies.

    The patched text is re-parsed and compared with *expected* in full; only an
    exact match is returned. Otherwise this falls back to a plain dump — correct,
    but comment-free — and says so in the log.
    """
    patched = apply_edit(text, edit)
    if patched is not None:
        try:
            if yaml.safe_load(patched) == expected:
                return patched
            logger.warning(
                "rules edit patch verification mismatch path=%s op=%s id=%s; falling back to full dump "
                "(comments in security_filters.yaml will be lost)",
                ".".join(edit.path), edit.op, edit.rule_id,
            )
        except yaml.YAMLError as exc:
            logger.warning(
                "rules edit patch produced invalid YAML path=%s op=%s id=%s error=%s; "
                "falling back to full dump",
                ".".join(edit.path), edit.op, edit.rule_id, exc,
            )
    else:
        logger.warning(
            "rules edit could not be applied as a text patch path=%s op=%s id=%s; "
            "falling back to full dump (comments will be lost)",
            ".".join(edit.path), edit.op, edit.rule_id,
        )
    return yaml.dump(expected, allow_unicode=True, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# action_map: leaf-scalar updates on an existing key path
# ---------------------------------------------------------------------------

def apply_scalar_update(text: str, path: list[str], value: Any) -> str | None:
    """Replace the inline value of an existing ``a: b: c`` key path."""
    lines = text.splitlines()
    start, end = 0, len(lines)
    for depth, key in enumerate(path):
        found = _find_key(lines, start, end, key)
        if found is None:
            return None  # key path does not exist yet; caller falls back
        key_index, key_indent = found
        match = _KEY_RE.match(lines[key_index])
        if match is None:
            return None
        if depth == len(path) - 1:
            existing = match.group(3).strip()
            if not existing or existing.startswith(("|", ">", "#")):
                return None
            rendered = _emit_scalar(value)
            if rendered is None:
                return None
            lines[key_index] = f"{match.group(1)}{key}: {rendered}"
            return "\n".join(lines) + "\n"
        if match.group(3):
            return None  # intermediate key has an inline value
        start = key_index + 1
        end = _block_end(lines, start, key_indent)
    return None


def render_scalar_updates(text: str, expected: dict, updates: list[tuple[list[str], Any]]) -> str:
    """Like :func:`render_rules_yaml`, for a batch of leaf-scalar updates."""
    patched = text
    for path, value in updates:
        result = apply_scalar_update(patched, path, value)
        if result is None:
            logger.warning(
                "action_map patch could not be applied path=%s; falling back to full dump "
                "(comments in security_filters.yaml will be lost)",
                ".".join(path),
            )
            return yaml.dump(expected, allow_unicode=True, default_flow_style=False, sort_keys=False)
        patched = result
    try:
        if yaml.safe_load(patched) == expected:
            return patched
    except yaml.YAMLError:
        pass
    logger.warning(
        "action_map patch verification mismatch; falling back to full dump "
        "(comments in security_filters.yaml will be lost)"
    )
    return yaml.dump(expected, allow_unicode=True, default_flow_style=False, sort_keys=False)
