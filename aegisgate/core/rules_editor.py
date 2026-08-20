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
it is re-parsed and compared against the structure the caller intended.

Only an exact match is returned. There is deliberately **no dump fallback**: a
write that silently swaps the documented policy file for a comment-free dump and
then reports success is worse than a write that refuses. Every renderer here
returns ``None`` when it cannot produce a verified patch, and the caller turns
that into a non-2xx response without touching the file.
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


@dataclass
class LeafOp:
    """One key-path level change: set a value, or remove the key entirely.

    ``delete`` is what restores "use the built-in default" for a key like
    ``redaction.relaxed_pii_ids``: writing today's default set back into the file
    would freeze it, so the key is removed instead.
    """

    path: list[str]
    op: str  # "set" | "delete"
    value: Any = None


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


def _flush_list_end(lines: list[str], start: int, indent: int) -> int:
    """End of a list whose items sit at the *same* indent as their key.

    ``yaml.dump`` writes lists that way, so any file that ever went through the
    old dump path has this shape — and ``_block_end`` reports such a block as
    empty, because the first item already dedents to the key's own level.
    """
    for index in range(start, len(lines)):
        if _is_skippable(lines[index]):
            continue
        line_indent = _indent_of(lines[index])
        if line_indent < indent:
            return index
        if line_indent == indent and not _ITEM_RE.match(lines[index]):
            return index
    return len(lines)


def _locate_list(lines: list[str], path: list[str]) -> tuple[int, int, int, int] | None:
    """Resolve *path* to its list: ``(key_line, first_item, end, item_indent)``.

    An empty list written inline as ``key: []`` is normalised in place to a block
    key so a first item can be added back to a group whose rules were all
    deleted.
    """
    start, end, parent_indent = 0, len(lines), -1
    key_index = -1
    for depth, key in enumerate(path):
        found = _find_key(lines, start, end, key)
        if found is None:
            return None
        key_index, key_indent = found
        match = _KEY_RE.match(lines[key_index])
        if match is None:
            return None
        inline = match.group(3).strip()
        if inline:
            if inline != "[]" or depth != len(path) - 1:
                return None  # an inline value this cannot patch
            lines[key_index] = f"{match.group(1)}{match.group(2)}:"
        start = key_index + 1
        end = _block_end(lines, start, key_indent)
        parent_indent = key_indent

    for index in range(start, end):
        if _is_skippable(lines[index]):
            continue
        item = _ITEM_RE.match(lines[index])
        if not item:
            return None  # first payload line is not a list item
        return key_index, index, end, len(item.group(1))

    # The indented block is empty. Either the list is written flush with its key,
    # or there really are no items and new ones go one level in.
    for index in range(start, len(lines)):
        if _is_skippable(lines[index]):
            continue
        if _ITEM_RE.match(lines[index]) and _indent_of(lines[index]) == parent_indent:
            return key_index, index, _flush_list_end(lines, index, parent_indent), parent_indent
        break
    return key_index, start, end, parent_indent + 2


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
    key_index, list_start, list_end, item_indent = located
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
        if len(ranges) == 1:
            # That was the last rule. A bare ``key:`` parses as null, not as an
            # empty list, so the emptiness has to be written out.
            key_match = _KEY_RE.match(lines[key_index])
            if key_match is None:
                return None
            lines[key_index] = f"{key_match.group(1)}{key_match.group(2)}: []"
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


def _key_path_absent(text: str, path: list[str]) -> bool:
    try:
        node: Any = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return False
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
        if node is None:
            return True
    return False


def _patch_rule(text: str, expected: dict, edit: RuleEdit) -> str | None:
    patched = apply_edit(text, edit)
    if patched is None and edit.op == "add" and _key_path_absent(text, edit.path):
        # The group's key is absent from the file altogether — a hand-edited
        # config, since the console writes ``key: []`` when the last rule goes.
        # Write the list out once so the group is not a dead end. Shapes that do
        # exist but cannot be patched stay a refusal: silently reformatting
        # someone's file is what this module is here to avoid.
        target: Any = expected
        for key in edit.path:
            target = target.get(key) if isinstance(target, dict) else None
        if isinstance(target, list):
            patched = apply_leaf_ops(text, [LeafOp(list(edit.path), "set", target)])
    if patched is None:
        logger.warning(
            "rules edit could not be applied as a text patch path=%s op=%s id=%s",
            ".".join(edit.path), edit.op, edit.rule_id,
        )
    return patched


def _verify(patched: str | None, expected: dict, label: str) -> str | None:
    if patched is None:
        return None
    try:
        if yaml.safe_load(patched) == expected:
            return patched
    except yaml.YAMLError as exc:
        logger.warning("rules patch produced invalid YAML %s error=%s", label, exc)
        return None
    logger.warning("rules patch verification mismatch %s", label)
    return None


def render_rules_yaml(text: str, expected: dict, edit: RuleEdit) -> str | None:
    """YAML text for *expected* with comments intact, or ``None``.

    The patched text is re-parsed and compared with *expected* in full; only an
    exact match is returned. ``None`` means the file's shape is not one this
    module can patch safely — the caller must fail the write rather than dump.
    """
    return _verify(
        _patch_rule(text, expected, edit),
        expected,
        f"path={'.'.join(edit.path)} op={edit.op} id={edit.rule_id}",
    )


def render_rule_with_leaf_ops(
    text: str, expected: dict, edit: RuleEdit, ops: list[LeafOp]
) -> str | None:
    """One rule edit *and* a batch of leaf changes, verified as a single patch.

    Deleting a PII rule that a custom ``relaxed_pii_ids`` list still names has to
    drop both in the same write: two writes would leave a window where the list
    references a rule that no longer exists.
    """
    patched = _patch_rule(text, expected, edit)
    if patched is None:
        return None
    if ops:
        patched = apply_leaf_ops(patched, ops)
    return _verify(
        patched, expected, f"path={'.'.join(edit.path)} op={edit.op} id={edit.rule_id} +leaf"
    )


# ---------------------------------------------------------------------------
# Leaf key paths: update, insert and delete, comments preserved
# ---------------------------------------------------------------------------

def _shallowest_indent(lines: list[str], start: int, end: int) -> int | None:
    for index in range(start, end):
        if _is_skippable(lines[index]):
            continue
        return _indent_of(lines[index])
    return None


def _trimmed_end(lines: list[str], start: int, end: int) -> int:
    """*end* with trailing blank/comment lines excluded.

    Those lines sit inside the block only by indentation; in practice they
    introduce whatever comes next. Sweeping them into a replaced or deleted block
    is exactly the silent comment loss this module exists to prevent.
    """
    stop = end
    while stop > start and _is_skippable(lines[stop - 1]):
        stop -= 1
    return stop


def _resolve_container(
    lines: list[str], path: list[str], *, create: bool
) -> tuple[int, int, int] | None:
    """``(start, end, child_indent)`` of the mapping that owns ``path[-1]``.

    With *create* set, a missing intermediate key is written as an empty mapping
    header so a brand-new nested key path can still be inserted.
    """
    start, end, indent = 0, len(lines), -1
    for key in path[:-1]:
        found = _find_key(lines, start, end, key)
        if found is None:
            if not create:
                return None
            child_indent = _shallowest_indent(lines, start, end)
            if child_indent is None:
                child_indent = indent + 2
            insert_at = _trimmed_end(lines, start, end)
            lines.insert(insert_at, f"{' ' * child_indent}{key}:")
            start, end, indent = insert_at + 1, insert_at + 1, child_indent
            continue
        key_index, key_indent = found
        match = _KEY_RE.match(lines[key_index])
        if match is None or match.group(3).strip():
            return None  # inline value: not a mapping this can descend into
        start, end, indent = key_index + 1, _block_end(lines, key_index + 1, key_indent), key_indent
    child_indent = _shallowest_indent(lines, start, end)
    if child_indent is None:
        child_indent = indent + 2
    return start, end, child_indent


def _render_mapping_item(entry: dict[str, Any], indent: str) -> list[str] | None:
    rendered: list[str] = []
    for position, (key, value) in enumerate(entry.items()):
        scalar = _emit_scalar(value, quoted=key in _ALWAYS_QUOTED_FIELDS)
        if scalar is None:
            return None
        prefix = f"{indent}- " if position == 0 else f"{indent}  "
        rendered.append(f"{prefix}{key}: {scalar}")
    return rendered or None


def _render_leaf(key: str, value: Any, indent: int) -> list[str] | None:
    """``key: value`` as lines, block-style for lists, or ``None`` if unsupported."""
    pad = " " * indent
    if isinstance(value, (list, tuple)):
        if not value:
            return [f"{pad}{key}: []"]
        rendered = [f"{pad}{key}:"]
        for entry in value:
            if isinstance(entry, dict):
                item_lines = _render_mapping_item(entry, pad + "  ")
                if item_lines is None:
                    return None
                rendered.extend(item_lines)
                continue
            item = _emit_scalar(entry)
            if item is None:
                return None
            rendered.append(f"{pad}  - {item}")
        return rendered
    scalar = _emit_scalar(value)
    if scalar is None:
        return None
    return [f"{pad}{key}: {scalar}"]


def _apply_leaf_op(lines: list[str], op: LeafOp) -> bool:
    if not op.path or op.op not in {"set", "delete"}:
        return False
    container = _resolve_container(lines, op.path, create=op.op == "set")
    if container is None:
        return False
    start, end, child_indent = container
    key = op.path[-1]
    found = _find_key(lines, start, end, key)

    if found is None:
        if op.op == "delete":
            return True  # already absent: the requested end state
        rendered = _render_leaf(key, op.value, child_indent)
        if rendered is None:
            return False
        insert_at = _trimmed_end(lines, start, end)
        lines[insert_at:insert_at] = rendered
        return True

    key_index, key_indent = found
    stop = _trimmed_end(lines, key_index + 1, _block_end(lines, key_index + 1, key_indent))
    # Replacing or dropping a block that documents itself would destroy the very
    # comments this module protects, so that shape is refused instead.
    if any(line.strip().startswith("#") for line in lines[key_index + 1 : stop]):
        return False
    if op.op == "delete":
        del lines[key_index:stop]
        return True
    rendered = _render_leaf(key, op.value, key_indent)
    if rendered is None:
        return False
    lines[key_index:stop] = rendered
    return True


def apply_leaf_ops(text: str, ops: list[LeafOp]) -> str | None:
    """Apply every op to *text* in memory, or ``None`` if any shape is unsupported."""
    lines = text.splitlines()
    for op in ops:
        if not _apply_leaf_op(lines, op):
            return None
    return "\n".join(lines) + "\n"


def render_leaf_ops(text: str, expected: dict, ops: list[LeafOp]) -> str | None:
    """Patched text whose re-parse equals *expected*, or ``None``."""
    patched = apply_leaf_ops(text, ops)
    if patched is None:
        logger.warning(
            "leaf patch could not be applied paths=%s",
            ",".join(".".join(op.path) for op in ops),
        )
        return None
    try:
        if yaml.safe_load(patched) == expected:
            return patched
    except yaml.YAMLError as exc:
        logger.warning("leaf patch produced invalid YAML error=%s", exc)
        return None
    logger.warning(
        "leaf patch verification mismatch paths=%s",
        ",".join(".".join(op.path) for op in ops),
    )
    return None


def render_scalar_updates(
    text: str, expected: dict, updates: list[tuple[list[str], Any]]
) -> str | None:
    """Like :func:`render_rules_yaml`, for a batch of leaf updates."""
    return render_leaf_ops(text, expected, [LeafOp(list(path), "set", value) for path, value in updates])
