"""The console's first paint must not fetch every panel.

``logs/audit.jsonl`` is already read backwards, one walk per request, and each
walk stops at 8MB. The overview was still paying for both walks — plus every
other panel — because the scripts call those loaders as soon as the page is
parsed. These tests pin the two halves of that:

* a query and a summary each walk the file once and stop at the byte budget;
* the startup script does not invoke the off-screen loaders. They run when the
  panel is opened.

There is no browser in CI, so the front-end half is structural, same as
``test_ui_console_usability.py``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from aegisgate.core.audit_query import (
    DEFAULT_MAX_SCAN_BYTES,
    iter_lines_reverse,
    query_log,
    summarize_log,
)

_WWW = Path(__file__).resolve().parents[2] / "www"
_APP_JS = _WWW / "assets" / "app.js"
_AUDIT_JS = _WWW / "assets" / "audit.js"

# Loaders that hit an API the overview does not need. ``loadBootstrap`` is in
# the set because it is the startup call that also pulls the docs catalogue.
_EAGER_LOADERS = frozenset(
    {
        "loadTokens",
        "loadForwards",
        "loadBootstrap",
        "loadDocs",
        "loadRedactValues",
        "loadRuleSections",
        "loadRules",
        "loadKeys",
        "loadStats",
        "loadComposeList",
        "loadComposeContent",
        "loadRequestRedaction",
        "loadRequestRedactionStat",
        "loadSummary",
        "loadAudit",
        "loadSampleDates",
    }
)

_BINDERS = (
    "bindRedactUI",
    "bindRulesUI",
    "bindKeysUI",
    "bindStatsUI",
    "bindComposeUI",
    "bindRequestRedactionUI",
)

_PANEL_REGISTRATIONS = (
    'registerPanelLoader("overview", loadTokens)',
    'registerPanelLoader("stats", loadStats)',
    'registerPanelLoader("request-redaction"',
    'registerPanelLoader("rules"',
    'registerPanelLoader("tokens", loadTokens)',
    'registerPanelLoader("forwards", loadForwards)',
    'registerPanelLoader("docs"',
    'registerPanelLoader("keys", loadKeys)',
    'registerPanelLoader("compose", loadComposeList)',
)


def _is_ident(ch: str) -> bool:
    return ch.isalnum() or ch in "_$"


def _keyword_at(src: str, index: int, word: str) -> bool:
    if not src.startswith(word, index):
        return False
    before = src[index - 1] if index else ""
    after_at = index + len(word)
    after = src[after_at] if after_at < len(src) else ""
    if before and _is_ident(before):
        return False
    if after and _is_ident(after):
        return False
    return True


def _skip_string(src: str, index: int) -> int:
    quote = src[index]
    index += 1
    limit = len(src)
    while index < limit:
        if src[index] == "\\":
            index += 2
            continue
        if src[index] == quote:
            return index + 1
        index += 1
    return limit


def _skip_line_comment(src: str, index: int) -> int:
    end = src.find("\n", index + 2)
    return len(src) if end < 0 else end


def _skip_block_comment(src: str, index: int) -> int:
    end = src.find("*/", index + 2)
    return len(src) if end < 0 else end + 2


def _regex_can_start(src: str, index: int) -> bool:
    cursor = index - 1
    while cursor >= 0 and src[cursor].isspace():
        cursor -= 1
    if cursor < 0:
        return True
    prev = src[cursor]
    if prev in "([{:;,=!?&|~^+-*%<>":
        return True
    if not _is_ident(prev):
        return False
    start = cursor
    while start >= 0 and _is_ident(src[start]):
        start -= 1
    word = src[start + 1 : cursor + 1]
    return word in {"return", "typeof", "case", "throw", "void", "delete", "await", "yield"}


def _skip_regex(src: str, index: int) -> int:
    index += 1
    limit = len(src)
    in_class = False
    while index < limit:
        ch = src[index]
        if ch == "\\":
            index += 2
            continue
        if ch == "\n":
            return index
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            index += 1
            while index < limit and src[index].isalpha():
                index += 1
            return index
        index += 1
    return limit


def _skip_braced(src: str, open_brace: int) -> int:
    """Index just after the ``}`` that matches ``open_brace``."""
    depth = 1
    index = open_brace + 1
    limit = len(src)
    while index < limit and depth:
        ch = src[index]
        if ch in "\"'":
            index = _skip_string(src, index)
            continue
        if ch == "`":
            index = _skip_template(src, index)
            continue
        if ch == "/" and index + 1 < limit and src[index + 1] == "/":
            index = _skip_line_comment(src, index)
            continue
        if ch == "/" and index + 1 < limit and src[index + 1] == "*":
            index = _skip_block_comment(src, index)
            continue
        if ch == "/" and _regex_can_start(src, index):
            index = _skip_regex(src, index)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return limit


def _skip_template(src: str, index: int) -> int:
    index += 1
    limit = len(src)
    while index < limit:
        ch = src[index]
        if ch == "\\":
            index += 2
            continue
        if ch == "`":
            return index + 1
        if ch == "$" and index + 1 < limit and src[index + 1] == "{":
            index = _skip_braced(src, index + 1)
            continue
        index += 1
    return limit


def _skip_function(src: str, index: int) -> int:
    brace = src.find("{", index)
    if brace < 0:
        return len(src)
    return _skip_braced(src, brace)


def _skip_parens(src: str, index: int) -> int:
    """Index just after the ``)`` that matches the ``(`` at *index*."""
    depth = 0
    limit = len(src)
    while index < limit:
        ch = src[index]
        if ch in "\"'":
            index = _skip_string(src, index)
            continue
        if ch == "`":
            index = _skip_template(src, index)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            index += 1
            if depth == 0:
                return index
            continue
        index += 1
    return limit


def _skip_arrow_expr(src: str, index: int) -> int:
    """Skip ``() => loadAudit(true)`` so the call stays inside the arrow.

    A block body is handled by the caller. This only covers an expression
    body: one call, plus a ``.then(...)`` / ``.catch(...)`` chain.
    """
    limit = len(src)
    while index < limit and src[index].isspace():
        index += 1
    if index < limit and _is_ident(src[index]):
        while index < limit and _is_ident(src[index]):
            index += 1
    while True:
        while index < limit and src[index].isspace():
            index += 1
        if index < limit and src[index] == "(":
            index = _skip_parens(src, index)
            continue
        if index < limit and src[index] == ".":
            index += 1
            while index < limit and (src[index].isspace() or _is_ident(src[index])):
                index += 1
            continue
        return index


def _direct_calls(src: str) -> set[str]:
    """Call names in *src* that are not inside a nested function.

    A whole script yields only the calls that run as the file is evaluated.
    A function body yields the calls that run when that function runs, not
    the ones parked inside a click handler or an arrow callback.
    """
    calls: set[str] = set()
    index = 0
    limit = len(src)
    while index < limit:
        ch = src[index]
        if ch.isspace():
            index += 1
            continue
        if ch in "\"'":
            index = _skip_string(src, index)
            continue
        if ch == "`":
            index = _skip_template(src, index)
            continue
        if ch == "/" and index + 1 < limit and src[index + 1] == "/":
            index = _skip_line_comment(src, index)
            continue
        if ch == "/" and index + 1 < limit and src[index + 1] == "*":
            index = _skip_block_comment(src, index)
            continue
        if ch == "/" and _regex_can_start(src, index):
            index = _skip_regex(src, index)
            continue
        if _keyword_at(src, index, "function"):
            index = _skip_function(src, index)
            continue
        if src.startswith("=>", index):
            cursor = index + 2
            while cursor < limit and src[cursor].isspace():
                cursor += 1
            if cursor < limit and src[cursor] == "{":
                index = _skip_braced(src, cursor)
                continue
            index = _skip_arrow_expr(src, cursor)
            continue
        if _is_ident(ch) and not ch.isdigit():
            cursor = index + 1
            while cursor < limit and _is_ident(src[cursor]):
                cursor += 1
            look = cursor
            while look < limit and src[look].isspace():
                look += 1
            if look < limit and src[look] == "(":
                calls.add(src[index:cursor])
            index = cursor
            continue
        index += 1
    return calls


def _function_body(src: str, name: str) -> str:
    marker = f"function {name}("
    start = src.find(marker)
    if start < 0:
        raise AssertionError(f"missing function {name}")
    brace = src.find("{", start)
    end = _skip_braced(src, brace)
    return src[brace + 1 : end - 1]


def _callback_body(src: str, registration: str) -> str:
    start = src.index(registration)
    function_at = src.index("function", start)
    brace = src.index("{", function_at)
    end = _skip_braced(src, brace)
    return src[brace + 1 : end - 1]


def _app_js() -> str:
    return _APP_JS.read_text(encoding="utf-8")


def _audit_js() -> str:
    return _AUDIT_JS.read_text(encoding="utf-8")


def _eager_startup_calls(app_js: str, audit_js: str) -> set[str]:
    found = _direct_calls(app_js) & _EAGER_LOADERS
    for name in _BINDERS:
        found |= _direct_calls(_function_body(app_js, name)) & _EAGER_LOADERS
    found |= _direct_calls(_function_body(audit_js, "initAuditExplorer")) & _EAGER_LOADERS
    if "function bootLazyPanels(" in app_js:
        found |= _direct_calls(_function_body(app_js, "bootLazyPanels")) & _EAGER_LOADERS
    return found


def test_first_screen_does_not_fetch_hidden_panels() -> None:
    """Opening the console must not pull every panel's API.

    The audit explorer's summary and page are part of that set: each one walks
    up to 8MB of the log, and both used to start before the reader left the
    overview.
    """
    found = _eager_startup_calls(_app_js(), _audit_js())
    assert not found, f"first screen still fetches panels: {sorted(found)}"


def test_hidden_panels_still_load_when_opened() -> None:
    app_js = _app_js()
    audit_js = _audit_js()
    missing = [item for item in _PANEL_REGISTRATIONS if item not in app_js]
    assert not missing, f"panels cannot be opened: {missing}"
    redaction = app_js[app_js.index('registerPanelLoader("request-redaction"') :]
    redaction = redaction[: redaction.index(");") + 2]
    assert "loadRequestRedaction" in redaction
    assert "loadRedactValues" in redaction

    assert 'registerPanelLoader("audit"' in audit_js
    callback = _callback_body(audit_js, 'registerPanelLoader("audit"')
    calls = _direct_calls(callback)
    assert {"loadSummary", "loadAudit", "loadSampleDates"} <= calls

    # The overview itself still loads. Config stays with it: one payload builds
    # the sidebar and the field links on the overview cards.
    script_calls = _direct_calls(app_js)
    assert "loadFirstScreen" in script_calls or "refreshOverview" in script_calls
    assert "loadConfigPanels" in app_js or "/__ui__/api/config" in _function_body(
        app_js, "loadFirstScreen"
    )


def test_audit_query_and_summary_each_walk_the_log_once(tmp_path: Path) -> None:
    """One request is one reverse walk, capped at 8MB, not a second full read."""
    line = (
        json.dumps(
            {
                "ts": "2026-08-01T00:00:00+00:00",
                "request_id": "r",
                "route": "/v1/chat/completions",
                "risk_score": 0.2,
                "request_disposition": "allow",
                "response_disposition": "pass",
            }
        )
        + "\n"
    )
    repeats = (DEFAULT_MAX_SCAN_BYTES // len(line)) + 80
    path = tmp_path / "audit.jsonl"
    path.write_text(line * repeats, encoding="utf-8")
    assert path.stat().st_size > DEFAULT_MAX_SCAN_BYTES

    # Record the walk as lines are yielded. Callers stop early (a page of 50,
    # or the summary's record cap), so the generator is abandoned and code
    # after its loop would not run.
    seen: list[int] = []

    def tracking(file: Path, end_offset: int, max_scan_bytes: int):
        seen.append(0)
        slot = len(seen) - 1
        for item in iter_lines_reverse(file, end_offset, max_scan_bytes):
            seen[slot] = item[2]
            yield item

    from aegisgate.core import audit_query

    original = audit_query.iter_lines_reverse
    audit_query.iter_lines_reverse = tracking
    try:
        queried = query_log(path, limit=50)
        summarize_log(path)
    finally:
        audit_query.iter_lines_reverse = original

    assert len(seen) == 2
    assert queried.scanned_bytes == seen[0]
    assert all(0 < walked <= DEFAULT_MAX_SCAN_BYTES for walked in seen)
    assert all(walked < path.stat().st_size for walked in seen)


# Ids the console treats as panels. Config sections such as #security are not
# in this set; a refresh of those hashes still shows the top of the page.
_LAZY_PANEL_IDS = frozenset(
    {
        "overview",
        "stats",
        "audit",
        "request-redaction",
        "rules",
        "tokens",
        "forwards",
        "docs",
        "keys",
        "compose",
        "logs",
    }
)


def _panel_entered(top: float, bottom: float, height: float) -> bool:
    """Evaluate ``panelIntersectsViewport``'s return expression at one rect."""
    body = _function_body(_app_js(), "panelIntersectsViewport")
    match = re.search(r"return ([^;]+);", body)
    assert match, body
    expr = match.group(1).replace("&&", " and ").replace("||", " or ")
    expr = re.sub(r"\brect\.top\b", repr(float(top)), expr)
    expr = re.sub(r"\brect\.bottom\b", repr(float(bottom)), expr)
    expr = re.sub(r"\bheight\b", repr(float(height)), expr)
    return bool(eval(expr, {"__builtins__": {}}, {}))


def test_lower_half_of_a_desktop_window_does_not_open_audit() -> None:
    """Stats sits near 180px; the audit heading sits near 700px.

    On an 800–1400px window the heading is still inside the viewport, but it
    is in the lower half. Loading it there scans the audit log on first paint.
    A window tall enough that 700px is in the upper half may still load it.
    """
    for height in (900, 1000, 1100, 1200):
        assert not _panel_entered(700, 1100, height), height
    for height in (800, 1000, 1400):
        assert _panel_entered(180, 500, height), height
    assert _panel_entered(700, 1100, 2000)


def _sweeps_visible_panels(hash_id: str) -> bool:
    """Whether ``refreshLazyPanels`` calls ``loadVisiblePanels`` for this hash."""
    body = _function_body(_app_js(), "refreshLazyPanels")
    compact = re.sub(r"\s+", " ", body)
    if re.search(r"if \(!panelIdFromHash\(\)\) loadVisiblePanels\(\)", compact):
        return hash_id == ""
    if "LAZY_PANEL_IDS.has" in body:
        return (not hash_id) or (hash_id not in _LAZY_PANEL_IDS)
    if "panelLoaders.has" in body:
        registered = _LAZY_PANEL_IDS - {"logs"}
        return (not hash_id) or (hash_id not in registered)
    raise AssertionError(f"unrecognized refreshLazyPanels policy:\n{body}")


def test_config_hash_still_loads_panels_already_on_screen() -> None:
    """#security and #general are config anchors, not lazy panels.

    A refresh of those hashes leaves the reader at the top of the page, so
    the upper-half panels (stats, tokens, the onboarding card) still have to
    load. A real panel hash such as #audit must not prefetch the panels
    scrolled past on the way there.
    """
    assert _sweeps_visible_panels("")
    assert _sweeps_visible_panels("security")
    assert _sweeps_visible_panels("general")
    assert not _sweeps_visible_panels("audit")
    assert not _sweeps_visible_panels("stats")


def test_docs_failure_is_reported_only_by_the_docs_loader() -> None:
    """A failed docs request must not leave the placeholder in place, and an
    overview or config failure must not write into the docs pane.
    """
    app_js = _app_js()
    callback = _callback_body(app_js, 'registerPanelLoader("docs"')
    assert "catch(showDocError)" in callback.replace(" ", "")
    assert "showDocError" not in _function_body(app_js, "loadFirstScreen")
    for site in re.finditer(r"loadFirstScreen\(\)\.catch", app_js):
        handler = app_js[site.start() : site.start() + 400]
        assert "showDocError" not in handler
