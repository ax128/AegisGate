"""Structural checks on the console stylesheet.

There is no browser in CI, so these do not test appearance. They pin the two
properties that break silently and are expensive to notice by eye:

* every custom property a rule uses is actually defined somewhere, and
* no colour is defined *only* inside the dark-theme block — the classic bug that
  renders one theme's text on the other theme's background.

They also guard against the previous design system creeping back in: hard-coded
indigo, per-component easing curves, and duplicate component definitions where a
stale rule later in the file silently wins over the intended one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_CSS_PATH = Path(__file__).resolve().parents[2] / "www" / "assets" / "app.css"

# Tokens that legitimately live only in :root: geometry, type, motion, and the
# legacy aliases, all of which resolve through tokens the dark block redefines.
_THEME_AGNOSTIC_PREFIXES = (
    "--radius", "--sp-", "--type-", "--font-", "--dur", "--ease",
    "--header-h", "--sidebar-w", "--material-",
)
_LEGACY_ALIASES = {
    "--bg", "--panel", "--text", "--muted", "--line",
    "--surface", "--surface2", "--border", "--shadow-glow",
}
_COLOUR_HINTS = (
    "label", "fill", "separator", "bg-", "accent",
    "success", "warning", "error", "shadow", "header-b", "header-t", "scrim",
)


@pytest.fixture(scope="module")
def css() -> str:
    return _CSS_PATH.read_text(encoding="utf-8")


def _block(css: str, selector: str) -> str:
    start = css.index(selector + " {")
    depth = 0
    for index in range(start, len(css)):
        if css[index] == "{":
            depth += 1
        elif css[index] == "}":
            depth -= 1
            if depth == 0:
                return css[start : index + 1]
    raise AssertionError(f"unbalanced block for {selector}")


def _declared(block: str) -> set[str]:
    return set(re.findall(r"(--[a-z0-9-]+)\s*:", block))


class TestStructure:
    def test_braces_balance(self, css: str) -> None:
        assert css.count("{") == css.count("}")

    def test_every_used_custom_property_is_defined(self, css: str) -> None:
        used = set(re.findall(r"var\(\s*(--[a-z0-9-]+)", css))
        defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
        assert sorted(used - defined) == []

    def test_the_previous_button_treatment_is_gone(self, css: str) -> None:
        """The old buttons were gradient-filled and lifted on hover. Apple's
        press feedback fades and settles instead, so a stale rule reintroducing
        either would visibly fight the new one."""
        assert "linear-gradient(135deg, var(--accent)" not in css
        assert "translateY(-2px)" not in css
        assert "translateY(-1px)" not in css
        assert "filter: brightness(" not in css


class TestThemeParity:
    def test_dark_block_introduces_no_new_token(self, css: str) -> None:
        light = _declared(_block(css, ":root"))
        dark = _declared(_block(css, ':root[data-theme="dark"]'))
        assert sorted(dark - light) == []

    def test_no_colour_is_defined_only_in_the_dark_block(self, css: str) -> None:
        light = _declared(_block(css, ":root"))
        dark = _declared(_block(css, ':root[data-theme="dark"]'))
        colours = {token for token in dark if any(hint in token for hint in _COLOUR_HINTS)}
        assert sorted(colours - light) == []

    def test_every_colour_token_is_redefined_for_dark(self, css: str) -> None:
        """Geometry may be shared; colour may not — an inherited light colour on a
        dark ground is exactly the unreadable-console failure."""
        light = _declared(_block(css, ":root"))
        dark = _declared(_block(css, ':root[data-theme="dark"]'))
        colours = {
            token
            for token in light
            if any(hint in token for hint in _COLOUR_HINTS)
            and not token.startswith(_THEME_AGNOSTIC_PREFIXES)
            and token not in _LEGACY_ALIASES
        }
        assert sorted(colours - dark) == []

    def test_body_paints_an_explicit_background(self, css: str) -> None:
        body = _block(css, "body")
        assert "background:" in body


class TestDesignSystemDiscipline:
    def test_no_hardcoded_indigo_from_the_previous_palette(self, css: str) -> None:
        assert re.search(r"rgba?\(\s*99,\s*102,\s*241", css) is None

    def test_motion_uses_the_shared_easing_token(self, css: str) -> None:
        """One easing curve, declared once — not a different bezier per component."""
        literals = re.findall(r"cubic-bezier\([^)]*\)", css)
        assert literals == ["cubic-bezier(0.32, 0.72, 0, 1)"], literals

    def test_monospace_goes_through_the_font_token(self, css: str) -> None:
        assert "Cascadia Code" not in css
        assert "Fira Code" not in css

    def test_reduced_motion_is_still_honoured(self, css: str) -> None:
        assert "@media (prefers-reduced-motion: reduce)" in css

    def test_switch_state_is_not_conveyed_by_colour_alone(self, css: str) -> None:
        """The thumb translates as well as the track changing colour."""
        assert ".bool-button.on::after" in css
        assert "translateX" in _block(css, ".bool-button.on::after")


class TestSilentFailures:
    """Rules whose absence breaks the page without erroring anywhere."""

    def test_the_hidden_class_actually_hides(self, css: str) -> None:
        """Scripts and markup toggle `.hidden` on ordinary elements.

        It used to be defined only as `.modal-overlay.hidden`, so every other
        toggle was a no-op: the register dialog showed the Token field it meant
        to hide, and the rules table rendered on top of the action map.
        """
        assert re.search(r"(?<![\w.-])\.hidden\s*\{[^}]*display:\s*none", css), (
            "a bare `.hidden { display: none }` rule is missing"
        )

    def test_a_config_control_does_not_starve_its_label(self, css: str) -> None:
        """`.field-card` is a flex row and the shared input rule sets width:100%.

        Without a constraint the control claims the whole card and `.meta`
        collapses to min-content — every config label rendered one character per
        line.
        """
        assert ".field-card:not(.wide) > input" in css
        assert ".field-card:not(.wide) > select" in css


class TestContentSecurityPolicy:
    """`style-src 'self'` with no `unsafe-inline` — see
    gateway_auth._apply_ui_security_headers. A `style="…"` attribute is not
    merely inelegant here: the browser blocks it, so the declarations never
    apply and the console logs a CSP violation for each one."""

    @pytest.mark.parametrize(
        "name",
        ["index.html", "login.html", "assets/app.js", "assets/audit.js", "assets/ui-kit.js"],
    )
    def test_no_inline_style_attributes(self, name: str) -> None:
        text = (_CSS_PATH.parents[1] / name).read_text(encoding="utf-8")
        offenders = re.findall(r'style="[^"]*"', text)
        assert offenders == [], (
            f"{name} carries inline styles the console's CSP blocks: {offenders}"
        )


class TestMarkupSemantics:
    @pytest.fixture(scope="class")
    def html(self) -> str:
        return (_CSS_PATH.parents[1] / "index.html").read_text(encoding="utf-8")

    def test_all_static_table_headers_declare_scope(self, html: str) -> None:
        """`<thead>` must not be caught by the `<th` prefix, hence the boundary."""
        offenders = re.findall(r"<th(?![a-z])(?![^>]*scope=)[^>]*>", html)
        assert offenders == []

    def test_segmented_controls_expose_tablist_semantics(self, html: str) -> None:
        assert html.count('role="tablist"') >= 2
        assert html.count('role="tab"') >= 2
        assert html.count('aria-selected=') >= 2

    def test_theme_script_runs_before_paint(self, html: str) -> None:
        """Otherwise dark-mode users get a white flash on every load."""
        head_end = html.index("</head>")
        assert "theme.js" in html[:head_end]


class TestScriptSemantics:
    @pytest.fixture(scope="class")
    def js(self) -> str:
        return (_CSS_PATH.parent / "app.js").read_text(encoding="utf-8")

    def test_boolean_control_is_announced_as_a_switch(self, js: str) -> None:
        assert 'setAttribute("role", "switch")' in js
        assert 'setAttribute("aria-checked"' in js

    def test_active_nav_item_sets_aria_current(self, js: str) -> None:
        assert 'setAttribute("aria-current", "page")' in js
        assert 'removeAttribute("aria-current")' in js

    def test_dynamic_table_headers_declare_scope(self, js: str) -> None:
        assert re.search(r"<th>(?!\$\{)", js) is None
