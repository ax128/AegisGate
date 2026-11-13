"""SECURITY.md must give reporters a private channel with a response window.

GitHub shows this file as the repository security policy. It has to name the
release line that still receives fixes, a private reporting path, and how
soon a report is acknowledged. There is no public security mailbox, so the
path is GitHub Private vulnerability reporting and the file must not invent
an address.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SECURITY_MD = _REPO_ROOT / "SECURITY.md"
_ADVISORY_URL = "https://github.com/ax128/AegisGate/security/advisories/new"
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _version_bounds() -> tuple[str, str]:
    """Return ``(0.1.x, 0.1.0)`` from the package version in pyproject.toml."""
    text = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"(\d+)\.(\d+)\.\d+"\s*$', text)
    assert match, "pyproject.toml version is not major.minor.patch"
    major_minor = f"{match.group(1)}.{match.group(2)}"
    return f"{major_minor}.x", f"{major_minor}.0"


def test_security_md_states_supported_versions_private_reporting_and_response_window() -> None:
    assert _SECURITY_MD.is_file(), "SECURITY.md is missing from the repository root"
    text = _SECURITY_MD.read_text(encoding="utf-8")
    series, floor = _version_bounds()

    assert "Supported Versions" in text
    assert "支持的版本" in text
    assert f"| {series} | yes |" in text
    assert f"| < {floor} | no |" in text

    assert "Private vulnerability reporting" in text
    assert _ADVISORY_URL in text
    assert _EMAIL.search(text) is None, "SECURITY.md must not invent an email address"

    assert "Response window" in text
    assert "响应时限" in text
    assert "within 7 days" in text
    assert "7 天内" in text
