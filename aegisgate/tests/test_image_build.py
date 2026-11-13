"""Image build cache, healthcheck, and the console document allow-list.

The dependency layer has to be installed from ``pyproject.toml`` before
application source is copied, otherwise every source edit rebuilds the wheels.
The image probes ``/health``. Root Markdown copied into the image is the
console allow-list (``_UI_DOCS``), not a wildcard.
"""

from __future__ import annotations

from pathlib import Path

from aegisgate.core.gateway_ui_config import _UI_DOCS

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE = _REPO_ROOT / "Dockerfile"
_DOCKERIGNORE = _REPO_ROOT / ".dockerignore"

# Patterns the image build must exclude. Matched as whole dockerignore lines
# so a comment or a nearby name does not count.
_DOCKERIGNORE_PATTERNS = (
    "aegisgate/tests",
    "docs/",
    "notes.md",
    "task_plan.md",
    ".venv",
    ".git",
    "*.egg-info",
    "__pycache__",
    ".coverage",
)


def _logical_instructions(text: str) -> list[str]:
    """Dockerfile instructions with backslash continuations joined.

    Full-line comments and blank lines are dropped. A trailing ``\\`` joins
    the next physical line, which is how the dependency install and the
    document COPY are written.
    """
    logical: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if buffer:
            buffer = f"{buffer} {stripped}"
        else:
            buffer = stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        logical.append(buffer)
        buffer = ""
    if buffer:
        logical.append(buffer)
    return logical


def _copy_sources(instruction: str) -> list[str]:
    tokens = instruction.split()
    if not tokens or tokens[0].upper() != "COPY":
        raise AssertionError(f"not a COPY instruction: {instruction}")
    tokens = tokens[1:]
    while tokens and tokens[0].startswith("--"):
        tokens = tokens[1:]
    if len(tokens) < 2:
        raise AssertionError(f"COPY instruction is incomplete: {instruction}")
    return tokens[:-1]


def _dockerignore_patterns(text: str) -> list[str]:
    patterns: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)
    return patterns


def test_image_installs_dependencies_from_pyproject_before_source() -> None:
    """A source edit must not bust the dependency layer, and there is no lockfile."""
    lines = _logical_instructions(_DOCKERFILE.read_text(encoding="utf-8"))
    copies = [(index, line) for index, line in enumerate(lines) if line.upper().startswith("COPY ")]
    problems: list[str] = []
    if not copies:
        problems.append("Dockerfile has no COPY instruction")
    else:
        meta_index, meta_line = copies[0]
        sources = _copy_sources(meta_line)
        if sources != ["pyproject.toml"]:
            problems.append(
                "the dependency-layer COPY must be only pyproject.toml "
                f"(no lockfile, no source); got {sources}"
            )
        if len(copies) < 2:
            problems.append("Dockerfile never copies application source after pyproject.toml")
        else:
            source_index = copies[1][0]
            install = [
                line
                for index, line in enumerate(lines)
                if meta_index < index < source_index and line.upper().startswith("RUN ")
            ]
            install_text = "\n".join(install)
            if "pip install" not in install_text or "semantic" not in install_text:
                problems.append(
                    "dependencies (including the semantic extra) must be pip-installed "
                    "after copying pyproject.toml and before any application source; "
                    f"the instructions in between are: {install or ['(none)']}"
                )
            if "uv.lock" in install_text or "poetry.lock" in install_text:
                problems.append("dependency install must read pyproject.toml, not a lockfile")
    assert problems == []


def test_image_healthcheck_targets_health_endpoint() -> None:
    """The image probe is the liveness endpoint, /health."""
    lines = _logical_instructions(_DOCKERFILE.read_text(encoding="utf-8"))
    checks = [line for line in lines if line.upper().startswith("HEALTHCHECK")]
    assert checks == [line for line in checks if "/health" in line and "/__ui__/health" not in line]
    assert len(checks) == 1


def test_image_copies_only_ui_doc_allowlist() -> None:
    """Root Markdown in the image is _UI_DOCS, not every *.md file."""
    text = _DOCKERFILE.read_text(encoding="utf-8")
    problems: list[str] = []
    if "_EXCLUDED_ROOT_DOCS" in text:
        problems.append("Dockerfile still names _EXCLUDED_ROOT_DOCS, which is not a real allow-list")
    copied_markdown: list[str] = []
    for line in _logical_instructions(text):
        if line.upper().startswith("COPY "):
            copied_markdown.extend(source for source in _copy_sources(line) if source.endswith(".md"))
    expected = [name for name, _title in _UI_DOCS]
    if copied_markdown != expected:
        problems.append(
            f"markdown COPY sources are {copied_markdown}, expected the _UI_DOCS allow-list {expected}"
        )
    assert problems == []


def test_dockerignore_excludes_tests_docs_and_local_artifacts() -> None:
    """Tests, local notes, and build artifacts are not part of the image context."""
    present = set(_dockerignore_patterns(_DOCKERIGNORE.read_text(encoding="utf-8")))
    missing = [pattern for pattern in _DOCKERIGNORE_PATTERNS if pattern not in present]
    assert missing == []
