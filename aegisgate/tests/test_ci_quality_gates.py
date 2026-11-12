"""CI quality gates are required checks.

The workflow file is the contract: coverage below the floor fails the job,
Codecov is given the v4 ``files`` input, and lint, typecheck, dependency
audit, and image build each run once on Python 3.12 (the image job has no
Python matrix). Advisory ``continue-on-error`` does not satisfy any of these.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_PYPROJECT = _REPO_ROOT / "pyproject.toml"

_RUFF_SELECT = "E9,F63,F7,F82"
_DEV_TOOLS = ("ruff", "mypy", "pip-audit")


def _load_workflow() -> dict:
    loaded = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _jobs() -> dict:
    jobs = _load_workflow()["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def _job(name: str) -> dict:
    jobs = _jobs()
    assert name in jobs, f"missing job {name!r}; have {sorted(jobs)}"
    job = jobs[name]
    assert isinstance(job, dict)
    return job


def _steps(job: dict) -> list[dict]:
    steps = job.get("steps") or []
    assert isinstance(steps, list)
    return [step for step in steps if isinstance(step, dict)]


def _runs(job: dict) -> str:
    return "\n".join(
        step["run"] for step in _steps(job) if isinstance(step.get("run"), str)
    )


def _python_version(job: dict) -> str:
    for step in _steps(job):
        if str(step.get("uses") or "").startswith("actions/setup-python@"):
            with_ = step.get("with") or {}
            assert isinstance(with_, dict)
            return str(with_.get("python-version"))
    raise AssertionError("job does not set up Python")


def _assert_single_python_312(job: dict) -> None:
    """Required check: one Python, and a failure is a failure."""
    assert job.get("continue-on-error") is not True
    for step in _steps(job):
        assert step.get("continue-on-error") is not True
    strategy = job.get("strategy") or {}
    assert isinstance(strategy, dict)
    matrix = strategy.get("matrix") or {}
    assert isinstance(matrix, dict)
    versions = matrix.get("python-version")
    assert versions in (None, "3.12", ["3.12"]), versions
    if any(
        str(step.get("uses") or "").startswith("actions/setup-python@")
        for step in _steps(job)
    ):
        assert _python_version(job) == "3.12"


def _invokes(runs: str, tool: str) -> bool:
    return (
        re.search(
            rf"(?m)(?:^|[;&|]\s*)(?:python(?:3)? -m )?{re.escape(tool)}\b",
            runs,
        )
        is not None
    )


def test_coverage_floor_fails_the_build() -> None:
    floor_steps = [
        step
        for step in _steps(_job("test"))
        if step.get("name") == "Check coverage floor"
    ]
    assert len(floor_steps) == 1
    assert "continue-on-error" not in floor_steps[0]

    pyproject = _PYPROJECT.read_text(encoding="utf-8")
    assert re.search(r"(?m)^fail_under\s*=\s*75\s*$", pyproject)


def test_codecov_action_uses_files_input() -> None:
    uploads = [
        step
        for step in _steps(_job("test"))
        if "codecov/codecov-action@" in str(step.get("uses") or "")
    ]
    assert len(uploads) == 1
    with_ = uploads[0].get("with") or {}
    assert isinstance(with_, dict)
    assert with_.get("files") == "coverage.xml"
    assert "file" not in with_


def test_ruff_job_is_a_required_python_312_check() -> None:
    job = _job("ruff")
    _assert_single_python_312(job)
    runs = _runs(job)
    assert _invokes(runs, "ruff check") or _invokes(runs, "ruff")
    normalized = re.sub(r",\s+", ",", runs)
    match = re.search(r"--select(?:=|\s+)([A-Za-z0-9,]+)", normalized)
    assert match is not None, runs
    assert match.group(1) == _RUFF_SELECT
    assert ".[dev" in runs


def test_mypy_job_is_a_required_python_312_check() -> None:
    job = _job("mypy")
    _assert_single_python_312(job)
    runs = _runs(job)
    assert _invokes(runs, "mypy")
    assert ".[dev" in runs
    # Production modules only. The test suite is a separate, pre-existing
    # typing backlog and is not part of this required check.
    assert re.search(r"--exclude(?:=|\s+)\S*tests", runs)


def test_pip_audit_job_is_a_required_python_312_check() -> None:
    job = _job("pip-audit")
    _assert_single_python_312(job)
    runs = _runs(job)
    assert _invokes(runs, "pip-audit")
    assert ".[dev" in runs


def test_docker_build_job_builds_without_pushing() -> None:
    job = _job("docker")
    _assert_single_python_312(job)
    runs = _runs(job)
    assert "docker build" in runs
    assert "docker push" not in runs
    rendered = yaml.safe_dump(job)
    assert "push: true" not in rendered


def test_quality_tools_live_only_in_dev_extras() -> None:
    text = _PYPROJECT.read_text(encoding="utf-8")
    runtime, dev, _rest = _split_dependency_blocks(text)
    for tool in _DEV_TOOLS:
        assert re.search(rf'"{re.escape(tool)}[>=<\[]', dev), tool
        assert tool not in runtime


def _split_dependency_blocks(text: str) -> tuple[str, str, str]:
    """Return (runtime dependencies, dev extra, everything after dev)."""
    dep_at = text.index("dependencies = [")
    optional_at = text.index("[project.optional-dependencies]", dep_at)
    dev_at = text.index("dev = [", optional_at)
    dev_end = text.index("]", dev_at)
    return text[dep_at:optional_at], text[dev_at : dev_end + 1], text[dev_end + 1 :]
