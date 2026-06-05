"""Fast guard that the coverage-gate wiring stays intact (WS5 — gate verification).

The §4 coverage gates are enforced by configuration (``pyproject.toml``) and CI jobs, not by the
test runtime — so a misconfiguration (a dropped marker, a renamed critical module, a broken omit)
could silently weaken the gate without any test going red. This module is a cheap, fast tripwire:

- the ``critical`` / ``abuse`` / ``integration`` markers are registered (``--strict-markers`` would
  otherwise turn an unregistered mark into an error only where it is *used*, not where it is
  *missing*);
- each designated 100%-critical module is importable under its frozen path (a rename would break
  the per-path critical-coverage job, so catch it here);
- the worker-side JVM bridge that is deliberately omitted from coverage still exists at its
  declared path (a moved file would silently void the omit).

It does NOT itself measure coverage — that is the coverage tool's job — it guards that the wiring
the gate depends on has not drifted (topic-testing: a guard you've never seen go red is unproven;
this one fails loudly if the designation is broken).
"""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest

# The four modules designated 100%-critical in pyproject.toml + the session manager
# (validation, envelope, errors, sessions.manager, security.limits — CLAUDE.md task brief).
_CRITICAL_MODULES = (
    "ghidra_mcp.core.validation",
    "ghidra_mcp.core.envelope",
    "ghidra_mcp.core.errors",
    "ghidra_mcp.sessions.manager",
    "ghidra_mcp.security.limits",
)

_REQUIRED_MARKERS = ("critical", "abuse", "integration")


def _repo_root() -> Path:
    """Return the repository root (two levels up from this test file: tests/unit → repo)."""
    return Path(__file__).resolve().parents[2]


def _load_pyproject() -> dict[str, object]:
    """Parse ``pyproject.toml`` from the repo root."""
    with (_repo_root() / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)


def test_required_markers_registered_in_config() -> None:
    """The critical/abuse/integration markers are declared in pytest config (--strict-markers)."""
    cfg = _load_pyproject()
    tool = cfg["tool"]
    assert isinstance(tool, dict)
    pytest_cfg = tool["pytest"]
    assert isinstance(pytest_cfg, dict)
    ini = pytest_cfg["ini_options"]
    assert isinstance(ini, dict)
    markers = ini["markers"]
    assert isinstance(markers, list)
    declared = {str(m).split(":", 1)[0].strip() for m in markers}
    missing = [m for m in _REQUIRED_MARKERS if m not in declared]
    assert not missing, f"markers missing from pyproject pytest config: {missing}"


def test_required_markers_visible_to_pytest(pytestconfig: pytest.Config) -> None:
    """The markers are visible to the running pytest (registered, usable without a warning)."""
    registered = {line.split(":", 1)[0].strip() for line in pytestconfig.getini("markers")}
    for marker in _REQUIRED_MARKERS:
        assert marker in registered, f"marker {marker!r} not registered with pytest"


@pytest.mark.parametrize("module_path", _CRITICAL_MODULES)
def test_critical_modules_importable(module_path: str) -> None:
    """Each designated 100%-critical module imports under its frozen path (rename tripwire)."""
    module = importlib.import_module(module_path)
    assert module is not None


def test_coverage_omit_target_exists() -> None:
    """The coverage-omitted JVM bridge still exists at its declared path (omit-drift tripwire)."""
    cfg = _load_pyproject()
    tool = cfg["tool"]
    assert isinstance(tool, dict)
    coverage = tool["coverage"]
    assert isinstance(coverage, dict)
    run = coverage["run"]
    assert isinstance(run, dict)
    omit = run["omit"]
    assert isinstance(omit, list)
    for rel in omit:
        target = _repo_root() / str(rel)
        assert target.is_file(), f"coverage omit path no longer exists: {rel}"


def test_baseline_fail_under_is_at_least_ninety() -> None:
    """The repo-wide baseline coverage floor is >=90% (master §4 baseline, not weakened)."""
    cfg = _load_pyproject()
    tool = cfg["tool"]
    assert isinstance(tool, dict)
    pytest_cfg = tool["pytest"]
    assert isinstance(pytest_cfg, dict)
    ini = pytest_cfg["ini_options"]
    assert isinstance(ini, dict)
    addopts = ini["addopts"]
    assert isinstance(addopts, list)
    fail_under = [opt for opt in addopts if str(opt).startswith("--cov-fail-under=")]
    assert fail_under, "no --cov-fail-under baseline configured"
    threshold = int(str(fail_under[0]).split("=", 1)[1])
    assert threshold >= 90, f"baseline coverage floor weakened below 90%: {threshold}"


def test_critical_modules_designated_in_pyproject_comment() -> None:
    """The four critical-path modules remain documented in pyproject (designation not lost).

    The 100%-critical designation lives as an authoritative comment block in pyproject.toml (the
    CI critical-path job reads it). If that block is edited away, the per-path gate loses its
    source of truth — assert the module paths are still present in the file text.
    """
    text = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")
    for rel in (
        "src/ghidra_mcp/core/validation.py",
        "src/ghidra_mcp/core/envelope.py",
        "src/ghidra_mcp/sessions/manager.py",
        "src/ghidra_mcp/security/limits.py",
    ):
        assert rel in text, f"critical-path designation dropped from pyproject: {rel}"
