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
import re
import tomllib
from pathlib import Path

import pytest

# The SEVEN modules designated 100%-critical (master §4). This tuple is the single source of truth
# the sync tripwire below enforces against the two config copies (CI `--include` + mutmut
# `only_mutate`). server.auth (the HTTP authN/authZ boundary) + jobs.streaming (BOLA + the N4 replay
# window) are the two most security-relevant — added round-4 Q3 after the tripwire was found to
# cover only 5 of the 7 (so a rename of either could have silently dropped it from the 100% gate).
_CRITICAL_MODULES = (
    "vivarium.core.validation",
    "vivarium.core.envelope",
    "vivarium.core.errors",
    "vivarium.sessions.manager",
    "vivarium.security.limits",
    "vivarium.server.auth",
    "vivarium.jobs.streaming",
)

#: The critical modules as coverage/mutmut path globs (``vivarium.core.validation`` →
#: ``*/vivarium/core/validation.py``) — the shape both the CI ``coverage report --include`` list
#: and the mutmut ``only_mutate`` list use. Derived from the SSOT tuple so the sync check is single.
_CRITICAL_GLOBS = frozenset(f"*/{m.replace('.', '/')}.py" for m in _CRITICAL_MODULES)

_REQUIRED_MARKERS = ("critical", "abuse", "integration")

#: The branch-protection **required status checks** on ``main`` (ten total). This is the canonical
#: in-repo record of the merge-blocking gate set: branch protection itself lives in the GitHub API
#: (off-repo), so ``docs/ci-cd.md`` is the human-facing source of truth for what an operator must
#: mark required — and it had silently drifted (round-6 V4: it still listed eight, omitting the two
#: always-run gates added in round-5). The doc-drift tripwire below asserts every one of these
#: appears in ``docs/ci-cd.md``, so adding/removing a required gate without updating the doc fails
#: loudly here rather than leaving an operator to under-protect ``main`` by following a stale list.
_REQUIRED_STATUS_CHECKS = (
    "quality",
    "quality-py314",
    "sast",
    "sca",
    "secret-scan",
    "container-iac-scan",
    "fid-license-gate",
    "fid-elf-match-gate",
    "image-scan-gate",
    "mtls-auth-gate",
)


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
    """All seven critical-path modules remain documented in pyproject (designation not lost).

    The 100%-critical designation lives as an authoritative comment block in pyproject.toml (the
    CI critical-path job reads it). If that block is edited away, the per-path gate loses its
    source of truth — assert every module path is still present in the file text.
    """
    text = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")
    for module in _CRITICAL_MODULES:
        rel = "src/" + module.replace(".", "/") + ".py"
        assert rel in text, f"critical-path designation dropped from pyproject: {rel}"


def _mutmut_only_mutate() -> set[str]:
    """Return the ``[tool.mutmut] only_mutate`` globs from pyproject.toml."""
    cfg = _load_pyproject()
    tool = cfg["tool"]
    assert isinstance(tool, dict)
    mutmut = tool["mutmut"]
    assert isinstance(mutmut, dict)
    only = mutmut["only_mutate"]
    assert isinstance(only, list)
    return {str(g) for g in only}


def _ci_critical_include_globs() -> set[str]:
    """Extract the critical-path ``coverage report --include=<globs>`` set from ci.yml.

    The 100%-critical gate lives in a ``run:`` shell block (not structured YAML), so parse the
    workflow text for the ``--include='a,b,...'`` argument and split it. Fails loudly if the gate
    step can't be found (a rename of the step would otherwise silently void this cross-check).
    """
    import re

    text = (_repo_root() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    m = re.search(r"--include=(['\"])(?P<globs>[^'\"]+)\1", text)
    assert m is not None, "could not find the critical-path `coverage report --include=` in ci.yml"
    return {g.strip() for g in m.group("globs").split(",") if g.strip()}


def test_critical_module_lists_are_in_sync() -> None:
    """The three copies of "the critical set" agree (gap round-4 Q3 — the drift root cause).

    The 100%-coverage gate (ci.yml ``--include``), the mutation-testing scope (pyproject
    ``[tool.mutmut] only_mutate``), and this module's SSOT tuple (``_CRITICAL_GLOBS``) are three
    hand-maintained copies. Nothing else asserts they agree, so they had drifted (the tripwire
    covered 5 of the 7 gated modules). Assert all three are IDENTICAL, so adding/removing/renaming a
    critical module in one place without the others fails this test — not silently weakens a gate.
    """
    ci = _ci_critical_include_globs()
    mutmut = _mutmut_only_mutate()
    assert ci == _CRITICAL_GLOBS, (
        f"ci.yml critical `--include` diverged from the designated set:\n"
        f"  only in ci.yml: {sorted(ci - _CRITICAL_GLOBS)}\n"
        f"  missing from ci.yml: {sorted(_CRITICAL_GLOBS - ci)}"
    )
    assert mutmut == _CRITICAL_GLOBS, (
        f"pyproject [tool.mutmut] only_mutate diverged from the designated set:\n"
        f"  only in mutmut: {sorted(mutmut - _CRITICAL_GLOBS)}\n"
        f"  missing from mutmut: {sorted(_CRITICAL_GLOBS - mutmut)}"
    )


def _ci_cd_doc_text() -> str:
    """Return ``docs/ci-cd.md`` text (the operator-facing CI/branch-protection reference)."""
    return (_repo_root() / "docs" / "ci-cd.md").read_text(encoding="utf-8")


def test_ci_cd_doc_lists_all_required_status_checks() -> None:
    """``docs/ci-cd.md`` names every required status check (round-6 V4 doc-drift tripwire).

    Branch protection lives in the GitHub API (off-repo), so this doc is the source of truth an
    operator follows to mark contexts required. It had drifted — listing eight while ``main``
    actually requires ten (the round-5 ``image-scan-gate`` + ``mtls-auth-gate`` were omitted), so an
    operator applying protection from the doc would leave two gates non-required. Assert each
    canonical required check appears in the doc so this can't silently recur.
    """
    doc = _ci_cd_doc_text()
    missing = [c for c in _REQUIRED_STATUS_CHECKS if f"`{c}`" not in doc]
    assert not missing, f"docs/ci-cd.md omits required status check(s) from its list: {missing}"


def test_ci_cd_doc_lists_all_critical_modules() -> None:
    """``docs/ci-cd.md`` names every 100%-critical module (round-6 V4 doc-drift tripwire).

    The doc's "Critical paths (100%)" line is the human-facing record of the designated set; it had
    dropped ``jobs.streaming`` (and said "six" not "seven"). Assert each critical module's dotted
    name (sans the ``vivarium.`` package prefix, the form the doc uses) appears, so the doc stays in
    sync with the SSOT tuple that the coverage/mutation gates enforce.
    """
    doc = _ci_cd_doc_text()
    missing = [m for m in _CRITICAL_MODULES if f"`{m.removeprefix('vivarium.')}`" not in doc]
    assert not missing, f"docs/ci-cd.md omits critical module(s) from its list: {missing}"


def _workflow_files() -> list[Path]:
    """Return every ``.github/workflows/*.yml`` file (the CI definition set)."""
    return sorted((_repo_root() / ".github" / "workflows").glob("*.yml"))


def test_cosign_identity_regexp_is_tail_anchored_to_refs_tags() -> None:
    """Every worker-image cosign verify anchors the identity to ``@refs/tags/`` (round-8 X7).

    W5 (#271) tail-anchored the cosign ``--certificate-identity-regexp`` at all verify sites so only
    a TAG-built signature verifies (3 of 4 were loose before). Those copies are hand-maintained with
    nothing asserting they stay anchored — the drift the doc/coverage tripwires kill elsewhere.
    Assert any workflow verifying the worker-image identity uses the ``@refs/tags/`` form and NONE
    uses the loose bare-``@`` form (``worker-image.yml@"``).
    """
    anchored = "worker-image.yml@refs/tags/"
    loose = 'worker-image.yml@"'  # bare @ immediately followed by the closing quote (pre-W5 form)
    checked = 0
    offenders: list[str] = []
    for wf in _workflow_files():
        text = wf.read_text(encoding="utf-8")
        if "worker-image.yml@" not in text:  # not a worker-image cosign-verify workflow
            continue
        checked += 1
        if anchored not in text or loose in text:
            offenders.append(wf.name)
    assert not offenders, f"worker-image cosign identity not @refs/tags/-anchored in: {offenders}"
    assert checked >= 4, f"expected >=4 worker-image cosign verify sites, got {checked} (deleted?)"


def test_required_checks_map_to_workflow_jobs() -> None:
    """Every required status check is emitted by a real workflow job (round-8 X8 tripwire).

    The doc-drift tripwire checks the required-check tuple against ``docs/ci-cd.md``, but nothing
    asserts each required context is actually PRODUCED by a job. A renamed job → branch protection
    waits forever for the old context (fail-closed hang) and no test flags it (doc + tuple can stay
    mutually consistent yet both stale). Assert each name appears as a ``^  <name>:`` job key in a
    workflow file.
    """
    texts = [wf.read_text(encoding="utf-8") for wf in _workflow_files()]
    missing = [
        ctx
        for ctx in _REQUIRED_STATUS_CHECKS
        if not any(re.search(rf"^  {re.escape(ctx)}:", t, re.MULTILINE) for t in texts)
    ]
    assert not missing, f"required status check(s) with no matching workflow job: {missing}"
