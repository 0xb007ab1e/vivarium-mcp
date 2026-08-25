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
import yaml

# The NINE modules designated 100%-critical (master §4). This tuple is the single source of truth
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
    "vivarium.core.debuglink",
    "vivarium.core.uimage",
)

#: The critical modules as coverage/mutmut path globs (``vivarium.core.validation`` →
#: ``*/vivarium/core/validation.py``) — the shape both the CI ``coverage report --include`` list
#: and the mutmut ``only_mutate`` list use. Derived from the SSOT tuple so the sync check is single.
_CRITICAL_GLOBS = frozenset(f"*/{m.replace('.', '/')}.py" for m in _CRITICAL_MODULES)

_REQUIRED_MARKERS = ("critical", "abuse", "integration")

#: The branch-protection **required status checks** on ``main`` (eleven). This is the canonical
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
    "actionlint",  # round-9 Y2: promoted from advisory to required (lint-workflows.yml)
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
    """All nine critical-path modules remain documented in pyproject (designation not lost).

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


def test_cosign_identity_regexp_is_anchored_to_a_ref() -> None:
    """Every worker-image cosign verify anchors the identity to ``@refs/(heads|tags)/``.

    W5 (#271) tail-anchored the cosign ``--certificate-identity-regexp`` at all verify sites so a
    LOOSE bare-``@`` no longer matches (3 of 4 were loose before). The anchor was originally
    ``@refs/tags/`` (tag-built only), but that makes a worker-code PR unverifiable pre-release
    (chicken-and-egg: the branch-built image is signed ``@refs/heads/<branch>`` and live-regression
    could never trust it before a tag exists). It is now ``@refs/(heads|tags)/`` — still the strong
    guarantee that the image was built + keyless-signed by THIS repo's ``worker-image.yml`` OIDC
    identity from a real ref, just not requiring a release tag; the loose bare-``@`` remains
    forbidden. Assert every worker-image cosign-verify workflow uses the anchored form and NONE the
    loose form (``worker-image.yml@"``).
    """
    anchored = "worker-image.yml@refs/(heads|tags)/"
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
    assert not offenders, f"cosign identity not @refs/(heads|tags)/-anchored in: {offenders}"
    assert checked >= 4, f"expected >=4 worker-image cosign verify sites, got {checked} (deleted?)"


def _job_contexts_from_text(text: str) -> set[str]:
    """The status-check contexts one workflow emits: each job's ``name:`` if set, else its job key.

    GitHub reports a job's ``name`` as the check context when present, falling back to the key — so
    the required-check ↔ job mapping must resolve the EMITTED context, not just the key.
    """
    data = yaml.safe_load(text)
    jobs = (data or {}).get("jobs") or {}
    contexts: set[str] = set()
    for key, job in jobs.items():
        name = job.get("name") if isinstance(job, dict) else None
        contexts.add(str(name) if name else str(key))
    return contexts


def _emitted_check_contexts() -> set[str]:
    """Union of the status-check contexts emitted across all workflow files."""
    contexts: set[str] = set()
    for wf in _workflow_files():
        contexts |= _job_contexts_from_text(wf.read_text(encoding="utf-8"))
    return contexts


def test_job_context_resolution_prefers_name_over_key() -> None:
    """Y1 regression: a job's EMITTED context is its ``name:`` (not its key) when ``name:`` is set.

    This is the exact resolution the round-8 X8 tripwire got wrong (it grepped the key only), so a
    job overriding ``name:`` could drift its emitted context past the check. Pin the resolution.
    """
    text = (
        "jobs:\n"
        "  mykey:\n"
        "    name: my-emitted-name\n"
        "    runs-on: ubuntu-latest\n"
        "  plainkey:\n"
        "    runs-on: ubuntu-latest\n"
    )
    ctxs = _job_contexts_from_text(text)
    assert "my-emitted-name" in ctxs  # name wins
    assert "mykey" not in ctxs  # the KEY is NOT the emitted context when name is set (the Y1 gap)
    assert "plainkey" in ctxs  # no name → the key is the context


def test_required_checks_map_to_workflow_jobs() -> None:
    """Every required status check is EMITTED by a real workflow job (round-8 X8; round-9 Y1 fix).

    The doc-drift tripwire checks the required-check tuple against ``docs/ci-cd.md``, but nothing
    asserts each required context is actually PRODUCED by a job. A renamed job → branch protection
    waits forever for the old context (fail-closed hang) and no test flags it (doc + tuple can stay
    mutually consistent yet both stale). Y1: the check now resolves each job's EMITTED context
    (``name:`` if set, else key) rather than only the key — ``image-scan-gate`` and
    ``fid-elf-match-gate`` both set ``name:`` (== key today), so a future ``name:`` change without a
    key rename would otherwise slip through (branch protection hangs while this stays green).
    """
    contexts = _emitted_check_contexts()
    missing = [c for c in _REQUIRED_STATUS_CHECKS if c not in contexts]
    assert not missing, f"required status check(s) with no matching emitted job context: {missing}"


def _load_workflow(name: str) -> dict[str, object]:
    """Parse a single ``.github/workflows/<name>`` file to a dict."""
    text = (_repo_root() / ".github" / "workflows" / name).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert isinstance(data, dict), f"{name} did not parse to a mapping"
    return data


def _shell_var(text: str, var: str) -> str:
    """Extract a ``VAR="value"`` (or ``VAR: "value"``) literal from workflow shell/env text."""
    import re

    m = re.search(rf'{re.escape(var)}\s*[:=]\s*"([^"]+)"', text)
    assert m, f"could not find {var} in the workflow"
    return m.group(1)


def test_gate_sibling_name_couplings_match_real_jobs() -> None:
    """Y8 (round-9): the always-run gates poll sibling jobs BY NAME — pin those couplings.

    ``fid-elf-match-gate`` (``live-regression.yml``) and ``image-scan-gate`` (``image-scan-pr.yml``)
    each carry a bounded "the sibling never appeared → fail LOUD" guard keyed on a hard-coded job
    name/prefix + expected leg count. That is fail-closed (not a false-green), but the coupling
    itself is unchecked: renaming the polled job (or adding/removing a matrix leg) without the
    gate's ``SIBLING``/``PREFIX``/``EXPECTED_LEGS`` turns the fast-fail into a 5-minute "never
    appeared" abort on every gated PR. Assert the constants still match the real jobs.
    """
    # --- fid-elf-match-gate → sibling `live-regression` (by emitted name) ---
    lr_text = (_repo_root() / ".github" / "workflows" / "live-regression.yml").read_text(
        encoding="utf-8"
    )
    sibling = _shell_var(lr_text, "SIBLING")
    lr_contexts = _job_contexts_from_text(lr_text)
    assert sibling in lr_contexts, (
        f"fid-elf-match-gate polls a sibling named {sibling!r}, but no job in live-regression.yml "
        f"emits that context (emitted: {sorted(lr_contexts)})"
    )

    # --- image-scan-gate → matrix legs of the `image-scan` job (name prefix + leg count) ---
    isc = _load_workflow("image-scan-pr.yml")
    isc_text = (_repo_root() / ".github" / "workflows" / "image-scan-pr.yml").read_text(
        encoding="utf-8"
    )
    prefix = _shell_var(isc_text, "PREFIX")  # e.g. "image-scan ("
    expected_legs = int(_shell_var(isc_text, "EXPECTED_LEGS"))
    jobs = isc.get("jobs")
    assert isinstance(jobs, dict) and "image-scan" in jobs, "image-scan job missing"
    scan_job = jobs["image-scan"]
    assert isinstance(scan_job, dict)
    # GitHub auto-names matrix legs "<emitted job name> (<matrix values>)"; the gate matches that
    # prefix. The emitted name is the job's `name:` if set, else the key.
    emitted = str(scan_job.get("name") or "image-scan")
    want_prefix = f"{emitted} ("
    assert prefix == want_prefix, (
        f"image-scan-gate matches leg prefix {prefix!r}, but image-scan emits legs {want_prefix!r}"
    )
    strategy = scan_job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    include = matrix.get("include") if isinstance(matrix, dict) else None
    assert isinstance(include, list) and len(include) == expected_legs, (
        f"image-scan-gate expects {expected_legs} matrix legs, but the image-scan matrix has "
        f"{len(include) if isinstance(include, list) else '?'}"
    )
