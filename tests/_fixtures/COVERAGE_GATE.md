# Coverage-gate verification harness (WS5)

How the §4 coverage gates are enforced and verified for `vivarium`. This note is the QA-side
map of the gate wiring; the live tripwire is `tests/unit/test_coverage_markers.py`.

## The two gates (master §4)

1. **Repo-wide baseline — ≥90% line + branch.** Enforced by `--cov-fail-under=90` (with
   `--cov-branch`) in `[tool.pytest.ini_options].addopts` (`pyproject.toml`). CI fails the build
   below it; coverage may not regress on a PR.

2. **100% on critical paths.** A *single number cannot* express this (topic-testing), so it is a
   **separate, path-scoped check**: a dedicated CI job runs coverage scoped to the designated
   critical modules with `--fail-under=100`. The authoritative designation lives as the comment
   block in `pyproject.toml` and is mirrored in `_CRITICAL_MODULES` in the marker test:

   | Critical module | Trust boundary / reason |
   |---|---|
   | `src/vivarium/core/validation.py` | TB1 — client tool-arg validation |
   | `src/vivarium/core/envelope.py`   | TB4 — untrusted-data + wrap chokepoint |
   | `src/vivarium/core/errors.py`     | safe, leak-free error surface |
   | `src/vivarium/sessions/manager.py`| session isolation / eviction / BOLA |
   | `src/vivarium/security/limits.py` | DoS bounds enforced before the worker |

   Example critical-path job (run after the implementations land — Wave-2):

   ```sh
   pytest -m critical \
     --cov=vivarium.core.validation \
     --cov=vivarium.core.envelope \
     --cov=vivarium.core.errors \
     --cov=vivarium.sessions.manager \
     --cov=vivarium.security.limits \
     --cov-branch --cov-fail-under=100
   ```

## Markers

- `critical` — critical-path tests (the per-path 100% job selects on `-m critical`).
- `abuse` — adversarial/abuse-path tests (WS4): decompile-bomb, injection, BOLA, exhaustion.
- `integration` — requires a real Ghidra worker; **excluded** from the unit/coverage job
  (gated image pull/run — PLAN §6) and skipped unless `VIVARIUM_INTEGRATION=1`.

All three are declared in `pyproject.toml` and run under `--strict-markers`, so an unregistered
mark is an error. `tests/unit/test_coverage_markers.py` additionally asserts they stay registered
and that the critical modules import under their frozen paths (rename/omit-drift tripwires).

## Verify the gate actually fails (topic-testing — no green negatives)

A gate you have never seen go red is unproven. To confirm the gates *catch* violations, use a
**public-named** fixture (a leading-underscore module is treated as private and may be exempted):

- **Baseline:** add a temporary public-named module under `src/vivarium/` with an uncovered
  branch and confirm `--cov-fail-under=90` **fails** (then remove it). Do not name the probe with
  a leading underscore.
- **Critical 100%:** drop one line of coverage from a critical module's tests and confirm the
  `--fail-under=100` job **fails** for that path.
- **Marker strictness:** apply an unregistered marker in a throwaway test and confirm
  `--strict-markers` errors.
- **Mutation (Wave-2):** run a mutation pass (e.g. mutmut/cosmic-ray) on the critical modules so
  coverage isn't gamed — coverage is a floor, mutation proves the suite catches injected faults.

> **No vacuous 100%-critical.** The five modules above ARE critical paths (validation, the
> untrusted/error envelopes, session isolation, DoS limits); the 100% claim is real, not asserted
> over a project with no critical paths.

## Wave-1 status (contracts only)

In Wave-1 the implementation modules are reserved `NotImplementedError` stubs, so the real
critical-path coverage cannot yet be measured. Wave-1 ships the *infrastructure* the gate runs on
(fakes, synthetic builders, harness scaffolds, the marker tripwire). **Wave-2** (post-integration)
wires the behavior + abuse coverage that drives the critical modules to 100% and reconciles the
stub-guard suite. See the QA hand-off note in the WS5 delivery summary.
