# CI/CD Gates & Branch Protection — `vivarium`

> Implements `@rules/workflow-cicd.md` + `@rules/std-supplychain.md`. CI lives in
> [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). A failing gate **blocks merge** — no
> overrides without a documented, time-boxed, human-approved exception.

## Merge-blocking gates (in order)

| # | Gate | Job · tool | Blocks on |
|---|------|-----------|-----------|
| 1 | Build | `quality` (editable install from hash-pinned lock) | build/import failure |
| 2 | Lint + format | `quality` · ruff (incl. `D` docstrings) | any error |
| 3 | Type-check | `quality` · mypy `--strict` | any error |
| 4 | Unit + coverage | `quality` · pytest | <90% line+branch baseline |
| 4b | **Critical-path coverage 100%** | `quality` · scoped pytest | <100% on critical modules |
| 4c | Forward-compat matrix | `quality-py314` · build/lint/type/test on Python 3.14 | any error on 3.14 |
| 5 | SAST | `sast` · bandit + semgrep | new high/critical |
| 6 | SCA | `sca` · pip-audit | known high/critical CVE w/o waiver |
| 6b | FID-DB license allow-list | `fid-license-gate` · `vivarium.fid_licenses` | disallowed/copyleft/missing SPDX in `deploy/fid/sources.toml` |
| 7 | Secret scan | `secret-scan` · gitleaks | any detected secret |
| 8 | Container/IaC scan | `container-iac-scan` · Trivy | high/critical misconfig |

**FID ELF-match gate** (`fid-elf-match-gate`, in
[`live-regression.yml`](../.github/workflows/live-regression.yml)): a deterministic same-toolchain
ELF FunctionID-match assertion (ADR-043). Path-filtered to **run per-PR on FID-path changes** and a
**required status check** on `main`; cross-toolchain matching stays advisory. The auto-trigger is
gated to same-repo PRs (fork-PR hardening — threat-model §4 delta).

**Critical paths (100% — master §4):** `core.validation`, `core.envelope`, `core.errors`,
`sessions.manager`, `security.limits`, `server.auth`, `jobs.streaming` — the input-validation,
untrusted/error envelopes, session isolation, DoS-limit, authN/authZ, and streaming-job (BOLA +
bounded replay) code (the trust boundaries). Designated in `pyproject.toml`.

**Mutation testing (test quality — master §4):** coverage proves the critical-path tests *execute*
every line; mutation testing proves they *catch faults*. [`mutation.yml`](../.github/workflows/mutation.yml)
runs `mutmut` over the same seven critical modules (config: `pyproject [tool.mutmut]`) on a **weekly
schedule + manual dispatch** — never per-PR (it re-runs the suite per mutant). It is **advisory**
(reports the score to the run summary + uploads a stats artifact); set `MUTATION_SCORE_MIN` > 0 to
turn it into a regression gate once the baseline is confirmed. Baseline at introduction: ~71%
(895 killed / 366 survived / 1261). A failed scheduled run alerts the repo owner (like
`scheduled-rescan.yml`).

**gVisor isolation verification (`gvisor-isolation.yml`).** The ADR-004 worker-isolation drill
(`deploy/verify-isolation.sh`) runs in CI under **real gVisor/runsc** against the pinned,
cosign-verified worker image — asserting all six controls (gVisor kernel, caps dropped, non-root,
no-new-privs, read-only rootfs, no network) from inside the worker. It runs on a **weekly schedule +
manual dispatch** (gated, not a per-PR merge gate — stock runners need a one-time runsc setup the job
performs). A failed scheduled run alerts the repo owner. The per-PR gated real-worker e2e
(`e2e-groundtruth` / `live-regression`) runs under `crun`; this job is the strong-tier (gVisor) check.

**Workflow lint (`lint-workflows.yml` → `actionlint`).** Statically lints the GitHub Actions
workflows AND the shell embedded in their `run:` blocks (actionlint invokes the runner's preinstalled
shellcheck) — covering the security-load-bearing workflow shell: the always-run gate-poll loops (the
anti-false-green linchpin), the four cosign-verify blocks, and the live repin trust-pin orchestration.
Runs on every PR; **promoted from advisory to a REQUIRED merge check in round-9** (Y2 — it had run
green since introduction and the repin flow is now live, so its regressions must block). actionlint is
pinned by version + a checksum-verified download (the repo's Ghidra/zlib supply-chain idiom, no new
marketplace action); `SHELLCHECK_OPTS` baselines only the pervasive SC2155 (`export FOO="$(id -u)"`,
benign) + SC2015 (intentional `… || true`) so it enforces every other code. Trade-off: as a required
gate it adds a CI-time github-release download dependency — low risk (same github as `checkout`,
pinned + integrity-checked, fail-closed on any download/checksum error).

**Fail closed:** an errored or skipped security stage counts as a failure, not a pass.

## Supply-chain integrity (std-supplychain)

- **Actions pinned by commit digest** (`@<sha>`), not tags. The committed workflow uses
  `REPLACE_WITH_DIGEST_FOR_<tag>` placeholders; resolving each to its SHA and pinning it is a
  **GATED** step done before CI runs (no network in WS0).
- **Dependencies:** install from a **hash-pinned lockfile** (`pip install --require-hashes`);
  generating the lock (`pip-compile --generate-hashes` — the project pins with pip-compile) is gated (see the lockfile-intent
  note in `pyproject.toml`).
- **Worker image:** pinned **by digest** (ADR-003); image scan + **SBOM** generation run in the WS3
  build/release workflow (not PR CI). Release artifacts are signed with provenance.

## Branch protection (configure on the GitHub remote — NOT created in WS0)

When the GitHub remote is set up, protect `main` with:

- **Require a pull request** before merging; **≥1 approving review**; security-relevant changes get
  a security-focused review (`workflow-code-review`). Dismiss stale approvals on new commits.
- **Require status checks to pass:** the **required** contexts are `quality`, `quality-py314`,
  `sast`, `sca`, `secret-scan`, `container-iac-scan`, `fid-license-gate`, `fid-elf-match-gate`,
  `image-scan-gate`, `mtls-auth-gate`, and `actionlint` (eleven total); require branches up to date.
  (`image-scan-gate` and `mtls-auth-gate` are always-run gates that internally verify their diff-gated
  matrix legs / integration suite; `actionlint` was promoted from advisory to required in round-9 —
  see the gate notes above; a `test_coverage_markers` tripwire asserts this list stays in sync with
  the gate set — matching each required context to the job's emitted `name:`/key.)
- **Require signed commits** (CI verifies signatures); require **linear history** (squash/rebase
  merge only — no merge bubbles).
- **No force-push / no deletion** of `main`; include administrators.
- **Restrict who can push**; enable **secret scanning** + **push protection** + **Dependabot/
  security updates** at the repo level.
- Least-privilege CI identity via **OIDC**; no long-lived cloud keys; ephemeral runners.

> These are documented here for the human to apply when the remote exists — WS0 does **not** create,
> push, or configure any remote (gated).

**Enforcement verification (V7 — a guard you've never seen go red is unproven).** Applying the
above is not the same as *proving* it. Two checks close that gap:
- **State is confirmed on the remote**, not just documented: query
  `gh api repos/<owner>/<repo>/branches/main/protection` and confirm `required_status_checks.strict:
  true` with **exactly** the ten contexts above, plus `required_signatures.enabled:
  true`, `enforce_admins.enabled: true`, and `required_linear_history.enabled: true`. Record the
  confirmation (date + the returned set) when the set changes — as ADR-043 did for
  `fid-elf-match-gate`. Last confirmed present: **2026-07-03** (round-6; all ten required,
  `strict:true`, signatures + admins + linear history on).
- **Each gate is proven to actually block:** when a check is first promoted to *required*, verify it
  **red-blocks** a merge with a deliberately-failing PR (not just that it runs). A gate that has
  never been observed failing a merge is unverified enforcement.

  **Red-block observation log** (W4 — discharge this per gate; a gate not listed as *observed* is
  structurally-fail-closed-by-inspection but not yet empirically proven to block):
  | Gate | Red-block observed? | Evidence |
  |---|---|---|
  | `fid-elf-match-gate` | ✅ 2026-06-24 | ADR-043 "Required-check VERIFIED end-to-end" |
  | `image-scan-gate` | ✅ 2026-07-03 | PR #274 (closed unmerged): a deliberate build-break in `Containerfile.worker` failed the `image-scan (worker,…)` matrix leg → `image-scan-gate` (requires **all** image-scan legs to complete+succeed) reported **FAILURE** and the PR went **`mergeStateStatus=BLOCKED`**, while `image-scan (server)` + all other required checks stayed green — proving the required gate red-blocks a merge on a failed scan leg. (A first attempt dropped a pinned-vulnerable pip lockfile, but Trivy's image scan didn't register the loose `requirements.txt`; the leg-fail proof is the gate's own requirement. Trivy's HIGH/CRITICAL `exit-code:1` behavior is configured in `infra/trivy.yaml` and upstream-tested.) |
  | `mtls-auth-gate` | ✅ 2026-07-03 | PR #272 (closed unmerged): flipped the mTLS cert-principal assertion to a wrong value → `mtls-auth-gate` reported **FAILURE** and the PR went **`mergeStateStatus=BLOCKED`** while every other required check stayed green (the integration-only break failed that gate alone) — proving the required gate red-blocks a merge |
  | others (`quality`, `sast`, `sca`, `secret-scan`, `container-iac-scan`, `fid-license-gate`, `quality-py314`) | observed implicitly | routinely go red on real failures in normal development |

  > **All required gates are now empirically observed to red-block** (2026-07-03). Each proof used a
  > throwaway deliberately-failing PR, observed the gate report red + the PR go `BLOCKED`, then closed
  > it unmerged. Re-run the applicable proof (and update the row) whenever a gate's failure logic
  > materially changes; a new required gate starts ⏳ **pending** until its first observed red-block.
