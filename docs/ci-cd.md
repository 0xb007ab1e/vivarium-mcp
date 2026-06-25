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
`sessions.manager`, `security.limits`, `server.auth` — the input-validation, untrusted/error
envelopes, session isolation, DoS-limit, and authN/authZ code (the trust boundaries). Designated in
`pyproject.toml`.

**Fail closed:** an errored or skipped security stage counts as a failure, not a pass.

## Supply-chain integrity (std-supplychain)

- **Actions pinned by commit digest** (`@<sha>`), not tags. The committed workflow uses
  `REPLACE_WITH_DIGEST_FOR_<tag>` placeholders; resolving each to its SHA and pinning it is a
  **GATED** step done before CI runs (no network in WS0).
- **Dependencies:** install from a **hash-pinned lockfile** (`pip install --require-hashes`);
  generating the lock (`uv lock` / `pip-compile --generate-hashes`) is gated (see the lockfile-intent
  note in `pyproject.toml`).
- **Worker image:** pinned **by digest** (ADR-003); image scan + **SBOM** generation run in the WS3
  build/release workflow (not PR CI). Release artifacts are signed with provenance.

## Branch protection (configure on the GitHub remote — NOT created in WS0)

When the GitHub remote is set up, protect `main` with:

- **Require a pull request** before merging; **≥1 approving review**; security-relevant changes get
  a security-focused review (`workflow-code-review`). Dismiss stale approvals on new commits.
- **Require status checks to pass:** the **required** contexts are `quality`, `quality-py314`,
  `sast`, `sca`, `secret-scan`, `container-iac-scan`, `fid-license-gate`, and `fid-elf-match-gate`;
  require branches up to date.
- **Require signed commits** (CI verifies signatures); require **linear history** (squash/rebase
  merge only — no merge bubbles).
- **No force-push / no deletion** of `main`; include administrators.
- **Restrict who can push**; enable **secret scanning** + **push protection** + **Dependabot/
  security updates** at the repo level.
- Least-privilege CI identity via **OIDC**; no long-lived cloud keys; ephemeral runners.

> These are documented here for the human to apply when the remote exists — WS0 does **not** create,
> push, or configure any remote (gated).
