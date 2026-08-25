# Contributing to Vivarium

Thanks for your interest. Vivarium is a security-focused tool (it runs hostile binaries through
Ghidra inside a hardened, disposable worker and exposes read-only analysis to LLM clients), so the
contribution bar leans toward **correctness, containment, and evidence**. This guide is the
practical workflow; the deeper "why" lives in the [ADRs](docs/adr/) and the
[threat model](docs/security/threat-model.md).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules (non-negotiable)

- **`main` is protected.** No direct pushes. Every change lands via a pull request with green CI.
- **Signed commits.** Commits must be cryptographically signed (GPG/SSH) and authored with the
  GitHub noreply email; CI verifies signatures and history is linear (squash/rebase, no merge bubbles).
- **Conventional Commits.** `type(scope): summary` — `feat`, `fix`, `docs`, `refactor`, `test`,
  `chore`, `build`, `ci`, `perf`, `security`. Imperative mood, ≤72-char subject, atomic commits.
- **Docs in the same PR.** New/changed public behavior updates the docs and the `CHANGELOG.md`
  `[Unreleased]` section in the same PR (a docstring/`ruff D` gate and a changelog check enforce this).
- **No secrets, ever.** Secrets come from a secret manager at runtime, never the repo. A secret scan
  blocks merge on any detected credential.

## Local setup

Requires **Python 3.12+** and a container runtime (podman/docker; gVisor `runsc` in production) for
the worker-backed integration tests.

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Common commands (there is no Makefile — run the tools directly):

```bash
ruff check .            # lint
ruff format --check .   # formatting (CI runs BOTH check and format --check)
mypy                    # strict type-check (reads pyproject: files = src, tests)
pytest -m "not integration"   # fast unit + coverage suite (hermetic, no worker)
```

Integration tests that drive a real worker are marked `integration` and skipped by default; they run
in the `live-regression` CI job against the pinned, signed worker image. See
[worker-change validation](docs/getting-started.md) if you touch worker-side code
(`src/vivarium/ghidra/_jvm_bridge.py` is baked into the image — a change isn't exercised until the
image is rebuilt and the pin bumped).

## The CI gates (all merge-blocking)

Your PR must pass the required checks (branch protection enforces them — see
[docs/ci-cd.md](docs/ci-cd.md) for the authoritative list and details):

`quality` (build + ruff + mypy + unit/coverage: ≥90% line+branch, **100% on the designated critical
modules**) · `quality-py314` (forward-compat) · `sast` (bandit + semgrep) · `sca` (pip-audit) ·
`secret-scan` (gitleaks) · `container-iac-scan` (Trivy) · `fid-license-gate` · `fid-elf-match-gate` ·
`image-scan-gate` · `mtls-auth-gate` · `actionlint`.

Plus scheduled drills: mutation testing (`mutation.yml`) and the gVisor isolation drill
(`gvisor-isolation.yml`).

A failing or skipped gate is a failure — fix it, don't work around it. If you add a test that must
run against the real worker, add it to the `live-regression` hard-gate list and bump the fail-loud
floor.

## Automated & AI-agent contributors

Agents (Claude Code, CI bots, or any automated contributor) are held to the **same rules as humans —
no exceptions and no drift.** The conventions below are enforced by machine, not trust, precisely so
an agent cannot quietly change style, relax a gate, or alter a contract.

**Authoritative rules for agents.** The repo-root [`CLAUDE.md`](CLAUDE.md) is the agent ground truth
(it inherits the maintainer's global SSDLC ruleset); this `CONTRIBUTING.md`, the [ADRs](docs/adr/),
the frozen [contracts](docs/contracts/), and [docs/ci-cd.md](docs/ci-cd.md) are binding. An agent
reads these first and conforms to them — it does not invent its own conventions.

**Agents MUST NOT:**

- **Relax, skip, or bypass any CI gate**, or edit gate/tooling config (ruff, mypy, coverage
  thresholds, `.trivyignore`, the required-check list) to make a red gate green. The config is the
  single source of truth for style/typing/coverage — code conforms to the config, never the reverse.
- **Change formatting, lint, or naming conventions.** `ruff format` + `ruff check` + `mypy --strict`
  define the style; run them, don't override them (no blanket `# noqa`, `# type: ignore`, or
  `per-file-ignores` to dodge a rule — a genuine exception is narrow, inline, and justified).
- **Alter a frozen contract** (`docs/contracts/*`, the RPC protocol, the untrusted-data/error
  envelope, the tool catalog) or the designated **critical-module set** without an ADR and human
  approval.
- **Self-approve a gated action.** Commit signing, pushing, opening/merging PRs, deploys, tag/release,
  secret operations, and image pin bumps are **human-gated** (`workflow-gated-actions`). An agent
  prepares them and stops; it never merges its own work.
- **Weaken a containment invariant** (ADR-001/002/004/005) or a threat-model mitigation.

**Why drift can't land (enforcement, not etiquette).** Branch protection requires **signed commits +
linear history + the full required-check set**; the `quality` gate runs both `ruff check .` **and**
`ruff format --check .` plus `mypy` and the 90%/100%-critical coverage floor; and a set of **lock-step
tripwires** fails the build if an agent's change drifts out of sync — `test_coverage_markers` keeps
the critical-module set / required-checks list / mutmut config identical across their four sources,
`changelog-check` requires a CHANGELOG entry, and the doc-drift tripwires catch a stale ci-cd/version
claim. A style or gate regression is therefore *caught by the gates*, not left to an agent to police.

If an agent believes a rule or gate is genuinely wrong, the move is to **raise it for a human
decision (an ADR or an issue)** — never to route around it.

## Design decisions & the containment model

Before changing architecture, read the load-bearing invariants — a PR that violates one will be
rejected:

- **ADR-001** — the server process **never loads the JVM or parses a binary**; all Ghidra work is in
  the out-of-process worker.
- **ADR-002** — one disposable worker per session, **killed on timeout/eviction** with a verified
  store wipe.
- **ADR-004** — worker isolation tier (non-root, read-only rootfs, dropped caps, no network, seccomp,
  gVisor).
- **ADR-005** — all binary-derived output is wrapped in the **untrusted-data envelope**; never
  execute, eval, render, or follow it.

Significant design changes get an **ADR**: copy the numbering + structure of an existing
[`docs/adr/`](docs/adr/) file (Status / Date / Context / Decision / Consequences), append-only, and
link it from `docs/adr/README.md`. New services or trust-boundary changes also get a threat-model
update.

## Pull requests

- Keep PRs small and single-purpose; large diffs get split.
- The description states **what, why, risk, and test evidence** (and any security/privacy impact).
- Security-relevant changes (auth, crypto, the worker, CI, data handling) get a security-focused
  review.
- All gates green before review is requested.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).
