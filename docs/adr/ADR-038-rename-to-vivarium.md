# ADR-038: Rename the project `ghidra-mcp` → `Vivarium`

- **Status:** Accepted (v1.7; human-ratified 2026-06-19). Ratified: **D2 = clean break to `VIVARIUM_*`,
  no `GHIDRA_MCP_*` fallback**; **D6 = `v0.9.0`** (stay pre-1.0); **D7 = no compat shims** beyond GitHub's
  automatic repo redirect (no env fallback, no `ghidra-mcp` console-script alias — clean break).
- **Date:** 2026-06-19
- **Deciders:** Human (ratifies the name — done — plus the load-bearing decisions D2 env-prefix, D6 version,
  D7 compat below) + PM; recorded by the Software Architect.
- **Context source:** the incumbent `ghidra-mcp` / `GhidraMCP` namespace is crowded (LaurieWired/GhidraMCP,
  bethington/ghidra-mcp, suidpit/ghidra-mcp, `ghidramcp` on PyPI, …). A distinct name avoids confusion.
  **Vivarium** was chosen + availability-confirmed clear (PyPI/npm/crates `vivarium-mcp` free; no RE/MCP
  GitHub repo or MCP-registry entry named "vivarium").

## Context

The project is at **v0.8.0** with published, signed artifacts (`ghcr.io/0xb007ab1e/ghidra-mcp-{worker,server}`),
a release history, and ~457 `ghidra_mcp` code references (90 files) + ~612 `GHIDRA_MCP_*` env references.
Renaming touches the Python package, the env-var contract, the MCP server display name, the CI/image
pipeline, the GitHub repo, and docs — so it is a deliberate **migration**, not a find-replace. This ADR
fixes the decisions and the cutover; execution happens on one branch + PR after ratification.

**Naming principle (important):** the project is renamed; it does **not** stop being a Ghidra front end.
"Ghidra" stays everywhere it refers to *the engine* ("Vivarium — a secure MCP server exposing **Ghidra**…").
Only the **project identity** changes. Vivarium = a sealed enclosure to safely keep + observe a live,
dangerous specimen → the per-session isolated hostile-binary worker (contain) you then inspect (reveal).

## Decisions

- **D1 — Python import package `ghidra_mcp` → `vivarium-mcp`.** Rename `src/ghidra_mcp/` → `src/vivarium/`;
  rewrite all `import ghidra_mcp` / `from ghidra_mcp…` across src, tests, scripts, and the `worker`
  package (which imports the bridge). `pyproject` `packages`, `[project.scripts]` (`ghidra-mcp` →
  `vivarium = "vivarium.__main__:main"`), `__main__` (`python -m vivarium`). Distribution name
  `ghidra-mcp` → `vivarium-mcp`; authors/URLs updated. Mechanical but large (≈457 refs).

- **D2 — Env-var prefix `GHIDRA_MCP_*` → `VIVARIUM_*` — RATIFIED: clean break, no fallback.** ≈612 refs
  renamed outright; the server reads only `VIVARIUM_*`. Justified pre-1.0 with no known external
  deployments. **Consequence:** the local real-worker / acceptance / verify recipes (and the
  `[[acceptance-run-recipe]]` memory) use `GHIDRA_MCP_*` and MUST be updated in lockstep, or they break
  on the next run.

- **D3 — MCP server display name `_SERVER_NAME` `"ghidra-mcp"` → `"vivarium"`** (`server/app.py:45`).
  Client-visible (the MCP handshake name). Aligns the protocol identity with the brand.

- **D4 — Container images `ghidra-mcp-{worker,server}` → `vivarium-{worker,server}`** on ghcr.io
  (Containerfiles, `worker-image.yml`, `scheduled-rescan.yml`, `live-regression.yml`, `e2e-groundtruth.yml`,
  `deploy/*`). **GATED** (publishes new image packages on the next tag). Old `ghidra-mcp-*` images **stay**
  as historical artifacts (not deleted). The new images publish on the first post-rename release tag.

- **D5 — GitHub repo `0xb007ab1e/ghidra-mcp` → `0xb007ab1e/vivarium-mcp`.** **GATED, outward-facing.** GitHub
  auto-redirects the old path (clones, links, and the v0.8.0 release URLs keep working), so this is low-risk
  but must be a deliberate, human-performed step. Update the `pyproject`/README URLs to the new path after.

- **D6 — Version on cutover — RATIFIED: `v0.9.0`** (stay pre-1.0). The rename changes the import package +
  env contract + server name (breaking for any consumer), but capabilities are unchanged and a 1.0 should
  be earned by a stability declaration, not a rename.

- **D7 — Compatibility shims — RATIFIED: none, beyond GitHub's automatic repo redirect.** No `GHIDRA_MCP_*`
  env fallback (consistent with D2's clean break), no `ghidra-mcp` console-script alias, and no PyPI
  `ghidra-mcp` shim release (the project was never published to PyPI under that name — nothing to redirect).
  GitHub auto-redirects the old repo path for links/clones (D5), which is the only carried-over
  compatibility. Justified pre-1.0 with no known external consumers.

- **D8 — Do NOT rewrite history.** Historical ADRs (001–037), CHANGELOG entries `[0.1.0]…[0.8.0]`, and the
  roadmaps are an immutable record — they keep "ghidra-mcp" as it was. Only **forward-facing** docs are
  rebranded: `README.md`, `CLAUDE.md`, `PLAN.md`, `docs/contracts/*`, `deploy/*`, this ADR, and a new
  CHANGELOG `[0.9.0]` entry documenting the rename + the env migration. (A one-line "formerly ghidra-mcp"
  note is added at the top of PLAN.md/README for discoverability.)

## Execution plan (one branch, sequenced; gated steps surfaced)

1. **Code+config sweep (non-gated, on branch):** rename `src/ghidra_mcp/`→`src/vivarium/` (`git mv`);
   mechanical rewrite of imports + module refs; `pyproject` identity/scripts/packages; `_SERVER_NAME`;
   env prefix per D2 (clean break — `VIVARIUM_*` only); Containerfile/CI/deploy image names per D4;
   forward-facing docs per D8; CHANGELOG `[0.9.0]`; version bump per D6.
2. **Gates:** ruff + mypy --strict + full pytest (the 1604-test suite must stay green) + the CI security
   gates. **`sdlc-reviewer`** pass (focus: no missed `ghidra_mcp`/`GHIDRA_MCP_`/`ghidra-mcp` reference, the
   clean-break env rename is complete, no secret/contract regression, the frozen contracts' *content*
   unchanged — only the brand string; the worker Containerfile installs the `vivarium-mcp` **dist** name).
3. **PR → human merge gate.**
4. **GATED outward steps (post-merge, human-performed/approved, in order):** rename the GitHub repo (D5);
   tag `v0.9.0` → `worker-image.yml` builds/scans/signs the **new** `vivarium-*` images; publish the release.
   Optionally reserve `vivarium-mcp` on PyPI if/when the project is ever published there.

## Consequences

**Positive.** Escapes the crowded GhidraMCP namespace; a distinct, confirmed-clear identity; the env/server
rename aligns the operator + protocol surface with the brand; history stays intact and auditable.

**Negative / risks.** Large mechanical diff (≈457+612 refs) — risk of a missed reference; mitigated by
mypy --strict (catches stale imports), a repo-wide `ghidra_mcp`/`GHIDRA_MCP_` grep-gate in review, and the
full suite. The env rename is the only operator-facing break — a deliberate clean break (D2/D7), so the
local real-worker / acceptance recipes (and the `[[acceptance-run-recipe]]` memory) that reference
`GHIDRA_MCP_*` MUST be updated in lockstep. Gated image/repo renames are deliberate, low-risk (old
artifacts + GitHub redirect persist).

## Alternatives considered

- **Brand-only rename** (docs + server name; keep package/env/images `ghidra_mcp`): least churn, but leaves
  the old identity in the import path + operator contract — half a rename. Rejected for a "real" rename.
- **Big-bang clean break** (no shims, rewrite everything incl. history): simplest mentally, but loses the
  audit trail (D8) and needlessly breaks local recipes. Rejected.
