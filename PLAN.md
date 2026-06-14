# PLAN — `ghidra-mcp`: Secure MCP Server for Headless Ghidra

> Owner: SDLC Project Manager (coordinator). Single source of truth for delivery.
> Status: **APPROVED (v2)** — red-team consensus reached; cleared to bootstrap. First commit GATED.
> Date: 2026-06-03.

## 1. Goal
A **secure MCP (Model Context Protocol) server** exposing Ghidra reverse-engineering capabilities
as LLM **tools**. Ghidra runs **isolated, headless, out-of-process**, reachable **only** through
the server's internal RPC. The analyzed binary is **hostile input**; containment of the analyzer
is the central security control.

## 2. Locked decisions (human + red-team)
- **v1 tool scope:** **Tier 1 read-only curated core only** — decompile, disassemble, list/inspect
  functions, xrefs to/from, strings, symbols/labels, data types, comments (read), memory map/
  segments, bounded read-bytes, bounded search, program metadata. **Read-only in v1** (no mutation
  tools); `runScript` out of scope.
- **v1.1:** ✅ **DONE** — Tier 2 reporting/metrics (cyclomatic complexity, code/data coverage,
  imports/exports, IOC/crypto scans, call-graph metrics, program-summary report); ✅ **DONE** —
  HTTP transport (ADR-011 / TB6, merged 2026-06-12); ✅ **DONE** — mutation/write tools (gated,
  default-deny per-session write-consent; ADR-012 annotations + ADR-013/014/015 structural A/B/C =
  composite types; catalog → 47 tools; merged 2026-06-14, #42/#44/#46/#48); ✅ **DONE** —
  behavioral-equivalence differential harness (ADR-016, completing ADR-010's deferred metric; merged
  2026-06-14, #50/#51); ✅ **DONE** — multi-principal authZ (ADR-017 — per-principal session
  ownership + multi-token bearer; threat-model TB6-I now ENFORCED; merged 2026-06-15, #52/#53).
  **🎉 v1.1 backlog COMPLETE.**
- **Transport:** design **configurable (stdio + HTTP)**; **build/harden stdio in v1**. ✅ **HTTP
  DONE** — shipped as a gated, separately threat-modeled (TB6) v1.1 increment (ADR-011, slices 1–6,
  merged 2026-06-12; stdio remains the default).
- **Sessions:** **persistent per-binary sessions w/ TTL + idle eviction**; **one worker per
  session, killed on eviction** (no cross-binary worker reuse).

## 3. Architecture (post-red-team)
- **Out-of-process Ghidra (MANDATORY — F1):** the MCP server process **never loads the JVM or
  parses a binary**. Ghidra runs in a separate hardened worker container; server ↔ worker over an
  internal RPC. In-process PyGhidra is **forbidden**.
- **MCP server:** Python 3.12+, official `mcp` SDK (FastMCP); pydantic validates **every** tool
  arg at the boundary. Ports & adapters: pure tool/validation/report **core** + Ghidra **adapter**
  (functional core / imperative shell).
- **Ghidra worker:** **container-only**, host unsupported (F5). Pin **Ghidra 12.1.2 + JDK 21 by
  digest**; SBOM + CVE-track. Integration via headless scripts / PyGhidra **inside the worker
  only**.
- **Isolation (F8):** rootless podman/OCI baseline — non-root, read-only rootfs, all caps dropped,
  seccomp `RuntimeDefault` (verified to load), **no network/egress**, CPU/mem/pids limits, tmpfs
  scratch. **gVisor (runsc) strongly considered** for the worker (no-network neutralizes its main
  rootless caveat). Decision recorded as an ADR.
- **DoS controls (F7):** hard per-analysis wall-clock timeout that **kills the worker**; max input
  size enforced **before** Ghidra; **worker-pool concurrency cap + backpressure**; decompile-bomb/
  oversized/malformed fuzz tests as acceptance criteria.

## 4. Trust boundaries (threat model — workflow-threat-model)
1. **MCP client (LLM) → server:** untrusted tool args → validate/allow-list.
2. **server → Ghidra worker:** internal RPC; server is the **sole** client; process/container
   boundary is the containment line.
3. **binary → Ghidra analyzer:** **HOSTILE**; primary containment boundary; bounded + isolated +
   no egress.
4. **Ghidra output → server → LLM:** **untrusted** (indirect prompt injection via strings/symbols/
   comments — std-owasp-llm LLM01/02) → wrap in a typed **untrusted-data envelope** (F3); never
   auto-execute; injection abuse tests in WS4.

## 5. Workstream decomposition (disjoint paths)
| WS | Title | Role | Owned paths (disjoint) |
|----|-------|------|------------------------|
| **WS0** | Bootstrap + threat model + **frozen contracts** (sequential, first) | Software Architect | repo root config, `CLAUDE.md`, `pyproject.toml`, CI, `/docs/**` (incl. `docs/security/threat-model.md`), contract specs |
| **WS1** | MCP protocol & tool layer (stdio) | backend-eng | `src/ghidra_mcp/server/**`, `src/ghidra_mcp/tools/**` |
| **WS2** | Ghidra worker + RPC adapter + session mgr | backend-eng | `src/ghidra_mcp/ghidra/**`, `ghidra_scripts/**`, `worker/**` |
| **WS3** | Isolation & infra | Infra Architect → SRE | `deploy/**`, `Containerfile*`, `infra/**` |
| **WS4** | Security hardening + abuse/injection tests | security-eng | `src/ghidra_mcp/security/**`, `tests/security/**` |
| **WS5** | QA & coverage | qa-eng | `tests/unit/**`, `tests/integration/**`, `tests/e2e/**` |

**WS0 must freeze before WS1/WS2 fork (F6):** (1) worker RPC protocol/process boundary, (2) every
tool's pydantic input+output schema, (3) the untrusted-data envelope, (4) the error envelope.
Contract changes route through the PM (batch-atomicity mandate).

## 6. Gated actions (PM surfaces to human; never auto-approved)
- `git init` — local/reversible (repo genesis).
- **First commit, any push, tags — GATED.**
- **Ghidra/base image pulls + dependency installs** — supply-chain; vet + pin by digest; surface
  pinned digests.
- **Container runs binding host ports / mounting host paths** — review.
- **No real malware in CI** — benign/synthetic binaries only (master §5).

## 7. Sequence
1. ✅ Plan → red-team challenge → consensus → human decisions locked.
2. ✅ Threat model + Bootstrap (WS0) — skeleton + frozen contracts + STRIDE threat model.
3. ✅ Parallel build fan-out **WS1–WS5** (worktree-isolated) — all merged to `main`.
4. ✅ **Integrate — real `server → worker` chain WIRED end-to-end + gated e2e GREEN (2026-06-11).**
   The ground-truth e2e (`tests/e2e/test_groundtruth_oss.py`) drives the real stdio server → hardened
   Ghidra worker on stripped OSS binaries and matches Ghidra's recovered functions/edges/leaf-first
   order to a source-derived (DWARF/disasm) ground truth. **Passes on GitHub-hosted CI**
   (`e2e-groundtruth.yml`) for **cJSON (113 fns/168 edges), zlib (149/216), lua (1087/3156)** —
   `3 passed`. Wiring the chain surfaced + fixed: the unwired SessionManager→port spawn (ADR-009),
   `seccomp=RuntimeDefault` (→ engine default), worker uid vs socket-dir owner under rootless
   keep-id, single-shot connect (→ retry), and the **AF_UNIX `sun_path` overflow** from doubling the
   256-bit session id in the UDS path (a latent prod bug — fixed via a short per-session dir token).
   CI gates green; `sdlc-reviewer` security/quality pass still pending before release.
5. ✅ **v1.1 increments shipped to `main` (post-integration):** semantic-naming tools + reference
   loop + sandboxed compile eval + `naming_accuracy` metric (PRs #26–29); Tier-2 reporting/metrics
   (8 read-only tools; PR #30); **HTTP transport** (ADR-011 / TB6; slices 1–6 = PRs #32–#36; merged
   2026-06-12); **mutation/write tools** (gated; ADR-012 annotations + ADR-013/014/015 structural
   A/B/C composite types; catalog → 47 tools; PRs #42/#44/#46/#48; merged 2026-06-14);
   **behavioral-equivalence harness** (ADR-016, completes ADR-010's deferred metric; PRs #50/#51;
   merged 2026-06-14); **multi-principal authZ** (ADR-017 — per-principal session ownership +
   multi-token bearer, TB6-I enforced; PRs #52/#53; merged 2026-06-15). **v1.1 backlog COMPLETE.**
6. Release prep (**`sdlc-release-manager`**) — tag/deploy gated.

## 8. ADR log (decisions to record in `docs/adr/`)
- ADR-001 Out-of-process Ghidra worker mandatory (F1). ADR-002 One worker per session, killed on
  eviction (F2). ADR-003 Container-only; Ghidra 12.1.2 + JDK 21 pinned by digest (F5).
  ADR-004 Isolation tier (rootless podman baseline; gVisor for worker) (F8). ADR-005 Untrusted-data
  envelope for binary-derived output (F3). ADR-006 stdio-first; HTTP gated v1.1 (F9).
  ADR-007/008 v1.1 semantic-naming + Tier-2 extraction primitives. **ADR-009 Concrete worker
  launcher + import-root mount + per-session socket dir** (WS2/WS3 seam; the chain-wiring work —
  short per-session UDS dir token keeps the path under the AF_UNIX limit). ADR-010 semantic-naming
  eval (sandboxed compile / TB5; its deferred behavioral-equivalence metric completed by ADR-016). **✅ ADR-011 HTTP transport (v1.1; DONE — merged 2026-06-12,
  slices 1–6 = PRs #32–#36)** — MCP Streamable HTTP; secure-by-default exposure
  (stdio→loopback→UDS→gated network), bearer auth (mTLS/OAuth port-ready stubs), TLS off-loopback,
  fail-closed startup; `std-owasp-api` edge (size-cap/rate-limit/CORS/headers); network boundary
  threat-modeled as **TB6** (BOLA now closed by an **enforced per-principal owner check** —
  ADR-017, per-principal session ownership + multi-token bearer; the ADR-011 §6 single-principal
  deferral is resolved); activates
  `std-owasp-api`/`std-zero-trust`/`topic-authn-authz`; operator runbook
  `docs/runbooks/http-exposure.md`; design `docs/design/http-transport.md`.

## 9. Open items
- ✅ **RESOLVED (WS0):** worker RPC = **JSON-RPC 2.0 over per-session UDS** (ratified 2026-06-03;
  see `docs/contracts/rpc-protocol.md`).
- ⏳ **WS3:** confirm exact Ghidra 12.1.2 patch version + digest (SME) at worker-image build; confirm
  project-store location (session-scoped volume vs tmpfs) + verified-wipe mechanism (ADR-002 fixes
  kill-then-verified-wipe).
- ✅ **DONE — Image hardening: both images off Debian to Chainguard/Wolfi (perl/ncurses CVEs
  retired).** The 6 no-upstream-fix Debian-base CVEs that `.trivyignore.yaml` waived (perl-base +
  ncurses, from `python:3.12-slim`) are **eliminated** — both images moved off Debian, Trivy
  HIGH,CRITICAL OS scan = 0 for each, and the waiver file is now empty (`vulnerabilities: []`). No
  more `2026-09-06` waiver deadline.
  - **Server — DONE/validated on `infra/server-distroless` (server-first proof, 2026-06-10).** Base:
    **Chainguard/Wolfi `cgr.dev/chainguard/python`** (glibc → manylinux wheels resolve; built-in
    non-root uid/gid 65532; shell-free + no pkg-mgr + ~0 CVEs). `Containerfile.server` rewritten to
    the standard `-dev` (venv build) → shell-free runtime pattern (digests pinned);
    `infra/pin-supply-chain.sh` `BASES` updated (Chainguard for the server, slim now worker-only).
    **Gated build validated** (podman build via cot): builds clean, venv is portable `-dev`→runtime,
    runs as uid 65532, `import ghidra_mcp` + the `ghidra-mcp` console script resolve, no shell/apk
    (25 Wolfi packages). **Trivy HIGH,CRITICAL scan: 0 findings** — the 5 perl CVEs are eliminated
    (perl absent) and the ncurses CVE is not flagged on Wolfi's build.
    - **Python 3.14 (parity note).** Chainguard's FREE tier is `:latest`-only = **Python 3.14**
      (`:3.12`/`:3.12-dev` are paid-tier). Decision (2026-06-10): **adopt 3.14** for the server.
      `requires-python = ">=3.12"` is unchanged (the worker stays 3.12), so BOTH runtimes are in
      scope; CI gains a `quality-py314` job running the suite on 3.14 (dev/prod parity —
      topic-config-environments) alongside `quality` on 3.12. ✅ **DONE (2026-06-10):** `main`
      branch protection enabled (via `gh api`; was previously unprotected — a `workflow-git` gap) —
      all 6 CI checks are required incl. `quality-py314` (so it's merge-blocking), strict +
      linear-history + no-force-push/no-deletions; no required PR reviews (solo repo; review is via
      `sdlc-reviewer`) + admin-bypass on so the maintainer isn't locked out. The (gated) dependency
      lockfile, when generated, must carry cp314 wheels for `mcp`/`pydantic` (the placeholder build
      installed `--no-deps`, so the 3.14 dep closure is first proven by the `quality-py314` CI leg).
  - **Worker — DONE/validated on `infra/worker-distroless` (2026-06-10).** Base: a single
    **`cgr.dev/chainguard/wolfi-base`** (digest-pinned) + `apk add python-3.12 openjdk-21`
    (replaces `python:3.12-slim` + the copied eclipse-temurin JDK). Worker stays on **Python 3.12**
    (matches PyGhidra/JPype bundled in Ghidra 12.1.2 — `requires-python >=3.12` covers it). Pip via
    `python3.12 -m ensurepip` (Wolfi ships none); `python` symlink → python3.12; the non-root 65532
    identity is built into wolfi-base (no useradd). `infra/pin-supply-chain.sh` `BASES` updated
    (wolfi-base → worker; no more temurin/slim anywhere). **Gated build validated** (podman via cot):
    builds clean (Ghidra 12.1.2 SHA-verified, hash-pinned runtime deps, **PyGhidra 3.1.0 + JPype1
    1.5.2 cp312** offline); build-time imports pass; a detached run proved **the JVM boots on Wolfi
    glibc** — `pyghidra.start()` → Ghidra 12.1.2, `import_binary(/bin/true)` opens it,
    `program_metadata` returns `x86:LE:64 ELF`. **Trivy HIGH,CRITICAL OS scan: 0.**
    - **Design trade-offs (accepted):** (1) the Wolfi runtime is NOT shell-free (carries apk + a
      shell — no turnkey python+JDK distroless image exists; hand-rolling scratch is high-effort for
      marginal gain over the already-hardened ADR-004 runtime); still CVE-clean + non-root. (2)
      `apk add` floats package versions (auto-patched/CVE-clean) anchored by the digest-pinned base.
    - **Caveats / follow-ups:** the full auto-analysis was not run to completion here — it exceeds
      cotd's 300 s per-job ceiling on a cold first run (a harness limit, not an image defect; the
      server grants the worker a 600 s budget). Authoritative full-analysis validation is the
      **integration test in the gated image-build/CI env** (same as the slim worker was validated).
      Trivy OS-only scan (Ghidra-JAR Java-CVE scan skipped — disk; those were never in the waivers
      and are a separate pre-existing concern flagged by the gated full image scan). HEALTHCHECK is
      ignored under podman's OCI format (cosmetic; readiness is the RPC `ping`).
  - History: investigated + deferred 2026-06-08 (PR #3 review, Low-3); server built+validated +
    Python 3.14 adopted 2026-06-10 (#8); worker built+validated 2026-06-10.
- ✅ **RESOLVED — Image scan↔sign binding (PR #3 review, Low-1; PR #12, validated 2026-06-10).**
  Previously `worker-image.yml` scanned a *second*, cache-identical `provenance:false` docker tarball
  rather than the exact pushed (manifest-list) artifact, so the "scanned == shipped" binding rested
  on intra-run buildx cache determinism. **Fixed:** the second build is replaced by `skopeo copy
  "docker://<image>@${{ steps.build.outputs.digest }}" docker-archive:<tar>` — Trivy now scans the
  **exact digest cosign signs**, resolving the pushed OCI index to its single linux/amd64 runtime
  manifest (`--override-os/--override-arch`) into a docker-archive (`manifest.json`) that
  `trivy --input` reads. skopeo (HTTP/1.1, retried) sidesteps the HTTP/2 PROTOCOL_ERROR that killed
  the ~1.3 GB worker `docker pull`; it is preinstalled on GitHub-hosted ubuntu runners (guarded
  install fallback) and reuses the GHCR creds `docker/login-action` writes to `~/.docker/config.json`.
  Prior `type=oci,dest=*.tar` attempt (CI run 27172201879) does NOT compose with Trivy `--input` and
  was rejected. **Validated** by a gated `worker-image.yml` dispatch (run 27292219036, 2026-06-10):
  the new "Export pushed image (by digest)" step → Trivy → SBOM → cosign all green on both images.
  Surfaced two pre-existing, latent worker-image failures fixed first (PR #13 hadolint config for the
  Wolfi/distroless bases; PR #14 stripped the unused `Features/GhidraServer`, removing the netty JAR
  with CVE-2026-44249/45416 — unreachable: headless worker, no GhidraServer, no-net).
- ✅ **RESOLVED — adapter builder hardening: malformed-worker result → `WORKER_UNAVAILABLE` (PR #6
  review, Low-2; INFO).** The `_build_*` builders in `ghidra/rpc_client.py` read required keys
  directly; a worker result with a missing key / wrong type previously raised a raw
  `KeyError`/`ValueError`/`TypeError`/pydantic `ValidationError` out of the adapter, which the
  server shell caught as a *generic* `internal-error` (already fail-closed + non-leaking — NOT
  fail-open — but misclassified a worker fault as a server bug). **Fixed:** a single `_fail_closed`
  decorator now wraps every worker-dict builder (+ a `_validate` helper for the `model_validate`
  paths), mapping exactly those shaping failures to the adapter's own `WORKER_UNAVAILABLE` (the
  adapter owns the worker fault domain). `GhidraMcpError` and genuine server bugs are deliberately
  NOT caught (the latter still surfaces as `internal-error`). Proven with negative tests
  (`tests/unit/test_tier2_metrics.py`) that the guard fires on a known-bad result; 100% coverage on
  `rpc_client.py`. Applied uniformly across ALL builders (Tier-1 + semantic + Tier-2).
- ✅ **RESOLVED — real `server → worker` chain wired end-to-end + gated ground-truth e2e GREEN on CI
  (2026-06-11; PRs #17–#24).** The unit suite injected fakes, so v1 was never actually exercised
  through the real stdio-server → launcher → hardened-worker → RPC → Ghidra path. Driving the gated
  ground-truth e2e (build OSS fixtures `-g -no-pie` → DWARF/disasm truth → strip → real worker →
  compare recovered functions/edges/leaf-first) wired it and fixed, in order surfaced: (1) the
  composition root never built the launcher / never triggered `start_worker` (ADR-009 concrete
  `ContainerWorkerLauncher` + manager-owned `ensure_worker`); (2) `--security-opt seccomp=RuntimeDefault`
  is read by podman as a profile path → omit it for the engine default; (3) under rootless podman
  `--userns keep-id` the worker uid must own the server-created 0700 socket dir (made worker uid/gid
  configurable; prod default stays 65532); (4) `_ensure_connected` was single-shot → retry on
  ENOENT/ECONNREFUSED within `connect_timeout_s`; (5) **the per-session UDS host path doubled the
  43-char (256-bit) session id (`{base}/{sid}/{sid}.sock`) and overflowed the AF_UNIX `sun_path`
  limit — 108 at the default `/run/ghidra-mcp` (a LATENT PROD BUG, not just CI) — fixed by using a
  short per-session dir token (`session_id[:16]`); the full id stays the socket filename + identity
  (rpc-protocol §2 / ADR-009 updated).** Also added permanent server-side `worker.rpc_failed`
  adapter logging (boundary-safe; named the AF_UNIX cause). **Validated:** ground-truth e2e passes
  locally and on GitHub-hosted CI (`e2e-groundtruth.yml`) for cJSON/zlib/lua; unit suite 468 passing
  at 98% coverage; ruff/format/mypy --strict/bandit clean.
