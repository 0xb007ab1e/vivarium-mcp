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
- **v1.1 (deferred):** Tier 2 reporting/metrics (cyclomatic complexity, code/data coverage,
  imports/exports, IOC/crypto scans, call-graph metrics, program-summary report); mutation tools
  (gated); HTTP transport.
- **Transport:** design **configurable (stdio + HTTP)**; **build/harden stdio in v1**, HTTP as a
  gated, separately threat-modeled v1.1 increment.
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
2. **▶ NOW: Threat model + Bootstrap (WS0)** — Software Architect; skeleton + frozen contracts +
   STRIDE threat model; **stops at first-commit gate**.
3. Parallel build fan-out **WS1–WS5** (worktree-isolated) once contracts frozen.
4. Integrate → **`sdlc-reviewer`** (security/quality) + all CI gates green + threat-model abuse
   tests pass.
5. Release prep (**`sdlc-release-manager`**) — tag/deploy gated.

## 8. ADR log (decisions to record in `docs/adr/`)
- ADR-001 Out-of-process Ghidra worker mandatory (F1). ADR-002 One worker per session, killed on
  eviction (F2). ADR-003 Container-only; Ghidra 12.1.2 + JDK 21 pinned by digest (F5).
  ADR-004 Isolation tier (rootless podman baseline; gVisor for worker) (F8). ADR-005 Untrusted-data
  envelope for binary-derived output (F3). ADR-006 stdio-first; HTTP gated v1.1 (F9).

## 9. Open items
- ✅ **RESOLVED (WS0):** worker RPC = **JSON-RPC 2.0 over per-session UDS** (ratified 2026-06-03;
  see `docs/contracts/rpc-protocol.md`).
- ⏳ **WS3:** confirm exact Ghidra 12.1.2 patch version + digest (SME) at worker-image build; confirm
  project-store location (session-scoped volume vs tmpfs) + verified-wipe mechanism (ADR-002 fixes
  kill-then-verified-wipe).
- ⏳ **Image hardening — distroless/perl-free base (durable fix behind the CVE waivers).** The 6
  no-upstream-fix Debian-base CVEs in `.trivyignore.yaml` (perl-base + ncurses) are waived
  not-reachable, **auto-expiring 2026-09-06**. The durable remediation is migrating the worker/server
  off `python:3.12-slim` to a distroless/perl-free base so those packages aren't present. Re-evaluate
  on/before the waiver expiry. (PR #3 review, Low-3.)
- ⏳ **Image scan↔sign binding (PR #3 review, Low-1).** `worker-image.yml` scans a *second*,
  cache-identical `provenance:false` docker tarball rather than the exact pushed (manifest-list)
  artifact — layers are byte-identical (intra-run buildx cache) but the manifest digests differ, so
  the binding rests on cache determinism. Harden by scanning the pushed artifact directly: single
  build with multi-output `type=image,push=true` + `type=oci,dest=` (the OCI exporter carries
  manifest lists/attestations) → Trivy `--input` the OCI tarball. Needs a real `docker buildx` env to
  validate the Trivy-on-OCI-with-attestations interaction (the dev box only has buildah).
