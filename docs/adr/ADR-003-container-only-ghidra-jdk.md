# ADR-003: Container-only worker; Ghidra 12.1.2 + JDK 21 pinned by digest

- **Status:** Accepted (locked by PLAN.md v2 / red-team F5); **amended 2026-06-06** (version 11.x → 12.1.2)
- **Date:** 2026-06-03 (amended 2026-06-06)
- **Deciders:** Human + red-team + PM; recorded by Software Architect (WS0)

> **AMENDMENT 2026-06-06 (human-directed).** The pinned version is updated from the original
> "Ghidra 11.x" to the **latest available release, Ghidra 12.1.2** (`Ghidra_12.1.2_build`, published
> 2026-06-05). The human confirmed the major-version bump is intentional ("use latest available"),
> superseding the 11.x lock. **JDK 21 is unchanged** — Ghidra 12.1.2 still requires JDK 21, so the
> worker base image (`eclipse-temurin:21`) is unaffected. The distribution-zip publisher SHA-256
> `b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d` was downloaded and verified
> (fail-closed) and is pinned in `Containerfile.worker` + `infra/Makefile`. The 11→12 API jump is
> contained to the still-unimplemented `_jvm_bridge._gh_*` PyGhidra bindings (built/validated against
> 12.1.2 at image build); no 11.x integration code exists yet to break. The constraints below
> (container-only, by-digest, JDK-paired) are unchanged; the *Context* facts are retained as the
> original 2026-06-03 reasoning.

## Context

Running Ghidra directly on the host couples the analyzer's hostile-input attack surface to the host
and makes isolation (ADR-004) impossible to guarantee. Version drift is also a correctness +
security hazard: Ghidra's API and its required JDK move together.

Confirmed facts (carried from PLAN; **exact patch version is an open SME item, see below**):
- Ghidra **11.3+ requires a minimum of JDK 21**.
- Ghidra **10.3.2 is API-incompatible** with the 11.x line we target.
- **JDK 25 is past Ghidra's tested baseline** — not used.

## Decision

The Ghidra worker is **container-only**; running Ghidra on the host is **unsupported**. The worker
image pins **Ghidra 11.x + JDK 21 by digest** (`@sha256:...`), never a floating tag. The image is
SBOM'd and CVE-tracked (`std-supplychain`, `workflow-cve-management`). All Ghidra integration
(headless / PyGhidra) lives **inside the worker only** (ADR-001).

Image pulls and the digest are a **gated supply-chain action** (PLAN §6): the digest is vetted and
surfaced for human approval before use, and recorded in `deploy/` (WS3).

## Consequences

- **Positive:** reproducible, isolatable, hardenable runtime; pinned digest defeats tag-mutation /
  supply-chain swaps; a CVE bump is a controlled digest change (see the dependency-patch runbook).
- **Negative:** image size + build/maintenance overhead; contributors need a container runtime;
  upgrades require a deliberate, tested digest bump.
- **Resolved (2026-06-06):** the exact version is **Ghidra 12.1.2** (`Ghidra_12.1.2_build`) + JDK 21,
  SHA-256-verified and pinned (see the amendment above). The headless/PyGhidra integration
  (`_jvm_bridge._gh_*`) is implemented + validated against 12.1.2's javadoc at worker-image build
  (still a gated supply-chain step). This ADR fixes the *constraint* (latest pinned Ghidra + JDK 21,
  by digest, container-only); the concrete built worker/server image digests are pinned post-build
  (WS3, `deploy/` + `.env.example`).
