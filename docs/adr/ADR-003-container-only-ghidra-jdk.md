# ADR-003: Container-only worker; Ghidra 11.x + JDK 21 pinned by digest

- **Status:** Accepted (locked by PLAN.md v2 / red-team F5)
- **Date:** 2026-06-03
- **Deciders:** Human + red-team + PM; recorded by Software Architect (WS0)

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
- **Open item (PLAN §9 — SME):** confirm the **exact Ghidra 11.x patch version** and the headless
  integration method against that version's javadoc before WS2/WS3 build the worker. This ADR fixes
  the *constraint* (11.x + JDK 21, by digest, container-only); WS3 fills the concrete digest.
