# Security Policy

`vivarium` runs **hostile input** (the analyzed binary) through Ghidra and exposes the results
to an LLM. Security is the central design concern, not an add-on. This document covers how to
report vulnerabilities and the security posture you can expect.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

- Use **GitHub Private Vulnerability Reporting** (the repository's *Security → Report a
  vulnerability* tab), or
- email the maintainers (see the repository owner profile) with the subject `SECURITY: vivarium`.

Please include: affected version/commit, a description, reproduction steps, impact, and any PoC.
**Use only benign/synthetic samples in reports — never attach real malware.**

### What to expect
- Acknowledgement within **3 business days**.
- Triage + severity (CVSS, per master severity taxonomy) within **7 days**.
- Coordinated disclosure: we fix under embargo, then publish an advisory + patched release with a
  CVE/credit. Remediation targets follow our SLAs: Critical/KEV 24–72h, High 7d, Medium 30d.

## Scope & threat model

The authoritative threat model is [`docs/security/threat-model.md`](docs/security/threat-model.md)
(STRIDE over the four trust boundaries). In short:

- **The analyzed binary is hostile.** Containment of the Ghidra analyzer is the primary control:
  it runs **out-of-process** in a hardened, **network-isolated** container (non-root, read-only
  rootfs, all caps dropped, seccomp, gVisor), with strict CPU/memory/pids/time limits. The MCP
  server process **never** loads the JVM or parses a binary (ADR-001).
- **Ghidra output is untrusted** (indirect prompt injection via strings/symbols/comments). All
  binary-derived content is returned in a typed **untrusted-data envelope** (ADR-005) and is never
  auto-executed, evaluated, or rendered.
- **Tool arguments are untrusted** and validated/allow-listed at the boundary (pydantic).

### In scope
Sandbox escape from the worker (TB3); bypass of input validation or resource limits; cross-session
data leakage (TB4); injection that escalates beyond returned data; denial of service (decompile
bombs, zip/oversized inputs, pool starvation). Now-shipped surfaces are **also in scope**: the
**HTTP transport** (TB6 — authN/authZ, rate-limiting, CORS, BOLA, and the mTLS/OAuth/bearer auth
modes); the **write/mutation tools** and their per-session consent gate (TB7 — e.g. consent bypass,
cross-session mutation, structural-type isolation); and **annotation import** (TB8).

### Out of scope
- **Arbitrary script execution / `runScript`** — permanently excluded by design (never built); the
  tool catalog is an allow-list with no script-execution path.
- Vulnerabilities in Ghidra or the JDK themselves — report those upstream; we track and patch the
  pinned image via CVE management (see the dependency-patch runbook).

## Supported versions
Pre-1.0: only the latest `main` is supported. Security fixes land on `main`.

## Handling of analyzed artifacts
Analyzed binaries and all derived artifacts are treated as **confidential** and **hostile-origin**.
They are never committed to the repository, never used in CI (synthetic fixtures only), and the
per-session project store is **wiped on eviction** (verified).
