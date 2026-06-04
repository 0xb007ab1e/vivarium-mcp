# ADR-006: stdio-first transport; HTTP is a gated v1.1 increment

- **Status:** Accepted (locked by PLAN.md v2 / red-team F9)
- **Date:** 2026-06-03
- **Deciders:** Human + red-team + PM; recorded by Software Architect (WS0)

## Context

MCP supports multiple transports (stdio, HTTP/SSE). HTTP introduces a network attack surface:
authentication, authorization, CORS, rate limiting, transport security, and exposure of the whole
tool surface to remote callers — a materially larger threat model than a local stdio process spawned
by a trusted host. v1 should ship the secure, minimal surface first.

## Decision

The transport is **designed configurable (stdio + HTTP)** but **only stdio is built and hardened in
v1**. HTTP is a **separately threat-modeled, gated v1.1 increment**.

Architecturally: the `server/` shell is the only transport-aware layer; `core`, `tools`, `sessions`,
`security`, and the `ghidra` adapter are transport-agnostic, so adding HTTP later is an additive
change to the shell, not a rewrite. Until HTTP lands, the rule modules `std-owasp-api` and
`std-zero-trust` are **deferred** in `CLAUDE.md` (re-imported and applied when HTTP is built).

## Consequences

- **Positive:** smallest possible attack surface in v1 (no network, no auth boundary inside one
  process); faster to harden and audit; the extensibility seam is preserved.
- **Negative:** no remote/multi-client access in v1 (acceptable for the local-host LLM use case).
- **For v1.1 (when HTTP is built):** add authn/authz (`topic-authn-authz`), per-request authZ +
  mTLS (`std-zero-trust`), API hardening (`std-owasp-api`: rate limits, CORS, payload caps), and a
  dedicated HTTP threat model before exposing any port. **Do not build this in v1.**
