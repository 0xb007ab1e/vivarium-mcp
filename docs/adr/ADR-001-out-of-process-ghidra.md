# ADR-001: Out-of-process Ghidra worker is mandatory

- **Status:** Accepted (locked by PLAN.md v2 / red-team F1)
- **Date:** 2026-06-03
- **Deciders:** Human + red-team + PM; recorded by Software Architect (WS0)

## Context

The analyzed binary is **hostile input**. Ghidra is a large JVM application with many loaders and
analyzers parsing attacker-controlled bytes — a broad memory-safety / deserialization attack
surface. The MCP server is the trusted control plane (validation, sessions, transport). If the
server process also loaded the JVM and parsed binaries (e.g. in-process PyGhidra), a single Ghidra
exploit would compromise the control plane: same memory space, same credentials, same network
namespace, no containment line.

## Decision

The MCP **server process MUST NEVER load the JVM or parse a binary.** Ghidra runs in a **separate,
hardened worker** (container — see ADR-003/004), reachable **only** through an internal RPC for
which the server is the **sole** client (trust boundary 2). **In-process PyGhidra is FORBIDDEN.**

This invariant is enforced by:
- Package structure: the JVM bridge lives in `src/ghidra_mcp/ghidra/_jvm_bridge.py` and runs
  **only inside the worker**; it is never imported by `core`/`sessions`/`security`/`server`/`tools`.
- A CI test (`tests/unit/test_architecture_invariants.py`) that statically scans server-side
  modules for `pyghidra`/`jpype`/`_jvm_bridge` imports and fails the build on any.
- The runtime container/process boundary itself.

## Consequences

- **Positive:** a Ghidra exploit is contained to a disposable, network-isolated worker; the worker
  is a clean fault domain (crash/poison → kill + evict, server unaffected); the server stays small
  and auditable; enables one-worker-per-session (ADR-002) and gVisor (ADR-004).
- **Negative:** added complexity of an RPC protocol + serialization (the frozen contract in
  `docs/contracts/rpc-protocol.md`); per-call latency of the process hop; lifecycle management of
  worker processes/containers.
- **Rejected alternative:** in-process PyGhidra (simpler, lower latency) — rejected: it collapses
  the primary containment boundary and is incompatible with the hostile-input threat model.
