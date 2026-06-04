# ADR-002: One worker per session, killed on eviction; verified store wipe

- **Status:** Accepted (locked by PLAN.md v2 / red-team F2)
- **Date:** 2026-06-03
- **Deciders:** Human + red-team + PM; recorded by Software Architect (WS0)

## Context

Sessions are **persistent per-binary** with TTL + idle eviction (PLAN §2), so analysis state
(Ghidra project, auto-analysis results) is reused across tool calls for the same binary. Two
binaries must never share a worker: a hostile binary could poison shared analyzer state, and a
reused worker risks **cross-session data leakage** (confidentiality) of another binary's artifacts.

## Decision

Each session owns **exactly one** Ghidra worker. Workers are **not** pooled or reused across
binaries. On eviction — TTL expiry, idle timeout, explicit `session_close`, worker poisoning, or
server shutdown — the session manager **kills that session's worker** and performs a **verified
wipe** of the per-session project store (confirm the store path no longer exists). A wipe failure
is treated as a confidentiality incident and **alerted on** (it is surfaced as `store_wiped:false`).

Eviction is **idempotent**. A per-analysis wall-clock timeout also kills the worker (DoS — F7).

## Consequences

- **Positive:** strong cross-session isolation; a poisoned/exploited worker is disposable and
  contained; clean resource accounting (kill = reclaim); supports BOLA defense (session id maps to
  exactly one worker the manager authorizes).
- **Negative:** higher resource cost (no warm pool reuse) — bounded by the concurrency cap
  (`max_sessions`) with backpressure; cold-start cost per new binary (analysis re-run).
- **Rejected alternative:** a shared worker pool processing multiple binaries — rejected for the
  leakage + state-poisoning risks above.
- **Open item (PLAN §9):** project-store location (session-scoped volume vs tmpfs) and the exact
  verified-wipe mechanism are finalized in WS2/WS3; the *contract* (kill-then-verified-wipe,
  idempotent, alert on failure) is fixed here.
