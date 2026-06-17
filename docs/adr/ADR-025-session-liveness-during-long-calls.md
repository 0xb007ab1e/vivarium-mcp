# ADR-025: Session liveness during a long in-flight call (no idle-eviction mid-call)

- **Status:** Accepted (v1.3; human-ratified 2026-06-16). Ratified: in-flight sessions exempt from the **idle** timeout (begin_call/end_call in-flight flag); absolute **TTL re-applied at the next call boundary** (in-flight work may finish, bounded by the timeout-kill DoS control); add startup invariant **idle_s >= analysis_timeout_s**; **keep current defaults**. Addresses **finding F4**.
- **Date:** 2026-06-16
- **Deciders:** Human + PM; recorded by Software Architect (v1.3 finding F4)
- **Supersedes/relates:** refines the eviction model of **ADR-002** (kill-on-evict + verified
  wipe is unchanged); interacts with **ADR-017** (the `_get_live_locked` ownership chokepoint that
  also performs the lazy expiry); bounded by `analysis_timeout_s` / `tool_timeout_s`
  (`security/limits.py`).

## Context

### The finding (F4)

During the blind acceptance run, an `analyze` on a large binary ran as a single tool call for
~18–26 minutes. The very next call (`list_functions`) failed with
`session_evicted reason="expired-on-authorize"` → `session-invalid`, aborting the workflow.

This is **not** a concurrent-reaper race. The server tool path is synchronous: the same thread that
called `SessionManager.authorize` runs the long `RpcGhidraAdapter.analyze` and only returns to the
client afterward. There is no scheduled invocation of `reap_expired` in the codebase today
(`sessions/manager.py:531` exists but nothing calls it on a timer). The eviction is **self-inflicted
by the next call's own `authorize`**:

1. `_handle_session_analyze` (`tools/registry.py:256`) calls `authorize`, which refreshes
   `last_used_mono = now` (`sessions/manager.py:327`).
2. It then calls `ctx.port.analyze(...)` (`tools/registry.py:257`), which blocks for ~18–26 min in
   `RpcGhidraAdapter.analyze` (`ghidra/rpc_client.py:265`). **`last_used_mono` is not touched again
   for the entire in-flight duration** — `authorize` refreshes it only at call *start*, and there is
   no refresh at call *end*.
3. The client issues `list_functions`. Its `authorize` → `_get_live_locked` evaluates
   `_is_expired` (`sessions/manager.py:648`): `now - last_used_mono` is now ~18–26 min, which is
   `>= idle_s` (default `900` = 15 min). The session is **lazily evicted** with
   `reason="expired-on-authorize"` (`sessions/manager.py:323-326`) and the call fails closed with
   the BOLA-safe `SESSION_INVALID`.

### Why the defaults make this near-certain

- `session_idle_s` default **900 s (15 min)**, `session_ttl_s` default **3600 s (1 hr)**
  (`config.py:82-83`).
- `analysis_timeout_s` default **600 s (10 min)**, hard ceiling **3600 s** (`security/limits.py:21,
  28`). The blind run had raised the analysis timeout well above the default to let a large binary
  finish (~18–26 min observed), but **left `session_idle_s` at 900**.

So **any** single `analyze` that runs longer than `session_idle_s` idle-expires its own session the
instant the next call authorizes. With a long-enough analysis on a very large binary, the elapsed
in-flight time can also approach the **absolute TTL** (3600 s), tripping the TTL branch the same way.

### Why idle/TTL is the wrong DoS control for *in-flight* work

The idle timeout and absolute TTL exist to bound **abandoned** sessions and cap worst-case resource
hold time (CWE-400, ADR-002). But for work that is **actively in flight**, the real DoS bound
already exists and is stronger: the **per-analysis / per-tool wall-clock timeout kills the worker**
on expiry (`ghidra/rpc_client.py:974-982`, ADR-002 "a per-analysis wall-clock timeout also kills the
worker"). A hung or hostile worker is bounded by `analysis_timeout_s`, not by idle/TTL. Using idle
expiry to police an in-flight legitimate analysis therefore conflates two unrelated controls and
produces the false-positive eviction in F4.

The design must reconcile: **(A)** never idle-evict a session whose call is legitimately in flight,
with **(B)** still bounding a hostile/hung worker (already done by the timeout-kill), and **(C)**
still evicting a *truly abandoned* (idle-between-calls) session and preserving the ADR-002 verified
wipe on every eviction.

## Decision

### D1 — Touch on call START + treat an in-flight session as non-idle (mechanism **(a)** + **(d)**)

Adopt mechanism **(a)** *combined with* **(d)**: mark the session **in-use when a call begins** and
**exempt an in-use session from idle eviction** for the duration of that call. Concretely, the
session manager gains an explicit *in-flight* notion rather than inferring liveness from a stale
`last_used_mono`:

- A new manager method **`begin_call(session_id, *, caller) -> SessionInfo`** authorizes the session
  through the existing `_get_live_locked` chokepoint (so ownership + unknown/evicted handling is
  unchanged and unbypassable — complete mediation, ADR-017), then **marks the session in-flight**
  (`in_flight = True`, and sets `last_used_mono = now` as today).
- A new method **`end_call(session_id)`** clears the in-flight mark and **refreshes
  `last_used_mono = now` again at call end** (so the *next* idle window is measured from when the
  long call finished, not when it started). `end_call` runs in a `finally` so it always fires —
  success, error, or worker-unavailable.
- `_is_expired` (the idle branch) treats an **in-flight session as non-idle**: while
  `in_flight is True`, `now - last_used_mono >= idle_s` does **not** evict. Idle eviction applies
  only to sessions that are *not* currently executing a call (mechanism **(d)** — "evict only
  idle-between-calls").
- The tool handlers replace the lone `authorize(...)` at the top of each handler with
  `begin_call(...)` and wrap the delegate in `try/finally: end_call(...)`. The existing
  `imperative-shell` shape (authorize → validate → delegate) becomes (begin_call → validate →
  delegate → end_call). This is the single chokepoint; per-tool handlers do not each re-implement it.

This is preferred over a bare touch-on-start because touch-on-start *alone* still leaves a window:
if the call runs longer than `idle_s`, `last_used_mono` (set at start) is again stale by the time the
next call authorizes. The explicit `in_flight` flag closes that window deterministically regardless
of how long the call runs, and the end-of-call refresh resets the idle clock cleanly.

### D2 — In-flight sessions are exempt from idle eviction **only**; the absolute TTL still applies, but is **not** the in-flight DoS bound

Decompose the two timers:

- **Idle timeout (`session_idle_s`):** an in-flight session is **exempt** (D1). Idle policing is for
  abandoned-between-calls sessions; an executing call is, by definition, not idle.
- **Absolute TTL (`session_ttl_s`):** a session is **not** lazily TTL-evicted while a call is in
  flight (so a single legitimate long analyze is never torn out from under itself mid-call), **but
  the TTL is still honored at the next call boundary** once the in-flight call completes. I.e.
  in-flight work may *finish* even if it crosses the absolute TTL, and then the session is TTL-evicted
  on the next `begin_call` (or by the reaper, D4) — the long operation is allowed to complete, the
  session is not allowed to *continue accepting new work* past its absolute lifetime.

  Rationale: the absolute TTL's job (cap total session lifetime / blast-radius window) is not
  defeated by letting one already-running operation run to completion, because the **worker is
  independently bounded by `analysis_timeout_s` (≤ hard ceiling 3600 s)** — a worker cannot run
  unbounded merely because its session is in-flight. So the in-flight exemption does **not** create
  an unbounded-resource hole: the timeout-kill is the real ceiling on in-flight worker time, and the
  session cannot start a *new* call past TTL.

This keeps fail-closed: a session that crosses TTL gets evicted (verified wipe, ADR-002) at the next
boundary; it simply isn't ripped out mid-operation.

### D3 — Defaults / config relationship (defense-in-depth, not the primary fix)

The primary fix is D1/D2 (correctness — the timeout, not idle, bounds in-flight work). As
*defense-in-depth* and to remove the foot-gun that produced F4, add a **startup validation
relationship** and document the operator guidance:

- **`session_idle_s` must be `>= analysis_timeout_s`** (the per-analysis ceiling). Today
  `config.py:648` already enforces `session_idle_s <= session_ttl_s`; add a second fail-closed check
  that `session_idle_s >= limits.analysis_timeout_s`, so an operator cannot configure an idle window
  shorter than the longest single analysis the deployment permits. This makes the F4 misconfiguration
  (idle 900 < analysis 1560+) **refuse to boot** rather than silently self-evict at runtime.

  Note this is **belt-and-suspenders**: with D1 in place, an in-flight analyze is already exempt from
  idle eviction, so even a short idle window would not break a long call. The check is retained
  because it (i) gives a clear startup error instead of a subtle behavior, and (ii) protects the
  *gap between calls* during a multi-step long workflow where the client pauses to think.

- We do **not** adopt mechanism **(c)** ("make idle proportional to analysis_timeout for the analyze
  path") as the mechanism, because special-casing one path's idle math is more surface than the
  uniform in-flight exemption (D1) and leaves the same staleness window for any *other* long call
  (a future long tool). D3 captures the useful part of (c) — `idle >= analysis_timeout` — as a
  startup invariant instead of per-call logic.

- We do **not** change the *default values* of `session_idle_s` / `session_ttl_s` /
  `analysis_timeout_s` in this ADR; that is flagged for ratification (R3 below) since the defaults
  themselves are a product decision (a 10-min default analysis vs a 15-min idle is internally
  consistent; the run that hit F4 had *raised* analysis without raising idle).

### D4 — Reaper interaction (forward-looking; the reaper is not wired today)

`reap_expired` (`sessions/manager.py:531`) is currently uncalled. **If/when** a periodic reaper is
wired, it MUST honor the in-flight exemption identically to the lazy path: `_is_expired` already
gates both, so an in-flight session is skipped by the reaper's idle branch too, and (per D2) the
reaper may TTL-evict only sessions that are **not** in flight. Because the manager serializes all
mutation under its `RLock` (`sessions/manager.py:190`), a reaper cannot evict a session in the middle
of `begin_call`/`end_call` state changes. (No reaper is added by this ADR — this is the contract a
future one inherits.)

### D5 — Unchanged invariants (explicit)

- **ADR-002 verified store wipe is unchanged.** Every eviction — idle (between calls), TTL (at the
  next boundary), `session_close`, poison, timeout-kill, shutdown — still kills the worker and
  performs the verified wipe; a wipe failure is still a confidentiality incident surfaced as
  `store_wiped:false`.
- **Fail-closed abandonment.** A session that finishes its call and is then left idle past
  `session_idle_s` (now correctly measured from `end_call`) **still evicts** — the abandoned-session
  bound is preserved.
- **BOLA / ownership.** Authorization is unchanged: `_get_live_locked` (with the owner check) remains
  the **sole** authZ gate, and `begin_call`/`end_call` grant no access and cannot resurrect an evicted
  session. As implemented, the in-flight marker is a **non-authorizing best-effort** call placed in the
  dispatch chokepoint **before** the handler's `authorize` (keyed only on `session_id`). A caller who
  supplied a *foreign* `session_id` would therefore transiently bump that session's idle clock /
  in-flight count even though `authorize` then denies them — but this is **not exploitable**: session
  ids are 256-bit CSPRNG (`secrets.token_urlsafe(32)`), so a foreign id is unguessable, and the
  **absolute TTL** (D2, computed from untouched `created_mono`) still bounds the session regardless.
  Optional future hardening: pass the resolved principal into `begin_call` and no-op on owner mismatch
  for strict isolation (a nicety, not required).
- **The timeout-kill remains the in-flight DoS control** (`analysis_timeout_s` / `tool_timeout_s`,
  ADR-002, CWE-400). The in-flight exemption only stops the *idle/TTL* timers from firing mid-call;
  it does not weaken the wall-clock kill that actually bounds a hung/hostile worker.

## Consequences

- **Positive:** a legitimate long `analyze` (or any long tool call) no longer self-evicts; the
  workflow that aborted in F4 completes. The idle clock is measured correctly (from call *end*),
  matching operator intuition. The two controls are cleanly separated — timeout bounds in-flight
  work, idle/TTL bound between-call/abandoned lifetime. No new background thread is introduced.
- **Negative / cost:** a small amount of new state (`in_flight: bool`) and a `begin_call`/`end_call`
  pairing the handlers must use in a `finally`. A handler that forgot `end_call` would leave a
  session permanently non-idle-evictable until TTL — mitigated by routing through the single
  imperative-shell chokepoint (one place to get right) and by the absolute TTL still being the
  backstop (D2). This is a verification item (a test that `end_call` runs on the error path).
- **Negative / TTL nuance:** allowing an in-flight operation to *finish* past the absolute TTL is a
  deliberate, bounded relaxation (bounded by the timeout-kill). Operators who want a hard cap on
  in-flight worker time tune `analysis_timeout_s` (the real lever), not `session_ttl_s`.
- **Rejected — mechanism (b) heartbeat:** a background thread/timer refreshing `last_used_mono`
  during a long call. Rejected: it adds a concurrency surface (a timer mutating session state under
  the lock while the call thread holds nothing), needs its own lifecycle/cancellation, and solves
  nothing that the synchronous in-flight flag doesn't solve more simply (the call path is already the
  thread that knows when it starts and ends). Heartbeats earn their keep only for genuinely
  out-of-band liveness (e.g. a streaming protocol), which v1 does not have.
- **Rejected — mechanism (c) as the mechanism:** proportional idle on the analyze path only —
  see D3. Its useful invariant (`idle >= analysis_timeout`) is kept as a startup check; its per-path
  special-casing is not.
- **Rejected — "exempt in-flight from BOTH idle and absolute TTL indefinitely":** would let an
  in-flight session evade the absolute lifetime cap entirely. We instead bound it via the
  timeout-kill and re-apply TTL at the next boundary (D2), so the absolute cap on *accepting new
  work* is preserved.

## Verification (for the implementing increment — design intent, not implemented here)

- A test where a session's idle window elapses **while a call is in flight** asserts the **next**
  call succeeds (does not get `expired-on-authorize`) — the F4 regression test (master §1: a failing
  test reproducing the defect first).
- A test that `end_call` refreshes `last_used_mono` and a subsequently-abandoned session **does**
  idle-evict (abandonment still fail-closed — D5).
- A test that `end_call` fires on the **error** path (delegate raises → session not left
  permanently in-flight).
- A test that a session crossing the **absolute TTL while in flight** completes its call, then is
  TTL-evicted at the next `begin_call` (D2), with the verified wipe occurring (ADR-002 unchanged).
- A `config` test that `session_idle_s < analysis_timeout_s` **refuses to boot** (D3 fail-closed).
- Ownership: a foreign caller cannot `begin_call`/`end_call` another principal's session (same
  BOLA-safe `SESSION_INVALID` — ADR-017).
```
