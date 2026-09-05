# ADR-076: Dashboard interactive backend (Phase 2)

- **Status:** **Proposed** (2026-09-04; drafted by the assistant). Phase 1 (author + visualize) is
  implemented (dashboard MVP → live bridge → panels → VSCode UI → RE browser → interactive call
  graph → workflows catalog/Runs/builder, PRs #317–#322). This ADR proposes Phase 2 — an
  **interactive command backend** — and is the design of record for threat-model **TB9** (§21).
- **Date:** 2026-09-04
- **Deciders:** Human operator (ratification + enablement pending); the interactive write path is a
  **gated action** (`workflow-gated-actions`).

## Context

The `vivarium.dashboard` surface is deliberately **read-only, GET-only, decoupled** from the MCP
server (it renders a file/demo `StatusProvider`). The standing goal is to make the dashboard cover
vivarium end-to-end and let RE engineers *drive* workflows — open/analyze, list parents/children,
recurse, scan, and **apply transforms (AI annotation)** — plus author custom workflows. Those last
capabilities require the browser to issue commands the server executes: a new **browser → server
command/write boundary (TB9)**. Per `workflow-threat-model`, TB9 is modeled before implementation
(threat-model §21).

Constraints that shape the design:

- **Mandates:** dashboard stays untrusted-inert (ADR-005), no external libs, strict CSP, tailnet-only
  bind; the **server never mutates a program directly** (ADR-001) — writes execute only in the
  worker via the gated path (ADR-012); sessions are owner-scoped + ephemeral (ADR-002/017).
- **Reuse, don't reinvent:** the authenticated HTTP surface (ADR-011/017/019) already provides
  per-principal auth (bearer/mTLS/OAuth), rate limits, size caps, CORS, and BOLA-closed session
  ownership; the write path (ADR-012/013) already provides default-deny write-consent + audit +
  per-write transactions/rollback.

## Decision

Add an **interactive command backend** to the dashboard, **secure-by-default**:

1. **Default OFF + fail closed.** Interactive is enabled only by explicit config *and* a wired
   command **executor**. With neither, command endpoints return **503 (disabled)** and Phase-1
   behavior is byte-for-byte preserved. No executor ⇒ no execution path.
2. **Auth required when on.** Enabling interactive REQUIRES authentication (the TB6 per-principal
   auth); an interactive bind without auth fails closed at startup. Commands bind to the principal.
3. **Command contract + policy first (`commands.py`).** A pure module validates each command against
   the served catalog (allow-listed op + typed/bounded params — CWE-20) and classifies it by a
   **two-tier policy**: **read-only** ops (list/decompile/callers/callees/scans/graph/metadata) may
   run under auth + limits; **gated** ops (import/analyze/close, all writes, `ai_annotate`) are
   **default-deny → needs-approval**. This module is implemented + tested first (this increment).
4. **Execute only through existing machinery.** When wired, the executor forwards to the MCP tool
   registry + session manager (owner-checked) and the gated write path — the dashboard is a thin,
   validated **forwarder**, never a privileged executor.
5. **AI annotation = propose-first, gated.** `ai_annotate` produces rename/comment **proposals** (the
   agent runs the LLM); the UI shows a **diff**; applying is a separate **approved write** through
   write-consent, reversible via `session_undo`. Never auto-applied from the browser.
6. **Results stay inert.** Command results are confidential, hostile-origin artifacts — returned
   `Untrusted`-enveloped and rendered `textContent`-only (ADR-005), exactly as today.

**This increment (rule-compliant groundwork):** the threat model (TB9), this ADR, the `commands.py`
policy module (validation + gating decision), a **default-off, fail-closed, auth-required**
`/api/command` endpoint that returns *disabled* without an injected executor, and a UI "run" that
degrades to the Phase-1 copy-spec when interactive is unavailable — all built + tested with **no live
server wiring**. Live wiring to the session manager and any production enablement are **separate
gated actions** requiring human approval.

## Consequences

- **Positive:** the interactive foundation exists, threat-modeled and fail-closed; the goal's
  interactive/apply-transform capabilities have a safe contract to build on; Phase 1 is unaffected.
- **Negative / residual:** until the executor is wired + enabled (gated), the browser has no live
  execution path (503) — interactive is not yet usable end-to-end by design. Wiring touches
  security-critical server surface (auth, write path, session isolation) and must be reviewed +
  human-approved before enablement.

## Alternatives considered

- **Dashboard as its own MCP client / separate write primitive** — rejected: duplicates auth + the
  write path, widens attack surface, violates "reuse the server" + ADR-001.
- **Keep author-only (Phase 1) permanently** — rejected: does not meet the goal's interactive/apply
  capabilities; TB9 is the sanctioned path to add them safely.
