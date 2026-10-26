# ADR-078: Generated target documentation (analysis report + finding records)

- **Status:** **Proposed** (2026-10-25; drafted by the assistant). No implementation yet — this
  record and its threat model (**TB10**, threat-model §22) are the design of record authored BEFORE
  any code (`workflow-threat-model`). It responds to the standing goal of making Vivarium emit
  rich, navigable documentation of an *analyzed target* (an archify-style atlas of the binary —
  every edge, finding record, catalog-surface artifact) as part of the analysis workflow.
- **Date:** 2026-10-25
- **Deciders:** Human operator (ratification + scoping pending). Any live/HTML/LLM tier, and any
  write of a report outside the ephemeral session store, is a **gated action**
  (`workflow-gated-actions`).
- **Related:** ADR-005 (untrusted-data envelope), ADR-001/002 (server never parses; ephemeral
  session), ADR-017 (per-principal owner check), ADR-076/TB9 (dashboard renders results inert),
  ADR-008 (Tier-2 reporting tools), `session_export_annotations` (existing deterministic export).

## Context

The request: make Vivarium, **as part of its RE analysis workflow, auto-generate detailed,
navigable documentation of the target binary** — the way the `.archify` atlas documents Vivarium
itself — covering "every edge, every ADR-style finding record, all surfaces of the generated
artifacts." It conflates two distinct capabilities:

1. **Analysis-report generation** — synthesize the existing read-only artifacts (call graph, xrefs,
   data-flow slices, function context, scans, program summary) into a single navigable document
   (HTML atlas / diagrams / Markdown).
2. **Finding records** — capture RE reasoning *during* the workflow as durable, ADR-shaped records
   (observation → inference → evidence), exportable with the analysis.

Both are **output-edge** features: they consume data that has already crossed the untrusted-data
envelope (TB4) and render or persist it. That is a genuinely new trust boundary — **hostile-origin
artifact → persisted/rendered document** — because the artifacts (symbol names, strings,
decompiled text, comments, inferred types, decoded strings) are **CONFIDENTIAL and of HOSTILE
ORIGIN** (project data-classification), and a generated document *renders* and *persists* them,
possibly off-box and possibly into an LLM narrative. This is distinct from TB9: TB9 renders results
**inert in a live browser** (`textContent`) under the dashboard's guarantees; a generated document
**outlives the session, travels, and may be opened without those guarantees**. Modeled as **TB10**
(threat-model §22) before implementation.

Constraints that shape the design:

- **Mandates preserved.** The server never loads the JVM or parses a binary (ADR-001); generation
  runs server-side (or client-side) at the output edge, **never in the worker**, and is **never a
  write primitive**. All inputs are consumed as `Untrusted[...]` (ADR-005) — the renderer is the
  single place the envelope's "never render" rule is deliberately relaxed, so it is the single place
  sanitization is enforced.
- **Reuse, don't reinvent.** Generation reads the existing read-only tool outputs and
  `session_export_annotations`; it adds no new analysis path and no new worker capability.
- **Bounded by default.** "Every edge / all surfaces" on a large binary is unbounded work
  (combinatorial graph, huge output, LLM cost) — a cost/DoS risk (CWE-400, API4, LLM04).

## Decision

Add **generated target documentation** as a read-only, bounded, opt-in capability at the output
edge, **secure-by-default and tiered** — lowest-risk tier first, higher tiers gated on the TB10
threat model and an abuse-test suite:

1. **Tier 0 — deterministic finding records + Markdown (default, ship first).** A
   `session_generate_report`-style read-only tool emits **deterministic Markdown only** (no HTML
   render, no diagrams, no LLM), built from the enveloped tool outputs and
   `session_export_annotations`. Every finding is tagged **observed vs inferred** and carries
   provenance (program SHA-256, session id, tool + revision). Low risk; useful immediately.
2. **Tier 1 — structured archify-style report (gated on TB10 + abuse tests).** HTML atlas +
   diagrams rendered through **one sanitizing renderer** — the sole chokepoint. Context-aware output
   encoding at point of use, **no `innerHTML`**, labels sanitized *before* entering diagram JSON,
   binary-derived URLs never auto-linked, **strict CSP including `connect-src 'none'`** so an opened
   document cannot beacon out. Output is **owner-scoped, classified confidential**, bounded by hard
   caps (functions/nodes/edges/strings/bytes/doc-size), opt-in, and killable.
3. **Tier 2 — LLM narrative (default-OFF).** Optional prose/summary. The model's output is treated
   as **untrusted** and passes through the same sanitizing chokepoint; indirect prompt-injection in
   artifact text must not steer it (LLM01/LLM02); AI narrative is labeled; the agent produces it,
   the server never auto-executes it.

**This increment (if approved):** Tier 0 only — the deterministic Markdown report + finding records
over the existing exports, with provenance and observed/inferred tagging. Tiers 1 and 2 are
**separate, gated** increments that cannot merge without the TB10 abuse-test suite green.

## Consequences

- **Positive:** analysts get durable, provenance-stamped documentation of a target as a byproduct
  of the workflow; it reuses the read-only tools and the existing export; the sanitizing renderer
  (Tier 1) becomes the single chokepoint that makes "render hostile content" safe.
- **Negative / residual:** a generated document is a **new persisted copy of confidential,
  hostile-origin artifacts** — a data-lifecycle concern (retention/deletion must be defined;
  sharing it = exporting confidential data, master §5, operator-owned). Tier 2 carries irreducible
  overreliance risk (label AI output, off by default). Tier 1/2 add real rendering attack surface
  (stored XSS / diagram-label / SVG injection — CWE-79) that only the chokepoint + CSP contain.

## Alternatives considered

- **Generate in the worker alongside analysis** — rejected: puts rendering/formatting in the
  containment boundary, bloats it, and tempts an envelope bypass (ADR-001/005). Generation belongs
  at the output edge over already-enveloped data.
- **Auto-generate a full HTML atlas on every analysis** — rejected: unbounded cost/DoS (LLM04/API4)
  and a confidential-data-at-rest surface created without consent. Generation is opt-in + bounded.
- **Emit HTML directly from tool output without a single renderer** — rejected: scatters the
  sanitization responsibility; the whole point of TB10 is one chokepoint + strict CSP.
- **Finding records only, no report** — rejected as the *end state* (doesn't meet the atlas goal)
  but **accepted as Tier 0 / the first increment** (low-risk, immediately useful).
