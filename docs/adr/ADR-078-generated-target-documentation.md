# ADR-078: Generated target documentation (analysis report + finding records)

- **Status:** **Proposed** (2026-10-25; drafted by the assistant). No implementation yet — this
  record and its threat model (**TB10**, threat-model §22) are the design of record authored BEFORE
  any code (`workflow-threat-model`). It responds to the standing goal of making Vivarium emit
  rich, navigable documentation of an *analyzed target* (an archify-style atlas of the binary —
  every edge, finding record, catalog-surface artifact) as part of the analysis workflow.
  **Amended 2026-10-26** (red-team scope review, PR #347): the rendering-safety model is made
  **tier-invariant** (A+B+C below); Tier 0 moves off raw Markdown to a CSP-wrapped, allow-list-
  projected HTML report and carries its **own** abuse-gate — "deterministic Markdown" was
  mis-classified as inert (F1); Tier 0 retention is bound to the ephemeral session store (F2);
  scope alternatives (on-demand per-subtree, `.archify` reuse, raster, client-side-only) are
  weighed (F3/F5).
  **Tier 0 implemented 2026-10-26** (`session_generate_report`, catalog 78→79;
  `src/vivarium/report/`). Retention is **realized in-memory, per-session, discarded on evict**
  (mirrors ADR-040 streaming jobs) — not an on-disk file: production runs `store_root=None` (the only
  on-disk store is the worker's in-container tmpfs, off-limits to the output edge), so the ADR-002
  "ephemeral session store / wipe-on-evict" guarantee is met in memory. Composed free-text (comments)
  is additionally secret-redacted on detection (abuse #4). Tiers 1 and 2 remain unbuilt/gated.
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
edge, **secure-by-default**. The rendering-safety model is the **same across every tier** (it is NOT
a per-tier variable — F1 amendment); tiers differ only by **scope and autonomy**.

### Rendering-safety model (applies to every tier — amended 2026-10-26)

A generated document is only as safe as its *least-trusted consumer*. No single control is relied on:

- **(C) Allow-list projection (content level — survives consumers we don't own).** Every
  binary-derived value is projected before it enters the document: symbol/identifier names to a
  `[A-Za-z0-9_$.]` class (else `\xNN`), strings to a hex dump + printable-ASCII preview, addresses to
  canonical hex. **The string preview is format-escaped at the projection chokepoint** — the
  markup/Markdown-active bytes that printable ASCII would otherwise pass verbatim
  (`< > & " ' [ ] ( ) : ! * _` and backtick) are HTML-entity-encoded (and, for any future
  inline-code Markdown export, escaped/stripped) or rendered `\xNN`, exactly as names are. Without this
  a verbatim preview of `](javascript:evil)` would stay active markup in raw Markdown and read as an
  instruction to an LLM — so the escape is what makes (C) true for strings, not only names. The
  document therefore never carries a raw hostile byte sequence that can be markup **in any consumer** —
  browser, GitHub/mkdocs Markdown, VS Code preview, or an LLM. This is the only
  control that holds in a renderer we do not control.
- **(B) Data/template separation (parse-don't-validate at the edge).** Generation emits a
  **structured data file** (findings/graph JSON) whose binary-derived fields are plain strings; a
  **separate trusted renderer** consumes it via an auto-escaping template / DOM `textContent` only —
  never string-built markup, never `innerHTML`. (The existing `.archify` model.)
- **(A) Inert-by-container (artifact level — defense-in-depth for the path we control).** Any HTML we
  emit is **self-contained** with an embedded **strict CSP** that **starts `default-src 'none'`** so
  every fetch directive fails closed, then opens only what the document needs
  (`default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'self' data:; style-src
  'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`) and renders dynamic
  content inside an `<iframe sandbox>` (no `allow-scripts`/`allow-same-origin`), so a surviving
  injection can neither execute nor beacon. `default-src 'none'` is load-bearing: `connect-src`
  governs only fetch/XHR/beacon, so without it an `object`/`font`/CSS `url()` load would be an
  uncovered exfiltration channel (OWASP CSP cheat sheet — start `default-src 'none'`, then open up).

**No standalone raw-Markdown artifact is shipped.** Markdown is the one format that cannot be wrapped
by (A): a raw `.md` opened in GitHub/mkdocs renders active `[x](javascript:…)` links and auto-loading
`![](http://…)` beacon images, so "deterministic Markdown" is **not** inert (red-team F1). If a
Markdown export is ever offered it is (C)-projected inline-code only, raw-HTML forbidden, and labeled
"not inert in all renderers." The first shippable artifact is the **(A+B+C) self-contained,
CSP-wrapped, allow-list-projected HTML report**, not raw Markdown.

### Tiers (scope + autonomy, not safety)

1. **Tier 0 — bounded on-demand report (ship first).** A `session_generate_report`-style read-only
   tool emits one (A+B+C) self-contained report for a **bounded scope** — a function / call-subtree /
   explicit selection, **composed, never a whole-program materialization** — plus **finding records**
   (observation → inference → evidence) over the enveloped tool outputs and
   `session_export_annotations`. Findings tagged **observed vs inferred**; provenance manifest
   (program SHA-256, session id, tool + revision). **Retained in the ADR-002 ephemeral session store
   by default** (inherits kill / verified-wipe-on-evict — F2) — realized **in-memory, per-session,
   discarded on evict** (mirrors ADR-040; prod has no on-disk server store, `store_root=None`), not an
   on-disk file; any persist outside the session is an explicit operator path with documented
   retention and is a **gated** action (`workflow-data-lifecycle`, master §5). Composed free-text
   (comments) is secret-redacted on detection before projection, so a key an analyst pasted cannot
   travel off-box verbatim (abuse #4; `secret_scan`/ADR-072, master §5).
2. **Tier 1 — whole-program navigable atlas (gated).** "Every edge / all surfaces," interactive,
   larger caps, more diagram types — the capability the original request named. Same A+B+C controls;
   diagrams via (B) `textContent` labels or (D) rasterization, **never live SVG**. Gated on the TB10
   abuse-test suite green and on any persist-outside-session.
3. **Tier 2 — LLM narrative (gated, default-OFF; not originally requested).** The request asked for a
   deterministic atlas, not generated prose (red-team F5) — Tier 2 is recorded for completeness with
   **no commitment**. If built, model output is **untrusted**, passes through the same A+B+C path,
   must not be steered by indirect prompt-injection in artifact text (LLM01/LLM02), and is labeled
   AI-generated.

**This increment (if approved):** Tier 0 only — the bounded (A+B+C) report + finding records, with
provenance and observed/inferred tagging, written to the ephemeral session store. **Abuse cases
#1–#5 and #9 (TB10 §22) are Tier-0 merge gates** (not deferred to Tier 1). Tiers 1 and 2 are
**separate, gated** increments that cannot merge without the full TB10 abuse-test suite green.

## Consequences

- **Positive:** analysts get durable, provenance-stamped documentation of a target as a byproduct
  of the workflow; it reuses the read-only tools and the existing export; the A+B+C model makes
  "render hostile content" safe **across consumers**, not just in a renderer we control; bounding
  Tier 0 to on-demand subtrees dissolves the whole-program DoS structurally.
- **Negative / residual:** a generated document is a **new persisted copy of confidential,
  hostile-origin artifacts** — a data-lifecycle concern bounded in Tier 0 by writing to the
  ephemeral session store (wipe-on-evict); any persist-outside / share = exporting confidential data
  (master §5, operator-owned, gated). **(C) allow-list projection is lossy for human reading**
  (mangled names / hex previews) — mitigated by (B)'s trusted view, but a real ergonomics cost. Tier
  2 carries irreducible overreliance risk (label AI output, off by default). Rendering attack surface
  (stored XSS / diagram-label / SVG injection — CWE-79) is contained by A+B+C **at every tier,
  including Tier 0** (F1 amendment).

## Alternatives considered

- **Generate in the worker alongside analysis** — rejected: puts rendering/formatting in the
  containment boundary, bloats it, and tempts an envelope bypass (ADR-001/005). Generation belongs
  at the output edge over already-enveloped data.
- **Auto-generate a full HTML atlas on every analysis** — rejected: unbounded cost/DoS (LLM04/API4)
  and a confidential-data-at-rest surface created without consent. Generation is opt-in + bounded.
- **Emit HTML directly from tool output without a single renderer** — rejected: scatters the
  sanitization responsibility; the whole point of TB10 is one chokepoint + strict CSP.
- **Finding records only, no report** — rejected as the *end state* (doesn't meet the atlas goal)
  but **accepted as part of Tier 0 / the first increment** (immediately useful), bundled with the
  bounded (A+B+C) report.
- **Standalone portable Markdown as the first tier** — rejected (red-team F1): Markdown cannot be
  (A)-wrapped and its normal consumers render active links / beacon images; "deterministic" ≠
  "inert." Replaced by the (A+B+C) self-contained HTML report.
- **Whole-program atlas, hard-capped, as Tier 0** — rejected in favor of **on-demand
  per-function/per-subtree** composition (red-team F3): bounding scope structurally dissolves the
  combinatorial DoS/cap problem and fits how RE is actually done (document as you reverse);
  whole-program is Tier 1, gated.
- **Reuse the existing `.archify` pipeline** (candidate JSON → renderer) against (C)-projected target
  artifacts — **adopted in spirit as model (B)**; whether to drive `.archify` directly or build a
  minimal equivalent depends on whether `.archify` can safely ingest projected hostile-origin data
  (open question for the Tier-1 increment).
- **Flatten to a non-active format post-generation (raster PNG / JS-disabled PDF)** — considered
  (model D); kept as the **diagram** option for Tier 1 (rasterize, never ship live SVG); rejected as
  the *primary* format (loses search / copy / navigation, large files).
- **Client-side-only generation, never persist (fold into TB9)** — considered (model E, red-team F3):
  safest (no at-rest hostile document) but defeats the portable/shareable atlas goal; retained as the
  fallback when persistence is not needed.
