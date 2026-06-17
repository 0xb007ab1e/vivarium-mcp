# ADR-027: Export only user-authored annotations (fix F7 over-inclusion)

- **Status:** Accepted (v1.3; human-ratified 2026-06-17 — **option (C) Hybrid**). Symbols/signatures stay source-type-enumerated (already correct); **comments + composites** use a session-scoped, in-memory, evict-wiped **change-log** (identity keys only — ADR-002-compatible) that the export reads instead of blind-enumerating. `export_annotations` RPC gains a server-supplied **targets** param (additive, server→worker). To be **live-verified** (rebuild worker + Mode-B known-count regression). Addresses **finding F7**.
  comments model choice). **Implementation gated** — no code lands until ratified and built via
  reviewed, gated PRs. Every Ghidra API assumption here is flagged **REQUIRES LIVE VERIFICATION**
  (the F2 lesson — see §"Live-verification obligations").
- **Date:** 2026-06-17
- **Deciders:** Human (ratifies D1–D4) + PM; recorded by the Software Architect.
- **Fixes:** v1.3 finding **F7** (correctness): `session_export_annotations` over-includes Ghidra
  **auto-generated** content, violating ADR-018's "**`USER_DEFINED` annotations only**" promise.
- **Relates to / constrained by:** ADR-018 (annotation export/import round-trip; the `USER_DEFINED`-
  only promise this corrects), ADR-012/013/014/015 (the gated write tools whose effects export is
  supposed to mirror), ADR-002 (no durable confidential state — session-lifetime state is OK,
  cross-session is **not**), ADR-001 (server never parses a binary; enumeration is worker-only),
  ADR-005 (untrusted-data envelope), ADR-017 (owner-scoped sessions). Touches **no** trust boundary
  (TB8 import side is unchanged); this is a correctness narrowing of an existing read-out.

## Context

### The defect (empirical)

A blind acceptance run made exactly **39 function renames** and nothing else. The exported
"annotation document" contained:

| Entry kind | Count | Expected | Status |
|---|---:|---:|---|
| `rename_function` | 39 | 39 | correct |
| `define_struct` | 13 | 0 | **leak — Ghidra auto-analysis structs** |
| `set_comment` | 1138 | 0 | **leak — Ghidra auto-generated comments** |

ADR-018 promises the export enumerates the program's **`USER_DEFINED`** annotations only — "**not**
Ghidra's auto-analysis output." The 13 auto-structs (switch tables, RTTI descriptors, etc.) and the
1138 auto-comments ("WARNING: ...", switch-table notes, decompiler hints) are a real **correctness
defect**: the document is meant to be "what the analyst authored," and it is bloated with
machine-generated content that then round-trips back through the (gated, transacted) import replay —
1190 entries for a 39-write session.

### Root cause — uneven provenance checks in `_gh_export_annotations`

Read against `src/ghidra_mcp/ghidra/_jvm_bridge.py`:

| Step | What it exports | Provenance filter | Verdict |
|---|---|---|---|
| 1 — composites (`_composite_export_kind`, ~L2679–2702; loop L2153–2163) | structs/unions | source **archive is program-local** (`getSourceArchive().getArchiveType().isProgramArchive()`, L2694–2696) | **too loose** → 13 leaks |
| 2 — signatures (L2165–2170) | function signatures | `func.getSignatureSource() == USER_DEFINED` (L2168) | **correct** (subject to live verify) |
| 3 — function renames (L2172–2183) | function names | `func.getSymbol().getSource() == USER_DEFINED` (L2175) | **correct** |
| 4 — symbol renames (L2185–2197) | data/label names | `symbol.getSource() == USER_DEFINED` (L2187) | **correct** |
| 5 — comments (L2199–2219) | every comment slot | **none** — emits every non-null comment via `Listing.getComment(type_id, addr)` (L2207–2209) | **no filter possible** → 1138 leaks |

Two distinct problems, with different fixes:

1. **Types (step 1).** The filter checks only that the type's source archive is *program-local*
   (not an external archive). But **Ghidra auto-analysis also creates program-local structs** —
   switch tables, RTTI, demangled-type artifacts all live in the program's own DataTypeManager. So
   "program-local" is a far-too-loose proxy for "user-created." The docstring's own claim that this
   yields "only user-authored annotations" (`_composite_export_kind`, L2680–2684) is **false in
   practice**.

2. **Comments (step 5) — the crux.** Ghidra **comments carry no source-type at all.** There is no
   `getCommentSource()`; `Listing.getComment(type, addr)` returns a `String` with no provenance.
   ADR-018's docstring assumption — "Ghidra does not auto-author EOL/PRE/etc. for the plate slots we
   read" (`_gh_export_annotations` docstring, ~L2127) — is **empirically FALSE**: auto-analysis
   authors EOL comments (e.g. "WARNING: ..."), PLATE comments (switch-table notes), and more. There
   is **no provenance signal on a comment to filter by.** This is the hard case.

### What the session tracks today (it does NOT track writes)

`src/ghidra_mcp/sessions/manager.py` `_Session` (L103–141) records lifecycle (`state`, TTL/idle
clocks), the owner principal, `binary_sha256`, and the **consent** state (`writes_enabled`,
`allow_structural`). It records **no per-session change log** — there is no record of *which* writes
this session actually performed. Today export reconstructs "user annotations" purely by **enumerating
the program** and filtering by provenance, which is exactly why a no-provenance signal (comments) or
a too-loose one (program-local types) leaks auto-content.

Crucially, every gated write already funnels through one server-side chokepoint:
`require_write_consent` → validate → `ctx.port.<write>` in each `_handle_*` (registry.py L658–893),
and import replays via the same handlers through `_replay_entry` (registry.py L976–1065). The server
**already mediates every write** — it just doesn't *remember* them.

## Decision (proposed — requires human ratification)

### D1 — Types: narrow with a stricter provenance signal; fall back to scope-narrowing if none exists

Replace the program-local-archive proxy with a stricter "user-created" discrimination, in priority
order, taking the **first that live-verification confirms exists and is reliable** on Ghidra 12.1.2:

1. **(Preferred) A direct user-origin signal on the DataType**, if Ghidra exposes one. Candidates to
   investigate at the WS image build (**REQUIRES LIVE VERIFICATION**):
   - `DataType.getSourceArchive()` returning the **`BuiltInDataTypeManager` / program-local-but-
     user** distinction is *not* sufficient (that's the current broken proxy).
   - A **category-path** convention: user-created composites land under the **root category** (`/`),
     whereas auto-analysis types are filed under analyzer-specific category paths (e.g. RTTI under a
     demangler/auto category, switch tables under an auto path). Filter `getCategoryPath()` to the
     root (or an explicit user allow-list of paths) and **exclude** known analyzer category paths.
     *This is a heuristic; see the Silent-Corruption caveat.*
   - Any `DataType` metadata/source-type analogue if one is found (none is known to exist — likely
     **does not**; verify).
2. **(Fallback, if no clean signal exists) Narrow scope** — combine D1's best-available type filter
   with **D2's change-log** (D4 hybrid): a composite is exported only if **both** (a) it passes the
   tightened program-local/root-category filter **and** (b) `define_struct`/`define_union` for that
   name was recorded in this session's change-log. The change-log makes the type filter *correct for
   the common case* (this session's own creations) without relying on a fragile category heuristic.

**Recommendation:** adopt the **change-log-gated** type export (D1 option 2 + D4) as the primary
path, using the tightened category filter only as a defense-in-depth secondary check. Reason: the
category-path heuristic alone carries the same Silent-Corruption risk as comment pattern-matching
(an analyzer that files a type under root, or a user type filed elsewhere, mis-classifies silently).

### D2 — Comments: a session-scoped change-log is the ONLY correct signal — adopt it

Because comments have **no provenance signal**, the only *correct* way to export "user-authored
comments" is to export the comments **this session's gated write tools actually authored**. The
server already mediates every `set_comment` (registry.py L700–723) and every import-replayed
`set_comment` (`_replay_entry`, L1024–1033). Record each into a **per-session, in-memory change-log**
keyed by the write's target, wiped on eviction (ADR-002-compatible — session-lifetime state, not a
durable store). Export then emits **only** logged comments.

This is **decision D4-(A)** below at the model level — it is the recommended answer for comments.

### D3 — Symbols & signatures: unchanged (keep source-type filtering)

Steps 2–4 already filter on `SourceType.USER_DEFINED` (`getSource()` / `getSignatureSource()`) and
are **correct** — no change beyond live re-verification. Source-type is the authoritative, Ghidra-
native provenance signal for symbols and signatures; the change-log is **not** needed for them.

### D4 — Export model: HYBRID (the recommendation) — program-enumeration where a source-type exists, change-log where it does not

The brief frames three options for the overall model. The recommendation is the **hybrid (C)**:

- **Symbols, function renames, signatures** → **program-enumeration filtered by `SourceType.USER_DEFINED`** (steps 2–4 unchanged). Source-type is reliable; enumeration even captures
  annotations from a *prior* session if the same program object carries them, which is a feature.
- **Comments** → **session-scoped change-log** (D2). They have no source-type; the change-log is the
  only correct discriminator.
- **Composite types** → **session-scoped change-log**, with the tightened category filter as a
  secondary safety net (D1 option 2). Program-local is too loose; source-type does not exist for
  composites; the change-log is the reliable signal for this session's creations.

#### The three options, weighed

- **(A) Pure session-change-log** (export = "exactly what I changed this session", *all* kinds).
  - **Most correct** for "what I authored": zero auto-content by construction, for every kind.
  - **Changes ADR-018's model** from program-enumeration to change-log for *all* kinds, including
    symbols/signatures that have a perfectly good source-type filter today.
  - **Loses prior-session annotations:** you cannot export annotations made in a *previous* session
    (e.g. re-imported from a document, then exported again) **unless** import-replays also write to
    the change-log (they do, via `_replay_entry` → `_handle_set_comment` etc. — so a re-export after
    import is preserved *within the same session*). But annotations applied by some *other* path, or
    surviving in the program object across a hypothetical resume, are invisible to a fresh session's
    log. Given ADR-002 (evict wipes the worker + store), there is **no** cross-session program reuse
    anyway — so "prior-session" only means "before this session's worker existed," which by ADR-002
    cannot carry annotations forward except via an imported document. **This narrows the practical
    cost of (A) considerably** — but it still discards source-type-bearing symbols a user might have
    renamed via a path not captured in the log (there is none today: all renames go through the
    gated handlers). Call this out for ratification.
- **(B) Program-enumeration with best-effort comment filtering.**
  - Comments: filter by a provenance signal **that does not exist** (verify — almost certainly no
    `getCommentSource()`), OR **drop comments from export entirely** (correct but lossy — defeats the
    feature for the analyst's comments), OR **heuristic pattern-exclusion** of known auto-comment
    text ("WARNING:", switch-table notes). **The heuristic is fragile and a Silent-Corruption
    risk** (`topic-anti-patterns` / `web-scraper-crawler` SCR): a benign user comment that happens
    to start "WARNING:" is silently dropped; a new Ghidra-version auto-comment phrasing silently
    leaks. **Rejected for comments** — pattern-matching attacker-influenceable text to guess
    provenance is exactly the kind of fragile correctness control this codebase avoids.
- **(C) Hybrid (RECOMMENDED):** source-type filtering where Ghidra gives one (symbols/signatures),
  change-log where it does not (comments, composites).
  - **Most correct *and* least model churn:** keeps the working, authoritative source-type path for
    symbols/signatures; uses the change-log only for the two kinds that genuinely lack a provenance
    signal. Smaller behavioral change than (A); no fragile heuristics like (B).
  - **Cost:** two export paths to reason about (enumeration + log); the change-log must be correctly
    maintained at every write chokepoint (including import-replay) or a comment/type silently drops
    from export (a *missing*-export bug, which is safe-failing — under-inclusion, not auto-content
    leakage).

> **Net recommendation: D4 = hybrid (C), with D2 (change-log for comments) and D1-option-2
> (change-log-gated types) as its concrete realization.** It fixes both leaks, keeps the
> authoritative source-type path for the kinds that have one, and avoids both the model churn of (A)
> and the Silent-Corruption fragility of (B). **The (A)/(B)/(C) choice is a model decision — it
> needs human ratification (it changes ADR-018's export semantics for comments + types).**

## The session-scoped change-log (design)

### What it is

A new per-session, **in-memory**, ordered structure on `_Session` recording the **target identity**
(not the value) of each comment/composite write this session performed:

- `set_comment` → record `(address, comment_type)` and whether it was a set or a **clear** (`text is
  None`, registry.py L715). A clear **removes** the key from the log (so an authored-then-cleared
  comment is correctly *absent* from export).
- `define_struct` / `define_union` → record the composite **name**.
- (Symbols/signatures are **not** logged — they export by source-type, D3.)

The log stores **only identity keys** (addresses, type names) — never comment text or field values
(those are re-read from the program at export time, then untrusted-wrapped per ADR-005). It is a
**set of "what I touched,"** not a copy of the data. This keeps it tiny and keeps confidential
binary-derived content out of the log.

### Where it lives & lifecycle (ADR-002 compliance)

- A field on `_Session` (in-memory, in the server process). **Wiped on eviction** with the rest of
  the session (`_evict_locked`, manager.py L562–613) — it is **session-lifetime state, not a durable
  store**, so ADR-002's no-durable-confidential-state posture is **preserved**. A cross-session /
  on-disk change-log would violate ADR-002 and is **explicitly out of scope**.
- Bounded: cap the number of logged keys (reuse/relate to `_MAX_RESULT_COUNT` = 10 000); over the cap
  → the *write* still succeeds but export fails closed with `limit-exceeded` (never a silent partial
  export — matches ADR-018's bound). The cap also bounds the log's memory (DoS).
- Owner-scoped implicitly (the log lives on the owner's session; export is owner-scoped via
  `authorize`, registry.py L939).

### Where it is recorded (the chokepoint)

The log must be written at the **single server-side write chokepoint** so a new write path cannot
forget it (complete mediation). Two candidate insertion points (decide at impl, **REQUIRES LIVE
VERIFICATION of the success contract**):

1. **In each `_handle_*` write handler, after a successful `result.applied`** (registry.py:
   `_handle_set_comment` L718, `_handle_define_struct` L845+, `_handle_define_union` L865+). Records
   only writes that the worker actually applied. **Preferred** — records intent-confirmed effects,
   and import-replay flows through these same handlers (`_replay_entry`) so re-imported comments are
   logged automatically.
2. Alternatively a small post-write hook in the registry dispatcher shared by all write handlers.

Recommendation: **(1)** — record on the `result.applied` path of the comment/composite handlers
(and ensure `_replay_entry` inherits it for free, which it does since it calls those handlers).

### Export consumes the log

`_gh_export_annotations` (the worker) currently enumerates the program. Under the hybrid:

- The **worker** still enumerates symbols/signatures by source-type (steps 2–4, unchanged) — ADR-001
  keeps enumeration worker-side.
- For **comments and composites**, the **server** passes the change-log's target keys to the worker
  (or the worker is asked to read exactly those targets), and the worker returns the **current value
  at each logged target** (re-read live, untrusted-wrapped). This keeps the values worker-sourced
  (ADR-001) while the *selection* of which targets to export comes from the server's change-log.
  - **Contract implication (see §Contracts):** the `export_annotations` RPC gains a parameter — the
    server-supplied list of comment/composite targets to read — or a second narrow RPC reads exactly
    those targets. The worker no longer blind-enumerates all comments. **REQUIRES LIVE VERIFICATION**
    that `Listing.getComment(type, addr)` reads cleanly for an arbitrary supplied address and that a
    composite lookup-by-name works (`DataTypeManager.getDataType(CategoryPath.ROOT, name)` or
    equivalent — verify).

## Architecture & invariants

- **ADR-001 preserved:** enumeration/read stays in the worker; the server contributes only the
  *selection* (the change-log of targets) and the hash binding. The server still **never parses a
  binary**.
- **ADR-002 preserved:** the change-log is **in-memory, session-lifetime, wiped on evict** — no
  durable confidential state. (A cross-session store is rejected, §Alternatives.)
- **ADR-005 preserved:** exported comment/type values are re-read from the program and **untrusted-
  wrapped**; the change-log stores only identity keys (addresses/names), which are server/worker-
  derived target references, not free binary text.
- **ADR-017 preserved:** the log lives on the owner's session; export is owner-scoped.
- **Import side UNAFFECTED:** import replays whatever the document contains (registry.py L1068–1114);
  a smaller, correct document simply replays fewer entries. No TB8 change. `STRUCTURAL_ENTRY_KINDS`
  and the consent gates are untouched.
- **Functional core / imperative shell:** the change-log is plain session state mutated at the write
  chokepoint (imperative shell); the export selection is a pure read of that state.

## Contracts

- **Tool catalog:** **no new tool** (export/import tools unchanged in count). `session_export_annotations` semantics are **corrected** (now: user-authored only, truly) — a
  catalog/doc note, not a surface change.
- **RPC protocol (`docs/contracts/rpc-protocol.md`):** the `export_annotations` worker RPC likely
  gains a server-supplied **targets** parameter (comment addr/type list + composite name list) so
  the worker reads exactly the logged targets instead of blind-enumerating. **This is the one real
  contract change** and routes through the PM (contracts are frozen — CLAUDE.md WS0). Confirm whether
  a parameter add to the existing RPC or a new narrow read RPC is cleaner at impl.
- **Error envelope:** unchanged — reuse `limit-exceeded` for the bounded log; no new `ErrorType`.
- **Document schema:** unchanged (`AnnotationDocument` / `Entry` union as in ADR-018) — only *which*
  entries are emitted changes.

## Live-verification obligations (the F2 lesson)

F2 was a **speculative `_gh_*` API call that only a live run caught.** Every Ghidra-binding assumption
below is **REQUIRES LIVE VERIFICATION** at the WS image build (ADR-003 open-item discipline) and via
the **blind-acceptance run** — the same validation path that *found* F7:

1. **No comment source-type exists** (`Listing`/`CodeUnit` expose no `getCommentSource()`). If one
   *does* exist on 12.1.2, it would simplify comments to source-type filtering (then re-evaluate D2).
2. **Composite user-origin signal:** whether `getCategoryPath()` reliably separates user (root) from
   analyzer composites, and the exact analyzer category paths to exclude — **or** confirm none is
   reliable (forcing the change-log path, D1 option 2).
3. **Targeted reads work:** `Listing.getComment(type_id, addr)` for a server-supplied address; the
   composite lookup-by-name API. These replace blind enumeration for the logged targets.
4. **`getSignatureSource()` / `getSource()` semantics** for steps 2–4 still behave as assumed
   (re-verify; they appear correct but were never live-confirmed for the auto-vs-user split here).

**Validation path:** un-redact `worker/dispatch.py` `_redacted_detail` (diag mode), rebuild the
worker image, and re-run the **blind-acceptance run in Mode B** with a known write-count fixture
(e.g. exactly N renames + M comments + K structs) and assert the exported document contains **exactly
N + M + K** entries of the right kinds — i.e. the F7 reproduction becomes a regression gate
(`topic-testing`: a failing test first, then the fix). No real binaries — synthetic fixtures only.

## Consequences

- **Positive:** the export document is **correct** — only user-authored annotations; the 39-rename
  run exports 39 entries, not 1190. Round-trip import is smaller and faithful. ADR-018's promise is
  honored. The change-log is a reusable substrate (e.g. future "what changed this session" reporting)
  while staying ADR-002-compliant.
- **Negative / trade-offs:** (a) a **model change** for comments + types (enumeration → change-log),
  to be ratified; (b) export now depends on the change-log being maintained at every write chokepoint
  — a missed chokepoint *under-includes* (safe-failing) but is a bug to guard with the regression
  test; (c) one **RPC contract change** (targets parameter); (d) comments/types authored outside this
  session's gated writes are not exported — acceptable under ADR-002 (no cross-session program
  reuse), but a behavior to document.
- **Deferred / out of scope:** a durable/cross-session change-log or export store (violates ADR-002);
  comment provenance via heuristic text-matching (Silent-Corruption — rejected); any import-side
  change (unaffected).

## Alternatives considered

- **(B) Heuristic auto-comment pattern exclusion** ("WARNING:", switch-table phrasings). **Rejected**
  — fragile, version-brittle, Silent-Corruption risk (drops benign user comments / leaks new auto
  phrasings); guessing provenance from attacker-influenceable text is an anti-pattern here.
- **Drop comments from export entirely.** Correct (zero leakage) but **lossy** — the analyst's
  comments are a core part of the triage they want to persist. **Rejected** — defeats the feature.
- **(A) Pure change-log for all kinds.** Most uniformly correct, but discards the authoritative,
  working source-type path for symbols/signatures and is a larger model change for no correctness
  gain on those kinds. **Rejected in favor of the hybrid (C)** — but **surfaced for ratification**:
  if simplicity-of-one-model is valued over minimal change, (A) is defensible.
- **Durable / cross-session change-log or server-managed export store.** Would let a fresh session
  export a prior analysis without an imported document. **Rejected** — reintroduces the durable
  confidential state ADR-002 deliberately removes (the same reason ADR-018 D2 rejected a server
  store).
- **Tighten only the type filter, leave comments enumerated.** Fixes 13 of the leaks, leaves 1138.
  **Rejected** — comments are the dominant leak and the real correctness problem.

## Decisions needing human ratification

1. **D4 — the comments/types export model: (A) pure change-log / (B) enumeration+filter / (C)
   hybrid.** *Recommended: (C) hybrid.* This is a **model decision** changing ADR-018's export
   semantics for comments + composites — the load-bearing call.
2. **D2 — adopt a session-scoped, in-memory, evict-wiped change-log** (target keys only, no values)
   as the comment provenance signal. Confirms ADR-002 reading: session-lifetime state is permitted;
   cross-session/durable is not.
3. **D1 — type discrimination approach:** change-log-gated (recommended) vs. category-path heuristic
   vs. accept-and-narrow-scope — pending the live-verification finding on whether any reliable
   DataType user-origin signal exists.
4. **Contract change ratification:** the `export_annotations` RPC gaining a server-supplied targets
   parameter (or a new narrow read RPC) — frozen-contract change, routes through the PM.
5. **Accept the behavior** that comments/types authored outside this session's gated writes are not
   exported (acceptable under ADR-002; document it).
