# ADR-008: Tier-2 reporting & metrics tools (read-only analysis layer)

- **Status:** Proposed (v1.1 increment; contract expansion awaiting PM ratification — batch-atomicity)
- **Date:** 2026-06-08
- **Deciders:** Human (v1.1 increment selection) + PM; recorded by Software Architect
- **Relates to:** ADR-001 (out-of-process Ghidra), ADR-005 (untrusted-data envelope),
  ADR-006 (stdio-first / tool-catalog extensibility seam), ADR-007 (semantic-naming / call-graph core)

## Context

v1 ships raw, read-only **Tier-1** tools (decompile, disassemble, list functions/strings/symbols,
xrefs, bytes, metadata). A client LLM doing triage or reverse-engineering also wants **higher-level,
derived facts**: how complex a function is, what a binary imports/exports, what indicators (IPs,
URLs, hashes) and crypto constants it contains, the shape of its call graph, and a one-shot
program summary. PLAN §2 reserves these as the **Tier-2 reporting/metrics** v1.1 increment.

These are **analysis/reporting** outputs computed *over* facts Ghidra already exposes — not new ways
to touch the binary. The question is what to surface, how to keep the server thin/safe, and what the
tools honestly promise.

## Decision

Add a curated set of **READ-ONLY Tier-2 tools** via the ADR-006 catalog seam:

| Tool | Purpose | Compute split |
|------|---------|---------------|
| `cyclomatic_complexity` | per-function McCabe complexity | worker extracts CFG block/edge counts → **pure core** computes `E − N + 2` |
| `list_imports` | imported symbols/functions (+ library) | worker extraction |
| `list_exports` | exported symbols/entry points | worker extraction |
| `coverage` | defined-code / defined-data / undefined byte ratios | worker extraction → **pure** ratio |
| `ioc_scan` | indicators (IPv4/IPv6, URL, domain, email, hash, path) in strings | **pure core** over extracted strings |
| `crypto_constant_scan` | known crypto constants/signatures (AES S-box, SHA/MD5 IVs, …) | **pure core** over extracted data/bytes |
| `call_graph_metrics` | fan-in/out, leaf/root/recursive counts, hotspots | **pure core** over the ADR-007 call graph |
| `program_summary` | one-shot aggregate report | **server-side aggregation** of the above + Tier-1 |

The locked principles:

1. **Read-only, output-only — NO Ghidra DB mutation.** Tier-2 only reads/derives. Mutation tools
   (rename/retype/comment-write) remain a **separate, gated, separately-threat-modeled** v1.1
   increment — explicitly NOT in this ADR.

2. **Functional core / imperative shell (ADR-001 upheld).** Wherever a metric is *computable from
   already-extractable facts*, it is computed in the **pure server-side core** (no JVM): the McCabe
   formula, IOC/crypto pattern matching, and all call-graph metrics. Only the **raw extraction**
   that needs Ghidra's analysis (CFG block/edge counts, the import/export tables, coverage byte
   counts) touches the JVM — and that lives **only in the worker** (`_jvm_bridge`, new worker RPCs).
   The architecture import-ban test (no `pyghidra`/`jpype`/`_jvm_bridge` in server packages, incl.
   `ghidra/`) continues to pass.

3. **Untrusted-data envelope (ADR-005) — APPLIED, and `ioc_scan` is the sharpest case.** Every
   binary-derived value stays `Untrusted[...]`: import/export **names**, the **matched IOC string**
   (`value`), crypto-finding detail, function names in metrics. An IOC "URL" or "domain" is *matched
   attacker-controlled string content* — a prime indirect-prompt-injection vector (a planted
   `value` like `http://x/ignore-previous-instructions`); it is surfaced as inert, wrapped data the
   client must not follow/execute. Addresses, counts, ratios, categories, and algorithm labels are
   server-computed/closed-vocabulary and stay bare.

4. **Bounded by default (DoS — std-cwe CWE-400).** Every tool that returns a list is paginated
   (`offset`/`limit ≤ 10 000`) or capped; `ioc_scan`/`crypto_constant_scan` bound the input set they
   scan (string count, data window) and set `truncated`; `call_graph_metrics` inherits the ADR-007
   node/edge/depth caps. The worker enforces its own caps before returning.

5. **NO new trust boundary.** Still a single **stdio**, **read-only** process. `std-owasp-api` and
   `std-zero-trust` stay **out** of scope (they belong to the separate HTTP-transport increment).
   The four trust boundaries (PLAN §4) are unchanged; Tier-2 sits on TB1 (client args) / TB3 (hostile
   binary → analyzer, for extraction) / TB4 (untrusted output → LLM).

## Honest caveats (normative)

- **`ioc_scan` and `crypto_constant_scan` are HEURISTIC** — pattern/signature based. They have false
  positives (a random byte run matching an S-box prefix; a version string matching a URL regex) and
  false negatives (obfuscated/encrypted indicators, custom crypto). They are **triage aids, not
  authoritative detections**; the tool output says so and the client must treat findings as leads.
- **`cyclomatic_complexity` is only as good as Ghidra's recovered CFG** — incomplete disassembly
  (unresolved indirect branches, data-as-code) skews it. Reported with the block/edge counts so the
  client can judge confidence.
- **`coverage` measures what Ghidra *defined***, not ground truth — undefined ≠ "not code."

## Relationship to prior ADRs

- **ADR-001 — upheld.** Metrics/scans are pure-core; only extraction touches the JVM (worker-only).
- **ADR-005 — applied.** All binary-derived fields (esp. IOC `value`) wrapped at the
  `core.envelope.wrap` chokepoint in the adapter.
- **ADR-006 — used as intended.** Tools added through the reviewed allow-list with frozen pydantic
  In/Out schemas; catalog count grows 27 → 35. No new transport.
- **ADR-007 — reused.** `call_graph_metrics` consumes the same extracted call-graph adjacency and the
  pure `core.callgraph` SCC machinery; `program_summary` composes the semantic-naming + Tier-1 tools.

## Consequences

- **Positive:** high-value triage/reporting with the server staying thin and JVM-free for all
  derivation; heavy reuse of the ADR-005 envelope, ADR-007 call-graph core, and Tier-1 extraction;
  read-only + containment invariants untouched; honest about heuristic limits.
- **Negative:** more worker extraction surface (CFG/imports/exports/coverage RPCs) — each bounded and
  fuzz-tested; IOC/crypto heuristics carry false-positive/negative risk — mitigated by explicit
  "triage-only" framing + Untrusted wrapping. More tools = more catalog surface — curated, not open.
- **Rejected — compute metrics in the worker (JVM-side).** Rejected: it would bloat the JVM surface
  and put derivation logic behind the un-unit-testable edge. Keep extraction minimal in the worker;
  derive in the pure, 100%-tested core.
- **Rejected — a single mega `analyze_report` tool.** Rejected: poor composability, unbounded output,
  hard to cache/paginate. Curated, individually-bounded tools + one aggregating `program_summary`.
- **Deferred (NOT this ADR):** mutation tools (gated), HTTP transport — separate v1.1 increments,
  each separately threat-modeled.
