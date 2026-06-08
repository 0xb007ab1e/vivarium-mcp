# ADR-007: Semantic-naming support tools (call-graph + leaf-first ordering + function context)

- **Status:** Accepted (v1.1; contract expansion PM-ratified — built on `feat/semantic-naming`)
- **Date:** 2026-06-08
- **Deciders:** Human (locked decisions) + PM; recorded by Software Architect (v1.1 bootstrap)
- **Relates to:** ADR-001 (out-of-process Ghidra), ADR-005 (untrusted-data envelope),
  ADR-006 (stdio-first / tool-catalog extensibility seam)

## Context

A common reverse-engineering workflow is to take Ghidra's mechanical pseudo-C — full of
auto-generated names (`FUN_00401000`, `iVar1`, `param_2`) — and turn it into readable,
well-named, plausibly-recompilable C. Doing this well requires working **leaf-first**: name the
lowest-level callees (which call little or nothing) first, then carry those names upward into the
functions that call them, accumulating context until you reach the entry roots ("start at the
lowest call site, work backwards"). To support that, a client needs three things the v1 Tier-1
catalog does not provide: (1) the **call graph** (who calls whom), (2) a **leaf-first ordering**
over it, and (3) a **per-function context bundle** (decompilation + signature + neighbors +
referenced strings) to feed a naming/synthesis step.

The naming and C-synthesis themselves are an LLM task. The question is *where* that intelligence
lives and *what guarantees* the server makes.

## Decision

Add **five new READ-ONLY MCP tools** via the ADR-006 tool-catalog extensibility seam:
`call_graph`, `callees`, `callers`, `analysis_order`, `function_context`. The four locked human
decisions shape them:

1. **The server is a pure tool layer; the client LLM does the naming + C synthesis.** There is
   **no server-side LLM.** The tools surface *facts* (graph edges, decompiled C, signatures,
   referenced strings) and a *plan* (the leaf-first order); the client orchestrates the loop and
   produces names/C. This keeps the server small, auditable, and free of model/agency risk
   (`std-owasp-llm` LLM08 excessive agency stays the client's concern, not ours).

2. **Output-only — the tools NEVER mutate the Ghidra database.** No rename, no retype, no comment
   write, no `runScript`. The client holds the assigned names/C in its own context and may pass
   prior assignments back into `function_context` purely as *additional inert input*; the server
   echoes them as context and never trusts or persists them. v1's read-only invariant is intact.

3. **Best-effort C — compile-rate and behavioral equivalence are MEASURED metrics, NOT
   guarantees.** Decompiler output is, in general, **not recompilable into a behaviorally
   equivalent program**: type recovery is lossy, calling conventions and ABI details are inferred,
   compiler intrinsics/inline asm/undefined behavior don't round-trip, and indirect control flow
   is often unresolved. We say this plainly. The feature *helps a client draft* C and lets it
   **measure** how close it got (compile rate; behavioral equivalence on a set of test inputs) —
   it does not promise either. Honesty over false assurance (master §2 fail-closed ethos).

4. **Off `main`, built as a v1.1 increment** in an isolated worktree, contracts frozen before the
   build fan-out (mirroring the WS0 pattern).

## Relationship to prior ADRs

- **ADR-001 (out-of-process; no JVM server-side) — UPHELD, and the split is the crux.** Graph
  *extraction* (which function calls which, who is external/thunk, which call sites are unresolved)
  is a Ghidra/JVM operation and lives **only in the worker** (`_gh_call_graph` + `_gh_referenced_
  strings` in `_jvm_bridge`, behind two new worker RPC methods `call_graph` + `referenced_strings`).
  The leaf-first **ordering** over the extracted adjacency is
  **pure graph theory with no JVM, no I/O, no binary parsing** — so it lives in the **pure
  server-side core** (`src/ghidra_mcp/core/callgraph.py`, the functional core). The server never
  loads the JVM; the architecture-invariant test that bans `pyghidra`/`jpype`/`_jvm_bridge` imports
  from server-side modules continues to pass (the ordering core imports none of them).

- **ADR-005 (untrusted-data envelope) — APPLIED.** Decompiled C in a `function_context` bundle, and
  every function/symbol **name** in graph nodes, is binary-derived and stays `Untrusted[...]`
  (`GHIDRA` origin for synthesized C/signatures, `BINARY` origin for extracted names/strings). The
  graph's structural data (addresses we normalize, the ordering itself, recursion/unresolved flags)
  is server-computed and stays bare. The client renders all `Untrusted` content as inert data and
  must not let a hostile binary's planted name/comment/string in the bundle act as an instruction
  (indirect prompt injection — LLM01/02).

- **ADR-006 (stdio-first; tool-catalog extensibility seam) — USED AS INTENDED.** These tools are
  added through the explicit, reviewed allow-list (no dynamic tool surface), with frozen pydantic
  In/Out schemas, exactly as ADR-006 reserved for catalog growth. **No new transport, no network
  surface** — still stdio, still read-only. The catalog count moves from 22 → 27.

## Honest no-equivalence-guarantee caveat (normative)

The server **does not** and **cannot** guarantee that any C a client synthesizes from these tools
compiles, links, or behaves identically to the original binary. Decompilation is a lossy,
heuristic recovery of source from machine code. The feature's value is **assistive + measurable**:
it structures the work leaf-first and surfaces the facts, and a client may *measure* compile-rate
and behavioral-equivalence-on-test-inputs as quality signals. Any product copy, tool description,
or downstream claim MUST reflect "best-effort, measured — not guaranteed."

## Consequences

- **Positive:** unlocks the highest-value RE workflow without a server-side LLM or any DB mutation;
  the algorithmic heart (leaf-first SCC ordering) is a pure, 100%-tested core that needs no Ghidra;
  the worker/JVM surface grows by exactly two extraction methods (`call_graph` +
  `referenced_strings`), and the public tools `callees`/`callers`/`analysis_order`/
  `function_context` are derived/aggregated server-side from them (no extra worker surface); the
  read-only + containment invariants are untouched; honesty about equivalence avoids over-promising.
- **Negative:** a hostile binary can present a huge/deep/cyclic call graph (DoS) — mitigated by
  node/edge/depth caps enforced at the tool boundary before the worker (threat-model addendum,
  TB4); unresolved indirect/virtual edges mean the graph (and any inferred purpose) is incomplete —
  surfaced explicitly, never silently dropped.
- **Rejected alternative — server-side naming/synthesis (an in-process LLM or agent):** rejected.
  It would put model/agency risk and cost in the trusted control plane, contradict locked decision
  #1, and bloat the server. Naming is the client's job; we supply facts + a plan.
- **Rejected alternative — a DB-mutating "apply names" tool:** rejected for v1.1 (violates the
  read-only invariant). A gated mutation tier remains a separate future increment (PLAN §2 v1.1
  "mutation tools (gated)"), out of scope here.
