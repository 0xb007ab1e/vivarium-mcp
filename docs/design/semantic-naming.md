# Design: Semantic-naming support (call graph, leaf-first ordering, function context)

> Status: built (v1.1, `feat/semantic-naming`). Implements ADR-007. The pure ordering core, the
> contract schemas, the server-side adapter (extraction wiring + one-hop projections + aggregation),
> and the worker RPC contract are all implemented and unit-tested. The two worker/JVM extraction
> bindings (`_gh_call_graph`, `_gh_referenced_strings`) are coverage-omitted edges whose end-to-end
> behavior is validated only by the real-worker integration suite (a gated Ghidra-image build).

## 1. Goal & scope

Help a client LLM turn Ghidra's mechanical pseudo-C into well-named, plausibly-recompilable C by
walking the call graph **leaf-first** (lowest callees first → entry roots last), naming each
function with the context of its already-named callees. The server is a **pure tool layer**: it
supplies facts (graph, decompilation, signatures, strings) and a plan (the order); the **client**
does the naming and C synthesis. **Read-only, output-only** — never mutates the Ghidra DB. C is
**best-effort**; compile-rate and behavioral equivalence are **measured, not guaranteed** (ADR-007).

## 2. New tools (READ-ONLY; pydantic source of truth: `tools/schemas.py`)

| Tool | Input | Output | Touches |
|------|-------|--------|---------|
| `call_graph` | `CallGraphIn{root?, max_depth, max_nodes, max_edges}` | `CallGraphOut{nodes[], edges[], unresolved_callers[], truncated}` | worker extraction |
| `callees` | `CalleesIn{function, offset, limit}` | `CallNeighborsOut{neighbors[], total, unresolved, truncated}` | worker extraction |
| `callers` | `CallersIn{function, offset, limit}` | `CallNeighborsOut{...}` | worker extraction |
| `analysis_order` | `AnalysisOrderIn{root?, max_depth, max_nodes, max_edges}` | `AnalysisOrderOut{components[], unresolved_callers[], self_recursive[], truncated}` | worker extraction → **pure core ordering** |
| `function_context` | `FunctionContextIn{function, include_decompilation, max_callees, max_callers, max_strings}` | `FunctionContext{address, name*, signature*, is_external, decompilation*?, callees[], callers[], referenced_strings[]*, has_unresolved_calls, truncated}` | server-side aggregation of existing read-only RPCs |

`*` = `Untrusted[...]`-wrapped (binary-derived) field. Node `name`s in graphs/neighbors are
`Untrusted` too. Addresses (server-normalized), counts, and the ordering/flags are bare.

All inputs are `frozen`, `extra="forbid"`, session-scoped (authorized server-side — BOLA), and
**bounded** (see §6).

## 3. Leaf-first reverse-topological ordering over SCCs (the algorithmic heart)

Implemented in **`src/vivarium/core/callgraph.py`** — pure, no JVM, no I/O, 100%-tested
(critical path). The worker extracts a resolved adjacency map (`caller → callees`); the server
computes the order:

1. **Why SCCs.** Real binaries have recursion and mutual-recursion cycles, so the call graph is
   *not* a DAG and a plain topological sort doesn't exist. We **condense each strongly-connected
   component** (a maximal mutually-reachable set — a recursion cycle, or a single function) into
   one node. The condensation of any directed graph **is** a DAG (Tarjan's theorem).
2. **Leaf-first order.** We compute SCCs with **Tarjan's algorithm (iterative)**, which emits
   components in reverse-topological order of the condensation — **sinks (leaves: call nothing
   further) first, sources (entry roots) last**. That is exactly the naming order: a callee's
   component is always ordered before its caller's.
3. **Cycles surfaced, not flattened.** A multi-member `Component` is a mutual-recursion cycle
   (`is_recursive=True`); the client names its members together (no strict leaf-first order
   *within* a cycle). A single-member component is `is_recursive=True` iff the function has a
   **self-loop** (direct recursion); self-loops are also listed in `self_recursive`.
4. **Unresolved edges surfaced, never silently dropped.** Indirect/virtual/computed call sites
   Ghidra cannot resolve to a concrete callee are reported in `unresolved_callers`. A function
   whose real callees are hidden behind a vtable/function-pointer is flagged so the client knows
   its inferred purpose rests on incomplete information (ADR-005 honesty; threat-model TB4).
5. **Robustness.** The algorithm is **iterative** (explicit work stack, no Python recursion), so a
   pathologically deep or long-cyclic graph cannot blow the interpreter stack; results are
   deterministic (sorted node/component membership). Disconnected nodes each form a singleton
   component; unknown callee ids (e.g. external imports with no own entry) are treated as leaf
   nodes and ordered.

```text
root ─▶ a ─▶ b ─▶ leaf            order (leaf-first):
        ▲    │                     [leaf] , [a,b](recursive) , [root]
        └────┘  (a↔b mutual rec)   sinks first ─────────────────▶ roots last
```

## 4. The `function_context` bundle

Server-side aggregation (no naming, no synthesis — no server-side LLM) of the per-function facts a
client needs to name one function and draft its C:

- `name`, `signature`, `is_external` — what Ghidra knows; `is_external=True` for imported/external/
  thunk functions whose names are **KNOWN** (libc `puts`, an import) and must **NOT** be re-inferred.
- `decompilation` — the pseudo-C (optional; `GHIDRA`-origin `Untrusted`).
- `callees` / `callers` — one-hop neighbors (bounded) for bottom-up + usage context.
- `referenced_strings` — string literals the function references (bounded) — a strong naming signal.
- `has_unresolved_calls` — honesty flag that the call context is incomplete.

Assembled server-side from `get_function` (name/signature/entry), a depth-1 `call_graph` (the
function's own node + direct callees), a reverse one-hop over the whole-program `call_graph`
(callers), `decompile_function` (the pseudo-C), and the dedicated `referenced_strings` worker
primitive — every binary-derived field wrapped at the single `core.envelope.wrap` chokepoint
(ADR-005). `is_external`/`has_unresolved_calls` are taken from the function's graph node. The
client may pass previously-assigned callee names back as *inert input* on later calls; the server
never trusts, executes, or persists them.

## 5. Client orchestration loop (the client builds this; documented for the contract)

```
graph  = call_graph(session)                 # or scoped to a root
order  = analysis_order(session)             # leaf-first components
assigned = {}                                # address -> client-chosen name (client-held)
for component in order.components:           # sinks → roots
    if component.is_recursive:               # name a cycle's members together
        ctxs = [function_context(session, f, assigned_callees=assigned) for f in component.members]
        names = LLM_name_and_synthesize(ctxs)        # CLIENT side
    else:
        ctx  = function_context(session, component.members[0], assigned_callees=assigned)
        names = LLM_name_and_synthesize([ctx])       # CLIENT side
    assigned.update(names)                   # carry forward into callers
# optional: client MEASURES compile-rate / behavioral-equivalence-on-test-inputs (not guaranteed)
```

The server exposes the facts/plan; the loop, the naming, the C synthesis, and any measurement are
the client's. External (`is_external`) functions are skipped for naming — their names are known.

## 6. Bounds / DoS caps (enforced at the tool boundary, before the worker)

A hostile binary can present a huge, deep, or densely-cyclic call graph (`std-owasp-llm` LLM04;
threat-model TB4). Caps (schema-level `le=`, mirrored in `core.validation`/`security.limits` for
the v1.1 build):

- `call_graph`/`analysis_order`: `max_nodes ≤ 50 000` (default 10 000), `max_edges ≤ 200 000`
  (default 40 000), `max_depth ≤ 256` (default 8). The worker stops at the cap and sets
  `truncated=True` (honest partial view).
- `callees`/`callers`: paginated (`offset` + `limit ≤ 10 000`).
- `function_context`: `max_callees`/`max_callers`/`max_strings ≤ 1024` each.
- `function`/`root` names: validated by `core.validation.validate_name` (charset, length).
- The pure ordering core is robust to any size (iterative, no recursion) regardless of caps —
  caps bound *cost*, not correctness.

## 7. Metrics (client-measured; the server enables, doesn't compute)

- **Compile-rate:** fraction of synthesized functions/programs that compile (client toolchain).
- **Behavioral equivalence on test inputs:** run original vs. recompiled on a set of inputs and
  compare observable behavior — a *sampled* signal, **not** a proof of equivalence.
- These are quality metrics the client tracks over a corpus; the server makes **no guarantee**
  about either (ADR-007 caveat). For correctness-sensitive use, treat synthesized C as a draft.

## 8. Module / boundary map

| Concern | Location | JVM? |
|---|---|---|
| Tool schemas (frozen In/Out) | `src/vivarium/tools/schemas.py` | no |
| Tool handlers (authorize → validate → delegate) | `src/vivarium/tools/registry.py` | no |
| **Leaf-first ordering (pure core)** | `src/vivarium/core/callgraph.py` | **no** |
| Adapter: extraction wiring + one-hop/aggregation + wrap | `src/vivarium/ghidra/rpc_client.py` (`call_graph`/`callees`/`callers`/`analysis_order`/`function_context`, `_one_hop`, `_build_*`) | no |
| Port interface | `src/vivarium/ghidra/port.py` | no |
| Worker RPC methods (allow-list + dispatch) | `worker/dispatch.py` (`call_graph`, `referenced_strings`) | no |
| **Graph + string extraction (worker/JVM)** | `src/vivarium/ghidra/_jvm_bridge.py` (`_gh_call_graph`, `_gh_referenced_strings`) | **yes — worker only (ADR-001)** |

## References
- ADR-007 (decision), ADR-001 (out-of-process), ADR-005 (untrusted envelope), ADR-006 (catalog seam).
- Tarjan, "Depth-first search and linear graph algorithms" (SCCs). `@rules/topic-architecture-patterns.md`
  (functional core / imperative shell). `docs/contracts/tool-catalog.md`, `docs/security/threat-model.md`.
