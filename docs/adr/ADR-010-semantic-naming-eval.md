# ADR-010: Semantic-naming reference client + naming-quality eval

- **Status:** Accepted (v1.1; first slice on `feat/semantic-naming-eval`, 2026-06-11)
- **Deciders:** Human (locked decisions, 2026-06-08) + PM; recorded by Software Architect.
- **Relates to:** ADR-001 (out-of-process Ghidra), ADR-005 (untrusted-data envelope),
  ADR-007 (semantic-naming tools), ADR-004 (isolation tier).

## Context

ADR-007 shipped the read-only semantic-naming **tools** (`call_graph`, `callees`, `callers`,
`analysis_order`, `function_context`, `referenced_strings`) — the server-side scope is complete
(locked decision #1: the server is a pure tool layer; the **client LLM** orchestrates naming + C
synthesis). What was missing is the thing that *uses* the tools and *measures* whether they deliver
the goal — named, plausibly-recompilable C — so quality is tracked honestly rather than asserted.

## Decision

Add a **pure, client-side** package `ghidra_mcp.naming` (a tool *consumer*, never server runtime;
the server never imports it; it never loads the JVM — ADR-001):

- **`naming/loop.py` — leaf-first orchestration core (functional core).** `orchestrate(order,
  contexts, namer)` walks `analysis_order` components **leaf-first** (sinks first; SCCs already
  condensed), and for each non-external function asks an injected **`Namer`** for a name + renamed
  pseudo-C, **carrying assigned callee names forward** to callers. External/imported functions keep
  their **known** name (never re-inferred — decision #1). Bounded (`max_functions`); honest `notes`
  for missing context, truncation, and unresolved indirect/virtual calls. Returns a
  `RenamedProgram` (per-function outcomes + assembled translation unit). Pure/deterministic — the
  `Namer` (client LLM in prod; deterministic stub in tests/eval) is injected.
- **`naming/metrics.py` — measured quality (decision #3: MEASURED, not guaranteed).**
  `name_coverage` (fraction renamed away from Ghidra `FUN_`-placeholders — pure); `score(program,
  compile_runner=…, ground_truth=…)` adds compilability via an injected **`CompileRunner`** and
  **`naming_accuracy`** (proposed names vs a known ground truth — strict `exact_match_rate` + a
  token-set `mean_token_f1` that credits `get_array_size` ≈ `cJSON_GetArraySize`); pure, given an
  injected address→name map. `behavioral_equivalence` is a present-but-deferred field. Compilability,
  accuracy, and behavioral equivalence are **honest metrics to track, never guarantees** — turning
  decompiler pseudo-C into a recompilable, equivalent program is not solvable in general; flagged +
  accepted as best-effort. Only the *client* namer (decision #1) yields a meaningful accuracy; the
  eval's stub scores ~0 by design.

Ports (`Namer`, `CompileRunner`) keep the cores hermetic and unit-tested with fakes; the real
implementations (LLM, sandboxed compiler) plug in at the edges.

## Security (NEW trust boundary — TB5)

The eval's compile/run step would **compile and execute C derived (via the namer) from a HOSTILE
binary's decompilation** — i.e. running attacker-influenced code. That is a new trust boundary on
par with the worker (ADR-001/004). Mandate, before any real compile/run lands:

- The compiler/runner runs in **worker-style isolation**: rootless container, `--network none`,
  read-only rootfs, dropped caps, no-new-privileges, seccomp, CPU/mem/pids caps, ephemeral tmpfs,
  killed on timeout (ADR-004). No host toolchain invocation on attacker-derived source.
- Decompiled **and** renamed C stay `Untrusted` (ADR-005); the **pure core never executes** any of
  it — it only assembles inert text. Only the isolated runner ever feeds it to a compiler.
- Abuse tests: malicious decompilation (compiler-bomb, `#include`/`__attribute__` abuse, huge TU)
  must be bounded + contained, not crash or escape the sandbox.

## Consequences

- **This slice (pure, hermetic):** the orchestration core + `name_coverage` + the `score()` scorer
  with injected ports; 100%-covered unit tests with a stub namer + fake compiler. No untrusted code
  is executed anywhere yet.
- **Shipped (gated increments):** the sandboxed `CompileRunner` (TB5 isolation, PR #27/#28) and the
  **gated naming-eval e2e** driving the reference loop over the real cJSON ground-truth fixture —
  it reports coverage + compilability and tracks **`naming_accuracy`** against the DWARF symbol
  truth the fixtures carry. The e2e's stub namer scores ~0 accuracy by design (a real client namer
  is the meaningful source); a truth-echoing namer asserts the real Ghidra↔DWARF address join +
  exact-match plumbing scores 1.0 end to end.
- **Deferred:** the behavioral-equivalence differential-run harness (research-hard; field present,
  `None`).
