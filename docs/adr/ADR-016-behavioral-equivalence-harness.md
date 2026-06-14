# ADR-016: Behavioral-equivalence differential-run harness

- **Status:** Accepted (v1.1 design; human-ratified decisions D1–D4, 2026-06-14). **Supersedes** the
  deferred `behavioral_equivalence` field left `None` by ADR-010.
- **Deciders:** Human (locked decisions D1–D4, 2026-06-14) + PM; recorded by the Software Architect.
- **Relates to:** ADR-010 (semantic-naming eval — the harness this completes), ADR-007 (semantic-naming
  tools), ADR-001 (out-of-process Ghidra; the server never loads the JVM), ADR-004 (isolation tier),
  ADR-005 (untrusted-data envelope).

## Context

ADR-010 shipped the naming eval — orchestration core, `name_coverage`, `score()`, the TB5 sandboxed
`CompileRunner` (`ContainerCompileRunner`), the gated naming-eval e2e, and `naming_accuracy`
(PRs #26–29). It deliberately left ONE field unbuilt: `metrics.py` carries
`behavioral_equivalence: float | None = None` — *"does the rebuilt artifact behave like the original
on test inputs?"* (`metrics.py:11`) — flagged research-hard and deferred.

The literal framing ("run **original** vs. recompiled and compare outputs", `docs/design/semantic-naming.md:126`)
collides with a foundational principle: **this system never executes the hostile sample** — Ghidra
*statically* analyzes it in the worker and nothing runs it (ADR-001/004). A naive differential harness
that executed the original binary would open the single most dangerous capability we have refused to
build. This ADR scopes a harness that measures behavioral fidelity **without ever running the attacker
artifact**.

## Decision (D1–D4, ratified)

### D1 — Never execute the original hostile binary.
The differential compares two **builds**, not the sample:
- **(A) reference build** — compiled from the fixtures own **trusted, known source** (e.g. cJSON),
- **(B) candidate build** — the **recompiled renamed-decompiled-C** produced by the naming loop,

run on a shared set of **synthetic** inputs and compared. The "original-behavior" baseline is the
trusted reference source, **not** the binary under analysis. The attacker artifact is never executed.
**Corollary:** `behavioral_equivalence` is computable **only for ground-truth fixtures that carry
trusted source**; for an arbitrary real hostile binary (no trusted reference) it stays **`None`** —
honestly "unavailable", never a fabricated number. Diffing against the actual hostile original is
**rejected for v1.1** (would breach ADR-001; recorded as out of scope).

### D2 — I/O differential oracle (bounded, measured-not-guaranteed).
For each synthetic input vector, run A and B and capture **(exit code, stdout bytes)** under a bounded
output cap. `behavioral_equivalence` = **fraction of input vectors whose (exit code, captured stdout)
match**. It is an **honest measured signal, never a guarantee** (same posture as compile-rate and
`naming_accuracy`): decompiled C frequently wont even recompile, so low scores are expected and are
themselves useful signal. Deeper notions (memory-state, coverage-guided, return-struct) are out of
scope. Output comparison is **byte-exact** in v1 (no normalization) to keep the oracle unambiguous;
normalization is a future refinement if it proves too brittle.

### D3 — Corpus + isolation (reuse + extend TB5).
- **Corpus:** the existing **cJSON DWARF ground-truth fixture** (already used by the naming-eval e2e);
  a small, committed, **synthetic** input-vector set (no real/PII data — master §5).
- **Isolation:** extend the TB5 runner so it can **compile → run → capture** under the **same**
  worker-style isolation `ContainerCompileRunner` already enforces (rootless, `--network none`,
  read-only rootfs, dropped caps, no-new-privileges, seccomp, CPU/mem/**pids** caps, ephemeral tmpfs,
  **killed on timeout** — ADR-004). **Both** builds (A and B) execute in-sandbox, uniformly — even the
  trusted reference — so the harness has a single contained execution path. Inputs are bounded;
  captured output is **size-capped** (anti output-flood DoS).

### D4 — New ADR-016 (this), superseding ADR-010s deferred field.
A distinct capability (execution + differential comparison, an extension of TB5) gets its own ADR
rather than reopening Accepted ADR-010. ADR-010s `behavioral_equivalence` field is now realized here.

## Architecture (ports & adapters — ADR-001/005 preserved)

- **Pure comparison core** in `naming/metrics.py`: `behavioral_equivalence(runs_a, runs_b) -> float | None`
  — a deterministic, I/O-free function over two lists of `(exit_code, stdout)` run-results (or `None`
  when no trusted reference exists). The **functional core never executes anything** — it only compares
  inert captured data. Renamed/decompiled C and all captured stdout stay **`Untrusted`** (ADR-005);
  nothing is executed, rendered, or evald by the core.
- **A new `ExecRunner` port** — `Callable[[bytes_or_source, inputs], list[RunResult]]` (the precise
  signature is an implementation detail of the impl increment) — implemented by the sandboxed runner
  at the edge; the cores are unit-tested against a **fake** runner. The real sandboxed compile+run
  adapter lives beside `ContainerCompileRunner` in `naming/compile.py`.
- The harness is **client-side eval only** (the `ghidra_mcp.naming` package): the **server never
  imports it and it never loads the JVM** (ADR-001). It is **not** a new MCP tool — no `tool-catalog`
  / `rpc-protocol` change.

## Security (TB5 extension)

The dangerous capability — executing attacker-derived recompiled C — **already exists** in TB5
(`ContainerCompileRunner`). This ADR adds, inside that same boundary:
- **Executing a trusted reference build** (lower risk than the candidate; still sandboxed uniformly).
- **Feeding synthetic, bounded inputs** to both builds and **capturing bounded output**. Inputs are
  **author-controlled synthetic vectors**, not attacker-controlled; output capture is size-capped so a
  malicious candidate cant flood/DoS via stdout.
- **No new "run the sample" boundary** opens (D1): the hostile binary is never executed.
- Abuse tests (impl increment, threat-model **TB5** delta + new abuse cases): a renamed-C TU that
  hangs, fork-bombs, over-allocates, over-reads, or emits unbounded output is **contained** (timeout
  kill / pids+mem caps / output cap), not an escape or a harness crash. Captured output is treated as
  **data** (compared, never executed/rendered).

## Consequences

- `behavioral_equivalence` becomes a **measured** metric **on ground-truth fixtures with trusted
  source**, and stays **`None`** otherwise (honest unavailability) — completing ADR-010s eval triad
  (coverage + accuracy + behavioral equivalence), all "measured, not guaranteed".
- Realistic scores will often be **low** (decompiled C rarely recompiles+runs cleanly) — that is
  honest signal, not a regression; product/tool copy must not present it as a guarantee (ADR-007).
- One contained execution path for both builds; the e2e that exercises it is **gated** (like the
  naming-eval e2e), not in the default unit run.
- **Deferred / out of scope (recorded):** diffing against the *real hostile original* (breaches
  ADR-001 — rejected for v1.1); deeper equivalence (memory/coverage-guided); fuzz/auto-generated input
  vectors; output normalization. Revisit only with a new ADR.

## Implementation increment (follows this design PR)

1. `naming/metrics.py`: pure `behavioral_equivalence(runs_a, runs_b)` + wire it into `score()` (only
   populated when a trusted reference + inputs are supplied; else `None`). 100% line+branch.
2. `naming/compile.py`: extend the TB5 adapter to compile+run+capture (the `ExecRunner` real impl)
   under the existing isolation, with input + output-size + timeout bounds.
3. Synthetic input-vector fixtures (committed, non-sensitive) for the cJSON ground truth.
4. Gated differential e2e driving A-vs-B over the fixture; threat-model **TB5** delta + new abuse
   cases (hang / fork / over-read / output-flood contained); `topic-testing` coverage gates.
