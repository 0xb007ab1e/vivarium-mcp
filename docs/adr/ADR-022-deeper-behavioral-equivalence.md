# ADR-022: Deeper behavioral-equivalence eval — output normalization + fuzz inputs

- **Status:** Accepted (v1.2 design; human-ratified D1–D2, 2026-06-15). Extends **ADR-016** — refines
  the *measured* behavioral-equivalence signal. Extends **TB5** (eval sandbox); **no new boundary**.
  **Client-side eval only** — no MCP tool / RPC / contract change (ADR-001: the server never imports
  `ghidra_mcp.naming`).
- **Deciders:** Human (scope = normalization + fuzz; reporting = strict + normalized alongside,
  2026-06-15) + PM; recorded by the Software Architect.
- **Relates to:** ADR-016 (the byte-exact I/O differential this refines), ADR-010 (the naming eval),
  ADR-001/005 (server-side isolation; captured bytes stay `Untrusted`).

## Context

ADR-016 ships the byte-exact **I/O differential** — `behavioral_equivalence(runs_a, runs_b)` compares
`(exit_code, stdout)` over shared synthetic input vectors, where **A** = a build from the fixture's
**trusted source** and **B** = the recompiled **renamed-decompiled-C**, both sandboxed (TB5); it
**never runs the hostile original**. ADR-016 flagged two weaknesses + deferred their fixes:
1. **False-negatives:** byte-exact stdout penalizes behaviorally-equivalent builds that differ only in
   **volatile output** (a printed pointer address, a timestamp). ADR-016: *"normalization is a future
   refinement if byte-exact proves too brittle."*
2. **Limited coverage:** a few fixed vectors exercise little behavior.

This refines the signal with **conservative output normalization** + **bounded, seeded fuzz inputs**.
It remains **measured, not guaranteed**, and still never runs the hostile original.

## Decision (ratified)

### D1 — Output normalization: **report strict AND normalized, side by side.**
Add a **pure, conservative** `normalize_output(stdout) -> bytes` applied identically to **both**
sides before a *second* comparison. Keep the **byte-exact** comparison as the **primary** signal:
- `behavioral_equivalence` (strict, **unchanged** — ADR-016 D2) — the conservative truth.
- `behavioral_equivalence_normalized` (new) — same oracle (`exit_code` still **exact**) but `stdout`
  compared **after** normalization.
Normalization is **conservative + documented** — e.g. canonicalize trailing whitespace / line
endings; mask pointer-like tokens (`0x[0-9a-fA-F]+`); mask obvious timestamps / PIDs — and **only
ever loosens** the match (`normalized >= strict`). Because over-normalization risks **false
positives**, strict stays primary and normalized is explicitly the "*equivalent modulo volatile
output*" signal. Pure over inert captured bytes (executes nothing — ADR-005); **100%** testable.

### D2 — Bounded, **seeded** fuzz-generated inputs.
Add a **pure, deterministic** `generate_fuzz_vectors(seed, count, max_len) -> list[bytes]` to broaden
behavioral coverage beyond the fixed vectors. The **same** generated vectors are fed to **both**
builds A and B through the existing sandboxed `ExecRunner` (TB5 — unchanged exec model). **Seeded ⇒
reproducible** (a fixed seed → fixed vectors; **no wall-clock / true randomness** — `topic-testing`
hermetic). Bounded `count` / `max_len` / per-run timeout (CWE-400). The metric is computed over the
fixed **and** fuzz vectors (reported per-set so a regression is attributable).

## Architecture & invariants
- All additions live in the **pure client-side** `ghidra_mcp.naming` package: `normalize_output`,
  `behavioral_equivalence_normalized`, `generate_fuzz_vectors` — all **pure** (no I/O, execute
  nothing). The sandboxed build+run stays the existing `ExecRunner` (TB5) — it just runs more
  vectors. **Server never imports `naming`** (ADR-001); captured bytes stay `Untrusted` (ADR-005).
- **No new MCP tool / RPC / catalog / envelope / dependency** — normalization uses stdlib `re`; fuzz
  uses a seeded deterministic generator (stdlib). No contract change.

## Security (TB5 — extends, no new boundary)
- **Still never runs the hostile original** (ADR-016 D1 preserved): A = trusted-source build, B =
  recompiled renamed-C, both sandboxed.
- **Fuzz inputs** are author-generated **synthetic, seeded** vectors fed to both builds — no untrusted
  input drives the host; bounded count/size/time; run only inside the TB5 sandbox.
- **Normalization** is a pure transform on **inert captured bytes** — no exec/eval/render.
- **Measured-not-guaranteed preserved:** the eval is a quality *signal*, not a guarantee; normalized
  is explicitly looser than strict (potential false-positives), strict stays the conservative truth.

## Consequences
- Fewer false-negatives (volatile-output differences no longer tank the score) **and** broader
  behavioral coverage — a more useful naming/decompilation quality signal, still honest.
- Two reported scores (strict + normalized) — clients/dashboards must not read normalized as a
  guarantee; strict is the conservative number.
- **Deferred / out of scope (unchanged):** memory-state equivalence; coverage-guided equivalence
  (need new sandbox instrumentation); diffing the real hostile original (breaches ADR-001). Revisit
  with their own ADR.

## Implementation increment (follows this design PR)
1. `naming/metrics.py`: pure `normalize_output(stdout: bytes) -> bytes` (conservative, documented
   rules) + `behavioral_equivalence_normalized(runs_a, runs_b)` (exit_code exact, stdout normalized) +
   keep `behavioral_equivalence` (strict) unchanged; wire **both** into `score()`. **100% line+branch.**
2. `naming/` pure `generate_fuzz_vectors(seed, count, max_len) -> list[bytes]` (deterministic, bounded).
   **100%.**
3. The **gated** differential e2e: run fixed **+** fuzz vectors through the `ExecRunner`, report strict
   + normalized (integration-gated, as today).
4. threat-model **TB5** note (normalization = pure inert transform; fuzz = seeded bounded synthetic;
   never runs the hostile original; measured-not-guaranteed) + tests: normalizer cases (pointer/
   timestamp/whitespace masking, and a **non-masking** case proving it doesn't over-strip); fuzz
   **determinism** (same seed → same vectors); a build differing **only** in a printed pointer →
   **strict < 1, normalized == 1**; `normalized >= strict` invariant. `topic-testing` gates.
