# ADR-035: Analyzer-option existence guard (fail closed on an unknown preset option)

- **Status:** Accepted (v1.5; human-ratified 2026-06-18). Ratified: **fail closed to the existing
  `internal-error`** (no frozen error-contract change) when a `light`/`deep` profile preset names an
  analyzer option the running Ghidra build does not expose; **collect ALL missing names** into one
  error; the check runs **only for a non-empty overlay** (`default` path byte-for-byte untouched);
  the existence check is membership against `options.getOptionNames()`. The missing names ride in
  the redacted, **log-only** `data.detail` (never the client envelope). **Live-verified** on the
  pinned Ghidra 12.1.2 image (see Consequences). Addresses v1.5 roadmap item #2.
- **Date:** 2026-06-18
- **Deciders:** Human (ratifies the error mapping + scope) + PM; recorded by the Software Architect.
- **Addresses:** `docs/archive/roadmap-v1.5.md` §2 — "analyzer-option existence guard (complete the
  profile-gate story — catch a renamed Ghidra option, not just a binding crash)."
- **Relates to / constrained by:** ADR-029 B (the analyzer-profile selector + the `_PROFILE_PRESETS`
  overlay this guards), ADR-028 (the live-regression profile gate that turns a fail-closed here into
  a red nightly — the two together make a *renamed* option a deterministic catch), ADR-024 (worker
  error detail is redacted/templated), ADR-001 (the check runs worker-side, at the JVM edge).
  Frozen error-envelope contract (`docs/contracts/error-envelope.md`) is **unchanged**.

## Context

ADR-029 B added `profile: default | light | deep` to `session_analyze`. `light`/`deep` map to a
preset overlay of Ghidra analyzer-option names applied via
`program.getOptions(ANALYSIS_PROPERTIES).setBoolean(name, enabled)` before auto-analysis
(`src/ghidra_mcp/ghidra/_jvm_bridge.py`). The v1.4 ADR-028 follow-up added a recurring live gate
(`tests/integration/test_analyze_profiles.py`) that exercises this JVM edge and asserts each profile
analyzes without an error envelope.

**The gap that gate cannot close on its own:** Ghidra's `Options.setBoolean(name, …)` is
**permissive** — setting an *unknown* option name silently creates/ignores it rather than raising.
So if a future Ghidra version **renames** an analyzer option (or a preset has a typo), the overlay
becomes a **silent no-op**: `light` would quietly stop disabling the expensive pass, `deep` would
quietly stop enabling the thorough one — and `session_analyze` still *succeeds*, so the ADR-028 gate
(which only asserts "analyze succeeded + a function surface exists") stays green. The drift is
invisible. This was explicitly considered and deferred during the v1.4 profile-gate follow-up as
"its own feature, not a harness change" (ADR-028 §Follow-ups; ADR-029 §D6 notes the one-off
name-validation diag that confirmed the 12.1.2 names, then was reverted).

## Decision

Before applying a non-empty overlay, **validate every preset option name exists** in the program's
analysis options and **fail closed** if any do not:

```python
overlay = _analyzer_options_for_profile(profile)   # PURE, unit-tested (empty for default)
if overlay:
    options = self._program.getOptions(self._program.ANALYSIS_PROPERTIES)
    available = set(options.getOptionNames())                 # JVM edge
    missing = _missing_profile_options(overlay, available)    # PURE, unit-tested
    if missing:
        raise WorkerError(CODE_INTERNAL, "analyzer profile references option(s) not "
                          "available in this Ghidra build")   # internal-error, redacted
    for option_name, enabled in overlay.items():
        options.setBoolean(option_name, enabled)
```

- **D1 — Error mapping = `internal-error` (no contract change).** An unknown preset option is a
  **server-side defect** (a stale preset vs the running Ghidra build), not a problem with the
  caller's binary — so `internal-error` (−32603 / 500) is the honest classification.
  `analysis-failed` was rejected: it is documented as *"not a server bug" (422)* and would
  misattribute the defect to the user's input. A new dedicated type was rejected for this increment:
  it would change the **frozen** error envelope (version bump + threat-model touch) for a
  should-never-fire internal guard — disproportionate (and it overlaps the separately-tracked v1.5
  #3 "dedicated 403 type" contract work).
- **D2 — Collect ALL missing names** into one error (don't fail on the first) for a complete
  diagnostic when a Ghidra bump renames several at once.
- **D3 — Scope = non-empty overlay only.** `default` → empty overlay → the guard block is skipped
  entirely; the byte-for-byte unchanged `pyghidra.analyze(program)` path (ADR-029 no-op guarantee)
  is preserved. No new RPC param, no contract change, no new trust boundary.
- **D4 — Redaction + actionable diagnostic.** The **client-facing** message is a fixed template
  (no option names). The collected missing names (D2) ride ONLY in the redacted, **log-only**
  `data.detail` (ADR-024): `WorkerError(CODE_INTERNAL, <template>, detail="… absent in this Ghidra
  build: [names]")` → the server logs it under a correlation id; it **never reaches the client
  envelope**. The names are our own preset constants (not binary-derived), so logging them is safe
  and makes a red ADR-028 nightly actionable (it names *which* option drifted) — without that, D2's
  "collect ALL" would be discarded. (`WorkerError` gains an additive optional `detail` kwarg,
  default `None` → every existing call site is unchanged.)
- **D5 — Purity split (the F2/F7 lesson).** The *decision* — which overlay names are absent from a
  given set of available names — is a **pure** helper `_missing_profile_options(overlay, available)`,
  unit-tested hermetically. The JVM *enumeration* (`getOptionNames()` / the options accessor) is the
  `# pragma: no cover` edge, validated only by a real-worker run.

## Consequences

- **Positive:** a renamed/removed analyzer option now **fails closed loudly** at analyze time
  instead of silently degrading the profile. Combined with the standing ADR-028 profile gate (which
  asserts analyze returns *no* error envelope), a Ghidra-version rename becomes a **deterministic red
  nightly** — closing the exact gap the v1.4 follow-up left open. No client-facing contract changes;
  `default` is wholly unaffected.
- **Negative / trade-offs:** one extra JVM call (`getOptionNames()`) per `light`/`deep` analyze
  (negligible vs analysis cost). The guard is a should-never-fire internal invariant in normal
  operation — its value is entirely in catching drift. Mapping to `internal-error` means a genuine
  preset/version mismatch surfaces as a 500 to the caller; acceptable (it *is* a server defect) and
  rare.
- **LIVE-VERIFIED (2026-06-18, branch worker image on the pinned Ghidra 12.1.2, crun):** (a) happy
  path — `options.getOptionNames()` is the correct accessor and **all** current `light`/`deep` preset
  names are present, so `tests/integration/test_analyze_profiles.py` is `3 passed` (default/light/deep
  analyze; the guard passes valid names); (b) negative path — a worker image with a bogus name seeded
  into the `light` preset returns `internal-error` / 500 / `retryable=false` on `analyze(profile=
  light)`, `store_wiped=true`, with **no option name in the client envelope** (the missing name
  appears only in the log-only `data.detail`). The guard fires, fail-closed, redacted — as designed.

## Alternatives considered

- **Reuse `analysis-failed`** — no contract change, but semantically misattributes a server defect to
  the user's input ("not a server bug"). Rejected (D1).
- **New dedicated error type** — most self-describing, but a frozen-contract change disproportionate
  to a should-never-fire internal guard. Rejected for this increment (D1).
- **Validate presets once at startup** instead of per-analyze — the program's analysis options are
  resolved per-program, and the cost per analyze is negligible; a per-analyze check is simpler and
  needs no separate lifecycle hook. Not pursued.
- **Do nothing (status quo)** — leaves a renamed option as a silent no-op the ADR-028 gate can't
  catch. Rejected (the whole motivation).
