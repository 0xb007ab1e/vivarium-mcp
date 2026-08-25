# ADR-073: Program-level fingerprint + offline family-match corpus (read-only)

- **Status:** **Accepted** (ratified by the human operator 2026-08-25). **`program_fingerprint`
  (D1) is IMPLEMENTED** in this increment with a scoped MVP field set (`structure_digest`,
  `import_digest`, `coverage` — the fields computable in-worker with no new dependency); VT
  `imphash`/`tlsh`/PE `rich_hash`/`authentihash` (D1) and `family_match` + the corpus (D2/D3) are a
  tracked **fast-follow** (need a vetted native dep or a fuzz-gated hostile-PE parser / a signed
  corpus artifact). Remediation item **R1** of the validation miss-analysis
  (`validation/reports/remediation-analysis.md`).
- **Date:** 2026-08-25
- **Deciders:** Human operator (ratification pending); drafted by the assistant from the 4-case
  validation exercise (Kelihos / Wirenet / LuckyCat / BumbleBee).
- **Context source:** the benchmark called threat **nature** correctly 4/4 but exact malware-family
  **proper-name** only 1/4 (miss **M1**). Root cause: static disassembly has **no oracle for a
  human-assigned family name**. Vivarium already ships the *function*-level similarity primitives
  (`function_hash` ADR-057, `bsim_similarity` ADR-058, `find_similar_functions` ADR-059,
  `bsim_search_corpus` ADR-062) and FID library matching (`identify_functions` ADR-042) — the gap is a
  **whole-program fingerprint** plus a **curated known-family corpus** to match it against.

## Context

The single mechanism that turns "obfuscated modular loader" into "BumbleBee" without live
threat-intel is a **similarity/signature match against known-family samples**. The industry pivot keys
for that are cheap, deterministic functions of already-parsed structure:

- **imphash** — MD5 of the ordered import (library!function) list; clusters builds of the same family
  (Kelihos, BumbleBee have well-known imphashes).
- **Rich-header hash** (PE) — MSVC toolchain fingerprint; strong same-builder signal.
- **authentihash** — PE hash excluding the certificate table (identity across re-signing).
- **fuzzy hash (TLSH)** — locality-sensitive whole-file hash; near-matches across minor variants.
- **BSim whole-program vector set** — semantic function fingerprints Vivarium already computes.

None of these require executing the sample, network access, or parsing the binary in the server — they
are pure functions of headers / IAT / already-extracted bytes, computed in the worker (ADR-001).

The validation **seal** (`groundtruth.sealed.json`) is effectively a hand-built instance of exactly
this corpus. This ADR productizes it as an **offline, bundled, versioned** store — no network, so
containment is preserved.

## Decision

### D1 — `program_fingerprint`: deterministic whole-program pivot keys (read-only)

Add a read-only Tier-2 tool `program_fingerprint` that emits the canonical pivot keys for the loaded
program:

| Field | Meaning | Availability |
|---|---|---|
| `imphash` | MD5 over the normalized ordered import list | PE / ELF / Mach-O (format-appropriate) |
| `rich_hash` | PE Rich-header hash | PE only (`null` otherwise) |
| `authentihash` | PE hash excluding the cert table | PE only (`null` otherwise) |
| `tlsh` | TLSH locality-sensitive digest of the file bytes | all (`null` if below TLSH's length floor) |
| `bsim_digest` | stable digest over the program's BSim function-vector set | all analyzed programs |
| `coverage` | defined-code / undefined-byte ratio (packed-loader signal, per the case-04 finding) | all |

All values are **server-computed scalars over worker-extracted facts** → emitted **bare** (not
`Untrusted`), like `sha256`/counts (ADR-005 §"server-computed scalars"). The raw import list feeding
imphash is binary-derived and stays `Untrusted` where separately returned (`list_imports` already is).

### D2 — `family_match`: offline corpus lookup (read-only, no network)

Add a read-only Tier-2 tool `family_match` that looks the program's fingerprint up against a
**bundled, offline, versioned family-signature corpus** and returns ranked candidates:

`FamilyMatchOut{candidates:[{family, confidence, basis[], corpus_version}], corpus_version, truncated}`

- **basis** enumerates *why* each candidate fired (`imphash` | `tlsh` | `bsim` | `rich`) — never a
  single opaque score; the analyst sees the evidence (mirrors the honest-labelling of `ioc_scan`).
- **confidence** is a bounded deterministic score from the match bases (exact imphash > TLSH-near >
  BSim-cluster), documented, not a black box.
- **Offline only.** The corpus ships in-image/bundled and is **versioned** (`corpus_version` in every
  response for reproducibility). **No network lookup** — that would breach containment and add an
  egress trust boundary; a future *gated* online-enrichment tool is explicitly out of scope here.

### D3 — Feedback loop (curation, human-gated)

Confirmed identifications (like the 4 validation reveals) SHOULD be appendable to the corpus so the
**next** run auto-IDs the sample. To avoid knowledge-poisoning (LLM03 / `workflow-knowledge-base`
gated-promotion posture), corpus additions are a **human-gated, offline curation step** (a build-time
corpus artifact under supply-chain control), **never** an agent-writable tool at runtime. The runtime
surface (`family_match`) is strictly read-only against a signed corpus artifact.

### D4 — Heuristic + honestly labelled

`family_match` is heuristic: obfuscation/repacking defeats TLSH/imphash, and an empty result is **not**
"benign / unknown-family-therefore-safe" — documented in the tool description (the same discipline the
benchmark surfaced for `crypto_constant_scan`: *empty ≠ none*). `program_fingerprint` is deterministic
but its *family meaning* is only as good as the corpus.

### D5 — Bounded before the worker (DoS)

Candidate count is `max_candidates`-capped and hard-clamped server-side before the worker (CWE-400 /
ADR-001), `truncated` set honestly. TLSH/imphash are O(file) single passes; the corpus lookup is
bounded by the corpus size (fixed artifact). Per-tool wall-clock (ADR-002) is the backstop.

### D6 — Contract delta (WS0, atomic — routes through the PM, not applied here)

Additive, read-only. **Proposed** catalog rows (to be applied to the FROZEN
`docs/contracts/tool-catalog.md` only via the PM batch-atomicity path, never ad-hoc):

```
| `program_fingerprint` | `ProgramFingerprintIn{session_id}` | `ProgramFingerprintOut{imphash?, rich_hash?, authentihash?, tlsh?, bsim_digest, coverage}` | **read-only** (no consent); server-computed scalars over worker-extracted headers/IAT/bytes; bare (not Untrusted); format-inapplicable keys → `null` honestly |
| `family_match` | `FamilyMatchIn{session_id, max_candidates?}` | `FamilyMatchOut{candidates:[{family, confidence, basis[]}], corpus_version, truncated}` | **read-only** (no consent); offline bundled+versioned corpus (NO network); `basis[]` enumerates match evidence; heuristic — empty ≠ unknown-safe; corpus curation is human-gated build-time (D3) |
```

Also: `schemas.py` (2 new IO models), `registry.py` (2 read-only names; `TIER1_TOOL_NAMES` 74 → 76,
neither in `WRITE_TOOLS`), `rpc-protocol.md` (2 worker verbs: `program_fingerprint`, `family_match`),
and the count assertions/prose in the catalog header (58 read-only → 60).

## Consequences

- **+** Directly attacks the benchmark's dominant miss (M1). imphash/TLSH plausibly move family-name
  accuracy 1/4 → 3–4/4 (BumbleBee/Kelihos have distinctive imphashes) with zero new agency.
- **+** Reuses existing BSim machinery; the corpus is seedable from confirmed samples incl. the 4
  validation cases (closes the loop the exercise ran by hand).
- **+** Fully read-only, offline, containment-preserving; no execution, no egress.
- **−** The corpus is a maintained asset (drift, coverage gaps) and a **supply-chain artifact** — it
  must be signed/provenance-tracked (`std-supplychain`) and its curation human-gated (D3).
- **−** Fingerprints are evadable (packers randomize IAT/bytes); `family_match` is a lead, not proof.

## Alternatives considered

- **Online VT/threat-intel lookup** — highest accuracy, but adds a network egress trust boundary and
  breaks the offline containment posture; deferred to a separate, explicitly-gated ADR.
- **Extend `bsim_search_corpus` to carry family labels** — viable, but conflates function-level search
  with program-level attribution; a dedicated `family_match` keeps the surfaces honest.
- **YARA scanning** — complementary (content signatures) and a strong future addition, but string/byte
  rules are easily broken by the padding/obfuscation the benchmark saw (case-04 decoy word-salad);
  fingerprint+BSim is more robust for packed samples. Tracked as a follow-up.

## Related
- Remediation analysis: `validation/reports/remediation-analysis.md` (R1).
- ADR-057/058/059/062 (function-level hash/BSim), ADR-042 (FID), ADR-001 (worker boundary),
  ADR-005 (untrusted envelope), ADR-002 (limits), `std-supplychain`, `std-mitre-attack`.
- Sibling proposals: **ADR-074** (capability/ATT&CK tagging), **ADR-075** (crypto detection).
