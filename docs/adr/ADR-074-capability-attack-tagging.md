# ADR-074: Capability detection + MITRE ATT&CK tagging (read-only, capa-style)

- **Status:** **Proposed** (drafted 2026-08-25 from the blind-triage validation benchmark; ratification
  pending human operator). Remediation item **R2** of the validation miss-analysis
  (`validation/reports/remediation-analysis.md`).
- **Date:** 2026-08-25
- **Deciders:** Human operator (ratification pending); drafted by the assistant from the 4-case
  validation exercise.
- **Context source:** on case-04 (BumbleBee) the analyst reached "obfuscated modular **loader**, run
  via regsvr32, reflective-load, named-pipe C2, anti-debug" **by hand** from imports + one decompile.
  That call — the highest-value triage output — is exactly what a **rule-based capability detector**
  produces mechanically. Vivarium has all the inputs (imports, strings, disassembly, p-code) but no
  tool that maps them to **named capabilities**.

## Context

Family-name (ADR-073) tells you *who*; **capabilities** tell you *what it does* — and the benchmark
showed the what-it-does call is both the most reliable static output (4/4 correct nature) and the most
labour-intensive (hand-traced each time). Mandiant **capa** codifies this: a curated, open rule set
matches disassembly / API / string / constant / number patterns to **named capabilities** (e.g.
"execute via regsvr32", "reflectively load DLL", "communicate over named pipe", "check for debugger",
"decrypt data using RC4") each mapped to **MITRE ATT&CK** technique IDs.

This is a pure read-only pattern pass over facts Ghidra already extracts — it fits the Tier-2 reporting
layer (ADR-008) and the ADR-001 worker-only boundary exactly like `ioc_scan`/`crypto_constant_scan`/
`secret_scan`. It also feeds `std-mitre-attack` (technique-mapped detections) and narrows the family
bucket that ADR-073 similarity then pins — the two compose.

Worked examples from the benchmark, all of which a capability pass emits automatically:
- **case-04 BumbleBee:** *executed-via-regsvr32*, *packed/self-decoding*, *reflective DLL load*,
  *named-pipe C2/IPC*, *anti-debug*, *single-instance mutex*.
- **case-02 Wirenet:** *decrypt Mozilla credentials*, *screen/desktop capture*, *spawn child process*.
- **case-01 Kelihos:** *sniff network traffic*, *registry Run-key persistence*, *harvest FTP creds*.

## Decision

### D1 — `capability_scan`: rule-based capability + ATT&CK tagger (read-only)

Add a read-only Tier-2 tool `capability_scan` running a curated rule set (a capa-compatible rule pack)
in the worker over already-extracted facts (imports, dynamically-resolved APIs, strings, constants,
disassembly features). Output:

`CapabilityScanOut{capabilities:[{name, namespace, attack:[{tactic, technique_id}], evidence:[{address, kind}], confidence}], rule_pack_version, truncated}`

- **evidence[]** anchors each capability to concrete addresses + match kind (api | string | const |
  insn) — the analyst sees *why*, never an opaque verdict (same honesty discipline as `ioc_scan`).
- **attack[]** carries MITRE tactic + technique IDs → directly consumable by `std-mitre-attack`
  detection-mapping and threat-model TTP enumeration.
- **rule_pack_version** in every response for reproducibility.

### D2 — Rules are a versioned, signed supply-chain artifact

The rule pack (capa-rules-compatible) is **bundled, offline, versioned, and signed/provenance-tracked**
(`std-supplychain`). It is **not** agent-writable at runtime (no rule injection — LLM03/LLM07):
`capability_scan` reads a fixed signed rule artifact. Rule updates are a build-time, human-reviewed
step. No network.

### D3 — Untrusted output + redaction

Capability **names / ATT&CK IDs / addresses** are server-safe metadata (bare). Any **binary-derived
string** surfaced as evidence stays `Untrusted`-wrapped (ADR-005) — inert, never executed/rendered/
followed. Server logs record capability names, technique IDs, counts, `rule_pack_version` — **never**
raw matched bytes/strings (master §5 / CWE-200/532).

### D4 — Bounded before the worker (DoS)

`max_capabilities` (+ scanned-feature caps) validated and hard-clamped server-side before the worker
(CWE-400 / ADR-001); `truncated` honest (ADR-005). Rule matching is bounded by the fixed rule-pack size
× the (already-capped) feature set; per-tool wall-clock (ADR-002) backstops a pathological program.

### D5 — Heuristic, honestly labelled

Rules match *observed* features — packing/obfuscation hides behaviour (case-04's real capabilities live
in the encoded stage, ADR-075/R4). An empty/thin result on a packed sample is expected and documented;
combine with `program_fingerprint`/`family_match` (ADR-073) and, for encoded stages, emulated unpack
(future R4). Read-only/output-only: no new agency (ADR-001/LLM08).

### D6 — Contract delta (WS0, atomic — routes through the PM, not applied here)

Additive, read-only. **Proposed** catalog row (applied to FROZEN `docs/contracts/tool-catalog.md` only
via the PM path):

```
| `capability_scan` | `CapabilityScanIn{session_id, max_capabilities?}` | `CapabilityScanOut{capabilities:[{name, namespace, attack:[{tactic, technique_id}], evidence:[{address, kind}], confidence}], rule_pack_version, truncated}` | **read-only** (no consent); capa-style rule pass over worker-extracted imports/strings/consts/insns; evidence-anchored + ATT&CK-mapped; rule pack = signed offline versioned artifact (D2, no runtime rule injection); binary-derived evidence strings Untrusted-wrapped; heuristic — empty ≠ benign on packed input |
```

Also: `schemas.py` (1 IO model + nested capability/evidence/attack models), `registry.py` (1 read-only
name; `TIER1_TOOL_NAMES` 76 → 77 assuming ADR-073 lands first, else 74 → 75; not in `WRITE_TOOLS`),
`rpc-protocol.md` (1 worker verb `capability_scan`), catalog header counts/prose (read-only +1).

## Consequences

- **+** Emits the benchmark's single most valuable output (loader-vs-payload, behaviour set) as
  structured, ATT&CK-mapped tags — no hand-tracing.
- **+** Feeds `std-mitre-attack` and `workflow-threat-model` TTP enumeration directly; composes with
  ADR-073 (capabilities narrow the family bucket).
- **+** Read-only, offline, containment-preserving; reuses the ioc/secret-scan tool shape.
- **−** Rule pack is a maintained, signed supply-chain asset; coverage/false-negatives track rule
  quality; must resist rule-injection (D2).
- **−** Blind to capabilities hidden behind packing/encryption (the case-04 stage) — needs the
  emulated-unpack follow-up (R4) to see through.

## Alternatives considered

- **Hard-code capability heuristics in the tool** — brittle, unversioned, diverges from the maintained
  capa-rules ecosystem; a signed external rule pack is auditable and upstream-trackable.
- **Fold capabilities into `program_summary`** — would bloat an already-large tool and mix
  deterministic structure with heuristic detection; a dedicated tool keeps honesty boundaries clean.

## Related
- Remediation analysis: `validation/reports/remediation-analysis.md` (R2).
- ADR-008 (Tier-2 reporting incl. `ioc_scan`/`crypto_constant_scan`), ADR-072 (`secret_scan` shape),
  ADR-001/005/002, `std-mitre-attack`, `std-owasp-llm` (LLM03/07), `std-supplychain`.
- Sibling proposals: **ADR-073** (fingerprint/family), **ADR-075** (crypto detection).
