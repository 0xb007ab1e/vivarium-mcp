# Vivarium Validation — Miss Analysis & Remediation Mechanisms

**Input:** the 4-case blind benchmark (Kelihos, Wirenet, LuckyCat, BumbleBee).
**Question:** what did the read-only battery miss, why, and what mechanisms would close each gap
**without breaking containment** (read-only, no sample execution, no auto-following binary output)?

Every proposed mechanism is static or emulation-only, honors ADR-001 (server never loads a JVM /
parses a binary — all work stays in the worker) and ADR-005 (binary-derived output is inert).

---

## 1. The misses, precisely

| # | Miss | Where | Consequence |
|---|---|---|---|
| M1 | Exact malware-family **proper name** | 02 Wirenet, 03 LuckyCat, 04 BumbleBee (3/4) | Bucket right, label wrong — analyst can't pivot to known TTPs/IOCs by name. |
| M2 | **Framework crypto invisible** | 02 (CommonCrypto AES), 03 (bespoke cipher), 04 (multiply-decode) | `crypto_constant_scan` empty ⇒ risk of "no crypto / plaintext C2" false conclusion. |
| M3 | **Encoded second stage not recovered** | 04 BumbleBee | Real C2 / capability of the payload unknown from the loader alone. |
| M4 | **`ioc_scan` numeric false positives** | 01 (version→IPv4, timestamp→IPv6) | Analyst hand-filtering; noisy IOC export. |
| M5 | **`secret_scan` keyword/entropy FPs** | all (base64 alphabets, api-ms-*, "Credential") | Low precision; useful leads buried in noise. |

Root cause of M1 is structural: **static disassembly has no oracle for a human-assigned name.**
The other four are addressable feature gaps.

---

## 2. Remediation mechanisms (ranked by leverage)

### R1 — Whole-program similarity & family fingerprinting  → fixes **M1** (biggest lever)
The one thing that turns "obfuscated modular loader" into "BumbleBee" without OSINT is a
**signature/similarity match against a known-family corpus.** Vivarium already has the primitives
(`function_hash`, `find_similar_functions`, `bsim_similarity`, `bsim_search_corpus`, FID
`identify_functions`) — the gap is a *program-level* fingerprint + a *curated malware corpus*.

- **R1a · Program-level hashes tool** (new, cheap): emit **imphash**, **Rich-header hash** (PE),
  **authentihash**, and a **fuzzy hash (TLSH/ssdeep)** for the whole program. Deterministic,
  read-only, no execution. These are the canonical VirusTotal/threat-intel pivot keys —
  imphash alone clusters Kelihos/BumbleBee builds.
- **R1b · Offline family-signature DB + lookup** (new): ship a bundled, versioned corpus keyed by
  imphash / TLSH / BSim function-vectors → family label + confidence. The validation seal is
  effectively a hand-built instance of this; productize it as a **local, offline** reputation
  store (no network ⇒ containment intact). Populate from BSim of confirmed-family samples.
- **R1c · Feedback loop:** after any confirmed identification (like these 4 reveals), auto-append
  the sample's BSim vectors + imphash to the corpus so the *next* run auto-IDs it. Closes the
  loop the validation exercise ran by hand.

> Priority **HIGH**. R1a is a few hours (hashes are pure functions of the headers/IAT). R1b/R1c
> are the durable win — they convert every solved case into future automatic hits.

### R2 — Capability detection (capa-style rules) → fixes **M1 (bucket→confident) + M3 (partial) + M2**
Add a **rule-based capability tagger** (Mandiant **capa**-style: match disassembly/API/const
patterns → named capabilities mapped to MITRE ATT&CK). This is read-only and would have
auto-emitted, e.g. for case-04: *"executed via regsvr32", "self-decoding / packed", "reflective
DLL load", "named-pipe C2", "anti-debug"* — i.e. the exact call the analyst made by hand, as
structured tags. For case-02 it flags *"decrypt Mozilla credentials", "screen capture"* directly.

- Maps behavior to ATT&CK technique IDs (feeds `std-mitre-attack`) — attribution-adjacent even
  when the proper name is unknown.
- Complements R1: capabilities narrow the family bucket that similarity then pins.

> Priority **HIGH**. Rule packs are maintained upstream (capa-rules) — bundle + run in-worker.

### R3 — Import/API-based crypto detection → fixes **M2** directly
`crypto_constant_scan` is constant-only by design. Add **crypto-by-API detection**: flag imports/
dynamically-resolved calls to CryptoAPI/CNG (`bcrypt`, `Crypt*`), CommonCrypto (`CCCrypt`), and
common library symbols, plus **mode/opcode heuristics** (AES-NI `aesenc`, big-integer patterns).
Report as `crypto_indicators` with source = {constant | import | api-name | instruction}. Turns the
recurring "empty ≠ no crypto" caveat into a positive signal.

> Priority **HIGH**, low effort (it's an import/symbol pass). Directly removes the one case-02 miss
> and the standing 3× caveat.

### R4 — Emulation-assisted unpack + embedded-object carving → fixes **M3**
Two read-only ways to see BumbleBee's stage without executing the sample on the host:

- **R4a · Embedded-PE/object carver** (new, cheap): scan undefined/high-entropy regions for MZ/PE,
  ELF, Mach-O, ZIP magics and **entropy transitions**; report offsets + let the analyst spawn a
  child session on a carved slice (Vivarium already supports `regions`/offset imports). Case-04's
  2.4 MB region would surface any embedded stage.
- **R4b · Emulated decode** (leverages existing `emulate` / pcode): run *only the identified decode
  loop* (e.g. case-04's multiply-scatter loop) under **pcode emulation** — no native execution, no
  host risk — and dump the decoded buffer for re-analysis. Bounded steps/memory (ADR-002 limits).

> Priority **MEDIUM** (R4a) / **MEDIUM-HIGH** (R4b — high payoff, needs careful step/mem bounds).
> This is the honest boundary the scorecard named; emulation is the containment-safe way past it.

### R5 — Scanner precision passes → fixes **M4 + M5**
- **ioc_scan context/confidence:** down-rank numeric matches near version/build/timestamp tokens or
  in resource/version sections; attach a confidence score and a `context` snippet; add a
  `network_context_required` mode. Removes the case-01 version→IPv4 / timestamp→IPv6 FPs.
- **secret_scan allow-list + provenance:** ship an allow-list of known-benign high-entropy strings
  (base64/hex alphabets, `api-ms-*`, RTTI/type descriptors) and label matches by *why* they fired,
  so the "Credential" masquerade lead stays visible without the base64-alphabet noise.

> Priority **MEDIUM**, low effort. Precision/UX, not capability — but cuts analyst filtering time.

---

## 3. What each mechanism would have changed on the benchmark

| Case | Miss | Mechanism that closes it | Post-fix outcome |
|---|---|---|---|
| 04 BumbleBee | M1 name | R1a imphash + R1b corpus lookup | Likely **HIT** (BumbleBee has well-known imphashes). |
| 04 BumbleBee | M3 stage | R4a carve + R4b emulated decode | Recovers stage ⇒ real C2/capability. |
| 03 LuckyCat | M1 name | R1b corpus / R2 capabilities → APT bucket | PARTIAL→**HIT** if corpus has it; otherwise stays strong bucket. |
| 02 Wirenet | M1 name | R1b + R2 (Mozilla-cred-decrypt capability) | PARTIAL→**HIT**-likely. |
| 02 Wirenet | M2 crypto | R3 API-crypto (CommonCrypto) | Crypto correctly reported (no more "empty"). |
| 01 Kelihos | M4 FP | R5 ioc precision | Clean IOC export, no version/timestamp FPs. |

Net: with **R1+R2+R3**, family-name accuracy plausibly goes 1/4 → 3–4/4 and the crypto caveat
disappears — all with read-only, containment-preserving mechanisms. R4 addresses the one genuine
static-analysis boundary (encoded stages).

---

## 4. Recommended sequencing
1. **R1a (program hashes)** + **R3 (API-crypto)** + **R5 (scanner precision)** — small, high-value,
   pure-static; land first.
2. **R2 (capa-style capabilities + ATT&CK)** — the highest-leverage single addition for triage.
3. **R1b/R1c (offline family corpus + feedback loop)** — durable attribution; seed from BSim of
   confirmed samples (incl. these 4).
4. **R4 (carve + emulated decode)** — the boundary-mover; do under strict pcode/step/mem bounds.

All read-only; none require executing a sample or following binary-derived data. Each maps to an
existing contract surface (new Tier-1 read-only tools or extensions to `crypto_constant_scan` /
`ioc_scan` / `secret_scan` / `bsim_*` / `emulate`), so they slot into the frozen-contract process
(route via PM, ADR + tool-catalog entry) rather than ad-hoc additions.
