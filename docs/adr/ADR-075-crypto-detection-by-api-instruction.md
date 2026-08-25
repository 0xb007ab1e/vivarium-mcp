# ADR-075: Crypto detection by API / import / instruction (read-only)

- **Status:** **Proposed** (drafted 2026-08-25 from the blind-triage validation benchmark; ratification
  pending human operator). Remediation item **R3** of the validation miss-analysis
  (`validation/reports/remediation-analysis.md`).
- **Date:** 2026-08-25
- **Deciders:** Human operator (ratification pending); drafted by the assistant from the 4-case
  validation exercise.
- **Context source:** `crypto_constant_scan` (ADR-008) is **constant-only by design** — it finds AES
  S-boxes, round constants, IV/magic. The benchmark hit its blind spot **three times**: case-02
  (Wirenet AES via **CommonCrypto** framework), case-03 (LuckyCat **bespoke rolling cipher**), case-04
  (BumbleBee **multiply-scatter decode**). Each returned an **empty** constant scan on a sample that
  demonstrably uses crypto — the recurring "**empty ≠ no crypto**" caveat, and a live false-conclusion
  risk ("plaintext C2 / no crypto"). Case-01 (Kelihos, textbook AES constants) is the *only* one the
  constant scan caught.

## Context

Crypto leaves signals beyond algorithm **constants**:

- **Imports / dynamically-resolved APIs** — Windows CryptoAPI (`Crypt*`), CNG (`BCrypt*`), macOS
  CommonCrypto (`CCCrypt*`, `CCCryptorCreate`), and common library symbols (OpenSSL `EVP_*`, libsodium
  `crypto_*`). Case-02's CommonCrypto AES is exactly this.
- **Instructions** — AES-NI (`aesenc`/`aesdec`/`aeskeygenassist`), SHA extensions, carry-less multiply
  (`pclmulqdq`), and rotate/xor-heavy inner loops typical of block/stream ciphers and bespoke encoders.
- **Structure** — the case-03/04 hand-rolled ciphers (rolling subtract; multiply-and-scatter) show as
  tight xor/rotate/mul loops with a small key — detectable as *cipher-shaped code* even with no known
  constant.

`crypto_constant_scan` is frozen (WS0) and correct at what it does; broadening its output schema is a
breaking contract change. This ADR adds a **complementary, additive** read-only tool rather than
mutating the frozen one — turning the standing caveat into a positive signal without contract churn.

## Decision

### D1 — `crypto_detect`: multi-source crypto indicators (read-only)

Add a read-only Tier-2 tool `crypto_detect` that reports crypto **indicators** from sources the
constant scan cannot see, each tagged with its provenance:

`CryptoDetectOut{indicators:[{address, kind, source, detail}], truncated}` where
`source ∈ {import | api_name | instruction | code_pattern}` and `kind` names the primitive/family
(`aes`, `sha`, `rc4`, `base64`, `custom_xor_cipher`, `custom_arith_cipher`, `crypto_api_generic`, …).

| source | What it matches | Benchmark case it fixes |
|---|---|---|
| `import` | CryptoAPI/CNG/CommonCrypto/OpenSSL/libsodium symbols in the IAT or dynamic-resolution table | case-02 (CommonCrypto) |
| `api_name` | crypto-symbol *names* in strings used with `GetProcAddress`/`dlsym` dynamic resolution | dynamically-resolved crypto |
| `instruction` | AES-NI / SHA-ext / `pclmulqdq` opcodes | HW-accelerated crypto |
| `code_pattern` | cipher-shaped loops (xor/rotate/mul with small key, high arithmetic density) | case-03/04 bespoke ciphers/decoders |

`code_pattern` is deliberately conservative (favour precision) and honestly labelled `confidence`;
it flags *candidate* cipher/decoder loops — the analyst confirms via `decompile_function`
(as done by hand on case-03/04).

### D2 — Complements, does not replace, `crypto_constant_scan`

`crypto_constant_scan` stays byte-for-byte frozen (WS0). `crypto_detect` is the **superset by
source**: run both; constants + imports + instructions + code-shape together answer "does this use
crypto, and how is it hidden?" The tool descriptions cross-reference each other and both restate
**empty ≠ no crypto** (an obfuscated/encrypted routine with no recognizable API/const/opcode can still
evade both — documented, not papered over).

### D3 — Untrusted output + read-only

Addresses / primitive names / sources are server-safe metadata (bare). Any binary-derived `detail`
string (e.g. a resolved symbol name) stays `Untrusted`-wrapped (ADR-005). Read-only/output-only over
worker-extracted facts (imports, disassembly, p-code); no DB mutation, no new agency (ADR-001/LLM08).
Server logs record `kind`/`source`/`address`/counts — never raw key material (that is `secret_scan`'s
redaction remit; `crypto_detect` reports *presence of crypto*, not the keys).

### D4 — Bounded before the worker (DoS)

`max_indicators` (+ scanned-insn/import caps) validated and hard-clamped server-side before the worker
(CWE-400 / ADR-001); `truncated` honest (ADR-005). The instruction / `code_pattern` passes are bounded
single sweeps over the (already function-capped) disassembly; per-tool wall-clock (ADR-002) backstops.

### D5 — Heuristic, honestly labelled

`import`/`api_name`/`instruction` are high-precision; `code_pattern` is heuristic (false positives on
checksum/compression loops; false negatives on well-obfuscated crypto). Documented, with `confidence`
per indicator. Read-only.

### D6 — Contract delta (WS0, atomic — routes through the PM, not applied here)

Additive, read-only. **Proposed** catalog row (applied to FROZEN `docs/contracts/tool-catalog.md` only
via the PM path):

```
| `crypto_detect` | `CryptoDetectIn{session_id, max_indicators?}` | `CryptoDetectOut{indicators:[{address, kind, source, detail?, confidence}], truncated}` | **read-only** (no consent); complements (does NOT replace) `crypto_constant_scan` — detects crypto by import/api-name/instruction/code-pattern (frameworks + bespoke ciphers the constant scan misses); binary-derived `detail` Untrusted-wrapped; heuristic on `code_pattern`; empty ≠ no crypto |
```

Also: `schemas.py` (1 IO model + nested indicator model), `registry.py` (1 read-only name;
`TIER1_TOOL_NAMES` +1; not in `WRITE_TOOLS`), `rpc-protocol.md` (1 worker verb `crypto_detect`),
catalog header counts/prose (read-only +1).

## Consequences

- **+** Erases the benchmark's most-repeated caveat (empty constant scan on 3/4 crypto-using samples);
  case-02's CommonCrypto AES becomes a positive `import` indicator.
- **+** `code_pattern` surfaces the bespoke case-03/04 ciphers as *candidate* crypto/decoders — a lead
  into the exact functions the analyst decompiled by hand.
- **+** Additive; leaves the frozen `crypto_constant_scan` untouched (no contract churn / breaking
  schema change).
- **−** `code_pattern` is heuristic (checksum/compression false positives); mitigated by conservative
  rules + `confidence` + analyst confirmation via decompile.
- **−** Still blind to crypto fully hidden inside an encoded stage (case-04) until that stage is
  recovered (R4 emulated-unpack, future ADR).

## Alternatives considered

- **Extend `crypto_constant_scan`'s output with a `source` field** — cleanest conceptually but a
  **breaking change to a FROZEN (WS0) schema**; rejected in favour of an additive tool (the freeze
  discipline wins; a future major-version consolidation could merge them).
- **Fold crypto indicators into `capability_scan` (ADR-074)** — capa rules do cover some crypto, but a
  dedicated crypto tool gives finer sources (instruction/code-pattern) and a stable surface analysts
  pair with `crypto_constant_scan`; the two are complementary, not redundant.

## Related
- Remediation analysis: `validation/reports/remediation-analysis.md` (R3).
- ADR-008 (`crypto_constant_scan`/`ioc_scan`), ADR-072 (`secret_scan` — key-material remit),
  ADR-052/053 (`get_pcode`/`get_high_pcode` — feed `code_pattern`), ADR-001/005/002.
- Sibling proposals: **ADR-073** (fingerprint/family), **ADR-074** (capability/ATT&CK). Encoded-stage
  recovery (R4) and scanner-precision (R5) are separate future ADRs.
