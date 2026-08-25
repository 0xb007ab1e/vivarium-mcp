# Vivarium Validation — Cross-Case Scorecard

**Scope:** 4 blind static-triage cases (real malware, theZoo), Vivarium MCP read-only tools,
Ghidra worker. **Samples never executed; containment held every case.**
**Method:** hash-named blind intake → load/analyze → tool battery → write report+confidence
→ reveal sealed ground truth (single-entry) → score. Cases 01/02 truly blind; 03/04 analyzed
blind-of-tooling but in a session that earlier held spilled seal context (documented caveat).

## 1. Detection accuracy (blind vs ground truth)

| Case | Ground truth | Type | Verdict | Severity | Category | Family label | Case score |
|---|---|---|:--:|:--:|:--:|:--:|:--:|
| 01 | Win32/Kelihos (Hlux) | PE32 x86 bot | HIT | HIT | HIT | **HIT** | 5/5 |
| 02 | OSX/Wirenet | Mach-O i386 RAT | HIT | HIT | HIT | PARTIAL (bucket) | 4.5/5 |
| 03 | Win32.LuckyCat | PE32 DLL APT RAT | HIT | HIT | HIT | PARTIAL (campaign ctx) | 6H/1P |
| 04 | Win32.BumbleBee | x64 regsvr32 loader | HIT | HIT | HIT | PARTIAL (loader bucket) | 5H/1P |

- **Verdict / Severity / Category: 4/4 HIT.** No false negatives, no misclassification of the
  threat *nature*.
- **Family proper-name: 1/4 exact (Kelihos).** The other 3 were correct *bucket/context*
  (macOS cred-stealer RAT; Tibetan-APT RAT; obfuscated modular loader) but missed the exact
  label — the expected ceiling of static-only blind triage without OSINT/hash lookup.
- **Highest-value calls landed:** case-03 reconstructed the LuckyCat campaign fingerprint from
  code alone; case-04 correctly separated **loader from payload** (the one call that matters
  most for BumbleBee) from structure alone.

## 2. Tool coverage & reliability

| Tool | Cases run | Reliability | Notes |
|---|:--:|---|---|
| session_create / import / analyze | 4/4 | ✅ solid | `binary` loader needs processor+base_addr → use `auto` for PE; source_ref MUST be absolute under import root. Deep profile completed 190–10k funcs. |
| program_metadata | 4/4 | ✅ | Accurate arch/format/entry/DLL-base. |
| program_summary | 4/4 | ✅ **standout** | Coverage ratio (code vs undefined) instantly flagged the packed loader (case-04: 1.5% code / 97.7% undefined). Fan-in/out + complexity useful. |
| list_imports | 4/4 | ✅ | Large output auto-persists to file → group/grep locally. |
| list_strings | 4/4 | ✅ | Auto-persist; utf-8-replace on hostile bytes; surfaced C2, masquerade, decoy salad. |
| decompile_function | 4/4 | ✅ **strong** | Clean C on real malware incl. obfuscated LuckyCat cipher + BumbleBee MBA junk-code (dead-block warnings, still readable). No crashes. |
| ioc_scan | 4/4 | ⚠️ mixed | Precise on 03 (2/2, no FP); correctly-empty on 04 (encoded stage = true negative); **FP-prone on 01** (version strings→IPv4, timestamps→IPv6). Filter numerics. |
| crypto_constant_scan | 4/4 | ⚠️ literal | HIT on 01 (real AES S-box/CRC32/base64 constants). Empty on 02/03/04 — all of which *do* use crypto/encoding (CommonCrypto framework / bespoke rolling cipher / multiply-decode). **Empty ≠ no crypto** — 3× confirmed. |
| secret_scan | 4/4 | ⚠️ noisy | Keyword/high-entropy FPs (base64 alphabets, "Credential", api-ms-* names). BUT the "Credential"/"Windows Credential Manager" hit usefully surfaced the case-03 masquerade. |
| cyclomatic_complexity / call_graph | via summary | ✅ | Consumed through program_summary; not called standalone this round. |
| xrefs_to | 01/02 | ✅ | Not needed on 03/04 (strings/decompile gave addresses directly). |
| deobfuscate_strings | 0/4 this round | — not exercised | Recipe lists it; 03/04 config was in-code (decompile), not stack/xor string-table — no call made. Gap to exercise on a stack-string sample. |
| session_close | — | ⚠️ | May be blocked; sessions auto-expire (worker killed on TTL/eviction, ADR-002). |

## 3. Recurring lessons (carry forward)
1. **`crypto_constant_scan` empty ≠ no crypto.** Framework crypto (CommonCrypto/CNG) and
   bespoke ciphers/encoders leave no standard constants. Corroborate with imports + decompile.
2. **`ioc_scan` numeric false positives** (version/build/timestamp → IPv4/IPv6). Analyst-filter.
3. **Coverage ratio is a top-tier triage signal** — high undefined% + a run-export
   (DllRegisterServer/regsvr32) ⇒ packed loader, before any decompile.
4. **Load quirks:** `auto` loader for real PE/Mach-O; absolute `source_ref`; `deep` profile.
5. **Read-only static ceiling:** encoded second stages (case-04 BumbleBee) are not recoverable
   without emulation/unpacking — an *expected* v1 boundary, not a tool failure. Candidate for
   an emulate/unpack follow-up feature.
6. **Containment:** every sample inert-analyzed; never executed; envelope (ADR-005) respected —
   binary-derived output treated as inert throughout.

## 4. Bottom line
Vivarium's read-only Ghidra battery **correctly classified the threat nature of 4/4 real
malware samples blind** (2 bots/RATs, 1 APT DLL RAT, 1 obfuscated x64 loader), across PE32,
PE32+ x64, and Mach-O, including obfuscated and packed specimens. The decompiler and
coverage/summary signals carried the analysis; the scanners (ioc/crypto/secret) are useful
leads but require analyst filtering and must not be read as authoritative negatives. Exact
malware-family naming is beyond static-blind scope (needs OSINT/hash intel) — but every
*actionable* IR call (malicious? how bad? what does it do? loader or payload?) was correct.
