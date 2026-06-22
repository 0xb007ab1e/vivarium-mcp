# FID database licensing — SPIKE-2 (ADR-042 Phase 2)

> **Status:** SPIKE-2 analysis complete (2026-06-21). Resolves the *technical/risk* path for shipping
> ELF FunctionID databases; the residual question for **copyleft-derived** databases is escalated to
> counsel (below). Feeds **[ADR-042](../adr/ADR-042-function-id-signature-identification.md)** Phase 2.
>
> ⚠️ **This is informational SDLC/licensing analysis, not legal advice, and not a substitute for
> counsel.** Copyright/database law is jurisdiction-dependent (US vs. EU differ) and **untested for
> this specific artifact** — no court has ruled on a Ghidra `.fidb`. Every verdict here is reasoned
> engineering judgment on sourced facts. **Do not ship any copyleft-derived database without an
> attorney sign-off.**

## 1. Context — what we would distribute, and under what license

**The artifact.** A Ghidra **FunctionID database** (`.fidb`) generated from compiled library
binaries. Empirically (SPIKE-1) a `.fidb` stores, per function: two **non-reversible numeric hashes**
of the function body (a "full hash" over mnemonics + addressing/registers excluding constants; a
"specific hash" adding constant operand values), the function's **symbol name** lifted from the
library (`deflate`, `OPENSSL_malloc`), library **metadata** (family/version/variant, processor
language), and caller/callee relation flags. It contains **no instruction bytes and no source** —
only hashes + names + metadata.

**Our distribution.** Vivarium is **Apache-2.0** (`LICENSE` + `NOTICE`). A Phase-2 `.fidb` would be
**baked into the worker container image** (which already bundles Apache-2.0 Ghidra) and distributed
that way — so a shipped FID DB *is* a distributed artifact and must satisfy its source library's
license. Attribution flows through `NOTICE` (Apache-2.0 §4) + the per-release SBOM (`std-supplychain`).

## 2. The core legal question (informational analysis)

**Is a `.fidb` a "derivative work" / "work based on the Library" of the source library?**
The well-supported answer is **almost certainly not**, on two independent US-copyright grounds, with
a separate EU note:

- **Hashes carry no expression.** A derivative work requires copying *protected expression*
  (17 U.S.C. §101). Non-reversible hashes over mnemonics/operands are not the code and cannot be
  reversed to it. This is the **same theory IDA FLIRT** has shipped on for ~25 years — Hex-Rays
  states FLIRT signatures contain *"no byte from the original libraries, except for the names of the
  functions."*
- **Symbol names are uncopyrightable facts.** Individual names/short phrases are not copyrightable
  (Copyright Office Circular 33; 37 C.F.R. §202.1); a *compilation* of facts is protected only for
  original selection/arrangement (*Feist v. Rural*, 499 U.S. 340), and a hash→name table arranged
  mechanically by Ghidra has minimal originality. *Google v. Oracle* (2021) treated API names +
  structure as freely reusable (decided on fair use, copyrightability left open).
- **EU *sui generis* database right (separate axis).** EU Directive 96/9/EC grants a DB *maker* who
  made substantial investment in *collecting* contents a right against extraction. Per
  *British Horseracing*/*Fixtures Marketing*, investment in *creating* the underlying data (the
  library) doesn't count — so this right, if any, vests in **us** (the `.fidb` maker), not the
  upstream author. Low risk to our distribution; confirm with EU counsel if shipping into the EU.

**Caveat:** well-reasoned and matching 25 years of industry practice (FLIRT), but **not
adjudicated** for a `.fidb`. The cautious posture (a plaintiff *might* argue the names+metadata are a
covered portion) drives the per-source policy below.

## 3. Per-source-library policy

SPDX IDs in parentheses. "Verdict" = engineering judgment under the cautious posture.

| Library (example) | License | Verdict | Why |
|---|---|---|---|
| zlib | `Zlib` | **SAFE** | Permissive, no copyleft; trivially reproducible. |
| musl libc | `MIT` | **SAFE** | Permissive; notice retention covered by NOTICE/SBOM. |
| OpenSSL **3.0+** | `Apache-2.0` | **SAFE** | Same license as our outbound; §4 attribution via NOTICE. |
| Boost | `BSL-1.0` | **SAFE** | Permissive; no notice required for compiled redistribution. |
| BSD libs (libevent, …) | `BSD-2/3-Clause` | **SAFE** | Permissive; preserve copyright/no-endorsement in NOTICE. |
| **glibc** | `LGPL-2.1-or-later` | **CAUTION** | LGPL's reach to a hash/name index is unsettled → counsel. |
| Qt | `LGPL-3.0` | **CAUTION** | Same LGPL question + GPLv3/LGPLv3 anti-tivoization → counsel. |
| readline | `GPL-3.0-or-later` | **AVOID** | Strong copyleft; one-way incompatible with Apache-2.0 outbound. |
| (any) | `AGPL-3.0` | **AVOID** | Network-copyleft; worst place to be wrong — counsel only. |
| OpenSSL **pre-3.0** | `OpenSSL` (+SSLeay) | **AVOID** | Advertising clause, historically GPL-incompatible — use 3.0+. |

**Apache-2.0 outbound compatibility:** clean for **permissive** sources (preserve each notice).
For **LGPL**, viable *only* under the not-a-derivative theory (else LGPL terms would attach) — the
item counsel must bless. For **GPL/AGPL**, not viable outbound (copyleft is one-directional: Apache
code can flow *into* GPL, not GPL-derived material *out* under Apache).

## 4. Recommendation — permissive-only v1 (no hard ruling required)

Ship the first ELF FID DB set derived **only from permissive, pinned-from-source libraries**, which
makes the Apache-2.0/copyleft question moot for the release:

1. **musl libc (MIT)** — highest identification value for the static-libc role in ELF
   malware/CTF/embedded targets, and the recommended **substitute for glibc** (covers most of the
   libc-identification value without the LGPL question).
2. **OpenSSL 3.0+ (Apache-2.0)** — high-value, common in ELF binaries, **same license as ours**.
3. **zlib (Zlib)** — ubiquitous, tiny, trivially reproducible.
4. **Boost (BSL-1.0)** — high value for C++ targets.
5. *(later, as the set matures)* selected BSD libs.

**Excluded from v1** (defer to counsel): glibc, Qt (LGPL — CAUTION); readline/GPL, AGPL, OpenSSL
pre-3.0 (AVOID).

### Required artifacts per shipped `.fidb` (Phase-2 implementation checklist)
- **Provenance manifest:** source library + **exact upstream version/tag**, source **tarball/commit
  digest**, compiler + flags, target processor/language, Ghidra version + generator-script version,
  build timestamp, resulting `.fidb` **digest** (`std-supplychain` pin-by-digest).
- **SBOM entry** (SPDX/CycloneDX) per DB recording the source library's **SPDX license ID** so
  downstream license/CVE scanners resolve cleanly.
- **`NOTICE`** aggregating each source library's copyright/attribution line.
- **Design disclaimer** recording that the DB contains only non-reversible hashes + symbol names +
  metadata, no library code/source (preserves the FLIRT "no code" rationale on the record).
- **Reproducible-build recipe** so a third party can regenerate + verify each DB.

### Recommended CI license gate (not yet wired)
`topic-license-compliance` is not currently imported and there is no license scanner in CI. For
Phase 2, add an **allow-list gate** over the FID-DB *source set*: allow `Zlib`/`MIT`/`Apache-2.0`/
`BSL-1.0`/`BSD-2-Clause`/`BSD-3-Clause`; **block** `LGPL-*`/`GPL-*`/`AGPL-*`/`OpenSSL` (pre-3.0) so a
copyleft source cannot be added to the DB build without an explicit, reviewed waiver.

## 5. Escalate to counsel before shipping ANY copyleft-derived (glibc/Qt/GPL/AGPL) DB
1. **Core question:** is a `.fidb` (non-reversible function-body hashes + lifted symbol names +
   metadata, **no instruction bytes/source**) a "derivative work" / "work based on the Library"
   under (a) US copyright and (b) LGPL-2.1/3.0 §0? (Provide the FLIRT precedent + threatrack-MIT
   precedent below.)
2. If **not** a derivative → confirm Apache-2.0 outbound is clean and only attribution survives.
3. If **arguably** a derivative → for **LGPL**: can the DB ship under LGPL terms inside an Apache-2.0
   image (relink/RE-allowance compliance)? For **GPL/AGPL**: confirm out-of-scope (incompatible
   outbound; AGPL §13 network exposure).
4. **EU:** does the *sui generis* right impose any obligation when distributing into the EU (and does
   it instead vest a thin right in us)?

## 6. Corrections, precedent & caveats
- **Precedent (supporting, not authoritative):** IDA **FLIRT** — ~25 years of "hashes + names, no
  code" signature distribution at commercial scale, no known successful copyright challenge.
  **`threatrack/ghidra-fidb-repo` is MIT-licensed** (corrects an earlier assumption that it was
  unlicensed) and ships glibc/OpenSSL/Boost/zlib/Qt-derived `.fidb` under MIT — an experienced
  practitioner publishing copyleft-derived FID DBs permissively. Persuasive, not a ruling.
- **NSA Ghidra ships only MSVC FID DBs by default:** the licensing-vs-mission rationale is an
  **inference, unconfirmed** by any official statement (plausibly: MSVC statics are the highest-value
  Windows-malware target, and hashing proprietary MS code sidesteps redistribution).
- **Untested + jurisdictional:** the not-a-derivative position is well-reasoned and matches FLIRT,
  but is not adjudicated for a `.fidb`; US and EU diverge.

## 7. Sources
US derivative-work standard — 17 U.S.C. §101 (Cornell LII). *Feist v. Rural*, 499 U.S. 340 (1991)
(Justia). U.S. Copyright Office Circular 33 (names/short phrases). *Google v. Oracle* (2021) — CRS
LSB10597; EFF analysis. EU Directive 96/9/EC (WIPO Lex; EUR-Lex). GNU LGPL-2.1 (§0 work-based-on
distinction); GNU AGPL-3.0 (§13); GNU license list (GPL/Apache one-way compatibility; OpenSSL
old-license incompatibility). OpenSSL license page + wiki (3.0+ Apache-2.0). Apache License 2.0 §4 +
ASF legal/resolved. SPDX license list (Zlib/MIT/BSL-1.0/BSD-3-Clause/Apache-2.0). Ghidra FunctionID
docs (default MSVC DBs). threatrack/ghidra-fidb-repo + its MIT LICENSE. Hex-Rays FLIRT In-Depth ("no
byte… except function names") + FLIRT signature generation. _(All accessed 2026-06; full URLs in the
SPIKE-2 research record.)_
