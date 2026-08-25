# CASE-04 — Reveal & Scoring

**Ground truth (theZoo seal, single-entry read):**
- Family: **Win32.BUMBLEBEE (v0.1)**  (`malware/Binaries/Win32.BUMBLEBEE_0.1`)
- sha256 `c34e5d36…09ee689a` · md5 `e815078b81bda42fd1d8029f82f63f8c` · 2,460,160 B

BumbleBee = a prominent malware **loader** (emerged 2022 as the BazarLoader successor;
initial-access broker tooling that loads Cobalt Strike / ransomware, incl. Conti-linked).
Signature traits: heavily-obfuscated **x64 DLL executed via `regsvr32` (DllRegisterServer)**,
junk-code + anti-analysis, decodes and reflectively loads its next stage. All observed here.

## Blind scorecard
| Dimension | Blind call | Truth | Score |
|---|---|---|---|
| Verdict | Malicious | Malicious | **HIT** |
| Nature | **Loader/packer stage, not final payload** | BumbleBee = a loader | **HIT** (core) |
| Severity | High | High (loads CS/ransomware) | **HIT** |
| Exec vector | regsvr32 / DllRegisterServer | BumbleBee's signature vector | **HIT** |
| Obfuscation | MBA junk code + decoy word-salad + size padding | matches BumbleBee | **HIT** |
| C2 | named-pipe here; network in decoded stage | BumbleBee C2 = HTTPS in stage | (consistent — pipe is internal) |
| Family (specific) | guessed Qakbot/PlugX/Emotet-loader class | BumbleBee | **PARTIAL** (loader bucket right, name wrong) |

**Result: 5 HIT / 1 PARTIAL / 0 MISS across scored dimensions.** The most valuable call —
distinguishing a **loader** from a payload/RAT — was correct, derived purely from static
structure (regsvr32 DllRegisterServer export + multiply-decode loops + 97.7%-undefined
padding), without unpacking. Only the proper-noun loader family was missed.

## Key methodology win
The `program_summary` coverage ratio (1.5% defined code vs 97.7% undefined) + the export
`DllRegisterServer` were sufficient to classify "packed regsvr32 loader" in seconds, before
any decompile. Decompiling `DllRegisterServer` then confirmed the self-decode + dispatch.

## Vivarium performance (case-04)
- `decompile_function` recovered decode loops + final GetProcAddress-style dispatch through
  dense MBA/junk-code obfuscation (10 dead-block warnings) — robust.
- `program_summary` coverage ratio = standout triage signal for packed loaders.
- `ioc_scan` correctly EMPTY (true negative — C2 is in the encoded stage; not a miss).
- `crypto_constant_scan` empty (bespoke multiply-decode) — empty≠none lesson holds (3rd case).
- Limitation (expected, by design): read-only static triage cannot recover the encoded
  second stage / real C2 — would need emulation/unpacking, which is out of Vivarium v1 scope.

## Blindness caveat
Seal read filtered to this sha256 only. Session held prior-case context (earlier spill); the
case-04 analysis used ONLY tool output + this sample's own code/strings; seal read AFTER
report.md + confidence.md.
