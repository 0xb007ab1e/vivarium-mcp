# CASE-03 — Reveal & Scoring

**Ground truth (theZoo seal, single-entry read):**
- Family/campaign: **Win32.LuckyCat**  (`malware/Binaries/Win32.LuckyCat`)
- sha256 `e89614e3…e1e9add4` · md5 `9f9723c5ff4ec1b7f08eb2005632b8b1` · 118,784 B

LuckyCat = the APT campaign documented by Trend Micro (2011–2012) targeting Tibetan
activists, India, Japan, and aerospace/military/energy — modular RAT delivered via
malicious documents, C2 over dynamic DNS. The `dalailamatrustindia.ddns.net` C2 and the
Windows-Credential-Manager DLL masquerade are on-signature.

## Blind scorecard
| Dimension | Blind call | Truth | Score |
|---|---|---|---|
| Verdict | Malicious | Malicious | **HIT** |
| Severity | High/Critical | High (targeted APT RAT) | **HIT** |
| Category | RAT / backdoor (DLL) | Modular RAT | **HIT** |
| Delivery/masquerade | Side-loaded DLL faking Windows Credential Manager | matches artifact | **HIT** (behavioral) |
| C2 | dalailamatrustindia.ddns.net:110/443, 5.126.6.16:110 | on-signature LuckyCat C2 | **HIT** |
| Config protection | custom rolling subtract cipher | — | (unverified vs GT, read from code) |
| Targeting/actor | Tibetan community / Dalai Lama Trust — Chinese-nexus APT | LuckyCat = exactly this | **HIT** |
| Family (specific label) | guessed Gh0st/PlugX-class | LuckyCat | **PARTIAL** (campaign context right, exact label wrong) |

**Result: 6 HIT / 1 PARTIAL / 0 MISS across scored dimensions.** Strongest case so far —
the blind analysis independently reconstructed the LuckyCat campaign fingerprint (Tibetan
targeting + ddns C2 + credential-manager masquerade) from static evidence alone, missing
only the proper-noun campaign name.

## Vivarium performance (case-03)
- `decompile_function` recovered the beacon loop AND the string-obfuscation cipher on real
  obfuscated APT malware — clean.
- `ioc_scan` precise (2/2 real, no FP) — better than case-01 (which FP'd version/timestamps).
- `crypto_constant_scan` empty & correct (bespoke cipher, no std constants) — carry-forward
  lesson from case-02 confirmed again: empty ≠ no crypto.
- `secret_scan` keyword rule surfaced the "Credential"/"Windows Credential Manager" masquerade
  (technically FP-as-credential, but operationally useful lead).
- `list_strings`/`list_imports` large outputs auto-persisted to file — grep-locally workflow.

## Blindness caveat
This session already held case-01/02 detail in context (prior seal-spill). Case-03 analysis
used ONLY tool output + this sample's own strings/code; the seal was read AFTER report.md +
confidence.md were written, filtered to this sha256 only (03/04 mutual blindness preserved).
