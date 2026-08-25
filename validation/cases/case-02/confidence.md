# CASE-02 — Confidence Report

| Assessment | Confidence | Basis |
|---|---|---|
| **Malicious** | **High** | Decompiled NSS credential-decryption loop over `signons.sqlite`/`moz_logins` is unambiguously theft; combined with HTTP C2, screen surveillance, and remote exec it is a full implant. |
| **Category: macOS RAT + browser/mail infostealer** | **High** | Multiple independent evidence lines converge — decompiled cred theft, C2 request templates, CGWindowList+CGEventPost, fork/exec, app-bundle infection. |
| **Credential theft (Mozilla NSS)** | **High** | `FUN_00008b88` decompiled end-to-end: NSS `PK11SDR_Decrypt` on `moz_logins`, per-browser dispatch. |
| **HTTP C2 + proxy tunnel** | **Medium-High** | Request templates (`GET`, `CONNECT`) and socket imports present; exact send call-graph not fully traced this pass. |
| **Desktop surveillance / input injection** | **Medium-High** | CGS window-list + `CGEventPost` imports present; capture/inject call sites not decompiled. |
| **Family attribution** | **Low-Medium** | Behavioral fingerprint characteristic of early-2010s macOS espionage RAT (Crisis/Morcut, Careto, or generic); no version/campaign string to confirm. |

## Evidence quality
- **Strong:** decompiled credential-theft function (clean C on a real Mach-O malware);
  concrete C2 request templates; explicit import capability map; app-bundle infection paths.
  Not packed (entropy 5.56) → decompiler reached real logic.
- **Gaps:** C2 host is runtime-built (no static domain); command dispatcher (`FUN_00002397`,
  cyclomatic 68 / fan-out 51) not decompiled — exact tasking command set unread; screen-capture
  path and input-injection call sites not traced; family not signature-confirmed.

## What would raise confidence
- Decompile `FUN_00002397` (top dispatcher) → enumerate the C2 command set.
- Trace `_send`/`GET %s` call site → recover URL construction + User-Agent.
- `function_hash` / `bsim` corpus match against known macOS RAT samples for family.

## Vivarium tool performance (CASE-02)
- **Worked well:** `session_import` (macho loader, sha256-verified), `program_summary`,
  `list_imports` (clean framework/dylib attribution), `list_strings`, `ioc_scan`, `xrefs_to`,
  `decompile_function` (clean, complete C on a 32-bit Mach-O — dlsym/NSS logic fully legible).
- **Caveat:** `session_import` requires an **absolute** `source_ref` under the import root; a
  relative path is rejected ("must be a path under the import root") because the resolver does
  `Path(source_ref).resolve()` against the server CWD. Minor ergonomics/doc gap.
- `crypto_constant_scan` correctly empty (no embedded crypto) — no false positives here.
