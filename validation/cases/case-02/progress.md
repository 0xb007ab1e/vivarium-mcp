# CASE-02 — Live IR Progress Log

**Status:** 🟢 COMPLETE — Malicious (High). macOS RAT + browser/mail infostealer w/ desktop surveillance. **Sample never executed.**
**Analyst:** Claude (Vivarium MCP static triage)

## Intake (blind)
| Field | Value |
|---|---|
| sha256 | `257da8c8b296dac6b029004ed06253fe622c5438b4a47b7dfbb87323b64f50a1` |
| md5 | `c3b48db40cf810cb63bf36262b7c5b19` |
| Type | Mach-O 32-bit i386 (magic `feedface`, cputype 0x07) · 78,664 B · entropy 5.56 |
| Staged at | `vivarium-imports/vld/257da8c8….bin` (git-ignored) |

## Timeline
- **[intake]** Hash-named sample staged (prior blind theZoo intake). Sanitized facts computed in an ephemeral `--network none` container (inert hash/size/entropy/magic; no execution). Ground-truth seal NOT read.
- **[load]** session_create → session_import (macho loader, absolute source_ref, sha256 verified) → session_analyze (deep). 402 functions.
- **[triage]** program_metadata/summary: Mach-O x86:LE:32, gcc, 145 imports, 385 strings, no crypto. Top dispatcher FUN_00002397 (cyclo 68 / fan-out 51).
- **[imports]** net `_socket/_connect/_send/_recv/_gethostbyname` (client-only); exec `fork/execl/execlp/setsid/waitpid/kill`; CGS window-list + `_CGEventPost` (surveil+inject); 13× AppleEvent; fs R/W + `dlopen`.
- **[strings]** `signons.sqlite`, `select * from moz_logins`, Firefox/Thunderbird/SeaMonkey `Application Support`, Opera `wand.dat`, bundled `libmozsqlite3.dylib`, `/Applications/%s.app/Contents/MacOS/%s`, `/tmp/.%s`. C2: `GET %s HTTP/1.1…`, `CONNECT %s:%d HTTP/1.0`, BEL(`\x07`)-delimited records.
- **[decompile]** `FUN_00008b88` = Mozilla **NSS credential decryptor** (`PK11SDR_Decrypt` over `moz_logins`, per-browser). ✅ clean C on real Mach-O malware. → artifacts/nss_cred_decrypt_FUN_00008b88.c
- **[assess]** Category HIGH (macOS RAT + infostealer + surveillance); family LOW-MED (Crisis/Morcut vs Careto vs generic). → report.md / confidence.md.
- **[reveal]** Sealed theZoo ground truth: family = **OSX/Wirenet** (cross-platform password-stealing backdoor + keylogger). Blind verdict/severity/category/cred-mechanism **HIT**; family specific MISS (bucket right); C2-crypto PARTIAL MISS (Wirenet uses AES via CommonCrypto — constant-scan can't see it). → reveal.md.
- **⚠️ Blindness:** seal read returned ALL entries — cases 03/04 now compromised (informed, not blind). Case-01/02 scores remain valid blind.
- **Vivarium note:** session_import needs ABSOLUTE source_ref under import root (relative rejected — resolver resolves vs server CWD). ioc_scan clean-ish (apple DTD/radr:// benign, correctly no C2 FP). crypto_constant_scan correctly empty of *constants* — but that ≠ no crypto (CommonCrypto framework path).
