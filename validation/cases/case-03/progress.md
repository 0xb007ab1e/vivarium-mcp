# CASE-03 — Live IR Progress Log

**Status:** 🟢 COMPLETE — Malicious (High). Win32.LuckyCat APT RAT (Tibetan-targeting). Blind: 6 HIT/1 PARTIAL. **Sample never executed.**
**Analyst:** Claude (Vivarium MCP static triage)

## Intake (blind)
| Field | Value |
|---|---|
| sha256 | `e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9add4` |
| md5 | `9f9723c5ff4ec1b7f08eb2005632b8b1` |
| Type | PE / MS-DOS executable (MZ) · 118,784 B · entropy 6.50 |
| Staged at | `vivarium-imports/vld/e89614e3….bin` (git-ignored) |

## Timeline
- **[intake]** Hash-named sample staged (prior blind theZoo intake). Sanitized facts computed in an ephemeral `--network none` container (inert hash/size/entropy/magic; no execution). Ground-truth seal NOT read.
- **[load]** session_create → session_import (auto loader; `binary` loader rejected w/o processor+base_addr — used auto for PE) → session_analyze(deep). 705 funcs, PE32 DLL base 0x10000000.
- **[triage]** program_summary: DLL, 2 exports (GetObjectCount masquerade), 130 imports, low complexity — small malicious core in ATL/MSVC CRT.
- **[imports]** WS2_32(ordinals)+GetAddrInfoW net client; CreatePipe+CreateProcessW+DuplicateHandle+SetStdHandle exec-w/-redirect; Reg* config; CoCreateGuid victim-id; host recon (ComputerName/Volume/SysInfo/Mem/Drives); IsDebuggerPresent.
- **[strings]** C2 dalailamatrustindia.ddns.net:110/:443 + 5.126.6.16:110; internal `Credential.dll`; FAKED version resource "Windows Credential Manager"/© Microsoft; RTTI classes CMyClientMain/ClientTran/MainTrans/TlntTrans(shell)/FileTrans.
- **[decompile]** FUN_100012e7 = C2 beacon: rolling subtract-cipher config decrypt + multi-target failover + srand/rand jitter + CMyClientMain vftable + transport threads. → artifacts/c2_beacon_FUN_100012e7.c
- **[assess]** RAT/backdoor HIGH; Tibetan-APT targeting inferred from ddns lure; family specific LOW. → report.md/confidence.md
- **[reveal]** theZoo seal (single entry): **Win32.LuckyCat**. Verdict/severity/category/C2/delivery/targeting HIT; family label PARTIAL (campaign context nailed). → reveal.md
- **Vivarium note:** ioc_scan precise 2/2; crypto_constant_scan correctly empty (bespoke cipher); decompiler clean on obfuscated APT malware.
