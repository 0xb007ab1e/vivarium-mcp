# CASE-01 — Live IR Progress Log

**Status:** 🟢 COMPLETE — Malicious (High). Credential-stealing network bot w/ sniffer + P2P.
**Analyst:** Claude (Vivarium MCP static triage) · **Sample never executed.**

## Intake (blind)
| Field | Value |
|---|---|
| sha256 | `89c2d370…896bc41` |
| md5 | `91f25b52d9bf833b9ac36e7258e44807` |
| Type | PE32 x86 GUI, MSVC/C++ + Boost · 1.96 MB · entropy 6.39 |

## Timeline
- **[intake]** Hash-named sample staged to Vivarium import root. No prior knowledge.
- **[load]** session_create → session_import (sha256 verified) → session_analyze (default). 10,106 functions.
- **[triage]** program_summary: AES + CRC-32; 231 imports; IOCs (domains/emails/paths).
- **[imports]** ws2_32 raw sockets (WSAAccept/WSASocket ⇒ listen), wininet HTTP (dynamic-resolved), dnsapi, iphlpapi, WinPcap sniffing, RegSetValueEx persistence, IsDebuggerPresent.
- **[strings]** Large FTP-client credential target list (BulletProof/CuteFTP/CoreFTP/FFFTP/Far/DirOpus). `SonyAgent` autorun. `Software\Sony` masquerade.
- **[crypto]** AES S-box + CRC-32 tables + Base64 alphabets confirmed.
- **[decompile]** `FUN_00440553` = self-healing Run-key persistence writing value `SonyAgent`. ✅ decompiler clean on real malware.
- **[assess]** Category HIGH confidence (credential-stealing bot); family MEDIUM (Kelihos/Hlux-class or Pony/Fareit-in-bot). → report.md / confidence.md.
- **[reveal]** OSINT (search + hash-indexed detection page): family = **Backdoor:Win32/Kelihos (Hlux)**. Blind verdict/severity/category/**primary family all HIT**. MB/VT API keyless this run. → reveal.md.
- **Vivarium note:** ioc_scan FP on version strings→IPv4 and timestamps→IPv6 (analyst-filtered).
