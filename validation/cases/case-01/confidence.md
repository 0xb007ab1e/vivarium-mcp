# CASE-01 — Confidence Report

| Assessment | Confidence | Basis |
|---|---|---|
| **Malicious** | **High** | Self-healing autorun + broad FTP-credential harvesting + WinPcap sniffer + dynamic API resolution are unambiguously hostile in combination. |
| **Category: credential-stealing network bot** | **High** | Multiple independent evidence lines (imports, registry target list, decompiled persistence, crypto, raw sockets) converge. |
| **P2P / listener behavior** | **Medium-High** | `WSAAccept`+`WSASocketA` prove inbound accept capability; exact P2P protocol not decompiled. |
| **Family = Kelihos/Hlux-class** | **Medium** | Behavioral fingerprint (Boost C++ + WinPcap + FTP theft + P2P + AES) is characteristic but not proven; no version/campaign string decoded. Alt: Pony/Fareit FTP stealer in a custom bot. |
| **Live C2 = oparle.com / SoftX.org** | **Low-Medium** | Present as strings; not traced to the HTTP-send call graph in this triage; could be config/decoy. |

## Evidence quality
- **Strong:** decompiled persistence function; concrete registry target list; embedded WinPcap PDBs; crypto constants; import capability map. Not packed → decompiler reached real logic.
- **Gaps:** C2 URL construction not traced end-to-end; P2P protocol and exact credential-exfil path not decompiled; family attribution is behavioral, not signature-confirmed.

## What would raise confidence
- Trace `HttpSendRequestA` call site → recover full C2 URL/User-Agent.
- Decompile the WSAAccept handler → confirm P2P command set.
- `bsim`/`function_hash` corpus match against known Kelihos/Pony samples.

## Vivarium tool performance (CASE-01)
- **Worked well:** `session_import` (sha256-verified), `program_summary`, `list_imports`, `search_strings`, `crypto_constant_scan`, `xrefs_to`, `decompile_function` (clean C on real malware), `secret_scan`.
- **Caveat:** `ioc_scan` false-positives on version numbers (→ IPv4) and timestamps (→ IPv6); analyst must filter. Otherwise high-value.
