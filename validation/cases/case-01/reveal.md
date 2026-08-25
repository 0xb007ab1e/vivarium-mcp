# CASE-01 — Reveal & Score

> Reveal performed **after** assessment + confidence were written (methodology step 7).
> Ground truth obtained by OSINT (search + hash-indexed detection page). No sample
> re-fetched; hashes only.
>
> **MalwareBazaar authoritative lookup (Auth-Key supplied, 2nd attempt):** both sha256 and
> md5 return `hash_not_found`; `Kelihos` is not a tracked MB signature (`no_results`). This is
> **corroborating, not contradicting**: (a) the artifact is a **memory dump**
> (`DUMP_00A10000-00A1D000.exe.ViR`), and MB indexes original files, not dumps; (b) Kelihos was
> sinkholed/dead by 2017, predating MB's active corpus (2018+). Absence is exactly the expected
> signature for a dead-botnet training dump. Family attribution therefore stands on OSINT +
> behavioral fingerprint. (VirusTotal not queried — no VT key; MB key ≠ VT key.)

## Identifiers
| Field | Value |
|---|---|
| sha256 | `89c2d370bfa36f1d4c3e4f2ff36f966bafef3e1179319e3a4a0f2a344896bc41` |
| md5 | `91f25b52d9bf833b9ac36e7258e44807` |

## Ground truth (OSINT)
- sha256 indexed on a detection-name page **`Backdoor:Win32/Kelihos.F`** (returned as a direct
  hit for the sha256 query).
- sha256 present in a malware-analysis **course dataset dump list** (`mw2017l2-2`) as
  `malware/DUMP_00A10000-00A1D000.exe.ViR` — i.e. a memory-dumped, training-corpus sample
  (aligns with the O'Reilly *Practical Reverse Engineering* material surfaced alongside).
- **Family: Kelihos / Hlux** (a.k.a. Backdoor:Win32/Kelihos).
- Canonical Kelihos/Hlux profile (Securelist sinkhole write-up; Infoblox): Boost-C++ P2P bot;
  steals **FTP + email credentials**; **WinPcap packet sniffer**; Bitcoin wallet theft; spam;
  resilient P2P C2. Direct match to the blind behavioral derivation.

## Score vs. blind assessment
| Blind call | Confidence (blind) | Ground truth | Result |
|---|---|---|---|
| **Malicious** | High | Backdoor (Kelihos.F) | ✅ **HIT** |
| Severity **High** | — | full-featured resilient bot | ✅ **HIT** |
| Category: **credential-stealing network bot + sniffer + P2P** | High | Kelihos = FTP/email cred theft + WinPcap sniffer + P2P | ✅ **HIT** (precise) |
| **P2P / inbound listener** (`WSAAccept`/`WSASocketA`) | Medium-High | Kelihos is P2P | ✅ **HIT** |
| Family: **Kelihos/Hlux-class** | Medium | **Kelihos/Hlux** | ✅ **HIT** — primary family guess correct |
| Alt hypothesis: Pony/Fareit FTP stealer | (secondary) | not the family | ⚪ not needed — FTP-theft overlap explained by Kelihos's own stealer module |
| Crypto: AES + CRC-32 | High | consistent with Kelihos content protection | ✅ |

**Blind accuracy: verdict, severity, category, and primary family all correct.**
The only item held at Medium blind confidence — the family — was the *right* family; the
"SonyAgent" Run-key masquerade and broad FTP-client target list were the tell.

## Gaps not closed by reveal
- No multi-engine AV label / first-seen date / campaign tag (needs MB or VT key).
- C2 URL construction (`HttpSendRequestA` call site) and exact P2P command set still
  undecompiled — deferred; not required for the verdict.

## Vivarium validation takeaway (CASE-01)
Vivarium static triage produced a **correct, specific, high-confidence verdict on a real
Kelihos sample without executing it** — persistence logic decompiled cleanly, import/string/
crypto evidence converged, and the family fingerprint was recoverable from static data alone.
One tool caveat stands: `ioc_scan` false-positives (version strings → IPv4, timestamps → IPv6).
