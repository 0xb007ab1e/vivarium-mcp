# CASE-03 — Static Triage Report (BLIND)

**Analyst:** Claude (Vivarium MCP static triage) · **Sample NEVER executed. Containment held.**
**Classification of artifact:** CONFIDENTIAL, HOSTILE ORIGIN (ADR-005 untrusted envelope).

## Verdict
**MALICIOUS — Remote Access Trojan (backdoor). Severity: HIGH/CRITICAL.**
Confidence: category **HIGH (certain)**; family **MEDIUM-LOW**; APT-attribution **inferential**.

## Sample
| Field | Value |
|---|---|
| sha256 | `e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9add4` |
| md5 | `9f9723c5ff4ec1b7f08eb2005632b8b1` |
| Type | PE32 DLL, x86 (base 0x10000000), 118,784 B on disk / 125,180 mapped, entropy 6.50 |
| Internal name | `Credential.dll` · export `GetObjectCount` (+ 1 ordinal) |
| Version resource (FAKED) | FileDescription "Windows Credential Manager"; OriginalFilename "Credential.dll"; ProductName "Microsoft® Windows® Operating System"; FileVersion 6.1.7600.16385; "© Microsoft Corporation" |
| Functions | 705 (deep analysis complete); mostly MSVC/ATL CRT — small malicious core |

## Why malicious (evidence)
1. **Hardcoded C2 + beacon loop** (`FUN_100012e7`, 0x100012e7): assembles target list
   `dalailamatrustindia.ddns.net:110`, `:443`, `5.126.6.16:110`; `srand(time())`; infinite
   connect loop with `rand()`+`Sleep` jitter; debug marker `DLL---Start connect to %ws:%d`.
2. **String obfuscation:** the config string is built byte-by-byte then decrypted with a
   rolling subtract cipher (7-byte key, `byte - key[i%7]`) to defeat static strings scanners.
3. **RAT class model (RTTI):** `CMyClientMain`, `CMyClientTran`, `CMyMainTrans`,
   `CMyTlntTrans` (telnet/remote shell), `CMyFileTrans` (file transfer) — a modular
   command/transport RAT.
4. **Command execution primitives:** `CreatePipe` + `CreateProcessW` + `DuplicateHandle` +
   `SetStdHandle` = spawn child process with redirected stdio (reverse shell / run command &
   capture output).
5. **Host recon:** GetComputerNameW/ExW, GetVolumeInformationW, GetNativeSystemInfo,
   GlobalMemoryStatusEx, GetLogicalDriveStringsW/GetDriveTypeW, GetFileAttributesExW +
   FindFirstFileW enumeration.
6. **Victim ID / config / persistence:** `CoCreateGuid` (unique victim id); ADVAPI32
   Reg{Create,Open,Set,Query}ValueExW (config/persistence in registry).
7. **Networking:** WS2_32 by ordinal (socket/connect/send/recv/WSAStartup) + GetAddrInfoW
   (DNS) — TCP client to the ddns C2.
8. **Anti-analysis:** IsDebuggerPresent, OutputDebugString-gated logging.
9. **Masquerade / delivery:** DLL faking the Windows Credential Manager, benign-looking
   export `GetObjectCount` (a GDI32 name) — consistent with **DLL search-order hijack /
   side-loading** by a legitimate signed host executable.

## Targeting / attribution (inferential)
- C2 hostname **`dalailamatrustindia.ddns.net`** impersonates the *Dalai Lama Trust (India)*.
  Dynamic-DNS C2 + Tibetan-institution lure is a hallmark of **Chinese-nexus APT** campaigns
  targeting the Tibetan community / CTA. Not proof of a specific group, but a strong signal.

## IOCs (extract, defanged)
- Domain: `dalailamatrustindia[.]ddns[.]net` (TCP 110, 443) — @0x1001a8c8
- IPv4: `5.126.6[.]16` (TCP 110) — @0x1001a958
- Host artifact: DLL named `Credential.dll`, export `GetObjectCount`
- Behavioral: OutputDebugString `DLL---Start connect to %ws:%d`

## Capabilities summary
Remote shell (telnet transport), arbitrary process execution w/ output capture, file
transfer (upload/download), filesystem enumeration, host fingerprinting, registry config,
GUID victim tracking, multi-target failover C2 with jitter.

## Vivarium tool notes
- `crypto_constant_scan` **empty** — correct: config uses a bespoke rolling cipher, not a
  standard algorithm with recognizable constants (carry-forward lesson from case-02 holds).
- `ioc_scan` **clean & precise** here (2 real IOCs, no version/timestamp FP) — good.
- `secret_scan` flagged the `Credential`/`Windows...Manager` masquerade strings and the
  base64 alphabet as "hardcoded_credential" (keyword/high-entropy) — FPs, but usefully
  surfaced the masquerade.
- `decompile_function` clean on real obfuscated malware — recovered the beacon + cipher.
