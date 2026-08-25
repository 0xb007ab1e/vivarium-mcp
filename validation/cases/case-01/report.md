# CASE-01 — Incident Analysis Report

> **Blind static triage via Vivarium MCP (Ghidra). Sample never executed.**
> All quoted strings/paths are inert binary-derived data (defanged where network-relevant).

## 1. Executive summary

CASE-01 is a **Windows credential-stealing network bot** — a large MSVC/C++ (Boost)
executable that (a) installs **self-healing autorun persistence** masquerading as a
"Sony" component, (b) **harvests stored FTP credentials** from a broad list of FTP
clients, (c) embeds a **WinPcap packet-capture driver** for network sniffing, (d) opens
**raw sockets that both connect out and accept inbound** (peer-to-peer / bot behavior),
(e) speaks **HTTP** with **dynamically resolved** WinINet APIs, and (f) carries **AES +
CRC-32** for content protection. Anti-analysis (`IsDebuggerPresent`) and a global named
object round out a full-featured bot.

**Verdict:** Malicious — credential-stealing / traffic-sniffing bot with P2P + HTTP C2.
**Severity:** High.

## 2. Intake

| Field | Value |
|---|---|
| sha256 | `89c2d370bfa36f1d4c3e4f2ff36f966bafef3e1179319e3a4a0f2a344896bc41` |
| md5 | `91f25b52d9bf833b9ac36e7258e44807` |
| Size | 1,987,880 bytes (Ghidra image; on-disk 1,965,568) |
| Format | PE32, x86 (32-bit), GUI subsystem, MSVC/C++ + Boost 1.45 |
| Entry | `0x0047d2b0` |
| Functions | 10,106 (mostly statically-linked CRT/Boost) · 231 imports · 2 exports · 3,100 strings |
| Entropy | 6.39 (not packed — code directly analyzable) |

## 3. Capability evidence (static)

| Capability | Evidence |
|---|---|
| **Persistence (self-healing)** | `FUN_00440553` decompiled: writes Run-key value **`SonyAgent`** → own path, rewrites if removed. `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. |
| **FTP credential theft** | Registry target list: BulletProof FTP, CuteFTP (GlobalSCAPE), CoreFTP (FTPWare), ClassicFTP (NCH), FFFTP (Sota), Far FTP plugin, Directory Opus FTP. Reads saved-site/bookmark files (`Default.bps`, `ftp.oxc`). |
| **Network sniffing** | Embedded **WinPcap 4.1.0** driver (`npf.pdb`, `wpcap.pdb`, `Packet.pdb`); `\Registry\Machine\SOFTWARE\CaceTech\WinPcapOem\NPF`; `DLT_*` link-type strings; `\\.\Global\%s` device format. |
| **Raw-socket P2P / listen** | ws2_32 (37 imports): `WSASocketA`, `WSAAccept`, `WSARecv`, `WSASend`, `WSAStringToAddressA` + `mswsock`. Accepting inbound ⇒ peer/bot node, not just a client. |
| **HTTP C2 (evasive)** | wininet `InternetOpenA`, `HttpSendRequestA`; API names present **as strings** (`HttpOpenRequestA`, `HttpQueryInfoA`) ⇒ dynamic `GetProcAddress` resolution. `HTTP/1.1` request scaffolding. `dnsapi`, `iphlpapi`. |
| **Crypto** | AES S-box @ `0x0051f748`; CRC-32 tables @ `0x00522ea4`, `0x0059e064`; embedded Base64 alphabets. |
| **Anti-analysis** | `IsDebuggerPresent`. |
| **Process/exec** | `CreateProcessA`, `ShellExecute` (shell32), `CreateFileMappingA`. |

## 4. Indicators of Compromise

| Type | Indicator | Note |
|---|---|---|
| Registry (persistence) | `HKLM/HKCU\...\CurrentVersion\Run\SonyAgent` | autorun value name |
| Registry (masquerade) | `Software\Sony` | fake-vendor key |
| Named object | `\\.\Global\%s` | global mutex/device format |
| Driver | WinPcap/NPF (`SOFTWARE\CaceTech\WinPcapOem\NPF`) | installed sniffer |
| Domain | `oparle[.]com` | defanged; candidate C2 |
| Domain | `SoftX[.]org` | defanged; candidate C2/vendor masquerade |
| Crypto | AES + CRC-32 + Base64 | content protection |

**False positives noted (Vivarium ioc_scan):** version strings (`1.8.1.15`, `2.0.0.15`)
mis-flagged as IPv4; timestamps (`10:21:47`, `15:38:39`) mis-flagged as IPv6; placeholder
`me@mysite.com`/`test@test.com`/`mysite.com`/`test.com` are library/config templates, not live C2.

## 5. MITRE ATT&CK

- **T1547.001** Registry Run-key persistence (self-healing).
- **T1555 / T1552.001** Credentials from FTP clients (registry + config files).
- **T1040** Network sniffing (WinPcap).
- **T1071.001** Web (HTTP) C2; **T1573** Encrypted channel (AES).
- **T1027** Obfuscation via dynamic API resolution.
- **T1622** Debugger evasion.
- **T1571 / T1090** Non-standard raw-socket P2P listener.

## 6. Family hypothesis (still blind)

The blend — **C++/Boost bot + WinPcap sniffer + broad FTP-client credential harvesting +
raw-socket P2P (accept) + AES + HTTP + spam/proxy-capable networking** — matches a
**Kelihos/Hlux-class peer-to-peer credential-stealing spam bot**. Alternative: a
Pony/Fareit-style FTP stealer embedded in a custom bot. See `confidence.md`.

## 7. Containment / response guidance

- Remove `Run\SonyAgent` value **and** the payload it points to (expect re-creation while running).
- Look for an installed **WinPcap/NPF service** (unexpected on endpoints) as a strong host IOC.
- Hunt outbound HTTP to `oparle[.]com` / `SoftX[.]org` and unusual inbound raw-socket listeners.
- **Rotate all FTP credentials** stored on the host (assume exfiltrated).
- Network capture ability ⇒ treat other host credentials seen on the wire as exposed.
