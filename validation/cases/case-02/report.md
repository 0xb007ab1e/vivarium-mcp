# CASE-02 — Incident Analysis Report

> **Blind static triage via Vivarium MCP (Ghidra). Sample never executed.**
> All quoted strings/paths are inert binary-derived data (defanged where network-relevant).

## 1. Executive summary

CASE-02 is a **macOS (Mach-O, x86 32-bit) surveillance backdoor + infostealer**. It:
- **steals stored browser/mail credentials** — opens `signons.sqlite` for **Firefox,
  Thunderbird, SeaMonkey** and decrypts the logins with the victim's own **NSS** library
  (`PK11SDR_Decrypt`), plus targets **Opera `wand.dat`**; drops a bundled
  `libmozsqlite3.dylib` to read the SQLite DBs;
- **beacons to an HTTP C2** with a `GET %s HTTP/1.1 … Connection: close` request and can
  tunnel via **`CONNECT %s:%d HTTP/1.0`** (proxy pivot); C2 records are **BEL(`\x07`)-delimited**
  with timestamps;
- **surveils the desktop** — enumerates on-screen windows (`_CGSGetOnScreenWindowList/Count`,
  `__CGSDefaultConnection`) and can **inject synthetic input** (`_CGEventPost`);
- **runs commands / controls processes** — `fork`/`execl`/`execlp`/`setsid` (daemonize),
  `waitpid`, `kill`/`KillProcess`;
- **reads & writes the filesystem** — `open/fopen/fwrite/write/mkdir/chmod/remove/rename`,
  `dlopen`, and **trojanizes app bundles** (`/Applications/%s.app/Contents/MacOS/%s`, patches
  `Contents/Info.plist`), staging in `/tmp/.%s`;
- **fingerprints the host** — system product/version/build dictionaries, `gethostname`,
  `sysctl`, `host_statistics`.

**Verdict:** Malicious — macOS remote-access/surveillance implant with credential theft.
**Severity:** High.

## 2. Intake
| Field | Value |
|---|---|
| sha256 | `257da8c8b296dac6b029004ed06253fe622c5438b4a47b7dfbb87323b64f50a1` |
| md5 | `c3b48db40cf810cb63bf36262b7c5b19` |
| Format | Mac OS X Mach-O · `x86:LE:32` · compiler gcc · entry `0x2294` |
| Size | 78,664 B on disk (98,376 mapped) · entropy 5.56 (not packed) |
| Functions / imports / strings | 402 / 145 / 385 |

## 3. Capability evidence (imports + strings + decompilation)
| Capability | Evidence |
|---|---|
| **Browser/mail credential theft** | `FUN_00008b88`: `signons.sqlite` + `select * from moz_logins` + NSS `PK11SDR_Decrypt` decrypt loop; per-browser `profiles.ini` (Firefox/Thunderbird/SeaMonkey). `libmozsqlite3.dylib` bundled. Opera `wand.dat`. **Decompiled, confirmed.** |
| **HTTP C2 + proxy tunnel** | `GET %s HTTP/1.1\r\nHost: %s …Connection: close`; `CONNECT %s:%d HTTP/1.0`; runtime URL `http://%s%s`; raw `_socket/_connect/_send/_recv/_gethostbyname`. Client-only (no bind/listen). |
| **Custom C2 protocol** | BEL(`\x07`)-delimited records w/ timestamps `%.2d/%.2d/%d %.2d:%.2d:%.2d`; cred record `%c%s\a%s\a%s\b\b\b\b`. |
| **Desktop surveillance** | `_CGSGetOnScreenWindowList/Count`, `__CGSDefaultConnection`, `_CGSGetConnectionIDForPSN`; input injection `_CGEventPost`. |
| **Remote command / process control** | `fork`, `execl`, `execlp`, `setsid`, `waitpid`, `kill`, `KillProcess`; `/bin/bash`, `/bin/sh`. |
| **Filesystem + app-bundle infection** | `open/fopen/fwrite/write/mkdir/chmod/remove/rename`, `dlopen`; `/Applications/%s.app/Contents/MacOS/%s`, patch `Contents/Info.plist`; `/tmp/.%s`. |
| **AppleEvent automation** | 13× `AE*` + `_LSOpenApplication` — script/drive other apps. |
| **Host recon** | product/version/build dicts, `gethostname`, `sysctl`, `host_statistics`, `getenv`. |
| **Crypto** | None detected (crypto_constant_scan empty) — C2 plaintext; only the victim's NSS is used, to *decrypt* stolen creds. |

## 4. Behavioral hypothesis + ATT&CK
macOS RAT / surveillance implant delivered as/into a trojanized `.app` bundle.
- **T1555.003** Credentials from Web Browsers (NSS/Mozilla decrypt) · **T1539**-adjacent
- **T1113** Screen Capture / window enumeration · **T1059.004** Unix Shell (fork+exec)
- **T1071.001** Web C2 · **T1090** Proxy (HTTP CONNECT) · **T1547/T1554** app-bundle/Info.plist persistence & trojanization
- **T1082** System Information Discovery

## 5. IOCs (defanged, inert)
- C2 URL is **runtime-built** (`http://%s%s`) — no hardcoded C2 domain recovered (host+path
  supplied by config/tasking; not present as a static string in this triage).
- `www.apple.com` / `PropertyList-1.0.dtd` / `radr://5614542` — benign (plist DTD + Apple
  bug-ID artifact), not C2.
- Host artifacts: bundled `libmozsqlite3.dylib`; targets `signons.sqlite`, Opera `wand.dat`;
  staging `/tmp/.%s`; trojanized `/Applications/<name>.app/Contents/MacOS/`.

## 6. Family (blind, pre-reveal)
Category **HIGH**: macOS RAT + browser-credential infostealer with desktop surveillance.
Family **LOW–MEDIUM**: feature set (NSS/Mozilla decrypt, `libmozsqlite3.dylib` bundling,
`wand.dat`, CGWindowList + CGEventPost, HTTP-CONNECT C2, app-bundle trojanization, 32-bit
gcc) is consistent with early-2010s macOS espionage/RAT families — candidates: **HackingTeam
RCS "Crisis/Morcut"**, **Careto/"The Mask" (OSX)**, or a generic macOS RAT/stealer. No
version/campaign string decoded to pin it.
