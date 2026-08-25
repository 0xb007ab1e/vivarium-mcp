# CASE-04 — Static Triage Report (BLIND)

**Analyst:** Claude (Vivarium MCP static triage) · **Sample NEVER executed. Containment held.**
**Classification:** CONFIDENTIAL, HOSTILE ORIGIN (ADR-005 untrusted envelope).

## Verdict
**MALICIOUS — obfuscated loader/packer stage of a modular implant. Severity: HIGH.**
Confidence: malicious **HIGH**; "loader not final payload" **HIGH**; family **LOW**
(the real stage is encoded and not statically present).

## Sample
| Field | Value |
|---|---|
| sha256 | `c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee689a` |
| md5 | `e815078b81bda42fd1d8029f82f63f8c` |
| Type | **PE32+ x64 DLL** (base 0x180000000), 2,460,160 B, entropy 5.95 |
| Exports | 3, incl. **`DllRegisterServer`** (→ run via `regsvr32.exe`) and `Cnt918` |
| Coverage | 190 funcs, only **1.5% defined code** (37 KB); **97.7% undefined** (2.4 MB) |
| Manifest | requestedExecutionLevel `asInvoker` (no elevation prompt) |

## Why malicious (evidence)
1. **Self-decoding loader** (`DllRegisterServer`, 0x18000261c): body is saturated with
   junk/opaque-predicate arithmetic over ~60 scratch globals (MBA anti-analysis), wrapping
   three byte-decode loops (`out = *p * mult >> {24,16,8,0}`) over large regions
   (0x22ba8 / 0x10e90 / 0x264c). Ends by resolving & dispatching `"DllRegisterServer"` of a
   decoded module via an indirect call `(*DAT_1800a9110)(...)` — reconstructs a second stage
   and enters it.
2. **regsvr32 execution vector:** primary export `DllRegisterServer` ⇒ launched with
   `regsvr32 /s <dll>` — a common LOLBIN/defense-evasion run + persistence method.
3. **Reflective loading / injection primitives:** VirtualAlloc + GetProcAddress +
   LoadLibraryExW + GetModuleHandleW + CreateThread + SuspendThread + DuplicateHandle.
4. **Named-pipe C2 / inter-module IPC:** CreateNamedPipeA, WaitNamedPipeA, TransactNamedPipe
   — modular implant channel (no WS2_32/wininet in this stage ⇒ network is in the decoded
   payload; pipes coordinate injected components / peer comms).
5. **Anti-signature obfuscation:** ~2.4 MB of undefined data at moderate entropy (5.95) plus
   decoy English **word-salad strings** ("sally# shone# scope, news# conquered; module
   imminent", "Customary tentacles 553", "builder %s? subsequently/ %d- Providence wage@ …")
   = builder-generated filler to defeat string/YARA signatures and inflate the file past
   sandbox upload/scan size limits.
6. **Anti-analysis / hygiene:** IsDebuggerPresent; CreateMutexA/OpenMutexA/ReleaseMutex
   single-instance guard; random module identity `nqvvr243he2.dll` + export `Cnt918`.

## What this is / isn't
- **Is:** the packer/loader outer layer of a modular Windows implant — heavily obfuscated,
  regsvr32-run, decodes and reflectively loads its real stage.
- **Isn't (statically):** the C2 endpoints, credential/module logic — those live in the
  encoded stage, which is not recoverable without emulation/unpacking (out of read-only scope).

## IOCs (this stage)
- Behavioral: x64 DLL run via `regsvr32`, export `DllRegisterServer` + `Cnt918`, internal
  name `nqvvr243he2.dll`.
- Host: named-pipe creation (name in decoded stage), single-instance mutex (name in stage).
- Static C2: **none** (encoded).

## Family hypothesis (LOW confidence)
Pattern — x64 `regsvr32` DLL, junk-code + decoy-string obfuscation, multi-MB padding,
named-pipe modular IPC — matches commodity modular loaders. Best guesses: **Qakbot/Qbot**
(regsvr32 DLL, named-pipe module comms, size-padding, junk obfuscation) or a **PlugX/Emotet
x64 loader**-class. Not determinable from this stage alone.

## Vivarium tool notes
- `decompile_function` **held up on heavily junk-obfuscated x64** — recovered the decode
  loops + final dispatch despite MBA padding and 10 unreachable-block warnings.
- `program_summary` coverage ratio (1.5% code / 97.7% undefined) was the key tell for
  "packed/padded loader" — a strong, cheap triage signal.
- `crypto_constant_scan` empty (custom multiply-decode, no std constants) — carry-forward
  lesson holds a 3rd time.
- `ioc_scan` empty & correct (no plaintext C2 in the loader stage — not a miss, a true negative).
- `secret_scan` only base64/api-ms FPs — decoy strings didn't trip it.
- Large `list_strings`/`list_imports` auto-persisted; word-salad decoys visible in strings.
