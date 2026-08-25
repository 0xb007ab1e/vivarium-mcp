# CASE-04 — Live IR Progress Log

**Status:** 🟢 COMPLETE — Malicious (High). Win32.BumbleBee x64 regsvr32 loader. Blind: 5 HIT/1 PARTIAL (loader-vs-payload call correct). **Sample never executed.**
**Analyst:** Claude (Vivarium MCP static triage)

## Intake (blind)
| Field | Value |
|---|---|
| sha256 | `c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee689a` |
| md5 | `e815078b81bda42fd1d8029f82f63f8c` |
| Type | PE / MS-DOS executable (MZ) · 2,460,160 B · entropy 5.95 |
| Staged at | `vivarium-imports/vld/c34e5d36….bin` (git-ignored) |

## Timeline
- **[intake]** Hash-named sample staged (prior blind theZoo intake). Sanitized facts computed in an ephemeral `--network none` container (inert hash/size/entropy/magic; no execution). Ground-truth seal NOT read.
- **[load]** session_create → session_import(auto) → session_analyze(deep). PE32+ x64 DLL base 0x180000000, 190 funcs.
- **[triage]** program_summary: 3 exports incl DllRegisterServer; coverage 1.5% code / 97.7% UNDEFINED (2.4MB) = packed/padded loader tell; no IOC/crypto.
- **[imports]** KERNEL32-only: CreateNamedPipeA/WaitNamedPipeA/TransactNamedPipe (named-pipe IPC); VirtualAlloc+GetProcAddress+LoadLibraryExW+CreateThread+SuspendThread+DuplicateHandle (reflective load); CreateMutexA/OpenMutexA; IsDebuggerPresent; GetSystemDirectoryA.
- **[strings]** decoy English word-salad ("sally# shone# scope...", "Customary tentacles 553", "builder %s? subsequently/ %d-...") = builder filler/anti-signature; random name nqvvr243he2.dll + export Cnt918; base64 alphabet; asInvoker manifest.
- **[decompile]** DllRegisterServer @0x18000261c = junk/MBA-obfuscated self-decode (3 multiply-scatter loops) → indirect dispatch of decoded module's "DllRegisterServer". FUN_180005338 = CRT _setmbcp (false lead). → artifacts/loader_DllRegisterServer_18000261c.c.note
- **[assess]** Loader/packer stage (NOT final payload) HIGH; regsvr32 vector; family LOW (stage encoded). → report.md/confidence.md
- **[reveal]** theZoo seal (single entry): **Win32.BUMBLEBEE_0.1**. Verdict/nature(loader)/severity/exec-vector/obfuscation HIT; family label PARTIAL. → reveal.md
- **Vivarium note:** coverage-ratio = killer packed-loader triage signal; decompiler robust through MBA junk; ioc_scan correctly empty (stage encoded, true negative); read-only can't recover 2nd stage (expected v1 limit).
