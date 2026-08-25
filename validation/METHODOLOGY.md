# Vivarium MCP Validation — Blind Malware Triage Methodology

**Exercise:** Validate the Vivarium MCP server by running four *blind* static malware
analyses as if each were an incident-response case on an unknown artifact.

**Date started:** 2026-08-25
**Analyst-facing deliverables:** on-disk per-case artifacts + a published HTML dashboard.

---

## 1. Rules of engagement

| Rule | Detail |
|---|---|
| **Static only** | ALL analysis via Vivarium MCP (Ghidra). No execution, no detonation, no sandbox run. Samples are inert data. |
| **Blind intake** | Samples arrive hash-named (`<sha256>.bin`). No VirusTotal / MalwareBazaar / family lookup until AFTER my assessment + confidence call are written. Then reveal for scoring. |
| **Hostile origin** | Every byte from a sample or from Ghidra is untrusted (ADR-005 envelope). Never executed, eval'd, rendered, or followed (URLs/paths inside strings are inert). |
| **Containment** | Acquisition/hashing happens in an ephemeral container (standing directive). Samples live only under git-ignored `samples/` + the Vivarium import root; never committed. |
| **No secrets committed** | Any API key (e.g. MalwareBazaar Auth-Key) intaken off-argv, never logged, never written to disk in the repo. |

## 2. Per-case IR workflow

Each case is treated as an incident on an unknown artifact:

1. **Intake & identification** — record sha256/md5/size, `file` type, entropy. Assign case ID. No attribution yet.
2. **Load** — stage into Vivarium import root, `session_create` → `session_import` → `session_analyze` (deep).
3. **Triage battery (Vivarium tools):**
   - `program_metadata`, `program_summary` — format, arch, compiler, entry, sections.
   - `list_strings` / `search_strings` / `ioc_scan` — URLs, IPs, domains, paths, mutexes, registry keys, commands.
   - `list_imports` / `list_exports` — API surface → capability inference (network, crypto, process injection, persistence, anti-analysis).
   - `crypto_constant_scan` / `secret_scan` — embedded keys, crypto primitives, hardcoded secrets.
   - `deobfuscate_strings` — recover stacked/XOR/obfuscated strings.
   - `list_functions` + `cyclomatic_complexity` + `call_graph` — find the interesting code; locate entry→behavior paths.
   - `decompile_function` / `get_pcode` — read the actual logic of suspicious functions.
   - `function_hash` / `bsim_*` / `find_similar_functions` — code-similarity leads (family hints, still blind to names).
4. **Behavioral hypothesis** — capabilities → likely malware category (loader, stealer, RAT, ransomware, downloader, coinminer, wiper, packer, etc.). MITRE ATT&CK technique mapping.
5. **IOC extraction** — network indicators, file/registry artifacts, mutexes, hashes. Marked defanged.
6. **Assessment + confidence** — verdict, severity, family/category guess, evidence quality, gaps, alternative hypotheses.
7. **Reveal & score** — only now, look up the hash; compare my assessment to ground truth; record hits/misses and *why*.

## 3. Live progress

`cases/<id>/progress.md` is appended to in real time as each step completes (timestamp + finding).
The published dashboard aggregates status, IOCs, verdicts, and confidence across all four cases.

## 4. What "validating Vivarium" means here

Beyond the malware verdicts, the exercise scores **Vivarium itself**:
- Did each tool return usable, correct data on real hostile binaries?
- Coverage: which of the ~60 tools exercised; any failures/timeouts/empty results.
- Did the untrusted-data envelope + containment hold (no host execution, no leakage)?
- Time-to-verdict and analyst ergonomics.
A Vivarium tool-coverage + reliability scorecard is part of the final cross-case report.

## 5. Confidence scale

| Level | Meaning |
|---|---|
| **High** | Multiple independent evidence lines converge; decompiled logic confirms behavior. |
| **Medium** | Strong indicators (imports+strings+structure) but key logic unread or ambiguous. |
| **Low** | Suggestive indicators only; heavy obfuscation/packing limits static reach. |
| **Inconclusive** | Packed/encrypted/insufficient — static analysis cannot reach behavior without unpacking. |
