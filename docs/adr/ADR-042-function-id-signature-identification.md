# ADR-042: Library-function identification via Ghidra FunctionID (FID)

- **Status:** **Accepted** (ratified 2026-06-21, v1.7 headline). **SPIKE-0 PASS** (see below) — Phase 1
  is viable; implementation may proceed. Phase 2 (ELF DBs) remains deferred behind SPIKE-1 + SPIKE-2.
- **Date:** 2026-06-21
- **Deciders:** Human (requested the v1.7 headline) + PM; recorded by the Software Architect.
- **Context source:** the v0.10.0 functional-gap review identified "no library/signature
  identification" as the single highest-leverage *new* capability for the core naming workflow. An SME
  pass on Ghidra 12.x FunctionID (sources in §References) surfaced two facts that shape this ADR:
  (1) Ghidra ships FID databases for **MSVC/Windows only** — there is **no out-of-the-box FID for
  glibc/OpenSSL/zlib or any ELF library**; ELF coverage means **generating and bundling our own
  `.fidb`** at build time; (2) the precise **headless API to activate a *custom* FidDb** and the
  **licensing of a generated `.fidb`** derived from copyleft/OpenSSL sources are both **unverified**.

## Context

Vivarium's value proposition is helping an LLM client understand a stripped binary. Today the client
must propose a name for **every** function from the decompiled code — but in a typical real binary the
*majority* of functions are known library code (libc, OpenSSL, zlib, the CRT). Auto-identifying those
collapses the bulk of unknown-symbol noise so the client can focus inference on the ~handful of
functions that are the actual program logic.

Ghidra has exactly this feature: the **FunctionID (FID)** analyzer hashes each function body and looks
the hash up in attached/active FID databases; on a confident match it sets the function name as a
symbol and adds a library-name/version comment + bookmark. It runs as part of auto-analysis.

The SME findings (§References) constrain how we can use it:

- **Coverage that ships:** only Microsoft Visual Studio runtime DBs (VS2012–2019, x86/x64) ship and
  are unpacked by a released Ghidra. So **MSVC/PE targets get FID for free**; **ELF/Linux targets get
  nothing by default.**
- **Generating ELF DBs is real work:** ingest requires the reference libraries **imported, analyzed,
  and carrying non-default symbol names** (i.e. **unstripped** libs) — built at image-build time from
  pinned sources, with the Function ID / Library Identification analyzers disabled during ingest.
- **Match quality is best-effort:** small functions match randomly against a large DB; identical code
  idioms collide; matches break across optimization/compiler-version changes; databases are
  processor-specific. Output can be **multiple, ambiguous, or wrong** — the analyzer surfaces
  thresholds/relation status, not a single 0–100 score.
- **Two unverified blockers for ELF:** the headless `FidFileManager`/`FidService` call to mark a
  custom DB **active** (Ghidra normally requires GUI attach+activate per #1847), and whether a `.fidb`
  derived from glibc (GPL/LGPL) / OpenSSL is a distributable derivative — **needs counsel**.

These align with our existing posture: binary-derived output is **untrusted** (ADR-005), and the LLM
must not over-rely on it (`std-owasp-llm` LLM09). FID results are hints, never authoritative names.

## Decisions

- **D1 — Phase it; ship the safe half in v1.7.**
  - **Phase 1 (v1.7, ships):** surface the matches Ghidra's **already-running** Function ID analyzer
    produces from the **bundled MSVC DBs**, via a new **read-only** tool `identify_functions`. Zero
    custom DBs, zero new library sources, **zero licensing exposure**, no new trust boundary. Delivers
    immediate value on PE/MSVC targets and establishes the contract surface.
  - **Phase 2 (deferred, gated):** build-time generation + bundling of **ELF** FID DBs
    (libc/OpenSSL/zlib/…) for Linux targets. This is where the value for Vivarium's primary targets
    lives, but it is **gated on SPIKE-1 + SPIKE-2 below** and gets its own ratification before build.

- **D2 — Read-only first; "apply" is a separate, later, gated tool.** Phase 1 ships only the
  **output-only** `identify_functions` (a hint surface). It does **not** rename anything. The client
  consumes the hints directly in its naming workflow. An `apply_signatures` **write** tool (rename
  matched functions to the library name) is **deferred**: it adds a mutation surface that must go
  through the existing write gate (`require_write_consent` + `validate_write_name`, ADR-012/013), and
  the read-only hint already captures most of the value. Revisit apply after Phase 1 is in use.

- **D3 — FID output is untrusted, multi-valued, best-effort — modeled as hints, never names.**
  `identify_functions` returns, per matched function: the address, the **matched library name +
  version** and the **function name** (both **wrapped in the ADR-005 untrusted envelope**), plus
  **match-quality metadata** — match kind (full-hash vs. specific-hash), whether a parent/child
  relation corroborated it, and **multiplicity** when several candidates survive (one entry per
  surviving candidate, capped). No fabricated single confidence score; we surface Ghidra's actual
  signals. The tool is **bounded** (max matches + `truncated` flag, mirroring `ioc_scan`), enforced
  server-side *and* worker-side (defense in depth). Docs state plainly: a match is a triage hint, not
  ground truth (LLM09).

- **D4 — FID databases are trusted, pinned, build-time supply-chain inputs — never runtime ingest.**
  - Phase 1 DBs are the MSVC DBs Ghidra already ships inside the **digest-pinned worker image** — no
    new artifact.
  - Phase 2 DBs are **generated at image-build time** from **pinned, unstripped, permissively-licensed
    reference libraries**, laid into the image at a stable read-only path, with **provenance recorded
    per DB** (source package, version, license, build inputs) and reflected in the **SBOM**. Adding a
    DB changes the **worker-image digest** — a controlled, gated change (`std-supplychain`,
    `workflow-cve-management`). The worker **never ingests/generates a DB at runtime** (preserves the
    read-only analysis posture and ADR-001/002 isolation).

- **D5 — Additive contract only; no RPC/envelope reshape.** `identify_functions` is a new worker-only
  RPC method (server is the sole client) returning data through the **existing** envelope + bounds
  machinery. Frozen-contract delta = **additive** (tool-catalog **55 → 56**, new pydantic `In/Out`,
  `RPC_METHODS` + `TIER1_TOOL_NAMES` entry, adapter wrap). Per WS0 this routes through the PM as a
  batch-atomic contract change; **expected bump: minor**, with a threat-model note (new untrusted
  output path + the FID-DB-as-trusted-input supply-chain edge). No new trust boundary is introduced.

- **D6 — Analyzer enablement is explicit and version-guarded.** Confirm the **Function ID** analyzer
  is enabled in the `default`/`deep` profiles (ADR-029) and that the bundled MSVC DBs are **active**
  in the headless worker (SPIKE-0 below). Analyzer-option names are checked against the running Ghidra
  12.1.2 per the **ADR-035 existence guard** (fail-closed on a renamed option across a Ghidra bump),
  and Ghidra stays **digest-pinned**.

- **D7 — Mechanism: active FID query, not just reading applied symbols.** `identify_functions`
  queries the FID service directly (`FidFileManager.openFidQueryService` → query per function),
  yielding matches with **explicit library/version + match metadata** independent of whether
  auto-analysis already renamed the function. This is richer and more honest than scraping
  FID-applied symbols/bookmarks (which lose the "this came from FID + how confident" signal and
  collide with user/other-analyzer names). Confirm the `FidQueryService` result API (match list,
  score/relation fields) in a brief implementation spike before freezing `IdentifiedFunction`'s
  fields; fall back to reading FID bookmarks only if the query API proves unusable headless.

## Open spikes (de-risk before committing implementation)

- **SPIKE-0 (Phase 1 prerequisite) — ✅ DONE, PASS (2026-06-21).** Ran a headless PyGhidra probe in
  the hardened worker image (`vivarium-worker:local`; crun, `--network none`, non-root 65532,
  read-only rootfs, caps dropped). Result: the **FunctionID feature is present** (only `GhidraServer`
  is stripped), **10 VS FID databases ship** (`vs2012/2015/2017/2019/vsOlder` × x86/x64,
  `.fidbf`), **all 10 report `installed=True active=True` headlessly** (no GUI unpack/activate
  needed — the core unknown), and the **`FidAnalyzer`** analyzer class is registered. Phase 1's
  assumption holds. **Bonus:** `FidFileManager` exposes `addUserFidFile`, `getUserAddedFiles`,
  `createNewFidDatabase`, and **`openFidQueryService`** — informing both the Phase-1 mechanism (D7)
  and SPIKE-1.
- **SPIKE-1 (blocks Phase 2) — ✅ DONE, PROVEN end-to-end (#150).** The headless custom-`.fidb`
  chain works: `createNewFidDatabase` → `addUserFidFile` → `getFidDB(true)` →
  `createNewLibraryFromPrograms([DomainFile], …)` → `saveDatabase` → `close` → **remove+re-add the
  FidFile** (a file attached while empty caches `canProcessLanguage()==False` → the query skips it) →
  `setActive(true)` → `openFidQueryService` → `processProgram` → matches. Locked as a live-regression
  hard gate (`tests/integration/test_identify_functions_selfmatch.py`, self-match n=7). Phase 2 is
  technically unblocked.
- **SPIKE-2 (blocks copyleft-derived DBs) — ✅ analysis DONE; see
  [`docs/security/fid-database-licensing.md`](../security/fid-database-licensing.md).** A `.fidb`
  (non-reversible hashes + uncopyrightable symbol names + metadata, no code) is **almost certainly
  not a derivative work** (US: *Feist*/Circular-33/*Google v. Oracle*; 25-yr IDA-FLIRT precedent of
  the same "hashes+names, no code" design) — but it is **legally untested for a `.fidb`**.
  **Resolution:** ship a **permissive-only** v1 set (**musl/MIT, OpenSSL 3.0+/Apache-2.0, zlib,
  Boost/BSL-1.0**) — which needs **no hard legal ruling** — with per-DB provenance + SBOM + NOTICE;
  **defer glibc/Qt (LGPL) and GPL/AGPL to counsel** (the escalation questions are in the doc). This
  makes Phase 2 shippable without blocking on a legal determination.

## Consequences

- **Positive:** immediate library identification on MSVC/PE targets in v1.7 with negligible risk;
  the highest-leverage gap-closer for the naming workflow; clean, additive contract; the heavy/risky
  ELF work is isolated behind explicit spikes + legal review instead of blocking the increment.
- **Negative / costs:** Phase 1's value is **Windows-skewed** (ELF — Vivarium's main target — waits
  for Phase 2); the Function ID analyzer adds some analysis time; false-positive/ambiguous matches
  must be communicated honestly (D3) or they mislead the client. Phase 2 carries ongoing build-time
  DB-generation + provenance maintenance and a genuine legal question.

## Alternatives considered

- **Ship third-party prebuilt ELF FID DBs (e.g. threatrack).** *Rejected* — no stated license,
  unaudited provenance; pulling an opaque binary DB into the trusted worker image violates
  `std-supplychain` (pin + provenance + SBOM). We must generate from sources we pin.
- **Runtime/user-supplied FID ingest.** *Rejected* — runtime ingest breaks the read-only analysis
  posture and needs unstripped reference libs the user won't have; also widens the worker surface.
- **Go straight to ELF (skip Phase 1).** *Rejected* — couples the whole feature to two unverified
  blockers (SPIKE-1/2); Phase 1 delivers value now and de-risks the contract independently.
- **Build a custom hashing/signature engine instead of FID.** *Rejected* — reinvents a mature Ghidra
  subsystem; FID is already integrated, processor-aware, and disambiguates via call relations.

## References

- ghidra-data **FunctionID** directory (only VS2012–2019 x86/x64 DBs ship) and **FID.md** (packed,
  unpack-on-first-use) — github.com/NationalSecurityAgency/ghidra-data.
- Ghidra in-tree **fid.xml** (ingest workflow, full/specific hashing, thresholds, Force
  Specific/Relation, multiple-match handling, accuracy limits).
- **FidServiceLibraryIngest.java**, **FidDB.java**, `FidService`/`FidFileManager` (ingest/activation
  API surface) — github.com/NationalSecurityAgency/ghidra.
- Issue **#1847** (custom DBs are not auto-loaded; attach+activate individually).
- **threatrack/ghidra-fidb-repo** (third-party ELF DBs; **no license stated**) — provenance caveat.
- Internal: ADR-001 (worker isolation), ADR-002 (worker lifetime/wipe), ADR-005 (untrusted envelope),
  ADR-012/013 (write gate), ADR-029 (analysis profiles), ADR-035 (analyzer-option existence guard);
  `std-owasp-llm` LLM09 (overreliance), `std-supplychain`.

---
_Open items before ratification → implementation: run SPIKE-0 (Phase 1 enabler); Phase 2 stays
deferred behind SPIKE-1 + SPIKE-2 with its own ADR/ratification._
