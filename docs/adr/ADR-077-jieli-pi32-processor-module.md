# ADR-077: Bundle the JieLi pi32 processor module (third-party SLEIGH) into the worker

- **Status:** **Accepted** (ratified by the human operator 2026-10-19). Implements **ask #1 only**
  of #338 (the JieLi processor support); asks #2 (general third-party-module mechanism), #3
  (field-named validation errors), and #4 (queryable supported-language list) are **explicitly
  deferred** at the operator's direction. Code for D1–D4 is implemented (allow-list, threat-model,
  `Containerfile.worker` jieli-sleigh stage, docs) and locally gate-green; the gated worker-image
  **build + repin + real-firmware e2e** (Wave-B) follows.
- **Date:** 2026-10-19
- **Deciders:** Human operator (ratified 2026-10-19); drafted by the assistant.
- **Context source:** GH issue #338 — a JieLi **AC632N** BLE smart-ring firmware (`app.bin`, raw,
  base `0x1E00120`) loads and indexes strings correctly under a placeholder arch, but every
  instruction is garbage: the JieLi core is a **custom 32-bit ISA ("pi32")** with no stock Ghidra
  processor module, and `core/languages.py`'s allow-list has no pi32 `LanguageID`. Only
  strings/data indexing works; `disassemble`/`decompile_function`/`list_functions` are meaningless.

## Context

Zhuhai JieLi (杰理) AC6xxx BLE SoCs (AC632N et al.) run a vendor-proprietary 32-bit core. Stock
Ghidra 12.1.2 ships no SLEIGH module for it, so Vivarium's raw-import path (ADR-045 F1) can load the
bytes but cannot disassemble them. The one community SLEIGH implementation is
**`kagaimiq/ghidra-jieli`** (Apache-2.0), which defines three JieLi variants.

Two structural facts constrain the fix:

1. **ADR-001** forbids the server process from loading the JVM, so the server validates a
   client-supplied `processor` hint against a **static allow-list** (`core/languages.py`) *before*
   the worker is contacted. That list is a **generated mirror of the languages actually installed in
   the pinned worker image** (ADR-045 §D2 drift property: server-list ⊆/= worker-installed, and
   drift is *safe* because the worker re-validates and fails closed). Adding a language therefore
   means adding it in **both** places — the installed Ghidra set (the image) and the allow-list.
2. **Trust Boundary 3** (`Containerfile.worker` header): the worker parses attacker-controlled
   binaries through the Ghidra JVM. A processor module is **code that executes inside TB3** on
   hostile input. A community-authored SLEIGH spec is *less audited* than a stock NSA module, so
   bundling one **widens TB3** and triggers the mandate-§1 "verify third-party code" duty and the
   std-supplychain pinning duty.

### The `kagaimiq/ghidra-jieli` module (vetted facts)

- **License:** Apache-2.0 (permissive; compatible with Vivarium's Apache-2.0 — passes license
  policy). Repo is **dormant** (last commit 2024-02-06).
- **Pin:** commit `b5e60122b6cd3e6b615387035994b8bed0ea1a26`.
- **Form:** **source-only** SLEIGH — `data/languages/*.slaspec` + `*.sinc` + a single `JieLi.ldefs`,
  with a shared `pi32.pspec` / `pi32.cspec`. **No prebuilt `.sla`** → it MUST be compiled with
  Ghidra's own SLEIGH compiler (`support/sleigh`) at image-build time.
- **Languages provided** (all `endian=little`, `size=32`):

  | LanguageID | README maturity | pspec / cspec |
  |---|---|---|
  | `pi32:LE:32:default` | "not complete, but somewhat usable" | pi32.pspec / pi32.cspec |
  | `pi32v2:LE:32:default` | "very early stage" | pi32.pspec / pi32.cspec |
  | `q32s:LE:32:default` | "very early stage" | pi32.pspec / pi32.cspec |

## Decision

### D1 — Bundle the module at build time, compiled, pinned, and checksum-verified

Add a build stage to `Containerfile.worker` that fetches `kagaimiq/ghidra-jieli` **pinned by the
commit SHA above and SHA-256-verified before use** (the same fail-closed source-pin pattern as the
FID stages 4a–4g: a checksum mismatch fails the build), drops `data/languages/` + `Module.manifest`
into a Ghidra extension module under `/opt/ghidra/Ghidra/Processors/JieLi/`, and **compiles every
`.slaspec` with `support/sleigh` during the build** so no `.sla` is produced at runtime (the
read-only rootfs could not write one anyway). A SLEIGH compile error **fails the build** (fail
closed) — if a given variant does not compile under Ghidra 12.1.2's SLEIGH, it is dropped from the
bundle **and** from D2 rather than shipped broken.

### D2 — Add all successfully-compiled JieLi LanguageIDs to the allow-list

Add to `_SUPPORTED_LANGUAGES` (`core/languages.py`), each at **32** address bits:

```
"pi32:LE:32:default": 32,
"pi32v2:LE:32:default": 32,
"q32s:LE:32:default": 32,
```

**All three**, not only the two #338 named: the list is defined as *equal to the installed set*, and
the module installs all three. "Installed = accepted"; the maturity of `pi32v2`/`q32s` is the
client's concern (an immature spec yields poor disassembly, not an unsafe one — see D4). If a
variant is dropped at D1 for failing to compile, it is omitted here too, keeping list == installed.

### D3 — The allow-list is no longer *purely* stock Ghidra; the drift guard must know that

`core/languages.py`'s docstring frames the list as "the FULL set of languages installed in the
pinned worker's Ghidra" with a drift check asserting `list == DefaultLanguageService …
getLanguageDescriptions`. That invariant **still holds** after D1+D2 (the module *is* installed, so
`getLanguageDescriptions` now includes the pi32 ids) — but the list is now **stock + one bundled
third-party module**. Update the docstring to say so, and ensure the drift guard (if/when live)
enumerates the *installed* set (which already includes the bundled module) rather than a hardcoded
"stock-only" expectation. No separate "extra" list is introduced — the single generated mirror
remains the one source of truth.

### D4 — TB3 threat-model entry (mandatory for this change)

Record in `docs/security/threat-model.md` that a **community-authored SLEIGH processor module now
parses hostile firmware inside the JVM worker (TB3)**. Mitigations already in place bound the blast
radius and are unchanged by this ADR: the worker is a disposable, network-isolated, non-root,
read-only-rootfs, all-caps-dropped, gVisor/seccomp-confined fault domain, killed on
timeout/eviction (ADR-002/003/004). A SLEIGH spec is **declarative disassembly data interpreted by
Ghidra's engine**, not native code we link — the attack surface it adds is "malformed instruction
stream drives the SLEIGH interpreter," already the TB3 threat for *every* processor, now over a
less-audited grammar. Residual risk is **Low** given the containment; no new runtime control is
required, but the module is pinned+checksummed (integrity) and its provenance is recorded.

### D5 — Reject the unpinned "mount a processor dir" alternative (the #338 ask-2 answer, deferred-but-noted)

#338 ask #2 floats a *general* mechanism to add third-party modules via a runtime mount/overlay or a
build-arg list of module repos. **Do not** take the runtime-mount route: an unpinned, operator-
mounted `Ghidra/Processors/<x>` is unverified code entering TB3 with no checksum/provenance — a
supply-chain hole (std-supplychain, fail-closed). The sanctioned shape of "general mechanism," if
pursued later, is a **list of pinned+checksummed module sources compiled at build** — i.e. a
parameterization of D1, not a runtime overlay. Ask #2 stays deferred; this ADR implements the
single-module case in exactly that pinned-at-build shape so a future generalization is additive.

## Consequences

**Positive**

- JieLi AC6xxx firmware becomes disassemblable/decompilable:
  `session_import(loader="binary", processor="pi32:LE:32:default", base_addr=0x1E00120)` then
  `disassemble`/`decompile_function` yield real pi32 instructions (the #338 acceptance criterion).
- The pinned-at-build pattern keeps the supply-chain property (checksum-verified, provenance-
  recorded) and leaves a clean seam for a future multi-module generalization (D5).

**Negative / costs**

- Worker image rebuild + **re-pin** of `.github/worker-image.pin` (gated) — the change is invisible
  to e2e until the pinned digest is bumped.
- TB3 surface widens (D4) — accepted at Low residual risk given containment.
- `pi32v2`/`q32s` ship at the module's own "very early" maturity; disassembly quality is not
  Vivarium's to guarantee. Documented, not hidden.

## Alternatives considered

- **Runtime-mounted processor dir (ask #2 literal form).** Rejected — unpinned code into TB3 (D5).
- **Only the two named ids (pi32, pi32v2).** Rejected — breaks the list == installed invariant (the
  module installs q32s too); either install-and-list all three or patch the module to not build
  q32s (needless fork of a dormant upstream). Install all, list all.
- **Vendor-fork the SLEIGH into the repo.** Rejected — carrying a third-party ISA grammar in-tree is
  a maintenance + license-attribution burden the build-time pinned fetch avoids; the NOTICE/
  attribution is handled via the pinned source + provenance.

## Acceptance / testing

- **Build:** the new stage compiles all bundled `.slaspec` with no SLEIGH error (fail-closed).
- **Unit:** `is_supported_language("pi32:LE:32:default")` etc. true; `address_bits` == 32; the
  allow-list parses/sorts; `SessionImportIn(loader="binary", processor="pi32:LE:32:default",
  base_addr=0x1E00120)` validates and an out-of-32-bit `base_addr` is rejected.
- **Drift:** the installed-set guard still passes (installed now includes the pi32 ids).
- **e2e (Wave-B, gated on rebuild+repin):** import the **real decrypted AC632N `app.bin`** (from
  the local `open-ring` RE project — `update.ufw_unpack/files/app.bin`, 279,564 B, entry
  `0x1E00120`, sha256 `dd5dd656…`, chipkey `0x2F1B`; the exact #338 sample) and confirm
  `session_import(loader="binary", processor="pi32:LE:32:default", base_addr=0x1E00120)` →
  `disassemble`/`decompile_function` return non-garbage pi32 instructions over the symboled
  BT/health/OTA routines. The sample is **hostile input** → analyzed only in the ephemeral,
  network-isolated worker container (never on the host). No *public* AC632N image exists (JieLi app
  images are passkey-encrypted); this local decrypted copy is the acceptance corpus.

## References

- GH issue #338. Upstream module: `kagaimiq/ghidra-jieli` @ `b5e6012` (Apache-2.0).
- ADR-001 (server JVM-free), ADR-002/003/004 (worker containment), ADR-045 (raw import + §D2
  language-set drift property). `core/languages.py`, `Containerfile.worker` (FID source-pin
  stages), `docs/security/threat-model.md` (TB3).
