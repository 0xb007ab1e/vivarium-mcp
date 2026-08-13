# ADR-072: Firmware-aware secret / credential / key-material scan (read-only)

- **Status:** **Proposed** (awaiting human ratification; v1.9). Item 9 (last) of the post-v1.8
  capability-gap batch (ADR-064..072).
- **Date:** 2026-08-13
- **Deciders:** Human operator (ratification pending); drafted by the assistant from the post-v1.8
  capability-gap survey (the firmware-secrets item).
- **Context source:** Vivarium already ships `crypto_constant_scan` (crypto S-box / round-constant /
  IV signatures — ADR-008) and `ioc_scan` (network/host IOCs in strings — ADR-008), but **nothing
  targeting embedded-firmware SECRETS**. The real T19 firmware RE found the BLE session token stored
  under a property named `WIFI_PWD` plus hardcoded command-gate strings — a scanner keyed to such
  patterns would have surfaced them mechanically instead of by hand-tracing.

## Context

Firmware images routinely embed **credential-grade secrets in the binary itself**: hardcoded
passwords/keys/tokens, PEM/DER certificate and private-key material, bootloader/format magic, and
property-store keys whose *names* betray a secret (`WIFI_PWD`, `*_KEY`, `*_TOKEN`, `admin_pass`).
`crypto_constant_scan` finds *algorithm* constants and `ioc_scan` finds *indicators*, but neither
answers "is a usable secret baked into this image?" — the highest-signal question for firmware triage
(CWE-798 hardcoded credentials).

This is a **read-only analysis** surface — no new agency, no write, no execution. It is a pure
heuristic pass over facts Ghidra already extracts (strings, defined-data bytes), fitting the Tier-2
reporting layer (ADR-008) and the ADR-001 worker-only boundary: the server never parses the binary;
the scan runs in the worker like the other scanners, over already-extracted bytes/strings.

A **secret-finding scanner is itself a redaction hazard**: naively logging what it finds would leak
the very secret it detected into server logs/telemetry (master §5, CWE-200/532). That constraint
shapes the decision as much as the detection itself.

## Decision

### D1 — `secret_scan`: a curated, read-only firmware-secret pass (the MVP)

Add a read-only Tier-2 tool `secret_scan` (a pure heuristic core over extracted strings + defined
data, mirroring `ioc_scan`/`crypto_constant_scan`). It flags a **curated, high-signal, extensible**
pattern set across four categories:

| Category | What it matches |
|---|---|
| `hardcoded_credential` | password/key/token-like strings (keyword-adjacent literals) and **high-entropy** blobs above a Shannon-entropy threshold + length floor (base64/hex key material). |
| `key_material` | embedded certificate/private-key material: PEM headers (`-----BEGIN … KEY-----`, `CERTIFICATE`), DER/ASN.1 key structures, known key magic. |
| `format_magic` | bootloader/firmware/container format magic (curated signature list) — provenance context for the finding, not a secret itself. |
| `property_secret_name` | property-store / config keys whose **name** implies a secret (`WIFI_PWD`, `*_KEY`, `*_TOKEN`, `admin_pass`, …) — the exact T19 case. |

Each finding: `{address, category, pattern_id, masked_preview, preview_hash, entropy?}`. It reports
**where** and **what kind**, never the raw secret in the tool's own logging path (see D3).

### D2 — Bounded before the worker (DoS)

`max_findings` (and the scanned-string/byte count) are validated + **hard-clamped server-side before
the worker** (CWE-400 / ADR-001 posture, mirroring every other bounded tool). The worker enforces the
same caps and sets `truncated` **honestly** (ADR-005) when a cap is hit — an adversarial image dense
with base64 can never produce an unbounded result set. The per-tool wall-clock (ADR-002) is the
backstop.

### D3 — Redaction is a first-class requirement (master §5 / CWE-200/532)

A secret scanner must not become a secret **leak**:

- **Server logs stay redacted.** Log only `address`, `category`, `pattern_id`, sizes, `preview_hash`,
  and `truncated` — **never** the raw matched value, and never the full `masked_preview`. This is an
  explicit exception-free rule for this tool (redaction-by-default, not opt-in).
- **The client receives the finding wrapped untrusted (ADR-005).** The `masked_preview` (e.g.
  first/last few chars with the middle masked) and a `preview_hash` (salted/truncated digest for
  correlation without disclosure) go to the client inside the untrusted-data envelope — inert data,
  never executed/rendered/followed. The raw secret value is **not** emitted verbatim even to the
  client; a masked preview + hash is sufficient for triage and avoids re-broadcasting live credentials
  through the transport and any downstream LLM context (LLM06 sensitive-information disclosure).

### D4 — Heuristic + read-only, honestly labelled

Like `ioc_scan`/`crypto_constant_scan`, `secret_scan` is **heuristic** — false positives (high-entropy
non-secrets) and false negatives (obfuscated/encrypted secrets) are expected and documented in the
tool description. It is read-only/output-only: no DB mutation, no new agency (ADR-001/LLM08).

### D5 — Contract delta (WS0, atomic)

Additive Tier-2 tool → `docs/contracts/tool-catalog.md` (new row) + `docs/contracts/rpc-protocol.md`
(new worker method). Catalog count +1. Lands **atomically** with the schema per the frozen-contract
mandate (routed through the PM, never edited ad hoc). The alternative of **extending `ioc_scan`** was
considered and rejected in D-alternatives (distinct category, distinct redaction contract → its own
tool).

## Security / threat-model delta

- **Hardcoded credentials (CWE-798):** the target weakness — surfacing baked-in secrets is the value.
- **Info exposure / logs (CWE-200/532, master §5):** the scanner's own output path is the risk;
  redacted server logs + masked/hashed client preview (D3) are the primary mitigations.
- **Untrusted output (ADR-005):** every returned field is binary-derived → envelope-wrapped; matched
  values are hostile-origin data, never instructions.
- **DoS (CWE-400):** caps clamp the finding set + scanned input before and inside the worker.
- **No new agency (ADR-001/LLM08):** read-only, no write, no execution, no script.
- **LLM06 (sensitive info disclosure):** masked-preview-only output keeps live secrets out of
  downstream LLM context by construction.
- **Trust boundary unchanged:** the scan runs at the TB3 worker edge over already-extracted bytes; the
  server never parses the binary.

## Alternatives considered

- **Extend `ioc_scan` with secret patterns** — rejected: secrets are a distinct category with a
  distinct **redaction contract** (IOC values are logged today; secret values must never be). A
  separate tool keeps the redaction rule clean and the false-positive profiles from cross-contaminating
  a summary.
- **A full entropy/ML secret classifier (e.g. trufflehog/gitleaks-style + verifiers)** — rejected for
  v1.9: verification means *using* the credential (outward, gated) and the ruleset breadth is
  research-heavy. A curated high-signal set is the 80% value at a fraction of the risk; the pattern set
  is extensible.
- **Return the raw secret value to the client** — rejected: re-broadcasts live credentials through the
  transport + any LLM context (CWE-200, LLM06). Masked preview + hash is sufficient for triage.
- **Server-side scan over decompiled text** — rejected: violates ADR-001 (server would parse
  binary-derived content at volume); the worker already has the strings/bytes.

## Consequences

- **Positive:** the missing firmware-triage primitive — mechanizes exactly the T19 `WIFI_PWD` /
  command-gate discovery; complements `crypto_constant_scan` (algorithms) and `ioc_scan` (indicators)
  to complete the "what's embedded in this image" trio.
- **Negative / cost:** heuristic → false positives/negatives (documented); a new worker method to
  validate via the gated live-regression; the redaction rule adds a logging-path constraint that must
  be tested, not just asserted.
- **Scope:** SemVer **minor** (additive read-only capability). Secret *verification* and an ML
  classifier = a future ADR if warranted.

## Testing (master §4)

- **Unit:** schema validation (categories enum; `max_findings` clamped server-side; caps enforced;
  unknown category rejected). Entropy threshold + length floor boundary cases.
- **Redaction (critical-path, security):** drive a scan whose input embeds a known fake secret, capture
  the tool's log output, and **assert the raw secret string never appears in any log line** — a
  known-bad fixture proving the redaction guard actually fires (not a green-by-omission negative). Also
  assert the full `masked_preview` is absent from logs.
- **Integration (gated real worker, live-regression):** analyze a micro-binary that embeds a benign
  fake PEM block + a `WIFI_PWD=<fake>` property string + a hardcoded token; assert each is flagged in
  the right category with a masked preview and a stable `preview_hash`; assert `truncated=true` under a
  tiny `max_findings`. Add to the live-regression hard-gate list.
- **Abuse:** a base64-dense / degenerate image must stay bounded (cap honored, `truncated=true`); a
  non-secret high-entropy blob is allowed to false-positive but must never crash or leak; an
  undecodable input fails closed category-safe.

## Rollout

Additive + read-only → no migration. Worker-side change → needs a worker rebuild + `.github/
worker-image.pin` bump (per the worker-change-validation-recipe) before the live gate exercises it.
Contract delta lands atomically (WS0). Merge stays gated.
