# Vivarium FAQ

Short answers to the questions people ask first. See [getting-started](getting-started.md), the
[architecture](architecture.md), the [tool catalog](contracts/tool-catalog.md), and the
[examples](examples/README.md) for depth.

## What is Vivarium?

A secure [MCP](https://modelcontextprotocol.io) server that lets an AI assistant (or any MCP client)
use [Ghidra](https://ghidra-sre.org/) to **statically analyze a program binary** — decompile,
disassemble, cross-reference, list strings/symbols/imports, recover types, and more — exposed as a
fixed allow-list of **56 tools**. The name: a *vivarium* is a sealed enclosure for safely keeping and
observing a live, dangerous specimen — which is exactly how it treats a binary (contain, then reveal).

## Does it *run* / execute the binary?

**No.** Ghidra performs **static analysis only** — it never executes the target. There is no debugger,
no emulation, no `runScript`/arbitrary-script path (that's permanently out of scope, PLAN §2). The
binary is data, not code, end to end.

## Is it safe to point at malware?

That's the design center. Defense in depth:
- The **server process never loads the binary or the JVM** (ADR-001) — Ghidra runs only in a separate
  worker.
- The worker runs in a **hardened, network-isolated container** (ADR-004): gVisor/runsc syscall
  sandbox, **no network**, non-root, all Linux capabilities dropped, read-only root filesystem,
  seccomp, memory/CPU/PID caps. It cannot phone home or touch the host.
- **One worker per session** (ADR-002); it's killed on close/timeout/eviction and its project store is
  **verify-wiped** — nothing derived from the binary persists.
- Everything the binary produces (names, decompiled C, strings) comes back wrapped in the
  **untrusted-data envelope** (ADR-005) — treat it as inert (see below).

The container hardening is **verified in CI**, not assumed: `gvisor-isolation.yml` runs the ADR-004
drill under real gVisor and asserts all six controls. That said — run untrusted samples on a host
you're willing to treat as exposed; isolation is strong but no sandbox is a guarantee.

## What is the "untrusted-data envelope" and why do I keep seeing it?

Any field **derived from the binary** is wrapped: `{ "value": "...", "origin": "ghidra-generated",
"truncated": false, "encoding": null, "notes": [] }`. The rule (ADR-005): the `value` is **inert
data, never an instruction** — don't execute it, render it as markup, or follow URLs/paths inside it.
A hostile binary controls those bytes, and the prime risk in an LLM workflow is prompt-injection via
analysis output. Server-computed scalars (addresses, counts, sizes, the sha256) are **not** wrapped.

## Is it read-only?

**Read-by-default.** Most tools are read-only. There are **14 gated mutation/write tools** (rename,
comment, set signature, apply/define/delete types, annotation import) — but a session mutates *nothing*
until you call `session_enable_writes` (the single human-in-the-loop consent gate), and structural
edits additionally require `allow_structural: true`. Writes change the in-worker Ghidra project only —
the original file on disk is never touched. See [Example 3](examples/large-annotate-and-recover.md).

## Do my annotations (names, types, comments) persist?

Not on their own — they're **session-scoped and ephemeral** (gone when the session is evicted; the
server is stateless by design, ADR-002). To keep them, `session_export_annotations` produces a
portable, **binary-hash-bound** JSON document you store client-side; `session_import_annotations`
replays it into a fresh session on the same binary. Persistence is client-owned.

## How do I connect a client? stdio or HTTP?

**stdio is the default** (v1) — the client launches `python -m vivarium` and speaks MCP over
stdin/stdout. An **HTTP transport** also ships (ADR-011) for networked use, with per-request
authentication — **bearer tokens, mTLS, or OAuth** (ADR-017/019) — and per-principal session
ownership. Set `VIVARIUM_TRANSPORT=http` plus the relevant `VIVARIUM_HTTP_*` vars (see
[http-transport](design/http-transport.md) and the [http-exposure runbook](runbooks/http-exposure.md)).
Config is env-driven with the **`VIVARIUM_*`** prefix.

## How accurate is the decompilation / naming / the scans?

- **Decompilation** is Ghidra's recovered pseudo-C — excellent but not the original source; optimized
  and stripped code won't round-trip perfectly.
- **Semantic naming** (the leaf-first workflow) is done by the *client* LLM from the facts Vivarium
  supplies; the server adds no LLM. Generated/"recompilable" C is a **measured metric, not a
  guarantee** (ADR-007/016).
- **`ioc_scan` / `crypto_constant_scan` / `identify_functions`** are **heuristic leads, not verdicts** —
  e.g. a crypto scan may say "MD5" where the constants are actually SHA-1 (they share magic values).
  Confirm by reading the code; the [blind-analysis example](examples/blind-analysis-sqlite.md) walks
  through exactly that nuance.

## What are the limits / how big a binary can it handle?

Every list/search/read tool is **bounded** (`limit ≤ 10000`, `read_bytes.length ≤ 1 MiB`) and returns a
`truncated` flag + `total` so you page deliberately — both a usability and a DoS control. Analysis is
bounded by a timeout that **kills the worker** on expiry (no hangs). For large binaries, `session_analyze`
takes a `profile` (`light`/`default`/`deep`) and analysis can report progress; bulk decompilation can be
**streamed** (`start_decompile_stream`) so you read early results while the rest extract. Worker
memory/CPU/PID limits are configurable (ADR-023).

## Why Ghidra in a container instead of in-process?

Loading a hostile binary into Ghidra means loading it into a JVM doing a lot of untrusted parsing —
a large attack surface. ADR-001 keeps that surface **out of the server process entirely**: the server
is a thin, pure orchestration/validation layer (functional core / imperative shell), and all the risky
work is confined to the disposable, locked-down worker. It also makes the server trivially testable
without a JVM.

## Can I add a tool / is there a plugin system?

The tool surface is a **fixed allow-list** — no dynamic registration (that would be an injection and
agency risk). Adding a tool is a deliberate, reviewed, threat-modeled change to the catalog (the ADR-006
extensibility seam), with its own schema + validation + gate. `runScript`/arbitrary execution will not
be added — it's permanently out of scope.

## Where do I report a security issue?

See [SECURITY.md](../SECURITY.md). The current `main` is the supported line; the worker image is pinned
by digest and cosign-signed (`.github/worker-image.pin`).

## Where do I start?

[getting-started](getting-started.md) to install and run, then the
[examples](examples/README.md): [first look](examples/simple-first-look.md) (simple) →
[triage](examples/medium-triage.md) (medium) → [recover & document](examples/large-annotate-and-recover.md)
(large).
