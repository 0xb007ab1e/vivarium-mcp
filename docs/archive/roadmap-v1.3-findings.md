# v1.3 findings — blind real-world acceptance run (2026-06-15)

> Source of truth for delivery: [`PLAN.md`](../PLAN.md). This document records the findings from a
> **blind real-world end-to-end acceptance run** and proposes the **v1.3 backlog** driven by them.
> Companion artifacts (gitignored, hostile-origin): `/tmp/blind-small-run/`. Harness:
> `scripts/acceptance_run.py` (to be landed via the normal rhythm).

## What was run

A blind end-to-end exercise of the full client workflow against a **stripped binary whose source
was not consulted** during naming:

- **Target 1 — 184 MiB ARM aarch64 ELF:** **could not be analyzed** on this host (see F1). The big
  binary was the original blind target; it surfaced the most important finding before any naming.
- **Target 2 — `/bin/gzip` 1.13-1, x86-64, 100 KB** (sha256 `1fdd0579…`; answer key = GNU gzip 1.13
  source): **completed end-to-end.**

**Pipeline (real hardened worker chain, gated writes):**
import → analyze (290 functions) → call-graph order → **select top-40** by in-edges → per-function
decompile + context dump (**39 ok, 1 `analysis-failed` skipped**) → **4 parallel blind LLM namers**
(decompiled C + context only) → merge → **Mode B apply: 39/39 `rename_function` applied** through the
`session_enable_writes` consent gate.

## Headline result (quality signal)

Blind naming confidence: **25 high / 13 med / 1 low** over 39 functions. Multiple proposals are the
**exact GNU gzip source symbol names** recovered from stripped decompiled code — e.g. `treat_file`,
`inflate_codes`, `display_ratio`, `do_exit`, `flush_window`, `flush_outbuf`, `send_bits`,
`read_gzip_header`, `fill_inbuf`(≈`fill_input_buffer`), `updcrc`(≈`update_crc32`),
`huft_build`(≈`build_huffman_table`), `xmalloc`(≈`xstrdup`). All four independent namers converged on
"gzip/deflate" purely from artifacts (magic `0x8b1f`, CRC tables, inflate window, `.gz` suffixes) —
**no source access**. Full proposed-name table: `/tmp/blind-small-run/names.json` +
`names/batch*.result.json` (address → proposed_name, rationale, confidence).

**Pending:** naming-accuracy score vs. the real gzip 1.13 symbol map (the comparison the binary's
owner reserved). Requires a symbol/debug build of the same gzip to map addresses → ground-truth names.

## Findings → proposed v1.3 backlog (prioritized)

| # | Sev | Finding | Proposed v1.3 fix |
|---|-----|---------|-------------------|
| F1 | **High** | **Worker OOMs on large binaries; worker memory is hardcoded & non-configurable.** Container `--memory 4g`/no-swap (`launcher.py:110`), JVM `MaxRAMPercentage=75 + ExitOnOutOfMemoryError` ≈ 3 GiB heap. The 184 MiB binary OOM-killed the JVM ~18 min into analyze → worker exited → `EOFError: worker closed connection mid-frame` → `worker-unavailable`. | Make worker `mem`/`cpus`/`pids`/`tmpfs` **env+config-configurable** (`GHIDRA_MCP_WORKER_MEM`, …) with safe defaults + a hard ceiling; **map worker OOM/exit to a distinct actionable error** (`worker-oom` / `binary-too-large`) instead of a generic transport drop; document RAM-vs-binary-size guidance. |
| F2 | **High** | **`session_export_annotations` fails with `internal worker error` on a real renamed program** (ADR-018). After 39 renames, the worker `export_annotations` RPC (`_gh_export_annotations` JVM enumeration of `USER_DEFINED` annotations) raises. Blocks the persistence round-trip e2e. | Fix the worker-side annotation enumeration on real programs (reproduce on gzip+renames); add an integration test that exports after a batch of real renames; **surface the worker-side error detail** (see F3). |
| F3 | **Med** | **Internal errors are undiagnosable from logs.** `_RedactingJsonFormatter` never renders `record.exc_info` (it's in `_RESERVED_RECORD_ATTRS`), so `_log.exception()` logs no traceback. Worker method errors collapse to a generic message with the real cause dropped. | Render `self.formatException(record.exc_info)` into a safe `payload["exc"]` (verified it surfaces the cause); also strip/guard **reserved LogRecord keys** in `extra` (passing `extra={"msg":…}` crashes with `KeyError: overwrite 'msg'`); surface a redacted worker-error detail field on method errors. |
| F4 | **Med** | **Long `analyze` can evict its own session.** A single long analyze call doesn't refresh the session idle clock; with defaults (idle 900s/TTL 3600s) a >15-min analyze is evicted on the next call (`session_evicted: expired-on-authorize`). | A long/active tool call must **heartbeat/refresh** the session idle clock (or `analyze` is exempt, or idle scales with `analysis_timeout`). |
| F5 | Low | **Independent namers produce name collisions** (two functions → `build_huffman_table`). A real client needs client-side **dedup/disambiguation** before apply. | Document the pattern; optionally a helper in the workflow/tooling to detect+disambiguate proposed-name collisions. |
| F6 | Low | **Harness:** a single per-function `analysis-failed` aborted the whole run (now fixed in `acceptance_run.py` to record-and-continue). | Land the resilient harness (record-and-continue + per-step envelope checks) via the normal rhythm. |

## Coverage gaps observed
- No automated **large-binary** path tested in CI (the 4 GiB cap was never exercised against a binary
  that needs more) — F1 went unnoticed until a real 184 MiB input.
- ADR-018 **export** lacked an integration test against a **real, renamed** program (only synthetic
  fixtures) — F2 hid behind that gap.
- Internal/worker error **observability** is untested for "can an operator find the cause?" — F3.

## Correct, working behavior confirmed (not regressions)
- Hardened worker chain bring-up; analyze on a real program; call-graph selection.
- **Gated write path**: `session_enable_writes` consent + 39/39 `rename_function` applied.
- **Fail-closed** posture held throughout: `GHIDRA_MCP_APPLY_BINARY` sha256 must match the manifest;
  per-session store wiped on every close; the worker died **safely** (no orphan) on OOM; redaction
  never leaked binary content.

## Next step
Score naming accuracy against the gzip 1.13 ground truth (owner-provided source, or a symbol build to
map addresses → names), then promote F1–F6 to ADRs/work items through:
**design ADR → human ratification → implement (isolated worktree) → `sdlc-reviewer` → CI green → gated merge.**
