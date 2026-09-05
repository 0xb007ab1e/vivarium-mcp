"""Pluggable data providers for the dashboard (display-only MVP).

The dashboard reads its data through the :class:`StatusProvider` Protocol so the UI is decoupled
from its source. The MVP ships :class:`DemoProvider` — deterministic synthetic data that exercises
every render path (live progress, an UNTRUSTED decompile output, a verdict, the build snapshot) so
the frontend + the untrusted-render harness can be built and reviewed without a live server.

The next increment implements a live provider over the same interface: ``list_sessions`` from the
MCP ``session_status`` + metrics (ADR-044); ``session_events`` from ``$/progress`` (ADR-030) +
streaming jobs (ADR-040); ``build_snapshot`` from the tool catalog + ``gh``/CI. UI unchanged.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Protocol

from vivarium.dashboard.models import (
    BuildSnapshot,
    GateStatus,
    SessionEvent,
    SessionSummary,
    UiValue,
    sym_ref,
    tag,
)


class StatusProvider(Protocol):
    """The read-only data source the dashboard renders."""

    def list_sessions(self) -> list[SessionSummary]:
        """Return current analysis sessions + their live status (safe scalars)."""
        ...

    def session_events(self, session_id: str) -> AsyncIterator[SessionEvent]:
        """Yield live events for one session (progress / tool / output / verdict) for SSE."""
        ...

    def build_snapshot(self) -> BuildSnapshot:
        """Return the build/deliverable snapshot (catalog, gates, PRs, benchmark)."""
        ...


#: A synthetic, benign decompiled-C excerpt used by the demo to exercise the UNTRUSTED render path.
#: It deliberately CONTAINS markup-looking + injection-shaped characters so a test/reviewer can
#: confirm the browser renders it inert (never as HTML) — it must appear on screen verbatim.
_DEMO_UNTRUSTED_OUTPUT = (
    "void FUN_00401000(void) {\n"
    "  /* attacker-controlled string, rendered INERT: */\n"
    '  puts("<img src=x onerror=alert(1)>");  // never executes in the dashboard\n'
    "  return;\n"
    "}\n"
)


class DemoProvider:
    """Deterministic synthetic provider (MVP). No I/O, clock, or randomness — hermetic + testable.

    Exercises every render path so the frontend and the untrusted-safe harness are buildable and
    reviewable end-to-end before a live provider exists.
    """

    def list_sessions(self) -> list[SessionSummary]:
        """Two demo sessions: one mid-analysis, one ready — all safe scalars."""
        return [
            SessionSummary(
                session_id="demo-analyzing",
                state="analyzing",
                progress_percent=42,
                phase="analyzing",
                binary_sha256="e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9add4",
                tool_count=6,
                last_tool="decompile_function",
                started_at="2026-09-04T00:00:00Z",
            ),
            SessionSummary(
                session_id="demo-ready",
                state="ready",
                progress_percent=100,
                phase="finalizing",
                binary_sha256="c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee689a",
                tool_count=11,
                last_tool="program_fingerprint",
                started_at="2026-09-04T00:00:00Z",
            ),
        ]

    async def session_events(self, session_id: str) -> AsyncIterator[SessionEvent]:
        """Emit a short deterministic event sequence: progress → an UNTRUSTED output → a verdict.

        A tiny inter-event delay makes the SSE stream observably "live" in the browser without any
        wall-clock dependence in tests (tests can drain without waiting on real time meaningfully).
        """
        for pct, phase in (
            (25, "importing"),
            (50, "analyzing"),
            (75, "analyzing"),
            (100, "finalizing"),
        ):
            yield SessionEvent(kind="progress", session_id=session_id, percent=pct, phase=phase)
            await asyncio.sleep(0.05)
        yield SessionEvent(
            kind="metadata",
            session_id=session_id,
            label="binary format",
            data={
                "fields": [
                    {"k": "format", "v": "ELF"},
                    {"k": "arch", "v": "x86:LE:64"},
                    {"k": "bits", "v": 64},
                    {"k": "endian", "v": "little"},
                    {"k": "entry", "v": "0x00401000"},
                    {"k": "size", "v": 51200},
                    # program name is binary-derived → tagged untrusted
                    {"k": "program", "v": tag("demo.elf")},
                    {"k": "compiler", "v": tag("GCC: (GNU) 13.2.0")},
                ]
            },
        )
        yield SessionEvent(
            kind="imports",
            session_id=session_id,
            label="imports",
            data={
                "total": 3,
                "truncated": False,
                "items": [
                    {
                        "id": "0x00402000",
                        "address": "0x00402000",
                        "name": tag("puts"),
                        "library": tag("libc.so.6"),
                        "referenced_by": [sym_ref("0x00401000", "main")],
                    },
                    {
                        "id": "0x00402008",
                        "address": "0x00402008",
                        "name": tag("system"),
                        "library": tag("libc.so.6"),
                        "referenced_by": [sym_ref("0x00401100", "FUN_00401100")],
                    },
                    {
                        "id": "0x00402010",
                        "address": "0x00402010",
                        "name": tag("<img src=x onerror=alert(1)>"),
                    },
                ],
            },
        )
        yield SessionEvent(
            kind="exports",
            session_id=session_id,
            label="exports",
            data={
                "total": 1,
                "truncated": False,
                "items": [{"address": "0x00401000", "name": tag("entry")}],
            },
        )
        yield SessionEvent(
            kind="strings",
            session_id=session_id,
            label="strings",
            data={
                "total": 2,
                "truncated": False,
                "items": [
                    {
                        "id": "0x00403000",
                        "address": "0x00403000",
                        "length": 13,
                        "value": tag("hello, world"),
                        "referenced_by": [sym_ref("0x00401000", "main")],
                    },
                    {
                        "id": "0x00403010",
                        "address": "0x00403010",
                        "length": 30,
                        "value": tag("</pre><script>alert(1)</script>"),
                        "referenced_by": [sym_ref("0x00401100", "FUN_00401100")],
                    },
                ],
            },
        )
        yield SessionEvent(
            kind="callgraph",
            session_id=session_id,
            label="call graph",
            data={
                "truncated": False,
                "nodes": [
                    {"id": "0x00401000", "label": tag("main")},
                    {"id": "0x00401100", "label": tag("FUN_00401100")},
                    {"id": "0x00402000", "label": tag("puts")},
                ],
                "edges": [
                    {"from": "0x00401000", "to": "0x00401100"},
                    {"from": "0x00401000", "to": "0x00402000"},
                    {"from": "0x00401100", "to": "0x00402000"},
                ],
            },
        )
        # --- functions: streamed as STUBS first (name + callers/callees), then hydrated with
        # decompile/variables/xrefs by a later event with the same id (progressive hydrate). ---
        yield SessionEvent(
            kind="function",
            session_id=session_id,
            label="main",
            data={
                "id": "0x00401000",
                "name": tag("main"),
                "callers": [sym_ref("0x00401200", "entry")],
                "callees": [sym_ref("0x00401100", "FUN_00401100"), sym_ref("0x00402000", "puts")],
                "provenance": {"tool": "call_graph", "address": "0x00401000"},
            },
        )
        yield SessionEvent(
            kind="function",
            session_id=session_id,
            label="FUN_00401100",
            data={
                "id": "0x00401100",
                "name": tag("FUN_00401100"),
                "callers": [sym_ref("0x00401000", "main")],
                "callees": [sym_ref("0x00402008", "system")],
                "provenance": {"tool": "call_graph", "address": "0x00401100"},
            },
        )
        await asyncio.sleep(0.05)
        yield SessionEvent(
            kind="tool", session_id=session_id, tool="decompile_function", label="main"
        )
        # hydrate main with decompiled C + variables + xrefs (same id → merged in the browser)
        yield SessionEvent(
            kind="function",
            session_id=session_id,
            label="main",
            data={
                "id": "0x00401000",
                "signature": tag("int main(int argc, char **argv)"),
                "decompile": tag(_DEMO_UNTRUSTED_OUTPUT),
                "variables": [
                    {"name": tag("argc"), "type": tag("int"), "kind": "param", "storage": "EDI"},
                    {
                        "name": tag("argv"),
                        "type": tag("char **"),
                        "kind": "param",
                        "storage": "RSI",
                    },
                ],
                "xrefs": [
                    sym_ref("0x00403000", "hello, world", kind="string", at="0x00401040"),
                    sym_ref("0x00402000", "puts", kind="import", at="0x00401048"),
                ],
                "provenance": {"tool": "function_context", "address": "0x00401000"},
            },
        )
        # AI-annotation proposals (apply-transform, propose-first). The agent proposes; the UI
        # reviews (diff) + approves; applying is a GATED write (write-consent), never auto here.
        yield SessionEvent(
            kind="annotations",
            session_id=session_id,
            label="AI annotation proposals",
            data={
                "id": "prop-1",
                "function_id": "0x00401000",
                "items": [
                    {
                        "kind": "rename",
                        "target": sym_ref("0x00401100", "FUN_00401100"),
                        "current": tag("FUN_00401100"),
                        "proposed": tag("parse_args"),
                        "rationale": tag("reads argv, dispatches on option chars (getopt-like)"),
                    },
                    {
                        "kind": "comment",
                        "target": sym_ref("0x00401000", "main"),
                        "current": tag(""),
                        "proposed": tag("entry: setup locale + parse args + dispatch"),
                        "rationale": tag("summarizes the observed prologue behavior"),
                    },
                ],
            },
        )
        # a workflow run tracker (agent-executed; the UI shows the step progress)
        yield SessionEvent(
            kind="workflow",
            session_id=session_id,
            label="Triage / overview",
            data={
                "id": "run-1",
                "name": "Triage / overview",
                "state": "done",
                "steps": [
                    {"op": "session_import", "label": "open binary", "state": "done"},
                    {"op": "session_analyze", "label": "analyze", "state": "done"},
                    {
                        "op": "program_metadata",
                        "label": "binary format",
                        "state": "done",
                        "view": "overview",
                    },
                    {"op": "list_strings", "label": "strings", "state": "done", "view": "strings"},
                    {"op": "ioc_scan", "label": "IOC scan", "state": "done"},
                    {
                        "op": "ai_annotate",
                        "label": "verdict summary",
                        "state": "done",
                        "view": "verdict",
                    },
                ],
            },
        )
        yield SessionEvent(
            kind="verdict",
            session_id=session_id,
            label="analyst verdict",
            content=UiValue(
                "MALICIOUS (loader) — heuristic; validate against source.", untrusted=True
            ),
        )

    def build_snapshot(self) -> BuildSnapshot:
        """A representative build snapshot (the numbers from this project's current state)."""
        return BuildSnapshot(
            tool_count=78,
            read_only_count=62,
            gates=[
                GateStatus("quality", "pass"),
                GateStatus("sast", "pass"),
                GateStatus("sca", "pass"),
                GateStatus("secret-scan", "pass"),
                GateStatus("live-regression", "pass"),
            ],
            recent_prs=[
                "#316 seed family_match corpus (ADR-073 D3)",
                "#315 bump worker-image trust pin",
                "#313 crypto_detect instruction source",
            ],
            benchmark={
                "cases": 4,
                "verdict_hits": 4,
                "families": ["Kelihos", "Wirenet", "LuckyCat", "BumbleBee"],
            },
        )
