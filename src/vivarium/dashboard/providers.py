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
            kind="tool", session_id=session_id, tool="decompile_function", label="FUN_00401000"
        )
        yield SessionEvent(
            kind="output",
            session_id=session_id,
            tool="decompile_function",
            label="decompile FUN_00401000",
            content=UiValue(_DEMO_UNTRUSTED_OUTPUT, untrusted=True),
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
