"""File-backed live state bridge for the dashboard.

The MVP :class:`~vivarium.dashboard.providers.DemoProvider` serves synthetic data. This module adds
the first LIVE path without coupling the dashboard process to the MCP server: a plain JSON **state
file** is the channel. A producer (an operator driving a real analysis through the vivarium MCP
tools) writes session summaries + events + the build snapshot into the file via :class:`Dashboard
State`; the dashboard reads them through :class:`FileStatusProvider` and tails the file for SSE.

Security note: the file is trusted-origin *structurally* (the operator writes it), but any
binary-derived text placed in an event ``content`` is STILL tagged ``untrusted`` and flows through
the same inert-render path (ADR-005) — the bridge never downgrades the envelope. The state file is a
LOCAL dev artifact (loopback/tailnet only, like the dashboard itself); it holds no secret.

Schema (``dict``)::

    {
      "sessions": [ <SessionSummary.json()>, ... ],
      "events":   { "<session_id>": [ <SessionEvent.json()>, ... ] },
      "build":    <BuildSnapshot.json()> | null
    }
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from vivarium.dashboard.models import (
    BuildSnapshot,
    GateStatus,
    SessionEvent,
    SessionSummary,
    UiValue,
)

#: Poll interval (seconds) for tailing the state file in :meth:`FileStatusProvider.session_events`.
_TAIL_INTERVAL_S = 0.5

#: Idle polls with no new event (and no terminal event) after which the SSE tail gives up — bounds
#: an orphaned stream so a browser tab left open cannot hold the file handle forever.
_TAIL_MAX_IDLE = 600  # 600 * 0.5s = 5 min of quiet before the stream closes


def _empty_state() -> dict[str, Any]:
    """Return a fresh, empty state document."""
    return {"sessions": [], "events": {}, "build": None}


def _read_state(path: Path) -> dict[str, Any]:
    """Read + parse the state file, returning an empty document if it is missing or unparseable.

    Fail-soft on read: a partially-written or absent file yields the empty state rather than
    raising, so the dashboard degrades to "nothing yet" instead of erroring mid-stream.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return _empty_state()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _empty_state()
    if not isinstance(data, dict):
        return _empty_state()
    data.setdefault("sessions", [])
    data.setdefault("events", {})
    data.setdefault("build", None)
    return data


def _event_from_json(payload: dict[str, Any]) -> SessionEvent:
    """Reconstruct a :class:`SessionEvent` from its serialized form (rewrapping untrusted)."""
    content = payload.get("content")
    ui = UiValue(str(content["value"]), bool(content["untrusted"])) if content else None
    return SessionEvent(
        kind=str(payload["kind"]),
        session_id=str(payload["session_id"]),
        percent=payload.get("percent"),
        phase=payload.get("phase"),
        tool=payload.get("tool"),
        label=payload.get("label"),
        content=ui,
    )


class FileStatusProvider:
    """A :class:`~vivarium.dashboard.providers.StatusProvider` backed by a JSON state file.

    Reads are snapshot-in-time; :meth:`session_events` tails the file so events appended by the
    producer stream to the browser live.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        """Bind the provider to the state-file ``path`` (read on every call — no caching)."""
        self._path = Path(path)

    def list_sessions(self) -> list[SessionSummary]:
        """Return the current session summaries from the state file (safe scalars)."""
        state = _read_state(self._path)
        return [SessionSummary(**s) for s in state["sessions"]]

    def build_snapshot(self) -> BuildSnapshot:
        """Return the build snapshot from the state file (empty if none has been written yet)."""
        state = _read_state(self._path)
        raw = state.get("build")
        if not raw:
            return BuildSnapshot(tool_count=0, read_only_count=0)
        gates = [GateStatus(g["name"], g["status"]) for g in raw.get("gates", [])]
        return BuildSnapshot(
            tool_count=int(raw.get("tool_count", 0)),
            read_only_count=int(raw.get("read_only_count", 0)),
            gates=gates,
            recent_prs=list(raw.get("recent_prs", [])),
            benchmark=dict(raw.get("benchmark", {})),
        )

    async def session_events(self, session_id: str) -> AsyncIterator[SessionEvent]:
        """Tail the state file, yielding this session's events as the producer appends them.

        Replays any events already present, then polls for new ones. Stops after a terminal
        ``verdict`` event, or after :data:`_TAIL_MAX_IDLE` quiet polls (bounded resource use).
        """
        cursor = 0
        idle = 0
        while idle < _TAIL_MAX_IDLE:
            events = _read_state(self._path)["events"].get(session_id, [])
            if cursor < len(events):
                idle = 0
                for payload in events[cursor:]:
                    event = _event_from_json(payload)
                    yield event
                    if event.kind == "verdict":
                        return
                cursor = len(events)
            else:
                idle += 1
            await asyncio.sleep(_TAIL_INTERVAL_S)


class DashboardState:
    """Producer-side writer for the dashboard state file (atomic replace on every save).

    An operator constructs this alongside a real analysis run and calls :meth:`upsert_session` /
    :meth:`append_event` / :meth:`set_build` as tool results arrive; each mutation persists the
    whole document atomically so a concurrent :class:`FileStatusProvider` read never sees a torn
    file.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        """Bind to ``path`` and load any existing state (fresh document if absent)."""
        self._path = Path(path)
        self._state = _read_state(self._path)

    def upsert_session(self, summary: SessionSummary) -> None:
        """Insert or replace a session summary (keyed by ``session_id``) and persist."""
        rows = [s for s in self._state["sessions"] if s.get("session_id") != summary.session_id]
        rows.append(summary.json())
        self._state["sessions"] = rows
        self._save()

    def append_event(self, event: SessionEvent) -> None:
        """Append one event to its session's event list and persist."""
        bucket = self._state["events"].setdefault(event.session_id, [])
        bucket.append(event.json())
        self._save()

    def set_build(self, snapshot: BuildSnapshot) -> None:
        """Set the build snapshot and persist."""
        self._state["build"] = snapshot.json()
        self._save()

    def _save(self) -> None:
        """Write the state document atomically (temp file in the same dir, then ``os.replace``)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._state, handle)
            Path(tmp).replace(self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
