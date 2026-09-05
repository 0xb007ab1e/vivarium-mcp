"""Interactive executor core (Phase 2 — ADR-076 / threat-model TB9).

Security-critical core of the interactive backend, kept **pure + transport-agnostic** so the
controls are exhaustively testable. A :class:`ToolCaller` is the (injected) transport to the
vivarium MCP server; the concrete transport (an MCP stdio client to a running server) is wired by
the operator when interactive is enabled — this module never spawns a worker or parses a binary.

Defense in depth (TB9): the endpoint already gates commands (only ``allow`` read-only decisions
reach an executor; gated ops → 202), but :class:`ReadOnlyExecutor` **re-evaluates** every command
and refuses anything that is not a read-only ``allow`` — so a wiring mistake can never turn it
into a write path. Writes (rename/comment/type/`ai_annotate`) are NEVER executed here; they go
through the gated, human-approved write-consent path (ADR-012), propose-first for AI annotation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol

from vivarium.dashboard.commands import evaluate
from vivarium.dashboard.state import _read_state


class ToolCaller(Protocol):
    """Transport to the vivarium MCP server for a single read-only tool call (raises on error)."""

    def call(self, op: str, params: dict[str, Any], /) -> dict[str, Any]:
        """Invoke ``op`` with ``params`` on the server and return its JSON-safe result."""
        ...


class ReadOnlyExecutor:
    """A :class:`~vivarium.dashboard.commands.CommandExecutor` that forwards ONLY read-only ops.

    Re-checks the gating policy for every command (defense in depth) and forwards an ``allow`` to
    injected :class:`ToolCaller`; any gated/unknown op raises :class:`PermissionError` (the endpoint
    collapses that to a safe 500 — never a write). The result is returned as-is (the server already
    wraps binary-derived fields in the untrusted envelope; the browser renders them inert).
    """

    def __init__(self, catalog: dict[str, Any], tool_caller: ToolCaller) -> None:
        """Bind the executor to the served ``catalog`` (policy source) + the server transport."""
        self._catalog = catalog
        self._caller = tool_caller

    def __call__(self, command: dict[str, Any]) -> dict[str, Any]:
        """Forward a read-only command; refuse anything not an ``allow`` (fail closed)."""
        verdict = evaluate(self._catalog, command)
        if verdict["decision"] != "allow":
            # Never execute a gated/unknown op here — writes only via the gated write-consent path.
            raise PermissionError(f"executor refuses non-read-only op: {verdict['op']!r}")
        # an ``allow`` verdict guarantees op is a known read-only tool with dict (or absent) params.
        op = str(command["op"])
        params = command.get("params") or {}
        return self._caller.call(op, params)


class StateFileToolCaller:
    """A safe :class:`ToolCaller` that answers READ-ONLY ops from the live state file.

    This is the first *enabled* transport: it serves read-only queries (metadata / listings / call
    graph / per-function callers-callees-decompile) from the artifacts already streamed into the
    dashboard's state file — the same confidential data the read-only API already serves. It spawns
    NO worker and parses NO binary (ADR-001 preserved), so enabling it adds no hostile-execution
    surface. Ops it cannot answer from the store return ``{"unavailable": op}`` (the agent/worker
    transport is required for fresh analysis); writes never reach here (the executor refuses them).
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        """Bind to the dashboard state-file ``path`` (re-read per call — always current)."""
        self._path = path

    def _store(self) -> dict[str, dict[str, Any]]:
        """Reconstruct per-session artifacts from the state file's event log."""
        data = _read_state(Path(self._path))
        out: dict[str, dict[str, Any]] = {}
        for sid, events in data.get("events", {}).items():
            s = out.setdefault(sid, {"functions": {}})
            for e in events:
                kind = e.get("kind")
                d = e.get("data")
                if kind in ("metadata", "imports", "exports", "strings", "callgraph") and d:
                    s[kind] = d
                elif kind == "function" and d and d.get("id"):
                    fn = s["functions"].setdefault(d["id"], {})
                    fn.update(d)
        return out

    def call(self, op: str, params: dict[str, Any], /) -> dict[str, Any]:
        """Answer a read-only op from the reconstructed store (safe scalars + tagged leaves)."""
        store = self._store()
        sid = params.get("session_id") or (next(iter(store), None))
        s = store.get(sid, {"functions": {}}) if sid else {"functions": {}}
        if op in ("list_strings", "list_imports", "list_exports"):
            key = {"list_strings": "strings", "list_imports": "imports", "list_exports": "exports"}[
                op
            ]
            return s.get(key) or {"items": [], "total": 0}
        if op == "program_metadata":
            return s.get("metadata") or {}
        if op == "call_graph":
            return s.get("callgraph") or {"nodes": [], "edges": []}
        if op == "list_functions":
            return {
                "functions": [{"id": i, "name": f.get("name")} for i, f in s["functions"].items()]
            }
        if op in ("callers", "callees", "function_context", "decompile_function"):
            fn = s["functions"].get(params.get("function"))
            if not fn:
                return {"unavailable": op}
            if op == "callers":
                return {"callers": fn.get("callers", [])}
            if op == "callees":
                return {"callees": fn.get("callees", [])}
            if op == "decompile_function":
                return {"decompile": fn.get("decompile")}
            return dict(fn)  # function_context
        return {"unavailable": op}
