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

from typing import Any, Protocol

from vivarium.dashboard.commands import evaluate


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
