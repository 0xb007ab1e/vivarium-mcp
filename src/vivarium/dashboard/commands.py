"""Interactive command validation + gating policy (Phase 2 — ADR-076 / threat-model TB9).

Pure, side-effect-free policy for the interactive command backend. It does NOT execute anything —
it validates a browser-issued command against the served catalog and returns a **decision**:

- ``allow`` — a read-only operation may run (subject to auth + rate limits at the transport).
- ``needs-approval`` — a **gated** operation (import/analyze/close, any write, ``ai_annotate``);
  default-deny, applied only via the human-in-the-loop write-consent path (never auto from the
  browser). AI annotation is propose-first (agent proposes → diff → approved write).
- ``deny`` — unknown op or malformed params (CWE-20); never dispatched.

The endpoint layer (``app.py``) is default-OFF + fail-closed: with no executor wired, every command
returns *disabled* and this policy is not even consulted. Kept pure so it is exhaustively testable
and reusable by the future live wiring.
"""

from __future__ import annotations

from typing import Any, Protocol


class CommandExecutor(Protocol):
    """Executes an ALLOW-decided read-only command. Wired only by the (gated) live integration."""

    def __call__(self, command: dict[str, Any], /) -> dict[str, Any]:
        """Run the command and return a JSON-safe result (binary-derived fields already tagged)."""
        ...


def _op_index(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map op name → its catalog entry (across all op groups)."""
    return {op["op"]: op for grp in catalog.get("op_groups", []) for op in grp.get("ops", [])}


def classify(catalog: dict[str, Any], op: str) -> str:
    """Classify an op as ``read-only`` / ``gated`` / ``unknown`` per the served catalog."""
    entry = _op_index(catalog).get(op)
    if entry is None:
        return "unknown"
    return "gated" if entry.get("gated") else "read-only"


def op_class(catalog: dict[str, Any], op: str) -> str:
    """Finer class: ``read-only`` / ``compute`` / ``write`` / ``unknown``.

    ``write`` mutates the program (rename/comment/type/consent/undo/ai_annotate) — always gated,
    never executed by any dashboard executor (write-consent path only). ``compute`` (import/analyze)
    is gated but may be executed by a worker-backed executor once interactive is enabled.
    """
    entry = _op_index(catalog).get(op)
    if entry is None:
        return "unknown"
    if entry.get("write"):
        return "write"
    if entry.get("gated"):
        return "compute"
    return "read-only"


def decision(kind: str, op: str, reason: str) -> dict[str, Any]:
    """Build a decision record (``allow`` | ``needs-approval`` | ``deny``)."""
    return {"decision": kind, "op": op, "reason": reason}


#: Hard cap on params keys — a browser command is small; a flood is rejected (DoS guard, CWE-400).
_MAX_PARAMS = 32


def evaluate(catalog: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    """Validate a command against the catalog and return a gating decision (pure).

    Never dispatches. ``deny`` for unknown op / malformed params; ``needs-approval`` for a gated op
    (default-deny — human write-consent only); ``allow`` for a read-only op.
    """
    op = command.get("op")
    if not isinstance(op, str) or not op:
        return decision("deny", "", "missing op")
    params = command.get("params", {})
    if not isinstance(params, dict):
        return decision("deny", op, "params must be an object")
    if len(params) > _MAX_PARAMS:
        return decision("deny", op, "too many params")
    kind = classify(catalog, op)
    if kind == "unknown":
        return decision("deny", op, f"unknown op {op!r}")
    if kind == "gated":
        return decision(
            "needs-approval",
            op,
            f"{op} is gated — requires human approval (write-consent); never auto-run from the UI",
        )
    return decision("allow", op, "read-only operation")


#: Sentinel for a request body that failed to parse as JSON (kept out of the auth oracle).
INVALID_JSON = object()


def dispatch(
    catalog: dict[str, Any],
    executor: CommandExecutor | None,
    authed: bool,
    body: Any,
) -> tuple[int, dict[str, Any]]:
    """Decide + (read-only) execute one command; return ``(http_status, payload)`` (fail closed).

    Order is deliberate: **disabled → unauthenticated → parse → validate/gate → execute**, so an
    unauthenticated caller learns nothing beyond "disabled/needs-auth". Gated ops are never executed
    here (202 needs-approval); a read-only op runs via ``executor`` with failures collapsed to a
    500 that leaks no internals.
    """
    if executor is None:
        return 503, {"error": "interactive-disabled"}
    if not authed:
        return 403, {"error": "interactive-requires-auth"}
    if body is INVALID_JSON:
        return 400, {"error": "invalid-json"}
    verdict = evaluate(catalog, body if isinstance(body, dict) else {})
    if verdict["decision"] == "deny":
        return 400, verdict
    if verdict["decision"] == "needs-approval":
        # A COMPUTE op (import/analyze) may run on a worker-capable executor; a WRITE never does.
        if op_class(catalog, verdict["op"]) == "compute" and getattr(
            executor, "supports_compute", False
        ):
            return _run(executor, body, verdict["op"])
        return 202, verdict
    return _run(executor, body, verdict["op"])


def _run(executor: CommandExecutor, body: Any, op: str) -> tuple[int, dict[str, Any]]:
    """Execute an approved command via the executor, collapsing any failure to a safe 500."""
    try:
        result = executor(body)
    except Exception:  # fail closed; never leak internals to the client
        return 500, {"error": "command-failed", "op": op}
    return 200, {"decision": "allow", "op": op, "result": result}
