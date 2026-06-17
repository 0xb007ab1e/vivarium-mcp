#!/usr/bin/env python3
"""Real-chain, progress-reporting acceptance-run harness for ghidra-mcp (dogfooding gap-finder).

A CLI driver that runs the *actual* analysis + (optional) naming workflow against an arbitrary
(possibly blind, possibly hostile) binary through the real, hardened worker chain, and dumps
artifacts for a post-hoc source comparison. This is an **acceptance / dogfooding tool**, NOT a unit
feature: it is glue + progress + artifact I/O over the existing server, session manager, adapter,
launcher, and pure naming core — it adds **no** new analysis logic.

Containment is the EXISTING worker isolation (ADR-001/002/004): the driver runs only server-side
code (it never loads the JVM or parses the binary itself); the out-of-process, network-isolated,
resource-bounded worker container does all binary parsing, and is killed + its store wiped on
session close. The driver brings the chain up exactly as the gated e2e suite does — it launches the
real MCP server (``python -m ghidra_mcp``) over the **stdio** transport and drives it as an MCP
client, so the full composition root (FastMCP app → ``RpcGhidraAdapter`` → hardened worker) is what
runs. FAIL CLOSED with a clear message if the worker image / container engine is unavailable.

Two modes:

* **analyze** — bring up one ephemeral session, import → analyze → list → leaf-first
  ``analysis_order`` → select the top-N non-external functions → per-function ``decompile_function``
  + ``function_context`` + referenced strings, writing one JSON per function plus a manifest and a
  names-template the (out-of-band) naming pass fills in.
* **apply** — read a filled names map (addr → proposed_name [+ optional proposed_c]), apply the
  renames via the gated write path (enable writes → ``rename_function``), export the resulting
  annotations, and — with ``--measure`` and a buildable trusted reference — compute the ADR-016
  behavioral-equivalence + name-coverage metrics into ``metrics.json``.

Progress is a first-class requirement: every phase prints ``step i/M: <desc>`` and every
per-function step prints ``function i/N: <addr>`` to **stderr** and to ``<out>/run.log``. A final
machine-readable ``<out>/summary.json`` records counts + per-phase timings.

Redaction (master §5, project rule): binary-derived content (decompiled C, strings, names) IS the
analysis output and is written to the (git-ignored) out dir — but it is NEVER echoed to normal
stdout/stderr; only safe scalars (addresses, counts, durations, outcomes) reach the progress log.

The out dir defaults under ``/tmp`` (git-ignored); binary samples are never written into the repo.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime
import hashlib
import json
import os
import shutil
import sys
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The driver runs SERVER-SIDE code only (ADR-001): the pure naming core + frozen schemas. The worker
# (spawned by the server it launches as a subprocess) is the sole thing that parses the binary.
from ghidra_mcp.naming.loop import ProposedName, orchestrate
from ghidra_mcp.naming.metrics import score
from ghidra_mcp.tools.schemas import AnalysisOrderOut, FunctionContext

#: Default cap on functions selected/named in one pass (DoS / cost bound — a hostile or huge binary
#: must not drive an unbounded loop; honestly surfaced as "selected N of total" in the summary).
_DEFAULT_CAP = 40

#: Default per-tool MCP client read timeout (seconds) for the long phases (import/analyze). Generous
#: so JVM boot + Ghidra auto-analysis on a real binary completes; the worker enforces its OWN hard
#: wall-clock + memory bounds and is killed on expiry (ADR-002) regardless of this client-side wait.
_DEFAULT_TOOL_TIMEOUT_S = 600

#: Truthy tokens for the integration gate (mirrors the e2e/integration conftests).
_TRUTHY = {"1", "true", "yes", "on"}


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (artifact timestamps are UTC — §i18n)."""
    return datetime.datetime.now(datetime.UTC).isoformat()


def _truthy(value: str | None) -> bool:
    """Return whether an environment flag is set to a truthy token."""
    return (value or "").strip().lower() in _TRUTHY


class HarnessError(RuntimeError):
    """A fail-closed harness error with a safe, operator-facing message (no host/binary detail)."""


# =====================================================================================
# Progress reporting (first-class requirement) — stderr + <out>/run.log, safe scalars only.
# =====================================================================================
@dataclass(slots=True)
class ProgressLog:
    """Append-only progress sink that mirrors safe scalar lines to stderr AND ``<out>/run.log``.

    Only safe values (addresses, counts, durations, phase descriptions, outcomes) are ever written
    — never binary-derived content (decompiled C, strings, names): those go only to the artifact
    files in the out dir (master §5 redaction, project logging rule).

    Attributes:
        log_path: The ``<out>/run.log`` file path the lines are appended to.
        _handle: The open append handle (line-buffered).
    """

    log_path: Path
    _handle: Any = field(default=None, init=False, repr=False)

    def open(self) -> None:
        """Open the run-log file for appending (line-buffered) — call before any :meth:`emit`."""
        self._handle = self.log_path.open("a", encoding="utf-8", buffering=1)

    def emit(self, line: str) -> None:
        """Write one safe progress line to stderr and the run log (timestamped in the file).

        Args:
            line: A safe, scalar-only progress message (no binary-derived content).
        """
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
        if self._handle is not None:
            self._handle.write(f"{_utc_now_iso()} {line}\n")

    def step(self, index: int, total: int, description: str) -> None:
        """Emit a phase-level ``step i/M: <desc>`` line.

        Args:
            index: 1-based phase index.
            total: Total number of phases.
            description: Safe, scalar-only phase description.
        """
        self.emit(f"step {index}/{total}: {description}")

    def function(self, index: int, total: int, address: str) -> None:
        """Emit a per-function ``function i/N: <addr>`` line (the address is safe).

        Args:
            index: 1-based function index.
            total: Total selected functions.
            address: The function entry address (hex) — a safe, server-normalized scalar.
        """
        self.emit(f"function {index}/{total}: {address}")

    def close(self) -> None:
        """Flush and close the run-log handle (idempotent)."""
        if self._handle is not None:
            self._handle.flush()
            self._handle.close()
            self._handle = None


# =====================================================================================
# MCP stdio chain bring-up — drive the REAL server as a client (the e2e pattern).
# =====================================================================================
def _preflight(import_root: Path) -> None:
    """Fail closed (clear message) if the real worker chain cannot be brought up.

    Checks the gated prerequisites the server's adapter needs to actually spawn a worker: the
    integration opt-in, a pinned worker image, and a container engine on PATH. The image pull /
    container run are GATED actions (PLAN §6); this driver only RUNS what is already provisioned and
    refuses to proceed (rather than silently "succeeding" against no worker) otherwise.

    Args:
        import_root: The resolved directory the binary lives under (the server's import root).

    Raises:
        HarnessError: If any prerequisite for the real chain is missing.
    """
    if not _truthy(os.environ.get("GHIDRA_MCP_INTEGRATION")):
        raise HarnessError(
            "GHIDRA_MCP_INTEGRATION is not set — this harness runs the REAL hardened worker "
            "(a gated image pull + container run). Set GHIDRA_MCP_INTEGRATION=1 and provide a "
            "pinned GHIDRA_MCP_WORKER_IMAGE to run it."
        )
    if not os.environ.get("GHIDRA_MCP_WORKER_IMAGE", "").strip():
        raise HarnessError(
            "GHIDRA_MCP_WORKER_IMAGE is not set — a pinned-by-digest worker image is required "
            "(e.g. localhost/ghidra-mcp-worker:dev for local validation)."
        )
    engine = os.environ.get("GHIDRA_MCP_CONTAINER_ENGINE", "podman").strip() or "podman"
    if shutil.which(engine) is None:
        raise HarnessError(
            f"container engine {engine!r} not found on PATH (set GHIDRA_MCP_CONTAINER_ENGINE)."
        )
    if not import_root.is_dir():
        raise HarnessError(f"import root {import_root} is not a directory")


@contextlib.asynccontextmanager
async def _mcp_session(import_root: Path) -> Any:
    """Launch the real MCP stdio server and yield an initialized client session.

    Brings the chain up exactly as the gated e2e suite does: spawns ``python -m ghidra_mcp`` (the
    composition root → real ``RpcGhidraAdapter`` → hardened worker container) over stdio with the
    import root pointed at the binary's directory, and hands back an initialized
    :class:`mcp.ClientSession`. The current environment is inherited so the operator's pinned
    ``GHIDRA_MCP_WORKER_IMAGE`` / engine / runtime config reaches the adapter.

    Args:
        import_root: Directory (read-only mounted into the worker) the binary must live under.

    Yields:
        An initialized MCP ``ClientSession`` bound to the live server.
    """
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ghidra_mcp"],
        env={**os.environ, "GHIDRA_MCP_IMPORT_ROOT": str(import_root)},
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured JSON output from an MCP ``CallToolResult`` (fail closed).

    Args:
        result: The MCP ``CallToolResult``.

    Returns:
        The tool's structured output dict.

    Raises:
        HarnessError: If the tool returned an error envelope or no structured content (fail closed —
            the error envelope is leak-free by contract, so its presence alone is the signal). The
            envelope can arrive either as ``isError`` OR as a structured ``{type, title,
            retryable}`` payload (FastMCP serializes a returned error model into
            ``structuredContent``), so both shapes are detected — never silently treated as success.
    """
    if getattr(result, "isError", False):
        raise HarnessError("tool returned an error envelope (see server logs for the safe detail)")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        _raise_if_error_envelope(structured)
        return structured
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parsed: dict[str, Any] = json.loads(text)
            _raise_if_error_envelope(parsed)
            return parsed
    raise HarnessError("tool result carried no structured content")


def _raise_if_error_envelope(payload: dict[str, Any]) -> None:
    """Fail closed when ``payload`` is the frozen error envelope rather than a tool result.

    The error envelope (``docs/contracts/error-envelope.md``) has the discriminating keys
    ``type`` + ``title`` + ``retryable`` + ``status``; a successful tool result never carries that
    set. Detecting it surfaces a ``worker-unavailable`` / ``analysis-failed`` / ``session-invalid``
    outcome as a clear harness failure (with the safe machine ``type``) instead of mistaking it for
    empty/zero data.

    Args:
        payload: A structured tool-result dict.

    Raises:
        HarnessError: If ``payload`` matches the error-envelope shape.
    """
    if {"type", "title", "retryable"} <= payload.keys() and "status" in payload:
        raise HarnessError(f"tool returned error envelope: {payload.get('type')!r}")


def _read_timeout(seconds: int) -> Any:
    """Build the MCP client per-call read timeout (a ``datetime.timedelta``)."""
    return datetime.timedelta(seconds=seconds)


# =====================================================================================
# Untrusted-envelope unwrap (artifact I/O only) — the value is inert data, never executed.
# =====================================================================================
def _unwrap(field_value: Any) -> Any:
    """Unwrap an ``Untrusted[...]`` envelope to its inert payload for artifact serialization.

    Binary-derived fields arrive as ``{"value": ..., "origin": ..., ...}`` (ADR-005). The harness
    writes the inert ``value`` (plus, when present, the truncation/notes provenance) into the
    artifact files for the post-hoc source comparison. The value is **only** serialized to a file —
    never executed, evaluated, rendered, or logged to the console.

    Args:
        field_value: A serialized envelope dict, a plain scalar, or ``None``.

    Returns:
        The inert payload (``value`` when an envelope, else the input unchanged).
    """
    if isinstance(field_value, dict) and "value" in field_value and "origin" in field_value:
        return field_value["value"]
    return field_value


# =====================================================================================
# Mode A — analyze: import → analyze → order → select → per-function context → artifacts.
# =====================================================================================
@dataclass(frozen=True, slots=True)
class _Selected:
    """One selected function with the safe scalar fields used for ranking + the manifest.

    Attributes:
        address: Entry address (hex) — safe.
        name: Current (untrusted-derived) name VALUE — written only to artifacts, never logged.
        size: Byte size — safe (server-computed).
        xref_count: Number of callers (xref proxy) — safe; the primary ranking key.
    """

    address: str
    name: str
    size: int
    xref_count: int


def _select_top_n(
    functions: list[dict[str, Any]],
    callers_by_addr: Mapping[str, int],
    externals: frozenset[str],
    cap: int,
) -> list[_Selected]:
    """Rank non-external functions by (xref count, size) and take the top ``cap``.

    Args:
        functions: ``list_functions`` rows (``{address, name(envelope), size}``).
        callers_by_addr: Map of address → caller count (the xref proxy from the call graph).
        externals: Addresses flagged external/imported (excluded — known names, not named).
        cap: Maximum number of functions to select.

    Returns:
        The selected functions, highest-ranked first, capped at ``cap``.
    """
    candidates: list[_Selected] = []
    for row in functions:
        address = row["address"]
        if address in externals:
            continue
        candidates.append(
            _Selected(
                address=address,
                name=str(_unwrap(row.get("name", ""))),
                size=int(row.get("size", 0)),
                xref_count=callers_by_addr.get(address, 0),
            )
        )
    candidates.sort(key=lambda s: (s.xref_count, s.size), reverse=True)
    return candidates[:cap]


async def _list_all_functions(session: Any, sid: str) -> list[dict[str, Any]]:
    """Page through ``list_functions`` until the listing is no longer truncated.

    Args:
        session: The live MCP client session.
        sid: The session id.

    Returns:
        Every function row (``{address, name, size}``) for the program.
    """
    rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = _structured(
            await session.call_tool(
                "list_functions", {"session_id": sid, "offset": offset, "limit": 1000}
            )
        )
        batch = page.get("functions", [])
        rows.extend(batch)
        if not page.get("truncated") or not batch:
            break
        offset += len(batch)
    return rows


async def run_analyze(
    *, binary: Path, cap: int, out: Path, tool_timeout_s: int, progress: ProgressLog
) -> dict[str, Any]:
    """Drive the real chain through the analyze workflow and write all artifacts.

    Phases (each emits ``step i/M``): import → analyze → list_functions → analysis_order →
    select top-N → per-function (decompile + function_context + referenced strings) → manifest +
    names template. Per-function steps emit ``function i/N: <addr>``.

    Args:
        binary: The binary to analyze (its parent dir becomes the worker's read-only import root).
        cap: Maximum non-external functions to select.
        out: The artifact output directory (created; defaults under /tmp, git-ignored).
        tool_timeout_s: Per-call MCP read timeout for the long import/analyze phases.
        progress: The progress sink.

    Returns:
        A machine-readable summary dict (counts + per-phase timings) also written to summary.json.

    Raises:
        HarnessError: Fail-closed on a missing chain or a tool error envelope.
    """
    binary = binary.resolve()
    if not binary.is_file():
        raise HarnessError(f"binary {binary} is not a file")
    import_root = binary.parent
    _preflight(import_root)

    functions_dir = out / "functions"
    functions_dir.mkdir(parents=True, exist_ok=True)

    total_phases = 6
    timings: dict[str, float] = {}
    dump_failures: list[dict[str, str]] = []
    binary_sha256 = _sha256_file(binary)
    summary: dict[str, Any] = {
        "mode": "analyze",
        "binary_sha256": binary_sha256,
        "generated_at": _utc_now_iso(),
    }

    async with _mcp_session(import_root) as session:
        sid = _structured(await session.call_tool("session_create", {}))["session_id"]
        try:
            # --- step 1/6: import (long; worker-bounded) ---------------------------------------
            with _phase(progress, 1, total_phases, "import_binary", timings):
                imported = _structured(
                    await session.call_tool(
                        "session_import",
                        {"session_id": sid, "source_ref": str(binary)},
                        read_timeout_seconds=_read_timeout(tool_timeout_s),
                    )
                )
                worker_sha = imported.get("binary_sha256")

            # --- step 2/6: analyze (long; worker-bounded) --------------------------------------
            with _phase(progress, 2, total_phases, "session_analyze", timings):
                await session.call_tool(
                    "session_analyze",
                    {"session_id": sid},
                    read_timeout_seconds=_read_timeout(tool_timeout_s),
                )

            # --- step 3/6: list functions (paginated) ------------------------------------------
            with _phase(progress, 3, total_phases, "list_functions", timings):
                functions = await _list_all_functions(session, sid)
                progress.emit(f"  total functions: {len(functions)}")

            # --- step 4/6: leaf-first analysis order + call graph (for the xref ranking) -------
            with _phase(progress, 4, total_phases, "analysis_order", timings):
                order_raw = _structured(
                    await session.call_tool(
                        "analysis_order",
                        {"session_id": sid, "max_nodes": 50000, "max_edges": 200000},
                    )
                )
                order = AnalysisOrderOut.model_validate(order_raw)
                cg = _structured(
                    await session.call_tool(
                        "call_graph",
                        {"session_id": sid, "max_nodes": 50000, "max_edges": 200000},
                    )
                )
                externals = frozenset(
                    n["address"] for n in cg.get("nodes", []) if n.get("is_external")
                )
                callers_by_addr = _caller_counts(cg.get("edges", []))

            # --- step 5/6: select top-N + per-function context ---------------------------------
            with _phase(progress, 5, total_phases, "select_and_context", timings):
                selected = _select_top_n(functions, callers_by_addr, externals, cap)
                total_selected = len(selected)
                progress.emit(f"  selected {total_selected} of {len(functions)} (cap={cap})")
                for index, sel in enumerate(selected, start=1):
                    progress.function(index, total_selected, sel.address)
                    # Per-function resilience: a single un-decompilable function
                    # (`analysis-failed` etc.) must NOT abort the whole run — record it as a
                    # failed-dump stub and continue. A real client tolerates per-function failures.
                    try:
                        artifact = await _build_function_artifact(session, sid, sel.address)
                    except HarnessError as exc:
                        dump_failures.append({"address": sel.address, "error": str(exc)})
                        progress.emit(f"    function {sel.address}: dump failed ({exc}) — skipped")
                        artifact = {
                            "address": sel.address,
                            "current_name": sel.name,
                            "dump_failed": True,
                            "error": str(exc),
                        }
                    (functions_dir / f"{_safe_addr(sel.address)}.json").write_text(
                        json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8"
                    )

            # --- step 6/6: manifest + names template -------------------------------------------
            with _phase(progress, 6, total_phases, "manifest_and_template", timings):
                manifest = _build_manifest(
                    binary_sha256=binary_sha256,
                    worker_sha256=worker_sha,
                    total_functions=len(functions),
                    selected=selected,
                    order=order,
                )
                (out / "manifest.json").write_text(
                    json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
                )
                template = {
                    sel.address: {
                        "current_name": sel.name,
                        "proposed_name": None,
                        "proposed_c": None,
                    }
                    for sel in selected
                }
                (out / "names.template.json").write_text(
                    json.dumps(template, indent=2, sort_keys=True), encoding="utf-8"
                )
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            progress.emit(f"  session_close: store_wiped={closed.get('store_wiped')}")

    summary.update(
        {
            "total_functions": len(functions),
            "selected": total_selected,
            "cap": cap,
            "dumped_ok": total_selected - len(dump_failures),
            "dump_failures": dump_failures,
            "phase_timings_s": {k: round(v, 3) for k, v in timings.items()},
            "artifacts_dir": str(out),
        }
    )
    return summary


async def _build_function_artifact(session: Any, sid: str, address: str) -> dict[str, Any]:
    """Assemble one function's artifact: decompiled C + context bundle + referenced strings.

    Args:
        session: The live MCP client session.
        sid: The session id.
        address: The function entry address (hex).

    Returns:
        ``{address, current_name, decompiled_c, context, referenced_strings}`` with every
        binary-derived field unwrapped to its inert value (written to a file, never executed).
    """
    decompiled = _structured(
        await session.call_tool("decompile_function", {"session_id": sid, "function": address})
    )
    context_raw = _structured(
        await session.call_tool("function_context", {"session_id": sid, "function": address})
    )
    context = FunctionContext.model_validate(context_raw)
    referenced = [_unwrap(s) for s in context_raw.get("referenced_strings", [])]
    return {
        "address": address,
        "current_name": _unwrap(decompiled.get("name")),
        "decompiled_c": _unwrap(decompiled.get("c_code")),
        "context": {
            "address": context.address,
            "name": context.name.value,
            "signature": context.signature.value,
            "is_external": context.is_external,
            "callees": [{"address": c.address, "name": c.name.value} for c in context.callees],
            "callers": [{"address": c.address, "name": c.name.value} for c in context.callers],
            "has_unresolved_calls": context.has_unresolved_calls,
        },
        "referenced_strings": referenced,
    }


def _build_manifest(
    *,
    binary_sha256: str,
    worker_sha256: str | None,
    total_functions: int,
    selected: list[_Selected],
    order: AnalysisOrderOut,
) -> dict[str, Any]:
    """Build the run manifest (the index the naming pass + comparison consume).

    Args:
        binary_sha256: The driver-computed SHA-256 of the input bytes (server-side, NOT via Ghidra).
        worker_sha256: The worker-computed program hash (cross-check; may be ``None``).
        total_functions: All functions Ghidra recovered.
        selected: The top-N selected functions.
        order: The leaf-first analysis order.

    Returns:
        The manifest dict.
    """
    return {
        "binary_sha256": binary_sha256,
        "worker_binary_sha256": worker_sha256,
        "total_functions": total_functions,
        "selected": [sel.address for sel in selected],
        "order": [
            {"members": comp.members, "is_recursive": comp.is_recursive}
            for comp in order.components
        ],
        "order_truncated": order.truncated,
        "ghidra_version": os.environ.get("GHIDRA_MCP_GHIDRA_VERSION", "12.1.2"),
        "generated_at": _utc_now_iso(),
    }


def _caller_counts(edges: list[dict[str, Any]]) -> dict[str, int]:
    """Count, per address, how many call edges target it (the xref-count ranking proxy).

    Args:
        edges: ``call_graph`` edges (``{from_address, to_address}``).

    Returns:
        Map of callee address → number of incoming call edges.
    """
    counts: dict[str, int] = {}
    for edge in edges:
        dst = edge.get("to_address")
        if isinstance(dst, str):
            counts[dst] = counts.get(dst, 0) + 1
    return counts


# =====================================================================================
# Mode B — apply: replay a filled names map via the gated write path, export, optionally measure.
# =====================================================================================
async def run_apply(
    *,
    names_path: Path,
    out: Path,
    tool_timeout_s: int,
    measure: bool,
    progress: ProgressLog,
) -> dict[str, Any]:
    """Apply a filled names map to a fresh session and export the resulting annotations.

    Re-imports the manifest's binary into a new ephemeral session, grants write consent (the
    human-in-the-loop gate — ADR-012), replays each ``addr → proposed_name`` via ``rename_function``
    (``function i/N`` progress), then exports the annotation document. With ``--measure`` and
    ``proposed_c`` present, additionally runs the ADR-016 sandboxed differential build (TB5) and
    scores name-coverage + behavioral-equivalence into ``metrics.json`` (skip-with-message when no
    buildable trusted reference is available — expected for a blind binary).

    Args:
        names_path: The filled names map (``{addr: {proposed_name, proposed_c?}}``).
        out: The artifact output directory (must already hold the analyze-run manifest).
        tool_timeout_s: Per-call MCP read timeout for import/analyze.
        measure: Whether to attempt the metrics build (needs a trusted reference + compiler image).
        progress: The progress sink.

    Returns:
        A machine-readable summary dict (counts + per-phase timings).

    Raises:
        HarnessError: Fail-closed on a missing manifest/binary, a bad names map, or a tool error.
    """
    names = _load_names_map(names_path)
    manifest_path = out / "manifest.json"
    if not manifest_path.is_file():
        raise HarnessError(f"no manifest.json in {out} — run mode 'analyze' there first")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    binary = _resolve_apply_binary(manifest, out)
    import_root = binary.parent
    _preflight(import_root)

    total_phases = 4
    timings: dict[str, float] = {}
    applied = 0
    rejected = 0

    async with _mcp_session(import_root) as session:
        sid = _structured(await session.call_tool("session_create", {}))["session_id"]
        try:
            with _phase(progress, 1, total_phases, "import_and_analyze", timings):
                await session.call_tool(
                    "session_import",
                    {"session_id": sid, "source_ref": str(binary)},
                    read_timeout_seconds=_read_timeout(tool_timeout_s),
                )
                await session.call_tool(
                    "session_analyze",
                    {"session_id": sid},
                    read_timeout_seconds=_read_timeout(tool_timeout_s),
                )

            with _phase(progress, 2, total_phases, "enable_writes", timings):
                # The human-in-the-loop write gate (ADR-012): default-deny until consent.
                await session.call_tool("session_enable_writes", {"session_id": sid})

            with _phase(progress, 3, total_phases, "apply_renames", timings):
                items = sorted(names.items())
                total = len(items)
                for index, (address, spec) in enumerate(items, start=1):
                    progress.function(index, total, address)
                    proposed = spec.get("proposed_name")
                    if not proposed:
                        rejected += 1
                        continue
                    result = _structured(
                        await session.call_tool(
                            "rename_function",
                            {"session_id": sid, "function": address, "new_name": proposed},
                        )
                    )
                    if result.get("applied"):
                        applied += 1
                    else:
                        rejected += 1

            with _phase(progress, 4, total_phases, "export_annotations", timings):
                exported = _structured(
                    await session.call_tool("session_export_annotations", {"session_id": sid})
                )
                (out / "annotations.json").write_text(
                    json.dumps(exported, indent=2, sort_keys=True), encoding="utf-8"
                )
                progress.emit(f"  applied={applied} rejected={rejected}")
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            progress.emit(f"  session_close: store_wiped={closed.get('store_wiped')}")

    metrics_note = None
    if measure:
        metrics_note = _maybe_measure(names=names, out=out, progress=progress)

    return {
        "mode": "apply",
        "applied": applied,
        "rejected": rejected,
        "total": applied + rejected,
        "phase_timings_s": {k: round(v, 3) for k, v in timings.items()},
        "measure": metrics_note,
        "artifacts_dir": str(out),
        "generated_at": _utc_now_iso(),
    }


def _maybe_measure(*, names: dict[str, dict[str, Any]], out: Path, progress: ProgressLog) -> str:
    """Attempt the ADR-016 metrics build; skip-with-message when no buildable reference exists.

    Reuses the pure naming core + scorer (``orchestrate`` + ``score``) and the sandboxed
    :class:`~ghidra_mcp.naming.compile.ContainerExecRunner` (TB5) exactly as the gated
    behavioral-equivalence e2e does. A blind binary typically has NO trusted reference source, so
    behavioral-equivalence is honestly unavailable — recorded as a skip reason rather than
    fabricated (the metric returns ``None`` for an absent reference). Name-coverage IS always
    computable from the proposed names alone and is written.

    Args:
        names: The filled names map (proposed_name [+ proposed_c]).
        out: The artifact output directory.
        progress: The progress sink.

    Returns:
        A short, safe status string recorded into the summary's ``measure`` field.
    """
    have_c = any(spec.get("proposed_c") for spec in names.values())
    if not have_c:
        msg = "no proposed_c in names map — name-coverage only (behavioral-equivalence unavailable)"
        progress.emit(f"  measure: {msg}")
        program = _program_from_names(names)
        metrics = score(program)
        _write_metrics(out, metrics, behavioral_available=False, note=msg)
        return msg

    compiler_image = os.environ.get("GHIDRA_MCP_COMPILER_IMAGE", "").strip()
    reference_source = os.environ.get("GHIDRA_MCP_REFERENCE_SOURCE", "").strip()
    if not compiler_image or not reference_source or not Path(reference_source).is_file():
        msg = (
            "behavioral-equivalence skipped: blind binary has no trusted reference build "
            "(set GHIDRA_MCP_COMPILER_IMAGE + GHIDRA_MCP_REFERENCE_SOURCE to enable) — "
            "name-coverage reported"
        )
        progress.emit(f"  measure: {msg}")
        program = _program_from_names(names)
        metrics = score(program)
        _write_metrics(out, metrics, behavioral_available=False, note=msg)
        return msg

    # A trusted reference + sandbox IS available: run the A-vs-B differential exactly like the e2e.
    from ghidra_mcp.naming.compile import ContainerExecRunner
    from ghidra_mcp.naming.metrics import generate_fuzz_vectors

    progress.emit("  measure: building A (reference) and B (candidate) in the TB5 sandbox")
    program = _program_from_names(names)
    runner = ContainerExecRunner(
        compiler_image=compiler_image,
        runtime=os.environ.get("GHIDRA_MCP_WORKER_RUNTIME", "runsc"),
        timeout_s=int(os.environ.get("GHIDRA_MCP_E2E_TIMEOUT", "120")),
    )
    vectors = generate_fuzz_vectors(seed=0xC0FFEE, count=16, max_len=64)
    runs_a = runner(Path(reference_source).read_text(encoding="utf-8"), vectors)
    runs_b = runner(program.translation_unit, vectors)
    metrics = score(program, behavioral_runs=(runs_a, runs_b))
    _write_metrics(out, metrics, behavioral_available=True, note="A-vs-B differential over fuzz")
    progress.emit(
        f"  measure: name_coverage={metrics.name_coverage:.3f} "
        f"behavioral_equivalence={metrics.behavioral_equivalence}"
    )
    return "behavioral-equivalence measured"


def _program_from_names(names: dict[str, dict[str, Any]]) -> Any:
    """Build a :class:`RenamedProgram` from a filled names map via the pure ``orchestrate`` core.

    Reconstructs a minimal leaf-first order + per-function contexts from the names map keys, then
    runs the real ``orchestrate`` with a map-backed namer — so name-coverage and the assembled
    translation unit come from the SAME core the production loop uses (no reinvented logic).

    Args:
        names: The filled names map.

    Returns:
        The :class:`~ghidra_mcp.naming.loop.RenamedProgram` for scoring.
    """
    from ghidra_mcp.core.envelope import DataOrigin, Untrusted
    from ghidra_mcp.tools.schemas import OrderedComponent

    addresses = sorted(names)
    order = AnalysisOrderOut(
        components=[OrderedComponent(members=[a], is_recursive=False) for a in addresses],
        unresolved_callers=[],
        self_recursive=[],
        truncated=False,
    )
    contexts: dict[str, FunctionContext] = {}
    for address in addresses:
        contexts[address] = FunctionContext(
            address=address,
            name=Untrusted[str](value=f"FUN_{address}", origin=DataOrigin.GHIDRA),
            signature=Untrusted[str](value="undefined", origin=DataOrigin.GHIDRA),
            is_external=False,
        )

    def namer(ctx: FunctionContext, _callees: Mapping[str, str]) -> ProposedName:
        spec = names[ctx.address]
        proposed = spec.get("proposed_name") or f"FUN_{ctx.address}"
        proposed_c = spec.get("proposed_c") or f"int {proposed}(void) {{ return 0; }}"
        return ProposedName(new_name=proposed, new_c=proposed_c)

    return orchestrate(order, contexts, namer)


def _write_metrics(out: Path, metrics: Any, *, behavioral_available: bool, note: str) -> None:
    """Serialize the measured naming metrics to ``<out>/metrics.json``.

    Args:
        out: The artifact output directory.
        metrics: The :class:`~ghidra_mcp.naming.metrics.NamingMetrics`.
        behavioral_available: Whether a trusted reference build was available.
        note: A short, safe status note recorded alongside the numbers.
    """
    payload = {
        "total_functions": metrics.total_functions,
        "inferred_functions": metrics.inferred_functions,
        "external_functions": metrics.external_functions,
        "named_functions": metrics.named_functions,
        "name_coverage": metrics.name_coverage,
        "behavioral_equivalence": metrics.behavioral_equivalence,
        "behavioral_equivalence_normalized": metrics.behavioral_equivalence_normalized,
        "behavioral_available": behavioral_available,
        "note": note,
        "generated_at": _utc_now_iso(),
    }
    (out / "metrics.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )


def _load_names_map(path: Path) -> dict[str, dict[str, Any]]:
    """Load + shape-check the filled names map (``{addr: {proposed_name, proposed_c?}}``).

    Args:
        path: The names-map JSON path.

    Returns:
        The validated map.

    Raises:
        HarnessError: If the file is missing or not the expected ``{addr: {...}}`` shape.
    """
    if not path.is_file():
        raise HarnessError(f"names map {path} is not a file")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HarnessError(f"names map {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise HarnessError("names map must be a JSON object of {address: {proposed_name, ...}}")
    shaped: dict[str, dict[str, Any]] = {}
    for address, spec in data.items():
        if not isinstance(spec, dict):
            raise HarnessError(f"names map entry for {address!r} must be an object")
        shaped[str(address)] = spec
    return shaped


def _resolve_apply_binary(manifest: dict[str, Any], out: Path) -> Path:
    """Resolve the binary to re-import for apply mode (explicit env override, else manifest sha).

    Apply mode re-imports the SAME binary the analyze run targeted. The path is supplied via
    ``GHIDRA_MCP_APPLY_BINARY`` (the operator points at the exact file again — the harness never
    writes the sample into the repo or the out dir). The binary's SHA-256 is cross-checked against
    the manifest to fail closed on a mismatched binary.

    Args:
        manifest: The analyze-run manifest.
        out: The artifact output directory (for the error message).

    Returns:
        The resolved binary path.

    Raises:
        HarnessError: If the override is unset/missing or its hash does not match the manifest.
    """
    override = os.environ.get("GHIDRA_MCP_APPLY_BINARY", "").strip()
    if not override:
        raise HarnessError(
            "set GHIDRA_MCP_APPLY_BINARY to the SAME binary the analyze run used "
            f"(its sha256 must match manifest.json in {out})"
        )
    binary = Path(override).resolve()
    if not binary.is_file():
        raise HarnessError(f"GHIDRA_MCP_APPLY_BINARY {binary} is not a file")
    actual = _sha256_file(binary)
    expected = manifest.get("binary_sha256")
    if expected and actual != expected:
        raise HarnessError(
            "GHIDRA_MCP_APPLY_BINARY does not match the analyze-run binary (sha256 mismatch)"
        )
    return binary


# =====================================================================================
# Shared helpers.
# =====================================================================================
@contextlib.contextmanager
def _phase(
    progress: ProgressLog, index: int, total: int, description: str, timings: dict[str, float]
) -> Iterator[None]:
    """Time a phase, emitting its ``step i/M`` line on entry and recording its duration.

    Args:
        progress: The progress sink.
        index: 1-based phase index.
        total: Total phases.
        description: Safe phase description (also the timing key).
        timings: The per-phase duration map to record into.
    """
    progress.step(index, total, description)
    started = time.monotonic()
    try:
        yield
    finally:
        timings[description] = time.monotonic() - started


def _sha256_file(path: Path) -> str:
    """Compute the SHA-256 of a file's bytes (server-side; never via Ghidra — ADR-001).

    Args:
        path: The file to hash.

    Returns:
        The lowercase hex digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_addr(address: str) -> str:
    """Return a filesystem-safe form of a hex address for an artifact filename.

    Args:
        address: The hex address (already a server-normalized scalar).

    Returns:
        The address with any non-alphanumeric character replaced by ``_``.
    """
    return "".join(ch if ch.isalnum() else "_" for ch in address)


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for the two modes.

    Returns:
        The configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="acceptance_run",
        description=(
            "Real-chain acceptance harness for ghidra-mcp (analyze a binary + dump artifacts; "
            "apply a filled names map). Runs the REAL hardened worker — gated; honors ADR-001."
        ),
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    analyze = sub.add_parser("analyze", help="analyze a binary and dump per-function artifacts")
    analyze.add_argument("--binary", required=True, type=Path, help="path to the binary to analyze")
    analyze.add_argument(
        "--cap",
        type=int,
        default=_DEFAULT_CAP,
        help=f"max functions to select (default {_DEFAULT_CAP})",
    )
    analyze.add_argument("--out", required=True, type=Path, help="artifact output directory")
    analyze.add_argument(
        "--tool-timeout",
        type=int,
        default=_DEFAULT_TOOL_TIMEOUT_S,
        help=f"per-call MCP read timeout for import/analyze (default {_DEFAULT_TOOL_TIMEOUT_S}s)",
    )

    apply = sub.add_parser("apply", help="apply a filled names map and export annotations")
    apply.add_argument("--names", required=True, type=Path, help="filled names map JSON")
    apply.add_argument("--out", required=True, type=Path, help="artifact output directory")
    apply.add_argument(
        "--measure",
        action="store_true",
        help="also compute name-coverage / behavioral-equivalence metrics (TB5 sandbox)",
    )
    apply.add_argument(
        "--tool-timeout",
        type=int,
        default=_DEFAULT_TOOL_TIMEOUT_S,
        help=f"per-call MCP read timeout for import/analyze (default {_DEFAULT_TOOL_TIMEOUT_S}s)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: parse args, run the selected mode, write summary.json, print a summary.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code (``0`` on success, ``2`` on a fail-closed harness error).
    """
    args = _build_parser().parse_args(argv)
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    progress = ProgressLog(log_path=out / "run.log")
    progress.open()
    try:
        if args.mode == "analyze":
            summary = asyncio.run(
                run_analyze(
                    binary=args.binary,
                    cap=args.cap,
                    out=out,
                    tool_timeout_s=args.tool_timeout,
                    progress=progress,
                )
            )
        else:  # apply
            summary = asyncio.run(
                run_apply(
                    names_path=args.names,
                    out=out,
                    tool_timeout_s=args.tool_timeout,
                    measure=args.measure,
                    progress=progress,
                )
            )
        (out / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
        )
        progress.emit(_final_summary_line(summary))
        return 0
    except HarnessError as exc:
        # Fail closed with a clear, safe operator message (no host/binary detail).
        progress.emit(f"FAILED (fail-closed): {exc}")
        return 2
    finally:
        progress.close()


def _final_summary_line(summary: dict[str, Any]) -> str:
    """Render the human final-summary line from the machine summary (safe scalars only).

    Args:
        summary: The run summary dict.

    Returns:
        A one-line, scalar-only summary.
    """
    if summary.get("mode") == "analyze":
        return (
            f"DONE analyze: selected {summary['selected']} of {summary['total_functions']} "
            f"functions; artifacts in {summary['artifacts_dir']}"
        )
    return (
        f"DONE apply: applied {summary['applied']} / {summary['total']} renames; "
        f"artifacts in {summary['artifacts_dir']}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
