"""Real-worker end-to-end test for ``identify_functions`` FID matching (ADR-042 Phase 1).

This exercises the ``# pragma: no cover - JVM edge`` in ``_jvm_bridge._gh_identify_functions``
against a **real** hardened Ghidra worker — the surface hermetic unit tests structurally cannot
reach (TB3, ADR-001). The risk it guards: the FID call shape
(``FidService().processProgram(program, monitor)`` → ``FidSearchResult.function`` / ``.matches`` →
``FidMatch.getOverallScore()`` …) is reflection-style attribute access; a renamed class/field or a
changed signature across a Ghidra version bump would land silently. Running the tool end to end —
real MCP stdio chain (``python -m vivarium`` → real ``RpcGhidraAdapter`` → worker container) —
fails the nightly if that binding regresses.

**Hard gate (deterministic):** ``identify_functions`` returns WITHOUT an error envelope and yields
a well-formed, bounded result — ``matches`` is a list, ``total == len(matches)``, ``truncated`` is a
bool. The FID *service path* (``processProgram`` + result shaping) is proven to run on real Ghidra.

**Why the count is zero here (expected, not a gap):** the only FID databases Ghidra ships are the
**MSVC** runtime DBs (``vsXXXX_x86/x64``); the benign micro-binary is a locally-compiled **ELF**, so
no function matches — the result is a well-formed *empty* set. This proves the edge executes and
shapes results correctly; it does NOT exercise the non-empty inner loop
(``getFunctionRecord().getName()`` / ``getLibraryRecord()`` getters — those are reflection-verified
to exist but not run here).

TODO(ADR-042 Phase 1 follow-up): exercise the non-empty match path — either a benign static-MSVC PE
fixture (matches the bundled VS DBs) or a self-built throwaway ``.fidb`` ingested from the fixture's
own named functions (hermetic; also de-risks the Phase-2 SPIKE-1 custom-DB activation API). Then
assert ``matched_name``/``library`` are ``Untrusted``-wrapped and ``limit``/``truncated`` bound a
multi-match result.

Posture mirrors ``test_analyze_profiles.py`` / ``test_export_known_count.py``: a tiny, benign,
locally-built micro-binary (no real malware, master §5), import root under ``tmp_path`` (never the
repo). ``read_timeout_seconds`` takes a ``datetime.timedelta``, NOT an int. Gating is reused from
``conftest.py`` (``integration``-marked → SKIPPED in the default hermetic run; runs only when
``VIVARIUM_INTEGRATION`` is truthy with a real worker + container engine + a C compiler).
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

#: A tiny, benign C source with two defined functions so analysis recovers a non-trivial surface.
#: Nothing hostile; compiled locally into the tmp import root (never the repo).
_MICRO_C = r"""
#include <stdlib.h>

int helper(int x) { return x * 3 + 1; }

int run(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) acc += helper(i);
    return acc;
}

int main(int argc, char **argv) {
    (void)argv;
    return run(argc) & 0xff;
}
"""


def _read_timeout() -> datetime.timedelta:
    """Build the MCP client per-call read timeout (a ``datetime.timedelta``, NOT an int)."""
    return datetime.timedelta(seconds=int(os.environ.get("VIVARIUM_E2E_TIMEOUT", "600")))


def _engine_available() -> bool:
    """Return whether the configured container engine binary is resolvable on ``PATH``."""
    engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
    return shutil.which(engine) is not None


def _compiler() -> str | None:
    """Return a C compiler binary on ``PATH`` (``cc`` preferred, then ``gcc``), or ``None``."""
    for candidate in ("cc", "gcc"):
        if shutil.which(candidate):
            return candidate
    return None


def _build_micro_binary(out_dir: Path) -> Path:
    """Compile the benign micro-binary into ``out_dir`` and return its path (fail closed).

    Built non-PIE so Ghidra recovers concrete entry addresses cleanly. The source is the small,
    benign :data:`_MICRO_C` — no real malware (master §5); the binary lives only under the test's
    ``tmp_path`` import root (never the repo).

    Args:
        out_dir: The directory to write the source + binary into (the server's import root).

    Returns:
        The path to the compiled micro-binary.

    Raises:
        AssertionError: If compilation fails (the captured stderr is surfaced).
    """
    compiler = _compiler()
    assert compiler is not None, "no C compiler on PATH"
    src = out_dir / "micro.c"
    src.write_text(_MICRO_C, encoding="utf-8")
    binary = out_dir / "micro"
    proc = subprocess.run(  # noqa: S603 — argv list (no shell); compiler resolved from PATH.
        [compiler, "-O0", "-no-pie", "-fno-pie", "-o", str(binary), str(src)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"micro-binary compile failed:\n{proc.stderr[-2000:]}"
    return binary


def _assert_not_error_envelope(payload: dict[str, Any]) -> None:
    """Fail closed when ``payload`` is the frozen error envelope rather than a tool result.

    Args:
        payload: A structured tool-result dict.

    Raises:
        AssertionError: If ``payload`` matches the error-envelope shape (``type``+``title``+
            ``retryable``+``status``) — surfaces worker-unavailable / analysis-failed / a JVM-edge
            crash mapped to ``internal-error`` as a clear failure.
    """
    if {"type", "title", "retryable"} <= payload.keys() and "status" in payload:
        raise AssertionError(f"tool returned error envelope: {payload.get('type')!r}")


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured JSON output from an MCP ``CallToolResult`` (fail closed).

    Args:
        result: The MCP ``CallToolResult``.

    Returns:
        The tool's structured output dict.

    Raises:
        AssertionError: If the tool returned an error envelope or no structured content.
    """
    if getattr(result, "isError", False):
        raise AssertionError(f"tool returned an error envelope: {getattr(result, 'content', None)}")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        _assert_not_error_envelope(structured)
        return structured
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parsed: dict[str, Any] = json.loads(text)
            _assert_not_error_envelope(parsed)
            return parsed
    raise AssertionError("tool result carried no structured content")


async def _drive_identify(binary: Path, import_root: Path) -> dict[str, Any]:
    """Drive the real stdio chain through ``identify_functions`` and return its structured output.

    Steps: ``session_create`` → ``session_import`` → ``session_analyze`` → ``identify_functions``.
    Every step fails closed on an error envelope (so a FID JVM-edge crash surfaces as a failure, not
    empty data). The session is always closed in a ``finally`` and its store-wipe asserted
    (ADR-002 containment).

    Args:
        binary: The compiled micro-binary to import.
        import_root: The directory the binary lives under (the server's confined import root).

    Returns:
        The structured ``identify_functions`` result dict.
    """
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "vivarium"],
        env={**os.environ, "VIVARIUM_IMPORT_ROOT": str(import_root)},
    )
    timeout = _read_timeout()

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        sid = _structured(await session.call_tool("session_create", {}))["session_id"]
        try:
            _structured(
                await session.call_tool(
                    "session_import",
                    {"session_id": sid, "source_ref": str(binary)},
                    read_timeout_seconds=timeout,
                )
            )
            _structured(
                await session.call_tool(
                    "session_analyze",
                    {"session_id": sid},
                    read_timeout_seconds=timeout,
                )
            )
            # The crux: run the FID service path on the real worker. _structured fails closed if the
            # JVM edge (processProgram + shaping) regressed (worker maps it to internal-error).
            return _structured(
                await session.call_tool(
                    "identify_functions",
                    {"session_id": sid},
                    read_timeout_seconds=timeout,
                )
            )
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            # Containment invariant (ADR-002): the per-session store is wiped on close.
            assert closed.get("store_wiped") is True


def test_identify_functions_runs_on_real_worker(tmp_path: Path) -> None:
    """``identify_functions`` runs the FID service on a real worker, returning a well-formed result.

    Hard gate: the tool returns without an error envelope and the result is a bounded, well-formed
    shape — ``matches`` a list, ``total == len(matches)``, ``truncated`` a bool. This proves the FID
    JVM edge (``FidService.processProgram`` + result shaping) executes correctly on real Ghidra (the
    reflection-style API binding has not regressed). The match count is **0** here — the
    micro-binary
    is ELF and Ghidra ships only MSVC FID DBs — which is the expected, well-formed empty result; the
    non-empty inner loop is the documented Phase-1 follow-up.

    Args:
        tmp_path: The pytest temp dir used as the (host) import root the micro-binary is built into.
    """
    if not _engine_available():
        engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
        pytest.skip(f"container engine {engine!r} not found on PATH")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) on PATH to build the benign micro-binary")

    import_root = tmp_path
    binary = _build_micro_binary(import_root)

    result = asyncio.run(_drive_identify(binary, import_root))

    # Well-formed, bounded shape (the FID edge ran and shaped results cleanly).
    matches = result.get("matches")
    assert isinstance(matches, list), f"matches not a list: {result!r}"
    assert result.get("total") == len(matches), f"total != len(matches): {result!r}"
    assert isinstance(result.get("truncated"), bool), f"truncated not a bool: {result!r}"
    # Expected empty: an ELF micro-binary does not match the MSVC-only shipped FID DBs.
    assert result.get("total") == 0, (
        f"expected 0 FID matches for an ELF micro-binary against MSVC-only DBs, got {result!r} — "
        f"if this is non-empty, FID coverage changed (good problem) and the assertion should relax "
        f"to exercise the non-empty path (ADR-042 Phase 1 follow-up)"
    )
    print(f"[live-regression] identify_functions matches={result.get('total')}")
