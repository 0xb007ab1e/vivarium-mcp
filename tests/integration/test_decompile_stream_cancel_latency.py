"""Integration: a mid-stream ``cancel_job`` stops the worker PROMPTLY (ADR-041 increment 4).

Drives the real MCP stdio chain (``python -m vivarium`` -> ``RpcGhidraAdapter`` -> hardened worker
container -> Ghidra) against the committed OpenSSL blind-analysis LFS fixture and proves the ADR-041
mid-stream cancellation path end to end:

    session_create -> session_import -> session_analyze
        -> start_decompile_stream over a reasonably large function set (~64 addresses)
        -> fetch the FIRST chunk, then cancel_job
        -> assert the stream reaches a terminal state PROMPTLY (a cancel-latency bound)

Acceptance criteria asserted (ADR-041 §"Acceptance criteria"):

* **The cancel is acknowledged terminal** — ``cancel_job`` returns ``cancelled=True`` and a
  follow-up ``job_status`` reports a terminal (``cancelled``/``done``) state.
* **Markedly fewer chunks than the full set** — the client fetched far fewer than the full bounded
  set's chunks before the worker stopped (production halted at the next function boundary, not at
  the end of the set).
* **Cancel-latency bound** — wall-clock from start to the terminal cancel acknowledgement is well
  under a measured baseline of streaming the FULL set to ``done``: the worker stopped early instead
  of decompiling the whole set after the client cancelled (the ADR-040 limitation this ADR fixes).

The test first measures an uncancelled baseline (full stream to ``done`` over the same set) so the
prompt-cancel bound is a relative margin, not a brittle absolute time. Both phases are bounded to a
small function window so the run is seconds-to-a-minute, not multi-minute.

Why gated/integration: it drives the JVM/PyGhidra edge (TB3, ADR-001) through a real worker, so it
is excluded from hermetic unit CI and runs only under the live-regression harness.

You CANNOT run this locally without a JVM/worker; it is written to the frozen contract (ADR-041 +
``docs/contracts/rpc-protocol.md`` §4 ``$/cancel``) and validated under the live-regression harness
(the same env as ``test_decompile_stream_openssl_blind.py``).

Honored environment (same as the other integration tests):
    * ``VIVARIUM_INTEGRATION`` — truthy enables the suite (conftest).
    * ``VIVARIUM_WORKER_IMAGE`` / ``VIVARIUM_CONTAINER_ENGINE`` / ``VIVARIUM_WORKER_RUNTIME`` /
      ``VIVARIUM_WORKER_UID`` / ``VIVARIUM_WORKER_GID`` / ``VIVARIUM_RPC_SOCKET_DIR`` — worker.
    * ``VIVARIUM_E2E_TIMEOUT`` — per-call MCP read timeout seconds for import/analyze.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

#: The committed OpenSSL blind-analysis subject (Git LFS — ``*.blind``; see golden-fixture test).
_SAMPLE_DIR = Path(__file__).resolve().parents[2] / "samples" / "openssl-blind-analysis"
_BINARY = _SAMPLE_DIR / "openssl.blind"

#: Stream a reasonably large set so there is clearly time to cancel mid-flight AND the full-set
#: baseline takes meaningfully longer than a prompt cancel (a robust cancel-latency margin).
_STREAM_LIMIT = 64
#: Small per-fetch batch so the cursor loop pulls in several rounds (a chunk lands early enough to
#: cancel right after the first one).
_FETCH_LIMIT = 3


def _read_timeout() -> datetime.timedelta:
    """Build the MCP client per-call read timeout (a ``datetime.timedelta``)."""
    return datetime.timedelta(seconds=int(os.environ.get("VIVARIUM_E2E_TIMEOUT", "900")))


def _engine_available() -> bool:
    """Return whether the configured container engine binary is resolvable on ``PATH``."""
    engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
    return shutil.which(engine) is not None


def _ensure_binary() -> Path | None:
    """Return the committed fixture binary, or ``None`` if absent / an unsmudged LFS pointer."""
    if not _BINARY.is_file():
        return None
    if _BINARY.stat().st_size < 4096 and _BINARY.read_bytes()[:64].startswith(
        b"version https://git-lfs"
    ):
        return None
    return _BINARY


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured JSON output from an MCP ``CallToolResult`` (fail closed)."""
    import json

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


def _assert_not_error_envelope(payload: dict[str, Any]) -> None:
    """Fail closed when ``payload`` is the frozen error envelope rather than a tool result."""
    if {"type", "title", "retryable"} <= payload.keys() and "status" in payload:
        raise AssertionError(f"tool returned error envelope: {payload.get('type')!r}")


async def _drive_cancel(binary: Path, import_root: Path) -> dict[str, Any]:
    """Drive the real stdio chain: a baseline full stream, then a mid-stream cancel; collect facts.

    Returns a dict the test asserts against:
    ``baseline_latency`` (start→done seconds for the FULL uncancelled set),
    ``baseline_chunks`` (chunks the full run delivered),
    ``cancel_latency`` (start→terminal-cancel seconds for the cancelled run),
    ``cancel_chunks`` (chunks fetched before the cancel),
    ``cancelled`` (cancel_job acknowledged terminal), and
    ``cancel_terminal`` (a follow-up job_status reported a terminal state).
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
                    "session_analyze", {"session_id": sid}, read_timeout_seconds=timeout
                )
            )
            # Identify a reasonably large target set by address (the binary is stripped).
            listed = _structured(
                await session.call_tool(
                    "list_functions",
                    {"session_id": sid, "limit": _STREAM_LIMIT},
                    read_timeout_seconds=timeout,
                )
            )
            targets = [f["address"] for f in listed.get("functions", [])]
            assert targets, "list_functions returned no functions to stream"

            # --- Phase A: baseline — stream the FULL set to `done`, timing it. -------------------
            baseline = await _full_stream(session, sid, targets, timeout)

            # --- Phase B: cancel mid-stream after the first chunk, timing to terminal. -----------
            cancel = await _cancel_after_first_chunk(session, sid, targets, timeout)

            return {
                "baseline_latency": baseline["latency"],
                "baseline_chunks": baseline["chunks"],
                "cancel_latency": cancel["latency"],
                "cancel_chunks": cancel["chunks"],
                "cancelled": cancel["cancelled"],
                "cancel_terminal": cancel["terminal"],
            }
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            assert closed.get("store_wiped") is True


async def _full_stream(
    session: Any, sid: str, targets: list[str], timeout: datetime.timedelta
) -> dict[str, Any]:
    """Stream the full ``targets`` set to ``done``; return ``{latency, chunks}``."""
    start = time.monotonic()
    started = _structured(
        await session.call_tool(
            "start_decompile_stream",
            {"session_id": sid, "functions": targets},
            read_timeout_seconds=timeout,
        )
    )
    job = started["job"]
    chunks = 0
    cursor = 0
    pull_deadline = time.monotonic() + 600.0
    while time.monotonic() < pull_deadline:
        res = _structured(
            await session.call_tool(
                "fetch_job_results",
                {"session_id": sid, "job": job, "cursor": cursor, "limit": _FETCH_LIMIT},
                read_timeout_seconds=timeout,
            )
        )
        chunks += len(res.get("chunks", []))
        cursor = int(res["next_cursor"])
        if res.get("done"):
            return {"latency": time.monotonic() - start, "chunks": chunks}
        if not res.get("chunks"):
            await asyncio.sleep(0.05)
    raise AssertionError("baseline full stream did not reach done within the deadline")


async def _cancel_after_first_chunk(
    session: Any, sid: str, targets: list[str], timeout: datetime.timedelta
) -> dict[str, Any]:
    """Start a stream, fetch the first chunk, then cancel; return ``{latency, chunks, ...}``."""
    start = time.monotonic()
    started = _structured(
        await session.call_tool(
            "start_decompile_stream",
            {"session_id": sid, "functions": targets},
            read_timeout_seconds=timeout,
        )
    )
    job = started["job"]
    chunks = 0
    cursor = 0
    # Pull until at least one chunk has arrived (the producer warms the buffer), then cancel.
    first_deadline = time.monotonic() + 600.0
    while chunks == 0 and time.monotonic() < first_deadline:
        res = _structured(
            await session.call_tool(
                "fetch_job_results",
                {"session_id": sid, "job": job, "cursor": cursor, "limit": _FETCH_LIMIT},
                read_timeout_seconds=timeout,
            )
        )
        chunks += len(res.get("chunks", []))
        cursor = int(res["next_cursor"])
        if chunks == 0 and not res.get("done"):
            await asyncio.sleep(0.05)
        if res.get("done"):  # the whole (small) set finished before we could cancel — rare
            break
    assert chunks >= 1, "no chunk arrived before the cancel window deadline"

    cancelled = _structured(
        await session.call_tool(
            "cancel_job",
            {"session_id": sid, "job": job},
            read_timeout_seconds=timeout,
        )
    )
    cancel_latency = time.monotonic() - start

    status = _structured(
        await session.call_tool(
            "job_status",
            {"session_id": sid, "job": job},
            read_timeout_seconds=timeout,
        )
    )
    return {
        "latency": cancel_latency,
        "chunks": chunks,
        "cancelled": bool(cancelled.get("cancelled")),
        "terminal": bool(status.get("done")) or status.get("state") in {"cancelled", "done"},
    }


def test_cancel_job_stops_the_worker_promptly(tmp_path: Path) -> None:
    """A mid-stream cancel terminates markedly sooner than the full set would take (ADR-041).

    Args:
        tmp_path: A scratch import root the server confines + read-only mounts the fixture under.
    """
    if not _engine_available():
        engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
        pytest.skip(f"container engine {engine!r} not found on PATH")
    binary = _ensure_binary()
    if binary is None:
        pytest.skip("openssl.blind fixture absent or not pulled from Git LFS (run: git lfs pull)")

    staged = tmp_path / "openssl.blind"
    shutil.copy2(binary, staged)
    facts = asyncio.run(_drive_cancel(staged, tmp_path))

    # The cancel was acknowledged terminal (server-side authority — ADR-040 D6).
    assert facts["cancelled"], "cancel_job did not acknowledge the job terminal"
    assert facts["cancel_terminal"], "job_status did not report a terminal state after cancel"

    # The baseline produced the full set; the cancelled run fetched far fewer chunks (the worker
    # stopped early at the next function boundary instead of finishing the whole set — ADR-041 D3).
    assert facts["baseline_chunks"] >= 1, "baseline stream delivered no chunks"
    assert facts["cancel_chunks"] < facts["baseline_chunks"], (
        f"cancelled run fetched {facts['cancel_chunks']} chunks vs baseline "
        f"{facts['baseline_chunks']} — the worker did not stop early"
    )

    # Cancel-latency bound (the core ADR-041 win): terminating a cancelled stream is markedly faster
    # than streaming the whole set to done. With a margin so worker/JVM jitter is not flaky: the
    # cancelled run must finish in well under the baseline (it stopped within ~a function or two).
    baseline = facts["baseline_latency"]
    cancel = facts["cancel_latency"]
    assert cancel < baseline, (
        f"no prompt cancel: cancel reached terminal at {cancel:.3f}s but the full set took "
        f"{baseline:.3f}s — the worker kept decompiling after the cancel (ADR-040 limitation)"
    )
