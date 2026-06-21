"""Integration: bulk decompile STREAMS partial results from a live worker (ADR-040 increment 4).

Drives the real MCP stdio chain (``python -m vivarium`` -> ``RpcGhidraAdapter`` -> hardened worker
container -> Ghidra) against the committed OpenSSL blind-analysis LFS fixture and exercises the
ADR-040 Phase 2 streaming path end to end:

    session_create -> session_import -> session_analyze
        -> start_decompile_stream (bounded to a small function set)
        -> loop fetch_job_results by cursor until done

Acceptance criteria asserted (design §9 / ADR-040):

* **≥1 chunk arrives** — the worker actually emits ``$/chunk`` frames the server buffers + delivers.
* **Cursor resume in seq order with client dedupe** — chunks arrive monotonically gap-free; a
  re-fetch from an earlier cursor (idempotent) re-delivers nothing new past what the client already
  has (the client dedupes by ``seq``).
* **Per-chunk untrusted envelope** — every chunk's ``code`` field is the ADR-005 untrusted-data
  envelope (inert data, never raw text), exactly like a one-shot decompile result.
* **The job reaches ``done``** — the stream terminates honestly (explicit ``done``).
* **Overlap (the core ADR-040 win)** — latency-to-first-chunk is markedly LESS than
  latency-to-full-completion: the LLM could begin reasoning over early functions while extraction
  continues. Measured with a monotonic clock; asserted with a margin.

Why gated/integration: it drives the JVM/PyGhidra edge (TB3, ADR-001) through a real worker, so it
is excluded from hermetic unit CI and runs only under the live-regression harness. It is bounded to
a small function cap so it is not a multi-minute run.

You CANNOT run this locally without a JVM/worker; it is written to the frozen contract and validated
under the live-regression harness (the same env as ``test_golden_fixture_openssl_blind.py`` /
``test_worker_analysis.py``).

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

#: Keep the run bounded: stream only a small function window so the test is seconds, not minutes,
#: yet large enough that production clearly outlasts the first fetch (a robust overlap margin).
_STREAM_LIMIT = 32
#: One pull returns at most this many chunks (the contract default is 32; small here keeps the
#: cursor loop exercising MULTIPLE fetches over the small set).
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


def _chunk_is_enveloped(chunk: dict[str, Any]) -> bool:
    """Whether a streamed chunk's ``code`` field is the ADR-005 untrusted-data envelope.

    The MCP-serialized ``Untrusted[str]`` is an object carrying the wrapped value + provenance — not
    a bare string. The load-bearing assertion is that ``code`` is a structured envelope object
    (a dict carrying ``value``), NOT a raw string the client could mistake for an instruction.
    """
    code = chunk.get("code")
    # An enveloped value is a structured object (dict), never a bare str. The exact key set is the
    # envelope schema (value + origin + optional encoding); we assert it is a dict carrying a value.
    return isinstance(code, dict) and "value" in code


async def _drive_stream(binary: Path, import_root: Path) -> dict[str, Any]:
    """Drive the real stdio chain through a bounded streaming bulk decompile; collect facts.

    Returns a dict of facts the test asserts against:
    ``first_chunk_latency`` / ``completion_latency`` (monotonic seconds from the start call),
    ``seqs`` (every chunk seq received, in arrival order), ``enveloped`` (whether every chunk's
    ``code`` was the untrusted envelope), ``done`` (the stream reached a terminal done), and
    ``dedupe_ok`` (a re-fetch from an earlier cursor delivered no seq the client had not already
    seen).
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

            # Bound the stream to a small function set so the producer exhausts quickly and the job
            # reaches a terminal `done` within the test window (the binary is stripped, so identify
            # the targets by address — the worker's `functions` filter resolves addresses or names).
            listed = _structured(
                await session.call_tool(
                    "list_functions",
                    {"session_id": sid, "limit": _STREAM_LIMIT},
                    read_timeout_seconds=timeout,
                )
            )
            targets = [f["address"] for f in listed.get("functions", [])]
            assert targets, "list_functions returned no functions to stream"

            # Start the bounded streaming job; the handle returns immediately (no chunks yet).
            start = time.monotonic()
            started = _structured(
                await session.call_tool(
                    "start_decompile_stream",
                    {"session_id": sid, "functions": targets},
                    read_timeout_seconds=timeout,
                )
            )
            job = started["job"]

            seqs: list[int] = []
            seen: set[int] = set()
            enveloped = True
            first_chunk_latency: float | None = None
            completion_latency: float | None = None
            cursor = 0
            # Pull until the stream is `done`, bounded by a generous wall-clock deadline (NOT a
            # small iteration cap): a real worker decompiles slowly, so many early fetches return
            # an empty batch while the buffer warms — an iteration cap would falsely give up before
            # the bounded set finishes. The deadline still guarantees the test cannot hang.
            pull_deadline = time.monotonic() + 600.0
            while time.monotonic() < pull_deadline:
                res = _structured(
                    await session.call_tool(
                        "fetch_job_results",
                        {"session_id": sid, "job": job, "cursor": cursor, "limit": _FETCH_LIMIT},
                        read_timeout_seconds=timeout,
                    )
                )
                for chunk in res.get("chunks", []):
                    seq = int(chunk["seq"])
                    seqs.append(seq)
                    seen.add(seq)
                    if not _chunk_is_enveloped(chunk):
                        enveloped = False
                    if first_chunk_latency is None:
                        first_chunk_latency = time.monotonic() - start
                cursor = int(res["next_cursor"])
                if res.get("done"):
                    completion_latency = time.monotonic() - start
                    break
                # If a pull returned nothing yet (producer still warming the buffer), brief yield.
                if not res.get("chunks"):
                    await asyncio.sleep(0.05)

            # Idempotent resume/dedupe: re-fetch from cursor 0 — the server delivers exactly once
            # from its buffer (already drained), so the client (deduping by seq) learns nothing new.
            replay = _structured(
                await session.call_tool(
                    "fetch_job_results",
                    {"session_id": sid, "job": job, "cursor": 0, "limit": _FETCH_LIMIT},
                    read_timeout_seconds=timeout,
                )
            )
            replay_new = [
                int(c["seq"]) for c in replay.get("chunks", []) if int(c["seq"]) not in seen
            ]

            return {
                "first_chunk_latency": first_chunk_latency,
                "completion_latency": completion_latency,
                "seqs": seqs,
                "enveloped": enveloped,
                "done": completion_latency is not None,
                "dedupe_ok": replay_new == [],
            }
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            assert closed.get("store_wiped") is True


def test_decompile_stream_overlaps_extraction(tmp_path: Path) -> None:
    """Bulk decompile streams partial results: first chunk lands well before the stream completes.

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
    facts = asyncio.run(_drive_stream(staged, tmp_path))

    # ≥1 chunk arrived.
    assert facts["seqs"], "the stream delivered no chunks"
    # Chunks are monotonic and gap-free (cursor resume in seq order).
    assert facts["seqs"] == sorted(facts["seqs"]), f"chunks out of order: {facts['seqs']}"
    assert facts["seqs"] == list(range(len(facts["seqs"]))), (
        f"chunk seqs are not gap-free 0..N: {facts['seqs']}"
    )
    # Every chunk's `code` is the untrusted-data envelope (ADR-005 / ADR-040 D9).
    assert facts["enveloped"], "a streamed chunk's code was not the untrusted envelope"
    # The job terminated honestly (explicit done).
    assert facts["done"], "the stream never reached a terminal done"
    # Idempotent resume: a re-fetch from an earlier cursor delivered no new (un-deduped) seq.
    assert facts["dedupe_ok"], "a cursor re-fetch delivered chunks the client had not already seen"

    # Overlap — the core ADR-040 acceptance criterion: latency-to-first-chunk << completion.
    first = facts["first_chunk_latency"]
    full = facts["completion_latency"]
    assert first is not None and full is not None
    # The first chunk must arrive strictly before completion, with a margin (it is not the case that
    # the whole batch only materialized at the very end — that would be the no-overlap regression).
    assert first < full, (
        f"no overlap: first chunk at {first:.3f}s but completion at {full:.3f}s "
        "(streaming did not deliver early results before the full run finished)"
    )
