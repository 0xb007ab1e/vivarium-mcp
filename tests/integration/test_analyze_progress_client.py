"""Integration: a real MCP client receives ``notifications/progress`` during ``session_analyze``.

ADR-030 (Phase 2) streams analysis progress to the client: when the client supplies a standard
MCP ``progressToken`` (which the SDK does automatically when a ``progress_callback`` is passed),
the server relays each worker ``$/progress`` frame as a ``notifications/progress`` (percent out of
100; a closed-vocabulary phase as the message), over both the stdio and HTTP/SSE transports. The
unit tests cover the relay binding with a fake Context; this test closes the gap by proving an
**actual MCP client** receives those notifications during a **real** analyze on a **live worker**.

It reuses the LFS-committed OpenSSL fixture (``samples/openssl-blind-analysis/openssl.blind``)
because it is large enough that auto-analysis reliably emits progress frames (a micro-binary
analyzes too fast to report any). The subject is benign (OpenSSL 4.0.1).

Redaction (master §5 / ADR-030): progress messages carry only a short, closed-vocabulary phase
and a percent — never binary-derived content. The test asserts that shape.

Why gated/integration: it drives the JVM/PyGhidra edge through a real worker; excluded from
hermetic unit CI, run only under the live-regression harness (gated by ``VIVARIUM_INTEGRATION``).
Honors the same worker-spawn environment as the other integration tests.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

_SAMPLE_DIR = Path(__file__).resolve().parents[2] / "samples" / "openssl-blind-analysis"
_BINARY = _SAMPLE_DIR / "openssl.blind"


def _read_timeout() -> datetime.timedelta:
    """Build the MCP client per-call read timeout (a ``datetime.timedelta``, NOT an int)."""
    return datetime.timedelta(seconds=int(os.environ.get("VIVARIUM_E2E_TIMEOUT", "900")))


def _engine_available() -> bool:
    """Return whether the configured container engine binary is resolvable on ``PATH``."""
    engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
    return shutil.which(engine) is not None


def _binary_or_none() -> Path | None:
    """Return the LFS-committed fixture binary, or ``None`` if absent / an unsmudged pointer."""
    if not _BINARY.is_file():
        return None
    if _BINARY.stat().st_size < 4096 and _BINARY.read_bytes()[:64].startswith(
        b"version https://git-lfs"
    ):
        return None
    return _BINARY


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured JSON output from an MCP ``CallToolResult`` (fail closed)."""
    if getattr(result, "isError", False):
        raise AssertionError(f"tool returned an error envelope: {getattr(result, 'content', None)}")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        if {"type", "title", "retryable"} <= structured.keys() and "status" in structured:
            raise AssertionError(f"tool returned error envelope: {structured.get('type')!r}")
        return structured
    raise AssertionError("tool result carried no structured content")


async def _drive_progress(
    binary: Path, import_root: Path
) -> list[tuple[float, float | None, str | None]]:
    """Drive a real analyze with a client progress callback; return the captured progress events.

    Args:
        binary: The fixture binary to import and analyze.
        import_root: The directory the binary lives under (the server's confined import root).

    Returns:
        The list of ``(progress, total, message)`` tuples the MCP client received.
    """
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    events: list[tuple[float, float | None, str | None]] = []

    async def _on_progress(progress: float, total: float | None, message: str | None) -> None:
        events.append((progress, total, message))

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
            # Passing progress_callback makes the SDK attach a progressToken, which the server
            # treats as opt-in: it forces worker progress emission and relays each frame here.
            info = _structured(
                await session.call_tool(
                    "session_analyze",
                    {"session_id": sid},
                    read_timeout_seconds=timeout,
                    progress_callback=_on_progress,
                )
            )
            assert info.get("binary_sha256"), (
                f"analyze did not return a populated SessionInfo: {info!r}"
            )
            return events
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            assert closed.get("store_wiped") is True


def test_client_receives_progress_notifications_during_analyze(tmp_path: Path) -> None:
    """A real MCP client gets ``notifications/progress`` (percent + closed phase) during analyze.

    Proves ADR-030 Phase 2 end to end: at least one progress notification reaches the client, and
    each carries only safe, bounded content (a numeric percent and a short closed-vocabulary phase,
    never binary-derived text).

    Args:
        tmp_path: The pytest temp dir used as the (host) import root the fixture is staged into.
    """
    if not _engine_available():
        engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
        pytest.skip(f"container engine {engine!r} not found on PATH")
    binary = _binary_or_none()
    if binary is None:
        pytest.skip("openssl.blind fixture absent or not pulled from Git LFS (run: git lfs pull)")

    staged = tmp_path / "openssl.blind"
    shutil.copy2(binary, staged)

    events = asyncio.run(_drive_progress(staged, tmp_path))

    assert events, (
        "client received no notifications/progress during analyze (ADR-030 Phase 2 regression?)"
    )
    for progress, total, message in events:
        assert isinstance(progress, (int, float)) and 0.0 <= float(progress) <= 100.0, (
            f"progress out of range: {progress!r}"
        )
        assert total is None or float(total) == 100.0, f"unexpected total: {total!r}"
        # Redaction: the phase message must be short, printable, and free of binary-derived content.
        if message is not None:
            assert isinstance(message, str) and len(message) <= 64 and message.isprintable(), (
                f"progress message is not a short safe phase label: {message!r}"
            )
