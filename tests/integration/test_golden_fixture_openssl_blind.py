"""Integration: the OpenSSL blind-analysis golden fixture reproduces against a live worker.

Promotes ``samples/openssl-blind-analysis/`` into a committed regression fixture. The blind
validation (see that directory's REPORT.md) identified 15 functions in a stripped, static
OpenSSL 4.0.1 binary and verified them against source; ``expected-analysis.json`` is the golden
record of that run (subject hashes, program-level counts, and the 15 function addresses).

This test re-runs the real MCP stdio chain (``python -m vivarium`` -> ``RpcGhidraAdapter`` ->
hardened worker container -> Ghidra) against the same binary and asserts the analysis still
reproduces the golden facts:

* the built binary's SHA-256 matches the golden subject hash (reproducibility gate), and
* ``program_summary`` returns the golden ``function_count`` / ``import_count`` / ``export_count``
  / ``entry_point``, and
* every one of the 15 golden function addresses still resolves to a function.

It does NOT re-assert the human-verified source identities (e.g. ``ERR_set_debug``): the subject
is stripped, so the tool emits ``FUN_<addr>`` names. The source identity lives in the report; the
fixture pins the binary + the structural analysis the tool produces.

Why gated/integration: it drives the JVM/PyGhidra edge (TB3, ADR-001) through a real worker, so
it is excluded from hermetic unit CI and runs only under the live-regression harness.

Honored environment (same as the other integration tests):
    * ``VIVARIUM_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``VIVARIUM_WORKER_IMAGE`` / ``VIVARIUM_CONTAINER_ENGINE`` / ``VIVARIUM_WORKER_RUNTIME`` /
      ``VIVARIUM_WORKER_UID`` / ``VIVARIUM_WORKER_GID`` / ``VIVARIUM_RPC_SOCKET_DIR`` — worker
      spawn config (read from the inherited environment by the composition root).
    * ``VIVARIUM_E2E_TIMEOUT`` — per-call MCP read timeout seconds for import/analyze.

Re-golding note: ``function_count`` is deterministic for the pinned-by-digest worker image. A
deliberate Ghidra/worker bump can shift it; when that happens, re-run the blind sample and update
``expected-analysis.json`` rather than loosening this assertion.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

#: Repo-relative location of the promoted sample (golden file + the LFS-committed subject binary).
_SAMPLE_DIR = Path(__file__).resolve().parents[2] / "samples" / "openssl-blind-analysis"
_GOLDEN_FILE = _SAMPLE_DIR / "expected-analysis.json"
_BINARY = _SAMPLE_DIR / "openssl.blind"


def _read_timeout() -> datetime.timedelta:
    """Build the MCP client per-call read timeout (a ``datetime.timedelta``, NOT an int)."""
    return datetime.timedelta(seconds=int(os.environ.get("VIVARIUM_E2E_TIMEOUT", "900")))


def _engine_available() -> bool:
    """Return whether the configured container engine binary is resolvable on ``PATH``."""
    engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
    return shutil.which(engine) is not None


def _load_golden() -> dict[str, Any]:
    """Load the committed golden analysis record (fail closed if missing/invalid)."""
    assert _GOLDEN_FILE.is_file(), f"golden fixture not found: {_GOLDEN_FILE}"
    data: dict[str, Any] = json.loads(_GOLDEN_FILE.read_text(encoding="utf-8"))
    return data


def _sha256(path: Path) -> str:
    """Return the hex SHA-256 of ``path`` (streamed, never loading the whole file)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _addr_int(addr: object) -> int:
    """Normalize an address (``"0x005c31c0"`` / ``"005c31c0"``) to an int for robust comparison."""
    return int(str(addr).strip().lower().removeprefix("0x") or "0", 16)


def _ensure_binary() -> Path | None:
    """Return the committed fixture binary, or ``None`` if absent / an unsmudged LFS pointer.

    The exact 7.9 MiB subject is committed via Git LFS (``.gitattributes``: ``*.blind``); the
    OpenSSL static build is not byte-reproducible across toolchains, so the recorded bytes are
    preserved rather than rebuilt. On a checkout that did not fetch LFS objects the path is a tiny
    text pointer (``version https://git-lfs...``), not the binary; return ``None`` then so the
    caller skips with a ``git lfs pull`` hint instead of failing the SHA-256 gate on pointer bytes.

    Returns:
        The path to the real binary, or ``None`` if absent or not yet pulled from LFS.
    """
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


async def _drive_golden(binary: Path, import_root: Path) -> dict[str, Any]:
    """Drive the real stdio chain through import + analyze and collect the facts to compare.

    Steps: ``session_create`` -> ``session_import`` -> ``session_analyze`` -> ``program_summary``
    -> ``get_function`` for each golden address. Returns the program-level summary plus the set of
    golden addresses that resolved to a function, for the caller to assert against the golden file.

    Args:
        binary: The fixture binary to import.
        import_root: The directory the binary lives under (the server's confined import root).

    Returns:
        A dict with ``summary`` (the program_summary output), ``resolved_addrs`` (golden
        addresses that resolved to a function), and ``golden_addrs`` (all golden addresses).
    """
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    golden = _load_golden()
    golden_addrs = {_addr_int(f["address"]) for f in golden["function_identifications"]}

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
            summary = _structured(
                await session.call_tool(
                    "program_summary", {"session_id": sid}, read_timeout_seconds=timeout
                )
            )
            resolved: set[int] = set()
            for addr in sorted(golden_addrs):
                hex_addr = f"{addr:08x}"
                try:
                    detail = _structured(
                        await session.call_tool(
                            "get_function", {"session_id": sid, "function": hex_addr}
                        )
                    )
                except AssertionError:
                    continue
                if _addr_int(detail.get("address", "")) == addr:
                    resolved.add(addr)
            return {"summary": summary, "resolved_addrs": resolved, "golden_addrs": golden_addrs}
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            assert closed.get("store_wiped") is True


def test_openssl_blind_golden_fixture_reproduces(tmp_path: Path) -> None:
    """The OpenSSL blind fixture reproduces its golden program facts and function addresses.

    Asserts the built binary's SHA-256 matches the golden subject hash, that ``program_summary``
    returns the golden ``function_count`` / ``import_count`` / ``export_count`` / ``entry_point``,
    and that every golden function address still resolves to a function.

    Args:
        tmp_path: Unused for the import root (the binary lives in the sample dir), kept for parity
            and any future scratch needs.
    """
    if not _engine_available():
        engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
        pytest.skip(f"container engine {engine!r} not found on PATH")
    binary = _ensure_binary()
    if binary is None:
        pytest.skip("openssl.blind fixture absent or not pulled from Git LFS (run: git lfs pull)")

    golden = _load_golden()
    subject = golden["subject"]
    program = golden["program_level"]

    # 1) Reproducibility gate: the binary is exactly the analyzed subject.
    actual_sha = _sha256(binary)
    assert actual_sha == subject["sha256"], (
        f"fixture binary SHA-256 mismatch: expected {subject['sha256']}, got {actual_sha}. "
        "The build is not reproducing the recorded subject; re-check the toolchain."
    )

    # 2) Real-worker analysis reproduces the golden program-level facts.
    # Stage the binary into the tmp import root the server confines + read-only mounts.
    staged = tmp_path / "openssl.blind"
    shutil.copy2(binary, staged)
    result = asyncio.run(_drive_golden(staged, tmp_path))
    summary = result["summary"]

    assert int(summary["function_count"]) == int(program["function_count"]), (
        f"function_count drift: got {summary['function_count']}, "
        f"golden {program['function_count']} (re-gold expected-analysis.json on a worker bump)"
    )
    assert int(summary["import_count"]) == int(program["import_count"])
    assert int(summary["export_count"]) == int(program["export_count"])

    entry = summary.get("metadata", {}).get("entry_point") or summary.get("entry_point")
    assert _addr_int(entry) == _addr_int(program["entry_point"]), (
        f"entry_point drift: got {entry!r}, golden {program['entry_point']!r}"
    )

    # 3) Every recorded function address still resolves to a function.
    missing = result["golden_addrs"] - result["resolved_addrs"]
    assert not missing, (
        f"{len(missing)} golden function address(es) no longer resolve: "
        + ", ".join(f"0x{a:08x}" for a in sorted(missing))
    )
