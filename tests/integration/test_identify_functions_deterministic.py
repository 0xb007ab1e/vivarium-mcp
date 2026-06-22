"""DETERMINISTIC, same-toolchain ELF FID hard gate against the BUNDLED DBs (ADR-043).

The deterministic counterpart to ``test_identify_functions_elf_match.py``, which builds its probe
with the *host/CI* compiler; cross-toolchain skew makes its count unstable, so that test is
advisory (correctness-when-matched, skip on 0). Here the probes are compiled with the worker
image's **own** toolchain (the same pinned wolfi gcc + pinned library source that produced the
bundled ``.fidbf``) by the non-shipped ``fid-probes`` Containerfile stage, extracted by the
live-regression CI job into ``VIVARIUM_FID_PROBE_DIR``. Same toolchain => FID full-hashes match
deterministically, so this asserts a hard **>= floor** match count per library, proving the
bundled DBs identify library code in an *independently compiled* consumer (which the in-worker
self-match does not cover).

Gated by ``conftest.py`` (``integration``-marked => SKIPPED in the default hermetic run). It also
SKIPs when ``VIVARIUM_FID_PROBE_DIR`` is unset (local dev without the CI-built probes) or a probe
file is absent. When the dir IS present this is a HARD gate (no skip on a low/zero count, which is
a real regression).
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

#: Per-probe gate: (filename, minimum match count, recognizable library-name substrings). The floors
#: sit well below the observed same-toolchain counts (zlib 52, musl 50 at authoring) so a deliberate
#: pin bump (wolfi base / library / Ghidra) that nudges the count does not flake the gate, but still
#: proving dozens of real cross-binary matches. A drop below the floor is a genuine regression.
_PROBES: tuple[tuple[str, int, tuple[str, ...]], ...] = (
    ("zlib_probe", 20, ("deflate", "inflate", "crc32", "adler32", "_tr_", "compress")),
    ("musl_probe", 20, ("mem", "str", "malloc", "__lib", "qsort", "intscan", "__std")),
)


def _read_timeout() -> datetime.timedelta:
    """Build the MCP client per-call read timeout (a ``datetime.timedelta``)."""
    return datetime.timedelta(seconds=int(os.environ.get("VIVARIUM_E2E_TIMEOUT", "1200")))


def _engine_available() -> bool:
    """Return whether the configured container engine binary is resolvable on ``PATH``."""
    engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
    return shutil.which(engine) is not None


def _probe_dir() -> Path | None:
    """Return the directory holding the CI-built same-toolchain probes, or ``None`` if unset."""
    raw = os.environ.get("VIVARIUM_FID_PROBE_DIR", "").strip()
    return Path(raw) if raw else None


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured JSON output from an MCP ``CallToolResult`` (fail closed)."""
    if getattr(result, "isError", False):
        raise AssertionError(f"tool returned an error envelope: {getattr(result, 'content', None)}")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parsed: dict[str, Any] = json.loads(text)
            return parsed
    raise AssertionError("tool result carried no structured content")


def _names(result: dict[str, Any]) -> list[str]:
    """Extract the matched library function names (unwrapping the untrusted-data envelope)."""
    names: list[str] = []
    for match in result.get("matches", []) or []:
        raw = match.get("matched_name")
        if isinstance(raw, dict):
            raw = raw.get("value", "")
        if isinstance(raw, str):
            names.append(raw)
    return names


async def _drive_identify(binary: Path, import_root: Path) -> dict[str, Any]:
    """Drive the real stdio chain through ``identify_functions`` and return its structured output.

    Steps: ``session_create`` → ``session_import`` → ``session_analyze`` → ``identify_functions``.
    Fails closed on any error envelope; the session is always closed and its store-wipe asserted.
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
            return _structured(
                await session.call_tool(
                    "identify_functions", {"session_id": sid}, read_timeout_seconds=timeout
                )
            )
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            assert closed.get("store_wiped") is True


@pytest.mark.parametrize(("filename", "min_matches", "hints"), _PROBES)
def test_bundled_db_matches_same_toolchain_probe(
    filename: str, min_matches: int, hints: tuple[str, ...]
) -> None:
    """A same-toolchain probe deterministically matches >= floor functions of its library.

    Asserts a well-formed result, ``total >= min_matches``, and that every matched row carries a
    recognizable library name. SKIPs only on missing prerequisites (no engine,
    ``VIVARIUM_FID_PROBE_DIR`` unset, or the probe file absent), NOT on a low/zero count, which is a
    real regression. Do NOT add a skip-on-zero here: these probes are same-toolchain, so a drop to
    zero means the bundled DB stopped matching (the gate's whole purpose). See
    ``test_identify_functions_elf_match.py`` for the advisory host-compiled cross-toolchain variant.

    Args:
        filename: The probe basename under ``VIVARIUM_FID_PROBE_DIR``.
        min_matches: The minimum deterministic match count this probe must reach.
        hints: Recognizable substrings; at least one matched name must contain one.
    """
    if not _engine_available():
        engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
        pytest.skip(f"container engine {engine!r} not found on PATH")

    probe_dir = _probe_dir()
    if probe_dir is None:
        pytest.skip(
            "VIVARIUM_FID_PROBE_DIR unset — same-toolchain probes are built by the live-regression "
            "CI job from the (non-shipped) fid-probes stage; not present in local dev."
        )
    binary = probe_dir / filename
    if not binary.is_file():
        pytest.skip(f"probe {filename!r} not found in {probe_dir} (fid-probes stage not extracted)")

    result = asyncio.run(_drive_identify(binary, probe_dir))

    matches = result.get("matches")
    assert isinstance(matches, list), f"matches not a list: {result!r}"
    assert result.get("total") == len(matches), f"total != len(matches): {result!r}"
    assert isinstance(result.get("truncated"), bool), f"truncated not a bool: {result!r}"

    total = int(result.get("total", 0))
    assert total >= min_matches, (
        f"DETERMINISTIC gate regression: {filename} matched {total} functions against the bundled "
        f"DB, below the floor of {min_matches}. Same-toolchain matches must be stable; investigate "
        f"the bundled DB / generator / toolchain pin before lowering this floor. Result: {result!r}"
    )

    names = _names(result)
    assert names, f"matched rows carried no names: {result!r}"
    assert any(any(h in name.lower() for h in hints) for name in names), (
        f"expected a recognizable library name (one of {hints}) among matches, got {names[:20]!r}"
    )
    print(f"[live-regression] deterministic FID gate: {filename} = {total} (floor {min_matches})")
