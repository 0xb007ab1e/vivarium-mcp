"""Real-worker end-to-end test for ELF FID matching via a BUNDLED DB (ADR-043 Phase 2).

This is the Phase-2 live-regression HARD GATE: a benign, statically-linked **zlib** ELF built at
test time, driven through the real MCP stdio chain, must yield **>=1 real FID match** from
``identify_functions`` against the **bundled** zlib FunctionID database (D3). It extends the proven
self-match approach (``test_identify_functions_selfmatch.py``) to the *shipped* DBs — proving the
worker-startup attach (``_attach_bundled_fid_dbs``) activates the bundled DB and that
``identify_functions`` then matches Linux library code (closing Phase 1's MSVC/Windows skew).

It mirrors the harness of ``test_identify_functions_fid.py`` (host-run server → real
``RpcGhidraAdapter`` → hardened worker under crun/runsc), and is gated by ``conftest.py``
(``integration``-marked → SKIPPED in the default hermetic run; runs only when
``VIVARIUM_INTEGRATION`` is truthy with a real worker image + container engine + a C compiler).

>>> IT WILL SKIP UNTIL THE PM BUNDLES THE zlib DB + BUILDS THE IMAGE. <<<
The deterministic code (the worker startup attach, the generator, the license gate) ships in this
PR; GENERATING the actual ``zlib.fidbf`` (scripts/fid/generate_fidb.py) and BAKING it into the
worker image (Containerfile.worker ``COPY deploy/fid/``) are the PM's GATED validation steps. Until
the image carries the bundled zlib DB, ``identify_functions`` returns 0 matches for the zlib ELF
(the pre-Phase-2 baseline) — so this test SKIPs with an explicit "DB not yet bundled" message rather
than failing. Once the DB is bundled, the 0-match path becomes a regression (flip the skip below to
an ``assert`` — see the marked line) and this becomes a hard gate in ``live-regression.yml``.
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

#: A tiny, benign C program that LINKS zlib statically so its compiled output contains recognizable
#: zlib library functions (e.g. ``deflate``/``inflate``/``crc32``) for the bundled zlib FID DB to
#: match. Nothing hostile (master §5); built locally into the tmp import root (never the repo).
_ZLIB_C = r"""
#include <string.h>
#include <zlib.h>

int main(int argc, char **argv) {
    (void)argv;
    unsigned char in[64];
    unsigned char out[128];
    memset(in, (unsigned char)argc, sizeof(in));

    z_stream s;
    memset(&s, 0, sizeof(s));
    if (deflateInit(&s, Z_DEFAULT_COMPRESSION) != Z_OK) return 1;
    s.next_in = in;
    s.avail_in = sizeof(in);
    s.next_out = out;
    s.avail_out = sizeof(out);
    deflate(&s, Z_FINISH);
    deflateEnd(&s);

    unsigned long c = crc32(0L, in, sizeof(in));
    return (int)(c & 0xff);
}
"""

#: A recognizable substring expected in a matched zlib function name, used to assert the match is
#: really zlib (not an incidental match). zlib exports include deflate/inflate/crc32/adler32.
_ZLIB_NAME_HINTS = ("deflate", "inflate", "crc32", "adler32", "zlib")


def _read_timeout() -> datetime.timedelta:
    """Build the MCP client per-call read timeout (a ``datetime.timedelta``, NOT an int)."""
    return datetime.timedelta(seconds=int(os.environ.get("VIVARIUM_E2E_TIMEOUT", "900")))


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


def _build_zlib_static_binary(out_dir: Path) -> Path | None:
    """Compile the benign zlib-static program into ``out_dir``; return its path or ``None``.

    Built non-PIE and statically linked against zlib so Ghidra recovers concrete zlib library
    functions to identify. Returns ``None`` (→ the test SKIPs) when zlib dev headers / the static
    archive are not present or the link fails — this test cannot run without zlib to link.

    Args:
        out_dir: The directory to write the source + binary into (the server's import root).

    Returns:
        The compiled binary path, or ``None`` when zlib is unavailable to link statically.
    """
    compiler = _compiler()
    if compiler is None:
        return None
    src = out_dir / "zlibprog.c"
    src.write_text(_ZLIB_C, encoding="utf-8")
    binary = out_dir / "zlibprog"
    # -static pulls the whole libc+libz in; if that toolchain support is missing, fall back to
    # static-linking only libz (-Wl,-Bstatic -lz). Either way we need libz to link.
    for link_args in (
        ["-static", "-lz"],
        ["-Wl,-Bstatic", "-lz", "-Wl,-Bdynamic"],
        ["-l:libz.a"],
    ):
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); compiler resolved from PATH.
            [compiler, "-O2", "-no-pie", "-fno-pie", "-o", str(binary), str(src), *link_args],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and binary.exists():
            return binary
    return None


def _assert_not_error_envelope(payload: dict[str, Any]) -> None:
    """Fail closed when ``payload`` is the frozen error envelope rather than a tool result."""
    if {"type", "title", "retryable"} <= payload.keys() and "status" in payload:
        raise AssertionError(f"tool returned error envelope: {payload.get('type')!r}")


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


async def _drive_identify(binary: Path, import_root: Path) -> dict[str, Any]:
    """Drive the real stdio chain through ``identify_functions`` and return its structured output.

    Steps: ``session_create`` → ``session_import`` → ``session_analyze`` → ``identify_functions``.
    Every step fails closed on an error envelope; the session is always closed in a ``finally`` and
    its store-wipe asserted (ADR-002 containment).
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
            return _structured(
                await session.call_tool(
                    "identify_functions",
                    {"session_id": sid},
                    read_timeout_seconds=timeout,
                )
            )
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            assert closed.get("store_wiped") is True


def _names(result: dict[str, Any]) -> list[str]:
    """Extract the matched library function names from an identify_functions result (unwrapped).

    ``matched_name`` is wrapped in the untrusted-data envelope; the value lives under ``value`` for
    a dict-shaped envelope, else the raw string. We only need the text to assert it is a zlib name.
    """
    names: list[str] = []
    for match in result.get("matches", []) or []:
        raw = match.get("matched_name")
        if isinstance(raw, dict):
            raw = raw.get("value", "")
        if isinstance(raw, str):
            names.append(raw)
    return names


def test_identify_functions_matches_bundled_zlib_elf(tmp_path: Path) -> None:
    """A zlib-static ELF yields >=1 real zlib FID match from the BUNDLED DB (ADR-043 hard gate).

    SKIPs cleanly when prerequisites are missing (no engine / no compiler / no zlib to link), and —
    until the PM bundles the zlib DB into the worker image — when the result is empty (the
    pre-Phase-2 baseline). Once the DB is bundled, flip the marked skip to a hard ``assert`` so this
    is a deterministic hard gate.

    Args:
        tmp_path: The pytest temp dir used as the (host) import root the binary is built into.
    """
    if not _engine_available():
        engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
        pytest.skip(f"container engine {engine!r} not found on PATH")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) on PATH to build the benign zlib-static binary")

    import_root = tmp_path
    binary = _build_zlib_static_binary(import_root)
    if binary is None:
        pytest.skip(
            "zlib dev headers / static archive (libz.a) unavailable to link the test binary"
        )

    result = asyncio.run(_drive_identify(binary, import_root))

    # The FID edge ran and shaped a well-formed result.
    matches = result.get("matches")
    assert isinstance(matches, list), f"matches not a list: {result!r}"
    assert result.get("total") == len(matches), f"total != len(matches): {result!r}"
    assert isinstance(result.get("truncated"), bool), f"truncated not a bool: {result!r}"

    if result.get("total", 0) == 0:
        # >>> PM-GATED: the worker image does not yet bundle the zlib FID DB. Once the PM generates
        # >>> zlib.fidbf (scripts/fid/generate_fidb.py) and bakes it in (Containerfile.worker COPY
        # >>> deploy/fid/), this becomes a regression: REPLACE this skip with
        # >>>   raise AssertionError("expected >=1 zlib FID match — bundled DB missing/inactive")
        # >>> so the hard gate fails loud instead of skipping.
        pytest.skip(
            "no FID matches for the zlib ELF — the bundled zlib DB is not yet baked into the "
            "worker image (PM-gated). This is the pre-Phase-2 baseline; flip to a hard assert once "
            "the DB is bundled (see the comment in this test)."
        )

    names = _names(result)
    assert names, f"matched rows carried no names: {result!r}"
    assert any(any(hint in name.lower() for hint in _ZLIB_NAME_HINTS) for name in names), (
        f"expected a recognizable zlib function name among matches, got {names!r}"
    )
    print(f"[live-regression] zlib-ELF FID matches={result.get('total')} names={names[:10]}")
