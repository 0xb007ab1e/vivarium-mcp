"""Integration: a session's export carries EXACTLY the user-authored writes — no auto content (F7).

Regression guard for the **F7 class** (ADR-027 / ADR-028): a session that makes a known number of
user-authored writes must export EXACTLY that many entries — ZERO auto-generated comments, structs,
or symbols leaked from Ghidra's own analysis. The prior bug exported the program's full annotation
surface (Ghidra-synthesized labels/comments/types), inflating the document with content the user
never authored. The fix (ADR-027) exports only the per-session *change log*; this test proves, end
to end against a **live worker**, that a session making 1 rename + 1 comment + 1 struct exports
EXACTLY those 3 entries and nothing else.

This is the committed promotion of the ad-hoc v1.3 ``verify_f7`` acceptance scenario into a
deterministic, hard-gated regression test. It is the **F7 hard gate** of the live-regression harness
(``.github/workflows/live-regression.yml``): a KNOWN-COUNT check (deterministic), distinct from the
advisory naming-accuracy metrics (non-gating, not run here).

Why a gated, in-container integration test (not a unit test): the export enumerates the real
program's change log through the JVM/PyGhidra edge (TB3, ADR-001) — excluded from server unit
coverage and only validatable against a real Ghidra worker. The pure change-log accounting is
unit-tested hermetically elsewhere; this test exercises the real chain.

Posture: it drives the **real MCP stdio chain** (mirroring ``scripts/acceptance_run.py``'s client
setup and ``tests/e2e/test_groundtruth_oss.py``'s stdio journey) — it launches ``python -m
ghidra_mcp`` (composition root → real ``RpcGhidraAdapter`` → hardened worker container) and drives
it as an MCP client. The input is a tiny, benign, locally-built micro-binary (no real malware,
master §5): the test compiles a 2-function C source into the ``tmp_path`` import root, which the
server confines + read-only mounts into the worker. (``read_timeout_seconds`` takes a
``datetime.timedelta``, NOT an int.)

Gating (reused verbatim from ``conftest.py``): this test is ``integration``-marked, so the default
``pytest`` / unit-coverage run SKIPS it (kept green + hermetic). It runs only when
``GHIDRA_MCP_INTEGRATION`` is truthy AND a real worker image + container engine + a C compiler are
available. The PM performs that live verification on a gated worker-image run.

Honored environment (same as the other integration/e2e tests):
    * ``GHIDRA_MCP_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``GHIDRA_MCP_WORKER_IMAGE`` — the pinned-by-digest worker image ref (reaches the adapter).
    * ``GHIDRA_MCP_CONTAINER_ENGINE`` / ``GHIDRA_MCP_WORKER_RUNTIME`` / ``GHIDRA_MCP_WORKER_UID`` /
      ``GHIDRA_MCP_WORKER_GID`` / ``GHIDRA_MCP_RPC_SOCKET_DIR`` — worker spawn config (composition
      root reads them from the inherited environment).
    * ``GHIDRA_MCP_E2E_TIMEOUT`` — per-call MCP read timeout seconds for import/analyze.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

# --- known-count constants -----------------------------------------------------------------------
#: Exactly the user-authored writes this session makes. The export must carry EXACTLY this multiset
#: of entry kinds (total 3) and ZERO auto-generated content — the crux of the F7 regression.
#: ADR-032: session-authored composites now export as ONE ``define_types`` batch entry (schema
#: v2), not an individual ``define_struct`` — the single struct below counts as ``define_types``.
_EXPECTED_COUNTS: dict[str, int] = {
    "rename_function": 1,
    "set_comment": 1,
    "define_types": 1,
}
_EXPECTED_TOTAL = sum(_EXPECTED_COUNTS.values())

#: The benign, recognizable names/values applied (server-side write-name validation IS in play here,
#: so they must satisfy the conservative write-name allow-list).
_RENAMED_FN = "adr028_f7_renamed_fn"
_COMMENT_TEXT = "adr028 f7 eol comment"
_STRUCT_NAME = "adr028_f7_struct"
_STRUCT_FIELD = "field0"

#: A tiny, benign C source with TWO defined functions so the import yields at least one renameable,
#: non-external function. Nothing hostile; compiled locally into the tmp import root.
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
    return datetime.timedelta(seconds=int(os.environ.get("GHIDRA_MCP_E2E_TIMEOUT", "600")))


def _engine_available() -> bool:
    """Return whether the configured container engine binary is resolvable on ``PATH``."""
    engine = os.environ.get("GHIDRA_MCP_CONTAINER_ENGINE", "podman").strip() or "podman"
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


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured JSON output from an MCP ``CallToolResult`` (fail closed).

    Fail-closed on an error envelope (``isError`` OR the ``{type,title,retryable,status}`` shape
    FastMCP serializes a returned error model into) — never silently treated as success.

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


def _assert_not_error_envelope(payload: dict[str, Any]) -> None:
    """Fail closed when ``payload`` is the frozen error envelope rather than a tool result.

    The error envelope (``docs/contracts/error-envelope.md``) has the discriminating keys
    ``type`` + ``title`` + ``retryable`` + ``status``; a successful tool result never carries that
    set. Detecting it surfaces a worker-unavailable / analysis-failed / session-invalid outcome as a
    clear failure instead of mistaking it for empty data.

    Args:
        payload: A structured tool-result dict.

    Raises:
        AssertionError: If ``payload`` matches the error-envelope shape.
    """
    if {"type", "title", "retryable"} <= payload.keys() and "status" in payload:
        raise AssertionError(f"tool returned error envelope: {payload.get('type')!r}")


async def _drive_known_count(binary: Path, import_root: Path) -> dict[str, int]:
    """Drive the real stdio chain through the F7 known-count scenario and return the export counts.

    Steps: ``session_create`` → ``session_import`` (the micro-binary) → ``session_analyze`` →
    ``session_enable_writes{allow_structural: true}`` → exactly 1 ``rename_function`` (the first
    listed function) + 1 ``set_comment`` (EOL at that function's address) + 1 ``define_struct``
    (a 1-field struct) → ``session_export_annotations``. The struct exports as ONE ``define_types``
    batch entry (ADR-032, schema v2). Returns the multiset of exported entry ``kind`` values for the
    caller to assert against :data:`_EXPECTED_COUNTS`.

    Args:
        binary: The compiled micro-binary to import.
        import_root: The directory the binary lives under (the server's confined import root).

    Returns:
        A ``{kind: count}`` map of the exported annotation entries.
    """
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ghidra_mcp"],
        env={**os.environ, "GHIDRA_MCP_IMPORT_ROOT": str(import_root)},
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

            functions = _structured(
                await session.call_tool(
                    "list_functions", {"session_id": sid, "offset": 0, "limit": 5}
                )
            )
            rows = functions.get("functions") or []
            assert rows, "no functions recovered; cannot exercise the known-count export path"
            first_addr = rows[0]["address"]

            # Grant write consent (default-deny gate, ADR-012); allow_structural for define_struct.
            _structured(
                await session.call_tool(
                    "session_enable_writes", {"session_id": sid, "allow_structural": True}
                )
            )

            # --- exactly the three user-authored writes -------------------------------------------
            rename = _structured(
                await session.call_tool(
                    "rename_function",
                    {"session_id": sid, "function": first_addr, "new_name": _RENAMED_FN},
                )
            )
            assert rename.get("applied") is True, f"rename_function did not apply: {rename!r}"

            comment = _structured(
                await session.call_tool(
                    "set_comment",
                    {
                        "session_id": sid,
                        "address": first_addr,
                        "comment_type": "EOL",
                        "text": _COMMENT_TEXT,
                    },
                )
            )
            assert comment.get("applied") is True, f"set_comment did not apply: {comment!r}"

            struct = _structured(
                await session.call_tool(
                    "define_struct",
                    {
                        "session_id": sid,
                        "name": _STRUCT_NAME,
                        "fields": [{"name": _STRUCT_FIELD, "type": {"base": "int32"}}],
                    },
                )
            )
            assert struct.get("applied") is True, f"define_struct did not apply: {struct!r}"

            # --- export and count the change log --------------------------------------------------
            exported = _structured(
                await session.call_tool("session_export_annotations", {"session_id": sid})
            )
            # The export result wraps the document: {"document": {"schema_version", "binary",
            # "entries": [...]}} — read entries from under `document` (fall back to top-level).
            document = exported.get("document")
            entries = (
                document.get("entries") if isinstance(document, dict) else None
            ) or exported.get("entries")
            assert isinstance(entries, list), f"export missing entries list: {exported!r}"
            kinds: list[str] = [
                str(e["kind"]) for e in entries if isinstance(e, dict) and "kind" in e
            ]
            return dict(Counter(kinds))
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            # Containment invariant (ADR-002): the per-session store is wiped on close.
            assert closed.get("store_wiped") is True


def test_export_carries_exactly_the_user_authored_writes(tmp_path: Path) -> None:
    """A session making 1 rename + 1 comment + 1 struct exports EXACTLY those 3 entries (F7).

    The crux: the export document carries EXACTLY :data:`_EXPECTED_COUNTS` (total 3) and nothing
    else — ZERO auto-generated comments/structs/symbols. A regression (exporting Ghidra's full
    annotation surface) re-surfaces here as an inflated count, instead of silently passing.

    Args:
        tmp_path: The pytest temp dir used as the (host) import root the micro-binary is built into.
    """
    if not _engine_available():
        engine = os.environ.get("GHIDRA_MCP_CONTAINER_ENGINE", "podman").strip() or "podman"
        pytest.skip(f"container engine {engine!r} not found on PATH")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) on PATH to build the benign micro-binary")

    import_root = tmp_path
    binary = _build_micro_binary(import_root)

    counts = asyncio.run(_drive_known_count(binary, import_root))

    assert counts == _EXPECTED_COUNTS, (
        f"export entry counts did not match the known authored set (F7 regression?): "
        f"got {counts!r}, expected {_EXPECTED_COUNTS!r} (total {_EXPECTED_TOTAL})"
    )
