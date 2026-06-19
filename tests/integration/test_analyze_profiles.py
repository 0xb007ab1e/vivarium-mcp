"""Integration: every analyzer ``profile`` analyzes on a real worker (ADR-029 B binding gate).

Regression guard for the **ADR-029 analyzer-profile JVM edge**, folded into the ADR-028
live-regression harness. The ``light``/``deep`` profiles are the *only* thing that drives the
speculative option-overlay binding in ``_jvm_bridge._gh_analyze``::

    options = self._program.getOptions(self._program.ANALYSIS_PROPERTIES)
    for option_name, enabled in overlay.items():
        options.setBoolean(option_name, enabled)

The ``default`` profile maps to an EMPTY overlay and skips that block entirely (the documented
no-op guarantee), so nothing recurring exercised the overlay path until now. That code is the
``# pragma: no cover - JVM edge`` class (TB3, ADR-001) that hermetic unit tests structurally cannot
reach — exactly the F2/F7 lesson: a renamed ``ANALYSIS_PROPERTIES`` constant or a changed
``getOptions``/``setBoolean`` signature across a Ghidra version bump would land silently. This test
runs each profile end to end against the real worker so such a binding regression fails the nightly.

**Hard gate (deterministic):** for every profile in :data:`_PROFILES`, ``session_analyze`` must
return WITHOUT an error envelope AND the program's function surface must be populated (``>= 1``
function) — the read tools depend on analysis having run. The pure profile→overlay *selector* is
unit-tested hermetically elsewhere (``tests/unit``); this exercises the JVM *application* of it.

**Advisory (non-gating):** the per-profile recovered-function count is recorded into the JUnit XML
(``record_property``) and printed, so the profiles' effect is observable as a trend — but only the
"analyze succeeds + surface populated" assertion gates (mirroring ADR-028: deterministic checks
gate, trend metrics are advisory). The counts are NOT asserted to differ (analysis-pass effects on a
tiny micro-binary are not deterministic enough to gate without flakiness).

Posture mirrors ``test_export_known_count.py``: it drives the **real MCP stdio chain** (launches
``python -m vivarium`` → real ``RpcGhidraAdapter`` → hardened worker container) over a tiny,
benign, locally-built micro-binary (no real malware, master §5). ``read_timeout_seconds`` takes a
``datetime.timedelta``, NOT an int.

Gating (reused from ``conftest.py``): ``integration``-marked, so the default hermetic ``pytest`` run
SKIPS it. It runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + container
engine + a C compiler are available; the PM performs that live verification on a gated worker-image
run. Honored environment matches the other integration tests (``VIVARIUM_WORKER_IMAGE`` /
``VIVARIUM_CONTAINER_ENGINE`` / ``VIVARIUM_WORKER_RUNTIME`` / ``VIVARIUM_WORKER_UID`` /
``VIVARIUM_WORKER_GID`` / ``VIVARIUM_RPC_SOCKET_DIR`` / ``VIVARIUM_E2E_TIMEOUT``).
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

#: The closed analyzer-profile vocabulary (ADR-029 B). ``default`` is the no-op control (empty
#: overlay); ``light``/``deep`` carry non-empty overlays that drive the JVM option-setting edge.
_PROFILES: tuple[str, ...] = ("default", "light", "deep")

#: A tiny, benign C source with TWO defined functions so analysis recovers a non-trivial surface.
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
    set. Detecting it surfaces a worker-unavailable / analysis-failed / session-invalid outcome — or
    a profile-overlay binding crash mapped to ``internal-error`` — as a clear failure.

    Args:
        payload: A structured tool-result dict.

    Raises:
        AssertionError: If ``payload`` matches the error-envelope shape.
    """
    if {"type", "title", "retryable"} <= payload.keys() and "status" in payload:
        raise AssertionError(f"tool returned error envelope: {payload.get('type')!r}")


async def _drive_profile_analyze(profile: str, binary: Path, import_root: Path) -> int:
    """Drive the real stdio chain through ``analyze(profile=…)`` and return the function count.

    Steps: ``session_create`` → ``session_import`` (the micro-binary) → ``session_analyze`` with the
    given ``profile`` → ``list_functions``. Every step fails closed on an error envelope (so a
    profile-overlay binding crash on the JVM edge surfaces as a test failure, not empty data). The
    session is always closed in a ``finally`` and its store-wipe asserted (ADR-002 containment).

    Args:
        profile: The analyzer profile to request (one of :data:`_PROFILES`); passed explicitly even
            for ``default`` so the additive ``profile`` param threading is exercised across the
            whole closed vocabulary.
        binary: The compiled micro-binary to import.
        import_root: The directory the binary lives under (the server's confined import root).

    Returns:
        The number of functions ``list_functions`` reports after analysis under this profile.
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
            # The crux: analyze under THIS profile. For light/deep this drives the option-overlay
            # JVM edge (getOptions(ANALYSIS_PROPERTIES) + setBoolean); _structured fails closed if
            # that binding regressed (the worker maps the JVM error to an internal-error envelope).
            _structured(
                await session.call_tool(
                    "session_analyze",
                    {"session_id": sid, "profile": profile},
                    read_timeout_seconds=timeout,
                )
            )
            functions = _structured(
                await session.call_tool(
                    "list_functions", {"session_id": sid, "offset": 0, "limit": 50}
                )
            )
            rows = functions.get("functions") or []
            return len(rows)
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            # Containment invariant (ADR-002): the per-session store is wiped on close.
            assert closed.get("store_wiped") is True


@pytest.mark.parametrize("profile", _PROFILES)
def test_analyze_profile_succeeds_and_populates_surface(
    profile: str,
    tmp_path: Path,
    record_property: Any,
) -> None:
    """``session_analyze(profile=…)`` succeeds and recovers a function surface on a real worker.

    Hard gate (per profile): analyze returns without an error envelope and ``list_functions``
    reports ``>= 1`` function. For ``light``/``deep`` this is the only recurring exercise of the
    ADR-029 option-overlay JVM edge — a renamed ``ANALYSIS_PROPERTIES`` / changed ``setBoolean`` is
    caught here, not in production. The recovered-function count is recorded as an advisory trend
    metric (``record_property``) but NOT asserted to differ across profiles.

    Args:
        profile: The analyzer profile under test (parametrized over :data:`_PROFILES`).
        tmp_path: The pytest temp dir used as the (host) import root the micro-binary is built into.
        record_property: pytest fixture that writes a ``<property>`` into the JUnit XML (the
            workflow uploads it as an artifact) for the advisory per-profile count.
    """
    if not _engine_available():
        engine = os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"
        pytest.skip(f"container engine {engine!r} not found on PATH")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) on PATH to build the benign micro-binary")

    import_root = tmp_path
    binary = _build_micro_binary(import_root)

    function_count = asyncio.run(_drive_profile_analyze(profile, binary, import_root))

    # Advisory trend metric (non-gating): observable in the JUnit artifact + console.
    record_property("profile", profile)
    record_property("function_count", function_count)
    print(f"[live-regression][profile={profile}] recovered_functions={function_count}")

    # Hard gate: analysis ran (the option overlay applied cleanly for light/deep) and the read
    # surface the downstream tools depend on is populated.
    assert function_count >= 1, (
        f"profile {profile!r}: no functions recovered after analyze — the analyzer-profile overlay "
        f"binding may have regressed (ADR-029 JVM edge), or analysis did not run"
    )
