"""Integration: a real Ghidra worker analyzes a real in-image ELF end-to-end (WS5).

Formalizes the manual in-worker smoke (12/12 ``_gh_*`` paths against ``/bin/true`` on Ghidra
12.1.2) into a repeatable, self-skipping pytest. It drives :class:`PyGhidraBackend` **directly
inside the worker container** — import → analyze → metadata → list/get/decompile a function →
memory map → strings — and asserts the **contract shapes** the WS2 ``rpc_client`` builders depend
on (``docs/contracts/`` frozen shapes), NOT exact values (the in-image binary may change).

Why drive the backend in-container (not the server-side RPC adapter): this test exercises trust
boundary TB3 — the JVM/PyGhidra edge that is excluded from server unit coverage (ADR-001) and is
the one un-unit-testable surface. The server↔worker RPC framing (TB2) and the SessionManager
lifecycle are covered by the sibling Wave-2 scaffolds; here we prove the Ghidra-facing dict shapes
are real against a live worker, so the (unit-tested) ``_build_*`` builders are wiring a true
contract rather than a hopeful one.

Gating (reused verbatim from ``conftest.py``): every test here is ``integration``-marked, so
``pytest -m "not integration"`` excludes it and the unit/coverage job stays green and hermetic.
When the flag IS set, the ``worker_image`` fixture resolves the pinned image (or skips), and this
test additionally skips cleanly if the container engine binary is absent. No real malware: the
analyzed input is a benign OS utility already present in the image (master §5, PLAN §6).

Honored environment:
    * ``GHIDRA_MCP_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``GHIDRA_MCP_WORKER_IMAGE`` — the pinned-by-digest worker image ref (conftest fixture;
      defaults to ``localhost/ghidra-mcp-worker:dev`` for local validation if unset).
    * ``GHIDRA_MCP_CONTAINER_ENGINE`` — container CLI to invoke (default ``podman``).
    * ``GHIDRA_MCP_INTEGRATION_TARGET`` — in-image ELF to analyze (default ``/bin/true``).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any

import pytest

pytestmark = pytest.mark.integration

# --- gating / engine constants -------------------------------------------------------------------
_ENGINE_ENV = "GHIDRA_MCP_CONTAINER_ENGINE"
_DEFAULT_ENGINE = "podman"
_TARGET_ENV = "GHIDRA_MCP_INTEGRATION_TARGET"
_DEFAULT_TARGET = "/bin/true"

#: Generous overall ceiling for JVM boot + Ghidra auto-analysis + the read-only queries.
_RUN_TIMEOUT_SECONDS = 300
#: In-worker analysis budget hint passed to ``analyze`` (the harness ceiling is the hard wall).
_ANALYZE_TIMEOUT_SECONDS = 180

#: Unique sentinel framing the single JSON result line on stdout, so the parser ignores all JVM /
#: Ghidra / log noise the worker prints around it.
_MARKER = "GHIDRA_MCP_INTEGRATION_RESULT:"

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")

# --- the in-container driver --------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image (image PYTHONPATH already exposes both the
# installed `ghidra_mcp` package and the `worker/` modules; image ENV provides writable HOME/tmpdir
# and the project-store dir). It drives the backend directly, collects plain JSON-serializable
# results, and prints exactly one marker-prefixed JSON line. It NEVER prints binary-derived content
# beyond the small, capped fields the contract returns (the test asserts shape, not payload), and
# it self-reports a structured error rather than crashing opaquely (fail closed, parseable).
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "GHIDRA_MCP_INTEGRATION_RESULT:"
TARGET = os.environ.get("GHIDRA_MCP_INTEGRATION_TARGET", "/bin/true")
ANALYZE_TIMEOUT = int(os.environ.get("GHIDRA_MCP_DRIVER_ANALYZE_TIMEOUT", "180"))


def main():
    from ghidra_mcp.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    out = {}

    out["import"] = backend.import_binary(
        {"source_ref": TARGET, "expected_sha256": None}
    )
    out["analyze"] = backend.analyze({"timeout_seconds": ANALYZE_TIMEOUT})
    out["program_metadata"] = backend.program_metadata({})

    functions = backend.list_functions({"offset": 0, "limit": 5})
    out["list_functions"] = functions

    rows = functions.get("functions") or []
    if rows:
        first = rows[0]["address"]
        out["get_function"] = backend.get_function({"function": first})
        out["decompile_function"] = backend.decompile_function({"function": first})

    out["memory_map"] = backend.memory_map({})
    out["list_strings"] = backend.list_strings(
        {"offset": 0, "limit": 5, "min_length": 4}
    )
    return out


try:
    result = {"ok": True, "data": main()}
except Exception as exc:  # noqa: BLE001 — surface ANY failure as a parseable, fail-closed envelope.
    result = {
        "ok": False,
        "error": "{}: {}".format(type(exc).__name__, exc),
        "traceback": traceback.format_exc(),
    }

# One marker-prefixed line on stdout; the test parses only this, ignoring JVM/Ghidra noise.
sys.stdout.write("\n" + MARKER + json.dumps(result) + "\n")
sys.stdout.flush()
"""


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str, target: str) -> list[str]:
    """Build the container-run argv that drives the backend against ``target`` in ``image``.

    The invocation overrides the entrypoint to ``python -c <driver>`` so it runs the analysis
    in-process inside the worker, with the same network-isolation and resource bounds as a real
    session (``--network=none``, capped memory). Writable scratch for the Ghidra project store and
    the JVM temp/home is provided via tmpfs so the (normally read-only) rootfs is not written.

    Args:
        engine: The container engine binary (``podman``/``docker``).
        image: The worker image reference (pinned by digest in CI; resolved by the fixture).
        target: The in-image ELF path to analyze (benign OS utility — no malware).

    Returns:
        The full argv list to pass to :func:`subprocess.run`.
    """
    return [
        engine,
        "run",
        "--rm",
        # No network: the worker never needs egress; mirrors the real session (ADR-004).
        "--network=none",
        # Bounded memory so a hostile/heavy analysis cannot exhaust the host (DoS bound F7).
        "--memory=3g",
        # Read-only rootfs + writable scratch ONLY via tmpfs — the exact deploy/ posture (ADR-004).
        "--read-only",
        # mode=1777 (the /tmp model): a fresh tmpfs is root-owned, but the worker is uid 65532;
        # without it Ghidra's LaunchSupport -save cannot write user.home and the JVM won't boot.
        # Mirrors deploy/worker-run.sh — this posture is what caught the missing mode there.
        "--tmpfs",
        "/work/project:rw,noexec,nosuid,nodev,mode=1777,size=2g",
        "--tmpfs",
        "/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size=1g",  # noqa: S108 — in-container tmpfs.
        # Point the backend's project store at the writable tmpfs (image default is /work/project).
        "--env",
        "GHIDRA_MCP_WORKER_PROJECT_DIR=/work/project",
        "--env",
        f"{_TARGET_ENV}={target}",
        "--env",
        f"GHIDRA_MCP_DRIVER_ANALYZE_TIMEOUT={_ANALYZE_TIMEOUT_SECONDS}",
        # Override the worker launcher entrypoint: drive the backend directly, not the RPC loop.
        "--entrypoint",
        "python",
        image,
        "-c",
        _DRIVER,
    ]


def _parse_marker_json(stdout: str) -> dict[str, Any]:
    """Extract and parse the single marker-prefixed JSON object from ``stdout``.

    Args:
        stdout: The captured container stdout (JVM/Ghidra log noise interleaved).

    Returns:
        The parsed result envelope (``{"ok": bool, ...}``).

    Raises:
        AssertionError: If no marker line is present or its payload is not valid JSON.
    """
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line found in worker stdout:\n{stdout[-2000:]}"
    payload = lines[-1][len(_MARKER) :]
    try:
        parsed: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive: marker present but corrupt
        raise AssertionError(f"marker payload was not valid JSON: {exc}\n{payload!r}") from exc
    return parsed


def test_worker_analyzes_real_elf_end_to_end(worker_image: str) -> None:
    """Drive ``PyGhidraBackend`` in the real worker over a real ELF and assert the contract shapes.

    Runs the in-container driver, parses the one marker JSON line, and asserts the import/analyze/
    metadata/list/get/decompile/memory-map/strings results carry the keys + coarse invariants the
    WS2 ``_build_*`` builders consume — proving the JVM edge (TB3, ADR-001) honors the frozen
    contract against a live worker. Values are not pinned (the in-image binary may change); only
    shapes and minimal sanity bounds are asserted.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    target = os.environ.get(_TARGET_ENV, "").strip() or _DEFAULT_TARGET
    cmd = _build_command(engine, worker_image, target)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd,
            capture_output=True,
            text=True,
            timeout=_RUN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:  # don't hang the suite — fail with what we captured.
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"worker analysis timed out after {_RUN_TIMEOUT_SECONDS}s "
            f"(engine={engine}, image={worker_image}, target={target})\n"
            f"--- stderr tail ---\n{captured[-2000:]}"
        )

    if proc.returncode != 0:
        pytest.fail(
            f"worker run exited {proc.returncode} (engine={engine}, image={worker_image})\n"
            f"--- stderr tail ---\n{proc.stderr[-2000:]}\n"
            f"--- stdout tail ---\n{proc.stdout[-1000:]}"
        )

    envelope = _parse_marker_json(proc.stdout)
    assert envelope.get("ok") is True, (
        f"driver reported failure: {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    _assert_import_shape(data["import"])
    _assert_analyze_shape(data["analyze"])
    _assert_program_metadata_shape(data["program_metadata"])
    _assert_function_list_shape(data["list_functions"])

    # get_function / decompile_function are present only when the program exposed >=1 function;
    # list_functions.total >= 1 is asserted above, so for an analyzed ELF these must be present.
    assert "get_function" in data, "expected get_function result for a function-bearing ELF"
    assert "decompile_function" in data, "expected decompile_function result"
    _assert_get_function_shape(data["get_function"])
    _assert_decompile_shape(data["decompile_function"])

    _assert_memory_map_shape(data["memory_map"])
    _assert_string_list_shape(data["list_strings"])


# --- contract assertions (mirror the dict shapes the WS2 rpc_client _build_* builders consume) ---
def _assert_import_shape(result: dict[str, Any]) -> None:
    """Assert the import result carries a 64-hex ``binary_sha256`` (worker-authoritative id).

    Args:
        result: The ``import_binary`` result dict.
    """
    sha = result.get("binary_sha256")
    assert isinstance(sha, str) and _SHA256_RE.match(sha), f"bad binary_sha256: {sha!r}"


def _assert_analyze_shape(result: dict[str, Any]) -> None:
    """Assert auto-analysis reported the terminal ``ready`` state.

    Args:
        result: The ``analyze`` result dict.
    """
    assert result.get("state") == "ready", f"analyze did not reach ready: {result.get('state')!r}"
    assert result.get("analysis_complete") is True, "analysis_complete should be True after analyze"


def _assert_program_metadata_shape(meta: dict[str, Any]) -> None:
    """Assert program metadata reports an ELF format, a truthy arch, and a non-negative func count.

    Args:
        meta: The ``program_metadata`` result dict.
    """
    fmt = meta.get("format")
    assert isinstance(fmt, str) and "ELF" in fmt.upper(), f"format not ELF-like: {fmt!r}"
    arch = meta.get("architecture")
    assert isinstance(arch, str) and arch, f"architecture not truthy: {arch!r}"
    count = meta.get("function_count")
    assert isinstance(count, int) and count >= 1, f"function_count not a positive int: {count!r}"
    endianness = meta.get("endianness")
    assert endianness in {"big", "little"}, f"bad endianness: {endianness!r}"


def _assert_function_list_shape(listing: dict[str, Any]) -> None:
    """Assert ``list_functions`` returns a non-empty, well-shaped, bounded page.

    Args:
        listing: The ``list_functions`` result dict.
    """
    total = listing.get("total")
    assert isinstance(total, int) and total >= 1, f"function total not >=1: {total!r}"
    functions = listing.get("functions")
    assert isinstance(functions, list) and functions, "functions list is empty"
    assert isinstance(listing.get("truncated"), bool), "truncated must be a bool"
    for func in functions:
        assert isinstance(func.get("address"), str) and func["address"], "function address missing"
        assert isinstance(func.get("name"), str) and func["name"], "function name missing"
        assert isinstance(func.get("size"), int) and func["size"] >= 0, "function size invalid"


def _assert_get_function_shape(detail: dict[str, Any]) -> None:
    """Assert ``get_function`` detail carries the expected scalar keys.

    Args:
        detail: The ``get_function`` result dict.
    """
    assert isinstance(detail.get("address"), str) and detail["address"], "detail address missing"
    assert isinstance(detail.get("name"), str) and detail["name"], "detail name missing"
    assert isinstance(detail.get("signature"), str), "detail signature must be a string"
    assert isinstance(detail.get("size"), int) and detail["size"] >= 0, "detail size invalid"
    assert isinstance(detail.get("is_thunk"), bool), "is_thunk must be a bool"


def _assert_decompile_shape(decompiled: dict[str, Any]) -> None:
    """Assert ``decompile_function`` returns non-empty C with the expected keys.

    Args:
        decompiled: The ``decompile_function`` result dict.
    """
    for key in ("address", "name", "c_code", "signature"):
        assert key in decompiled, f"decompile result missing key {key!r}"
    c_code = decompiled.get("c_code")
    assert isinstance(c_code, str) and c_code.strip(), "decompiled c_code is empty"


def _assert_memory_map_shape(memory_map: dict[str, Any]) -> None:
    """Assert ``memory_map`` returns a non-empty list of well-shaped blocks.

    Args:
        memory_map: The ``memory_map`` result dict.
    """
    blocks = memory_map.get("blocks")
    assert isinstance(blocks, list) and blocks, "memory_map blocks is empty"
    block = blocks[0]
    for key in ("name", "start", "end", "size", "permissions", "initialized"):
        assert key in block, f"memory block missing key {key!r}"
    assert isinstance(block["size"], int) and block["size"] >= 0, "block size invalid"
    assert isinstance(block["permissions"], str), "block permissions must be a string"


def _assert_string_list_shape(strings: dict[str, Any]) -> None:
    """Assert ``list_strings`` matches the ``{strings, total, truncated}`` paginated shape.

    Args:
        strings: The ``list_strings`` result dict.
    """
    assert isinstance(strings.get("strings"), list), "strings must be a list"
    assert isinstance(strings.get("total"), int) and strings["total"] >= 0, "total invalid"
    assert isinstance(strings.get("truncated"), bool), "truncated must be a bool"
    for row in strings["strings"]:
        assert isinstance(row.get("address"), str) and row["address"], "string address missing"
        assert isinstance(row.get("value"), str), "string value must be a string"
        assert isinstance(row.get("length"), int) and row["length"] >= 0, "string length invalid"
