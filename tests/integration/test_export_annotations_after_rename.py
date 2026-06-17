"""Integration: ``session_export_annotations`` succeeds on a real, renamed program (ADR-024 F2).

Regression guard for **F2 of ADR-024**. The bug: against a real analyzed program with at least one
USER_DEFINED rename, ``session_export_annotations`` died with an opaque ``internal worker error``
because step 4 of the export (``rename_symbol`` enumeration) stringified ``symbol.getAddress()`` for
USER_DEFINED symbols that have *no concrete memory address* (namespace/class/library/global/external
symbols), where ``getAddress()`` returns a null Java reference. PR-2 (this fix) skips address-less
symbols (``_is_address_keyable``); this test proves, against a **live worker**, that exporting after
a real function rename now SUCCEEDS and carries the ``rename_function`` entry.

Why a gated, in-container integration test (not a unit test): the enumeration is the JVM/PyGhidra
edge (TB3, ADR-001) — excluded from server unit coverage and only validatable against a real Ghidra
worker. The *pure* guard predicate is unit-tested hermetically in
``tests/unit/test_export_address_guard.py``; this test exercises the real JVM loop end-to-end.

Gating (reused verbatim from ``conftest.py``): every test here is ``integration``-marked, so the
default ``pytest`` / unit-coverage run SKIPS it and stays green + hermetic. It runs only when
``GHIDRA_MCP_INTEGRATION`` is truthy AND a real worker image + container engine are available — the
PM performs that live verification on a gated worker-image rebuild. No real malware: the analyzed
input is a benign OS utility already in the image (master §5, PLAN §6).

Honored environment (same as ``test_worker_analysis.py``):
    * ``GHIDRA_MCP_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``GHIDRA_MCP_WORKER_IMAGE`` — the pinned-by-digest worker image ref (conftest fixture).
    * ``GHIDRA_MCP_CONTAINER_ENGINE`` — container CLI to invoke (default ``podman``).
    * ``GHIDRA_MCP_INTEGRATION_TARGET`` — in-image ELF to analyze (default ``/bin/true``).
    * ``GHIDRA_MCP_WORKER_SRC_MOUNT`` — OPTIONAL dev hook: bind a host repo root read-only over the
      image's installed package (validate working-tree code against the pinned image, no rebuild).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

import pytest

pytestmark = pytest.mark.integration

# --- gating / engine constants (mirror test_worker_analysis.py) ----------------------------------
_ENGINE_ENV = "GHIDRA_MCP_CONTAINER_ENGINE"
_DEFAULT_ENGINE = "podman"
_TARGET_ENV = "GHIDRA_MCP_INTEGRATION_TARGET"
_DEFAULT_TARGET = "/bin/true"
_SRC_MOUNT_ENV = "GHIDRA_MCP_WORKER_SRC_MOUNT"

#: Generous ceiling for JVM boot + Ghidra auto-analysis + rename + export.
_RUN_TIMEOUT_SECONDS = 300
#: In-worker analysis budget hint passed to ``analyze`` (the harness ceiling is the hard wall).
_ANALYZE_TIMEOUT_SECONDS = 180

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "GHIDRA_MCP_INTEGRATION_RESULT:"

#: The new name applied to the first function before export — a benign, recognizable rename so the
#: assertion can confirm the rename_function entry round-tripped through the (formerly crashing)
#: export path. Server-side new-name validation is not in play here (we drive the backend directly).
_RENAMED_FN = "adr024_f2_export_probe"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: import -> analyze -> list functions ->
# rename the FIRST function -> export_annotations. It prints exactly one marker-prefixed JSON line
# and self-reports any failure as a parseable, fail-closed envelope (so a crash in the export path
# surfaces as ok=False with the error string, NOT an opaque non-zero exit). It never prints
# binary-derived content beyond the small capped fields the contract returns.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "GHIDRA_MCP_INTEGRATION_RESULT:"
TARGET = os.environ.get("GHIDRA_MCP_INTEGRATION_TARGET", "/bin/true")
ANALYZE_TIMEOUT = int(os.environ.get("GHIDRA_MCP_DRIVER_ANALYZE_TIMEOUT", "180"))
RENAMED_FN = os.environ.get("GHIDRA_MCP_DRIVER_RENAMED_FN", "adr024_f2_export_probe")


def main():
    from ghidra_mcp.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    out = {}

    out["import"] = backend.import_binary({"source_ref": TARGET, "expected_sha256": None})
    out["analyze"] = backend.analyze({"timeout_seconds": ANALYZE_TIMEOUT})

    functions = backend.list_functions({"offset": 0, "limit": 5})
    rows = functions.get("functions") or []
    if not rows:
        raise RuntimeError("no functions to rename; cannot exercise the export-after-rename path")

    first = rows[0]["address"]
    out["rename_function"] = backend.rename_function({"function": first, "new_name": RENAMED_FN})

    # The formerly-crashing call: enumerate USER_DEFINED annotations on a renamed program.
    out["export_annotations"] = backend.export_annotations({})
    return out


try:
    result = {"ok": True, "data": main()}
except Exception as exc:  # surface ANY failure as a parseable, fail-closed envelope.
    result = {
        "ok": False,
        "error": "{}: {}".format(type(exc).__name__, exc),
        "traceback": traceback.format_exc(),
    }

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
    """Build the container-run argv that drives the export-after-rename path in ``image``.

    Mirrors ``test_worker_analysis.py``'s posture exactly (network-isolated, capped memory,
    read-only rootfs + tmpfs scratch) so the regression is validated under the real deploy
    constraints, then overrides the entrypoint to ``python -c <driver>``.

    Args:
        engine: The container engine binary (``podman``/``docker``).
        image: The worker image reference (pinned by digest in CI; resolved by the fixture).
        target: The in-image ELF path to analyze (benign OS utility — no malware).

    Returns:
        The full argv list to pass to :func:`subprocess.run`.
    """
    cmd = [
        engine,
        "run",
        "--rm",
        "--network=none",
        "--memory=3g",
        "--read-only",
        "--tmpfs",
        "/work/project:rw,noexec,nosuid,nodev,mode=1777,size=2g",
        "--tmpfs",
        "/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size=1g",  # noqa: S108 — in-container tmpfs.
        "--env",
        "GHIDRA_MCP_WORKER_PROJECT_DIR=/work/project",
        "--env",
        f"{_TARGET_ENV}={target}",
        "--env",
        f"GHIDRA_MCP_DRIVER_ANALYZE_TIMEOUT={_ANALYZE_TIMEOUT_SECONDS}",
        "--env",
        f"GHIDRA_MCP_DRIVER_RENAMED_FN={_RENAMED_FN}",
    ]
    src_mount = os.environ.get(_SRC_MOUNT_ENV, "").strip()
    if src_mount:
        cmd += [
            "--volume",
            f"{src_mount}:/host-repo:ro",
            "--env",
            "PYTHONPATH=/host-repo/src:/host-repo",
        ]
    cmd += ["--entrypoint", "python", image, "-c", _DRIVER]
    return cmd


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


def test_export_annotations_succeeds_after_function_rename(worker_image: str) -> None:
    """Renaming a function then exporting annotations must succeed (ADR-024 F2 regression).

    Drives the in-container backend: import → analyze → rename the first function → export. Asserts
    the export did NOT raise (the F2 ``internal worker error`` is gone) and that the export document
    carries the expected ``rename_function`` entry for the renamed function.

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
            f"export-after-rename timed out after {_RUN_TIMEOUT_SECONDS}s "
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
    # The crux: the export path no longer raises. A regression re-surfaces here as ok=False with the
    # 'internal worker error' (or a null-deref) string, instead of silently passing.
    assert envelope.get("ok") is True, (
        f"export-after-rename reported failure (F2 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    rename = data.get("rename_function") or {}
    assert rename.get("applied") is True, f"rename_function did not apply: {rename!r}"

    export = data.get("export_annotations") or {}
    entries = export.get("entries")
    assert isinstance(entries, list), f"export missing entries list: {export!r}"

    rename_fn_entries = [
        e
        for e in entries
        if isinstance(e, dict)
        and e.get("kind") == "rename_function"
        and e.get("new_name") == _RENAMED_FN
    ]
    assert rename_fn_entries, (
        f"expected a rename_function entry for {_RENAMED_FN!r} in the export document; "
        f"got kinds={[e.get('kind') for e in entries if isinstance(e, dict)]!r}"
    )
