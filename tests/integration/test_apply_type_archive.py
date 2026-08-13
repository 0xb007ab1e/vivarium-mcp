"""Integration: bundled type-archive application runs against a real worker (ADR-051, v1.8).

Regression + capability gate for the ``apply_type_archive`` tool: applying a bundled Ghidra Data
Type archive (``.gdt``) resolves library function prototypes onto same-named functions — the RE win
that turns an ``undefined`` libc call into its real signature. Proven live end-to-end:

    * import a tiny x86-64 blob, create a function named ``strlen``, apply ``generic_clib_64``, and
      its signature becomes ``size_t strlen(char * __s)`` (``functions_updated >= 1``).

This is the increment program's first **mutation** tool: it writes to the program DB. The test
drives the worker backend directly (setup: import + create the named function; act: apply).

Why a gated in-container test (not a unit test): ``FileDataTypeManager`` +
``ApplyFunctionDataTypesCmd`` are the JVM/PyGhidra edge (TB3, ADR-001) — excluded from server unit
coverage and only validatable against a real Ghidra worker. Gating + fixture posture are reused
verbatim from ``test_import_emulate.py``: ``integration``-marked (the default unit run SKIPS it),
runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No
real malware — the input is a tiny synthetic x86-64 blob the driver writes in-container (master §5).

Honored environment (same as ``test_import_emulate.py``):
    * ``VIVARIUM_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``VIVARIUM_WORKER_IMAGE`` — the pinned-by-digest worker image ref (conftest fixture).
    * ``VIVARIUM_CONTAINER_ENGINE`` — container CLI to invoke (default ``podman``).
    * ``VIVARIUM_WORKER_SRC_MOUNT`` — OPTIONAL dev hook: bind a host repo root read-only over the
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

_ENGINE_ENV = "VIVARIUM_CONTAINER_ENGINE"
_DEFAULT_ENGINE = "podman"
_SRC_MOUNT_ENV = "VIVARIUM_WORKER_SRC_MOUNT"

#: Generous ceiling for JVM boot + import + opening the ~20k-type archive + the apply.
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: import a tiny x86-64 blob, disassemble +
# create a function named `strlen` at the entry, then call `apply_type_archive` with generic_clib_64
# and read `strlen`'s signature back. Ends with an explicit stdout flush + os._exit(0): opening a
# FileDataTypeManager leaves a lingering non-daemon JVM thread that would otherwise block the
# interpreter shutdown (so a plain end-of-script would hang until the harness timeout).
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    base = 0x400000
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "libc_caller.bin")
    with open(path, "wb") as handle:
        handle.write(b"\xb8\x05\x00\x00\x00\xc3")  # mov eax, 5 ; ret  (a tiny valid function)

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": "x86:LE:64:default",
         "base_addr": base, "entry": base}
    )
    program = backend._require_program()

    # Setup: disassemble the entry and create a function NAMED `strlen` so the archive's
    # `strlen` prototype has a same-named target to apply to.
    from ghidra.program.flatapi import FlatProgramAPI
    fpa = FlatProgramAPI(program)
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(base)
    tx = program.startTransaction("setup-named-function")
    fpa.disassemble(addr)
    fn = fpa.createFunction(addr, "strlen")
    program.endTransaction(tx, True)

    before = str(fn.getSignature().getPrototypeString())
    result = backend.apply_type_archive({"archive": "generic_clib_64"})
    after = str(fn.getSignature().getPrototypeString())
    return {"before": before, "after": after, "result": result}


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
os._exit(0)  # force exit past the lingering FileDataTypeManager JVM thread
"""


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the container-run argv that drives the type-archive apply in ``image``.

    Mirrors ``test_import_emulate.py``'s posture exactly (network-isolated, capped memory, read-only
    rootfs + tmpfs scratch), then overrides the entrypoint to ``python -c <driver>``.

    Args:
        engine: The container engine binary (``podman``/``docker``).
        image: The worker image reference (pinned by digest in CI; resolved by the fixture).

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
        "VIVARIUM_WORKER_PROJECT_DIR=/work/project",
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


def test_apply_type_archive_sets_library_signature_on_real_worker(worker_image: str) -> None:
    """Applying ``generic_clib_64`` must set the real ``strlen`` prototype on a same-named function.

    Drives the in-container backend: import a blob, create a function named ``strlen``, then
    ``apply_type_archive("generic_clib_64")``. Asserts the function signature changed from the bare
    ``undefined strlen(void)`` to the archive prototype (``size_t strlen(char * __s)``) and that
    ``functions_updated >= 1``. A regression re-surfaces here as ``ok=False`` or an unchanged
    signature.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image)

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
            f"apply_type_archive run timed out after {_RUN_TIMEOUT_SECONDS}s "
            f"(engine={engine}, image={worker_image})\n--- stderr tail ---\n{captured[-2000:]}"
        )

    if proc.returncode != 0:
        pytest.fail(
            f"worker run exited {proc.returncode} (engine={engine}, image={worker_image})\n"
            f"--- stderr tail ---\n{proc.stderr[-2000:]}\n"
            f"--- stdout tail ---\n{proc.stdout[-1000:]}"
        )

    envelope = _parse_marker_json(proc.stdout)
    assert envelope.get("ok") is True, (
        f"apply_type_archive reported failure (ADR-051 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    result = data.get("result", {})
    assert result.get("archive") == "generic_clib_64", f"wrong archive echoed: {result!r}"
    assert result.get("applied") is True, f"apply did not commit: {result!r}"
    assert int(result.get("functions_updated", 0)) >= 1, (
        f"expected >=1 function updated (strlen); got {result!r}"
    )

    # The applied prototype resolved the bare function to the archive's libc signature.
    after = str(data.get("after", ""))
    assert after != str(data.get("before", "")), f"signature did not change: {data!r}"
    assert "strlen" in after and "size_t" in after and "*" in after, (
        f"expected the archive prototype 'size_t strlen(char * ...)'; got {after!r}"
    )
