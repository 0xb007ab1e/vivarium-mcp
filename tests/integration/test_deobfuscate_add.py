"""Integration: ADD-const decoder recovery on a real worker (ADR-068/ADR-081, #401).

Capability gate for the #401 ADD-const extension to ``deobfuscate_strings`` (``xor_decode``). Stage
detection keeps every constant ``INT_XOR`` but accepts a constant ``INT_ADD`` **only** when its
output feeds a ``STORE`` value — otherwise an ``INT_ADD`` const is address arithmetic or a loop
counter, not a decode op. This writes a tiny x86-64 single-pass ADD decoder (``buf[i] += 0x10``)
whose loop also contains ``inc ecx`` (an ``INT_ADD ecx, 1`` that is NOT a stored value), imports it
raw, analyzes, and asserts the worker recovers ``"Hello!"`` with a single ``add 0x10`` stage — i.e.
the ADD decode op is detected AND the loop-counter add is filtered out (a one-entry chain, not two).

Why a gated in-container test (not a unit test): the p-code walk + decode-loop emulation are the
JVM/PyGhidra edge (TB3, ADR-001), only validatable against a real Ghidra worker; the pure
value-feeds-store filter (``core.multidecode.select_decode_ops``) is hermetically unit-tested.
``integration``-marked (the default unit run SKIPS it); runs only when ``VIVARIUM_INTEGRATION`` is
truthy AND a real worker image + engine are available. No real malware — a tiny synthetic x86-64
blob written in-container (master §5).

This test is added to the live-regression hard-gate list only at the worker **repin** (the pinned
worker must carry the #401 code first — the worker-change-validation-recipe); until then it runs on
demand with ``VIVARIUM_INTEGRATION=1`` against a locally built worker.

Honored environment (same as the other gated integration tests):
    * ``VIVARIUM_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``VIVARIUM_WORKER_IMAGE`` — the pinned-by-digest worker image ref (conftest fixture).
    * ``VIVARIUM_CONTAINER_ENGINE`` — container CLI to invoke (default ``podman``).
    * ``VIVARIUM_WORKER_SRC_MOUNT`` — OPTIONAL dev hook: bind the working tree over the image.
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
_RUN_TIMEOUT_SECONDS = 300
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

_EXPECTED = "Hello!"
_PROCESSOR = "x86:LE:64:default"
_BASE_ADDR = 0x1000

# A tiny headerless x86-64 single-pass ADD decoder (#401): rdx=BUF(0x1020); per byte:
# al=buf[i]; al+=0x10; buf[i]=al; inc ecx; cmp ecx,6; jl. CT = "Hello!" - 0x10 (mod 256) at 0x1020.
# The `add al,0x10` output (AL) feeds the STORE value → a real decode stage; the `inc ecx`
# (INT_ADD ecx,1) output is NOT a stored value → must be filtered. So the chain is exactly
# [add 0x10] (length 1), proving both ADD detection and address/counter rejection.
_ADD_BLOB_HEX = "ba2010000031c98a040a041088040affc183f9067cf1c300000000000000000038555c5c5f11"

_DRIVER_ADD = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
BLOB = bytes.fromhex("__ADD_BLOB_HEX__")
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x1000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "adddec.bin")
    with open(path, "wb") as handle:
        handle.write(BLOB)

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": PROCESSOR,
         "base_addr": BASE_ADDR, "entry": BASE_ADDR}
    )
    backend.analyze({"timeout_seconds": 120})
    out = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["xor_decode"], "min_length": 4}
    )
    return {"strings": out.get("strings") or []}


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
os._exit(0)
""".replace("__ADD_BLOB_HEX__", _ADD_BLOB_HEX)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str, driver: str) -> list[str]:
    """Build the network-isolated container-run argv driving ``driver`` in ``image``."""
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
    cmd += ["--entrypoint", "python", image, "-c", driver]
    return cmd


def _parse_marker_json(stdout: str) -> dict[str, Any]:
    """Extract + parse the single marker-prefixed JSON object from ``stdout``."""
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line found in worker stdout:\n{stdout[-2000:]}"
    payload = lines[-1][len(_MARKER) :]
    try:
        parsed: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive: marker present but corrupt
        raise AssertionError(f"marker payload was not valid JSON: {exc}\n{payload!r}") from exc
    return parsed


def test_deobfuscate_add_decoder_on_real_worker(worker_image: str) -> None:
    """``deobfuscate_strings`` recovers an ADD-const decoder, filtering the loop-counter add (#401).

    The decoder does ``buf[i] += 0x10``; its loop also runs ``inc ecx`` (``INT_ADD ecx, 1``). The
    ADD whose output feeds the stored byte is the real decode op; the counter add is not a stored
    value and must be filtered. Asserts a recovered ``"Hello!"`` with ``encoding="add"`` and a
    single-entry ``[add 0x10]`` chain — a regression (missing ADD detection, or the counter add
    leaking into the chain) re-surfaces as the string missing or a wrong ``stages``.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image, _DRIVER_ADD)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"add decoder run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"add decoder reported failure (#401 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    strings = envelope["data"].get("strings") or []
    hits = [
        s
        for s in strings
        if s.get("technique") == "xor_decode" and _EXPECTED in str(s.get("text", ""))
    ]
    assert hits, f"expected an add-decoder recovery of {_EXPECTED!r}; got {strings!r}"
    rec = hits[0]
    assert rec.get("encoding") == "add", f"expected encoding='add'; got {rec!r}"
    stages = rec.get("stages") or []
    assert stages == [{"op": "add", "key": "0x10"}], (
        f"expected a single [add 0x10] stage (counter add filtered); got {rec!r}"
    )
