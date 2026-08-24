"""Integration: uImage container unwrap on a real worker (ADR-070 container follow-up).

Regression + capability gate for the ``session_import`` ``container="uimage"`` path: the worker
strips the 64-byte U-Boot legacy header and unwraps the payload per its ``ih_comp`` field, under the
zip-bomb caps, then loads the recovered payload. Proven live:

    * wrap a synthetic ARM ELF in a gzip payload inside a uImage envelope (``ih_comp`` = gzip);
      import with ``container="uimage"``; the unwrapped ELF loads and analysis finds its function.
      This exercises BOTH the header strip AND the nested gzip decompress. A regression in
      ``_unwrap_uimage`` re-surfaces as ``ok=False`` or no function found.

Why a gated in-container test (not a unit test): the unwrap streams through the worker filesystem
and then drives the real loader/analysis (JVM/PyGhidra edge, TB3, ADR-001) — the pure header parser
(``core.uimage``) + its fuzz test are the hermetic unit coverage; this proves the end-to-end
worker path. Gating + fixture posture mirror ``test_import_raw_binary.py``: ``integration``-marked
(the default unit run SKIPS it), runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real
worker image + engine are available. No real malware — the input is a synthetic ARM ELF wrapped
in-container (master §5).

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

#: The same synthetic ARM ELF used elsewhere (self-contained; the ``tests`` tree is NOT in-image).
_ARM_ELF_HEX = (
    "7f454c4601010100000000000000000002002800010000005400010034000000770000000002000534002000010028"
    "000300020001000000000000000000010000000100ef000000ef00000005000000001000"
    "0000bf00bf00bf00bf00bf00bf00bf00bf7047002e74657874002e73687374727461620000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000"
    "0600000054000100540000001200000000000000000000000200000000000000070000000300000000000000000000"
    "00660000001100000000000000000000000100000000000000"
)

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: gzip the ARM ELF, wrap it in a uImage
# envelope (ih_comp=gzip=1), import with container="uimage", analyze, and report the function count.
_DRIVER = r"""
import gzip, json, os, struct, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
ARM_ELF = bytes.fromhex("__ARM_ELF_HEX__")
UIMAGE_MAGIC = 0x27051956


def _build_uimage(payload, comp):
    hdr = bytearray(64)
    struct.pack_into(">I", hdr, 0, UIMAGE_MAGIC)
    struct.pack_into(">I", hdr, 12, len(payload))  # ih_size
    hdr[31] = comp                                   # ih_comp (1 = gzip)
    return bytes(hdr) + payload


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    image = _build_uimage(gzip.compress(ARM_ELF), 1)
    path = os.path.join(project_dir, "firmware.uimg")
    with open(path, "wb") as handle:
        handle.write(image)

    backend = PyGhidraBackend()
    backend.import_binary({"source_ref": path, "container": "uimage"})
    backend.analyze({"timeout_seconds": 120})
    fns = backend.list_functions({"offset": 0, "limit": 10}).get("functions") or []
    return {"function_count": len(fns)}


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
""".replace("__ARM_ELF_HEX__", _ARM_ELF_HEX)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the network-isolated container-run argv driving the uImage unwrap in ``image``."""
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
    """Extract + parse the single marker-prefixed JSON object from ``stdout``."""
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line found in worker stdout:\n{stdout[-2000:]}"
    payload = lines[-1][len(_MARKER) :]
    try:
        parsed: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive: marker present but corrupt
        raise AssertionError(f"marker payload was not valid JSON: {exc}\n{payload!r}") from exc
    return parsed


def test_uimage_unwrap_loads_payload_on_real_worker(worker_image: str) -> None:
    """A gzip-payload uImage must unwrap (header strip + nested decompress) and load its ELF.

    Drives the in-container backend: wrap the ARM ELF's gzip in a uImage envelope, import with
    ``container="uimage"``, analyze, then count functions. Asserts ``ok`` and at least one function
    (the payload ELF loaded + analyzed). A regression in ``_unwrap_uimage`` re-surfaces as
    ``ok=False`` or a zero function count.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"uImage unwrap run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"uImage unwrap reported failure (ADR-070 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert int(data.get("function_count", 0)) >= 1, (
        f"expected the unwrapped uImage payload to load + analyze into >=1 function; got {data!r}"
    )
