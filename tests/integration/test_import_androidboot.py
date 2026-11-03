"""Integration: Android boot image (`androidboot`) container unwrap on a real worker (#380).

Capability + regression gate for `session_import` `container="androidboot"`: the worker parses the
`ANDROID!` header, slices the page-aligned **kernel** region, and hands it to the loader. Here the
kernel region is a known ARM ELF (the synthetic fixture), so a correct unwrap loads + analyzes into
>= 1 function; a regression in `_unwrap_androidboot` / the header parser re-surfaces as `ok=False`
or a zero function count. The pure `core.androidboot` parser + its fuzz test are the hermetic unit
coverage; this proves the end-to-end worker filesystem slice. Benign synthetic input (master §5).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

import pytest

from tests._fixtures import binaries

pytestmark = pytest.mark.integration

_ENGINE_ENV = "VIVARIUM_CONTAINER_ENGINE"
_DEFAULT_ENGINE = "podman"
_SRC_MOUNT_ENV = "VIVARIUM_WORKER_SRC_MOUNT"
_RUN_TIMEOUT_SECONDS = 300
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: The kernel region = a real synthetic ARM32 ELF (reused fixture) so the unwrapped payload actually
#: loads + analyzes; injected into the in-container driver as hex.
_ARM_ELF_HEX = binaries.synthetic_arm32_elf().hex()

# Runs as `python -c <DRIVER>` INSIDE the worker: build an ANDROID! image whose kernel region is
# the ARM ELF (uncompressed, page-aligned), import with container="androidboot", analyze, count fns.
_DRIVER = r"""
import json, os, struct, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
ARM_ELF = bytes.fromhex("__ARM_ELF_HEX__")
PAGE = 2048


def _build_android_boot(kernel, page):
    hdr = struct.pack(
        "<8sIIIIIIIIII16s512s32s1024s",
        b"ANDROID!", len(kernel), 0x10008000, 0, 0x11000000, 0, 0, 0x100, page, 0, 0,
        b"itest", b"", b"", b"",
    )

    def pad(b):
        return b + b"\x00" * ((( len(b) + page - 1) // page) * page - len(b))

    return pad(hdr) + pad(kernel)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    image = _build_android_boot(ARM_ELF, PAGE)
    path = os.path.join(project_dir, "boot.img")
    with open(path, "wb") as handle:
        handle.write(image)

    backend = PyGhidraBackend()
    backend.import_binary({"source_ref": path, "container": "androidboot"})
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
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
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
        "/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size=1g",  # noqa: S108
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
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line in worker stdout:\n{stdout[-2000:]}"
    try:
        parsed: dict[str, Any] = json.loads(lines[-1][len(_MARKER) :])
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise AssertionError(f"marker payload not valid JSON: {exc}") from exc
    return parsed


def test_androidboot_unwrap_loads_kernel_on_real_worker(worker_image: str) -> None:
    """An `androidboot` image must unwrap its kernel region and load+analyze it (ADR-070 / #380)."""
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image)
    try:
        proc = subprocess.run(  # noqa: S603 — argv list, no shell; engine + image operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"androidboot unwrap timed out after {_RUN_TIMEOUT_SECONDS}s\n{captured[-2000:]}"
        )

    if proc.returncode != 0:
        pytest.fail(f"worker exited {proc.returncode}\n--- stderr ---\n{proc.stderr[-2000:]}")

    envelope = _parse_marker_json(proc.stdout)
    assert envelope.get("ok") is True, (
        f"androidboot unwrap reported failure (#380 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert int(data.get("function_count", 0)) >= 1, (
        f"expected the unwrapped androidboot kernel to load + analyze into >=1 fn; got {data!r}"
    )
