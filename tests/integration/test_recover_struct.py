"""Integration: `recover_struct` proposes a real struct layout on a live worker (ADR-069).

The HighFunction access walk is the JVM/PyGhidra edge (TB3, ADR-001) — `# pragma: no cover` in the
worker and only validatable against a real Ghidra worker. Gating + fixture posture mirror
``test_data_flow_slice.py``: ``integration``-marked (the default unit run SKIPS it), runs only when
``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No malware — the
analyzed input is a benign in-image OS library (master §5).

Unlike the slice test, ``/bin/true`` is too small to exercise struct access, so this drives a
struct-rich in-image library (glibc — ``/usr/lib/libc.so.6``) so the union of proposed fields is
non-empty; a regression in the access walk surfaces as ``ok=False`` or an empty union. The target is
overridable via ``VIVARIUM_STRUCT_TARGET`` for images where the default path differs.

Honored environment (same as the other gated integration tests):
    * ``VIVARIUM_INTEGRATION`` — truthy enables the suite (see conftest).
    * ``VIVARIUM_WORKER_IMAGE`` — the pinned-by-digest worker image (conftest fixture).
    * ``VIVARIUM_CONTAINER_ENGINE`` — container CLI (default ``podman``).
    * ``VIVARIUM_STRUCT_TARGET`` — struct-rich in-image ELF (default ``/usr/lib/libc.so.6``).
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
_TARGET_ENV = "VIVARIUM_STRUCT_TARGET"
_DEFAULT_TARGET = "/usr/lib/libc.so.6"
_SRC_MOUNT_ENV = "VIVARIUM_WORKER_SRC_MOUNT"
_RUN_TIMEOUT_SECONDS = 900  # glibc analysis + a bounded recover_struct sweep; generous for slow CI.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

# Driver: import -> analyze -> for the largest functions, enumerate high-symbol names and
# recover_struct on each until >=1 field is proposed (a struct-rich library must yield some).
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
TARGET = os.environ.get("VIVARIUM_STRUCT_TARGET", "/usr/lib/libc.so.6")


def _drain(it):
    out = []
    while it.hasNext():
        out.append(it.next())
    return out


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    backend.import_binary({"source_ref": TARGET, "expected_sha256": None})
    backend.analyze({"timeout_seconds": 600})

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    rows = backend.list_functions({"offset": 0, "limit": 400}).get("functions") or []
    if not rows:
        raise RuntimeError("no functions found")
    program = backend._require_program()

    tried = 0
    accesses = set()
    for row in sorted(rows, key=lambda r: -int(r.get("size") or 0))[:40]:
        func = backend._resolve_function(row["address"])
        dec = DecompInterface()
        try:
            dec.openProgram(program)
            res = dec.decompileFunction(func, 0, ConsoleTaskMonitor())
            if res is None or not res.decompileCompleted():
                continue
            high = res.getHighFunction()
            if high is None:
                continue
            names = [str(sym.getName()) for sym in _drain(high.getLocalSymbolMap().getSymbols())]
        finally:
            dec.dispose()
        for nm in names:
            out = backend.recover_struct(
                {"function": row["address"], "base": nm, "max_fields": 64, "max_accesses": 400}
            )
            tried += 1
            fields = out.get("fields") or []
            if fields:
                for f in fields:
                    accesses.add(f.get("access"))
                return {
                    "tried": tried,
                    "field_count": len(fields),
                    "total_span": out.get("total_span"),
                    "accesses": sorted(accesses),
                    "sample": fields[:5],
                }
    return {"tried": tried, "field_count": 0, "accesses": sorted(accesses)}


try:
    result = {"ok": True, "data": main()}
except Exception as exc:
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
    """Build the network-isolated container-run argv driving struct recovery in ``image``."""
    cmd = [
        engine,
        "run",
        "--rm",
        "--network=none",
        "--memory=4g",
        "--read-only",
        "--tmpfs",
        "/work/project:rw,noexec,nosuid,nodev,mode=1777,size=2g",
        "--tmpfs",
        "/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size=2g",  # noqa: S108 — in-container tmpfs.
        "--env",
        "VIVARIUM_WORKER_PROJECT_DIR=/work/project",
        "--env",
        f"{_TARGET_ENV}={target}",
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


def test_recover_struct_on_real_worker(worker_image: str) -> None:
    """Struct recovery over a real struct-rich library must propose non-empty, well-formed fields.

    Drives the in-container backend: import → analyze → for the largest functions, enumerate their
    high-symbol names → recover_struct on each until a field is proposed. glibc is nothing but
    struct manipulation, so the union must be non-empty; a regression in the HighFunction access
    surfaces here as ``ok=False`` or an empty result. Every proposed access stays within the closed
    ``{load, store, addr}`` set.

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
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"recover_struct run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"recover_struct reported failure (ADR-069 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert int(data.get("field_count") or 0) >= 1, (
        f"expected >=1 proposed field over a struct-rich library; got {data!r}"
    )
    assert set(data.get("accesses") or []) <= {"load", "store", "addr"}, (
        f"unexpected access kinds: {data!r}"
    )
    assert int(data.get("total_span") or 0) >= 1, f"non-empty layout must span >=1 byte: {data!r}"
