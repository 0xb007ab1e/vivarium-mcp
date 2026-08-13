"""Integration: companion-PDB symbol application on a real worker (ADR-061, v1.8 pdb_ref).

Regression + capability gate for the ``session_import`` ``pdb_ref`` companion (ADR-061): a Windows
PE imported with its Microsoft PDB gets the PDB's function names/types applied to the freshly-loaded
program. Proven live:

    * import a tiny synthetic PE **with** its PDB (``pdb_ref``); the PDB-recovered function name
      ``the_answer`` appears in the program's symbols. Importing the SAME PE **without** ``pdb_ref``
      does NOT surface that name (the PDB is the only source of it).

Why a gated in-container test (not a unit test): the PDB pipeline (Ghidra's cross-platform ``pdb2``
reader + ``DefaultPdbApplicator.applyNoAnalysisState``) is the JVM/PyGhidra edge (TB3, ADR-001) —
excluded from server unit coverage and only validatable against a real Ghidra worker. Gating +
posture reuse ``test_version_track.py`` verbatim.

The fixture is a **hermetic, embedded** PE+PDB pair built once with
``clang --target=x86_64-pc-windows-msvc -c -gcodeview`` + ``lld-link /debug /nodefaultlib``
(LLVM 19, no Windows SDK) and stored gzip+base64 (the PDB is mostly zero-padding, compresses ~60x).
No real malware — two trivial C functions.

Honored environment (same as ``test_version_track.py``):
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

#: Generous ceiling for JVM boot + a PE import + a PDB parse/apply.
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: gzip+base64 of a tiny PE32+ built by clang+lld-link (x86_64-pc-windows-msvc, /nodefaultlib) with
#: three named C functions; ~2.5 KB raw.
_PE_B64 = (
    "H4sIANZ7fWoC//ONqmBgZGBgYGFABQ4MhEEFEPPJ7+Jj2MJ5VnEHo89ZxZCMzGKFgqL89KLEXIXkxLy8/BKFpFSFot"
    "I8hcw8BRf/YIXc/JRUPRUGhgBXBoaUNmaGpxW1WTDzPjAoMXAz8TEwMCEc5CAAJAQgTJA7wWygPBtUDxuyg6F6mBkS"
    "GmGaYBQmH4WJCQwYGCSwiSswMMgwUA/olaRWlADpECS/oUcG0MoEvaKUxJJEBoYSqABYHRtGnDnoFUDUSUD9AFbHga"
    "mOYRSMAiDYoQUkDqfp8cu3gPkezW80On1UVLpdVFQ6XVQUXtz+//9/50EgV4HxhEfzEY3DaSCAon4nKGO+OARUOAGs"
    "4swoGDIAFIewMhhUVLgDsQyojAOWLUHBLsHPD0/wUw1N8vHxcVEIcHHSA0W1fkZ+bqp+koGBeWKSYaq+XnJOYmlKqn"
    "5WflKxflKqZZKBsVGqfklugX4JsDRKYmBgZGFkYHFC0KNg8AABYJ1jBMQpCpC6NgSIcxRGw2WkAAAvDbgDAAoAAA=="
)

#: gzip+base64 of the matching MSVC PDB v7.00 (~60 KB raw; mostly MSF zero-padding).
_PDB_B64 = (
    "H4sIANZ7fWoC/+3d72scRRjA8dnL9celTbwTKSFIWUF90ZKdO4WmjQrRBItwkWJqoVhod28n5tq73WN3z6RvxFe+lL"
    "zwfxHUd/pCfOVf0LeCCKXvpXFmZ/e8pk01b9re+f2QZYaZ2R83ubx4nt2dbHQ7SZzGW5m7JtfOn3c3Nj90l71mc252"
    "cX1TaHUhKrp4SW83hDUjAAAAAADAJNkHAAAAAABTT3zFHAAAAAAAMO3meQQCAAAAAID/xfP/izX5wNSrFeYDAAAAAI"
    "BpdFHH/KcP6StzAwu6XtfjHGG314ry/aJ8kuqkT8zzzIW4kzll5ntkviurk/0xAAAAAGAqnRXzDRPq1vNYflv1Biq5"
    "mcTDrBup8f7VvL/vd6O1T65uZn6SDQemf7HoF3l/tq1u+lG6oxJmFgAAAACAF8epX1vORVEkAOq2zdz3r+Yl/+kPAA"
    "AAAIBp4GVqN9Pl1TIHYG7mH3h43xXilpeEfuYLkRUN+bjjj45b1T/ewI4zz4GLZjHu5OPjmHkAAAAAAJ4dE+q/LJyG"
    "qZ9z293ojkrcc0K8Kd5tnNBtv41GzotZ8YOO7NvtaxvFQN16T7zXEJ2dUMjtuK9k0Gwu+0FLSa/T84ehkrfjIJWBuh"
    "Q0335Lyaw/EGpXCTlME9nrBrLX+6K/1Lokg26k6+FSTx9XDMLgPx9OZp4Z3unrK4iH2Urm6eO7Uret5D2uDFUw/NyV"
    "URyqLX/Yy/RpXamiLLm78ujrDK5Mh0F6N81Uf6UTR2ncU+b9hgsNx7zZXrc5kjwXUuRMzojlRtlmZsgpsilmn4rZx7"
    "X5kjwvUuRPFvU+9aItzNMj3q7tseeaMfs1R+/Rj/IpZr+FsdzJjCh7AAAAAAD4d+ZZ/51ayzHr+B0Xp74xMb+5Xf+n"
    "3vaEjXnH1wc8o7d2Xgu/LtvKNQBtLHwlj4U/+8O5UJ7haec/QpwfB7ePOtxeW3kF5rM+fkWz4udDFjF0DuRElr73Hj"
    "zts5brILxaxOnjh60U7ZcP6TO5AJsXaObxffW7v96xcb61MNb3497rd2zupirmHHul5Wcz11Vz7FHLtmzUNjNqM8c7"
    "WbFH+Wde9vcrY7/Rh/cf3je15hF/USYhUxn7XjjFsa3aWJ2/PwAAAAB4VsoYrzKKRJ0DUT0AAAAAAJh0rP8HAAAAAM"
    "D0+9ZrOb//tPexudtvyjc+Ddrt9rp7Zf0DzywKIM3j7x9FW7GQkd9X6Wh9QPvCgDVrEglF/RhzCgAAAADAi6Z8t/+6"
    "3sxzAF9WbGm8ouu39HZD13f19ouO+c/qck5vJ4qw/3SRDjhWpAPM2gG1sXQAAAAAAAB4/v4GL6sZSgDwAAA="
)

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: decode the embedded PE+PDB, import the PE
# WITH its companion PDB, then read the program's symbols and report whether the PDB-recovered name
# is present. Ends with an explicit flush + os._exit(0).
_DRIVER = r"""
import base64, gzip, json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
PE_B64 = "__PE_B64__"
PDB_B64 = "__PDB_B64__"


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    exe = os.path.join(project_dir, "t.exe")
    pdb = os.path.join(project_dir, "t.pdb")
    with open(exe, "wb") as h:
        h.write(gzip.decompress(base64.b64decode(PE_B64)))
    with open(pdb, "wb") as h:
        h.write(gzip.decompress(base64.b64decode(PDB_B64)))

    backend = PyGhidraBackend()
    backend.import_binary({"source_ref": exe, "pdb_ref": pdb})  # auto PE load + PDB apply
    program = backend._require_program()
    names = sorted({str(s.getName()) for s in program.getSymbolTable().getAllSymbols(True)})
    return {
        "symbol_count": len(names),
        "has_the_answer": any("the_answer" in n for n in names),
        "has_helper": any("helper_routine" in n for n in names),
    }


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
""".replace("__PE_B64__", _PE_B64).replace("__PDB_B64__", _PDB_B64)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the container-run argv that drives the PDB apply in ``image``.

    Mirrors ``test_version_track.py``'s posture exactly (network-isolated, capped memory, read-only
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


def test_import_pdb_applies_companion_symbols_on_real_worker(worker_image: str) -> None:
    """``session_import`` with ``pdb_ref`` must apply the PDB's symbols to the loaded PE.

    Drives the in-container backend: import the embedded synthetic PE WITH its companion PDB, then
    read the program's symbols. Asserts the PDB-recovered function name ``the_answer`` (and
    ``helper_routine``) is present — proof the ``pdb2`` reader + ``DefaultPdbApplicator`` ran. A
    regression re-surfaces as ``ok=False`` (e.g. the applyNoAnalysisState path breaking) or a
    missing name.

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
            f"import_pdb run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"import_pdb reported failure (ADR-061?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    assert bool(data["has_the_answer"]), (
        f"PDB-recovered function 'the_answer' missing after companion-PDB import; got {data!r}"
    )
    assert bool(data["has_helper"]), f"PDB-recovered 'helper_routine' missing; got {data!r}"
