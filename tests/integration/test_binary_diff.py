"""Integration: function-granularity `binary_diff` on a real worker (ADR-067, v1.9 binary_diff).

Regression + capability gate for the ``binary_diff`` tool: Ghidra loads TWO binaries fresh in one
worker, analyzes each, pairs functions by name, and reports added/removed/changed. Proven live:

    * write two IDENTICAL synthetic ARM ELFs; ``binary_diff(a, b, match_by="name")`` returns an
      empty diff — ``summary.added == summary.removed == summary.changed == 0`` and all three entry
      lists empty (identical programs have no deltas). A regression in the two-program load / pair /
      compare pipeline re-surfaces as ``ok=False`` or a spurious non-zero delta.

Why a gated in-container test (not a unit test): the diff pipeline (two fresh domain-file loads +
two auto-analyses + the name-pairing comparison over the loaded programs) is the JVM/PyGhidra edge
(TB3, ADR-001) — excluded from server unit coverage and only validatable against a real Ghidra
worker. Gating + fixture posture are reused verbatim from ``test_version_track.py``:
``integration``-marked (the default unit run SKIPS it), runs only when ``VIVARIUM_INTEGRATION`` is
truthy AND a real worker image + engine are available. No real malware — the inputs are two copies
of a tiny synthetic ARM ELF.

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

#: Generous ceiling for JVM boot + TWO imports + TWO auto-analyses + the diff.
_RUN_TIMEOUT_SECONDS = 420

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: A 239-byte synthetic ARM ELF (from ``tests/_fixtures/binaries.synthetic_arm32_elf`` — embedded
#: so the in-container driver is self-contained; the ``tests`` tree is NOT in the worker image).
#: Ghidra analyzes it into ``ARM:LE:32:v8`` with one function; two copies diff to nothing.
_ARM_ELF_HEX = (
    "7f454c4601010100000000000000000002002800010000005400010034000000770000000002000534002000010028"
    "000300020001000000000000000000010000000100ef000000ef00000005000000001000"
    "0000bf00bf00bf00bf00bf00bf00bf00bf7047002e74657874002e73687374727461620000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000"
    "0600000054000100540000001200000000000000000000000200000000000000070000000300000000000000000000"
    "00660000001100000000000000000000000100000000000000"
)

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: write two identical ELFs, then diff them
# by name. Ends with an explicit flush + os._exit(0) — the two-program pipeline's non-daemon JVM
# threads otherwise keep the process alive and lose buffered stdout.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
ARM_ELF = bytes.fromhex("__ARM_ELF_HEX__")


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path_a = os.path.join(project_dir, "a.bin")
    path_b = os.path.join(project_dir, "b.bin")
    for path in (path_a, path_b):
        with open(path, "wb") as handle:
            handle.write(ARM_ELF)

    backend = PyGhidraBackend()
    return backend.binary_diff(
        {
            "program_a": path_a,
            "program_b": path_b,
            "match_by": "name",
            "include_unchanged": True,
            "max_entries": 100,
        }
    )


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


def _build_command(engine: str, image: str, driver: str = _DRIVER) -> list[str]:
    """Build the network-isolated container-run argv driving ``driver`` in ``image``.

    Mirrors ``test_version_track.py``'s posture exactly (network-isolated, capped memory,
    read-only rootfs + tmpfs scratch), then overrides the entrypoint to ``python -c <driver>``.

    Args:
        engine: The container engine binary (``podman``/``docker``).
        image: The worker image reference (pinned by digest in CI; resolved by the fixture).
        driver: The in-container Python driver to run (defaults to the name-diff driver).

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
    cmd += ["--entrypoint", "python", image, "-c", driver]
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


def test_binary_diff_identical_programs_on_real_worker(worker_image: str) -> None:
    """``binary_diff`` of two identical programs must report an empty diff (no false deltas).

    Drives the in-container backend: write two identical synthetic ARM ELFs, then
    ``binary_diff(a, b, match_by="name")``. Asserts ``ok`` and that every category count and entry
    list is empty — two byte-identical programs have no added/removed/changed functions. A
    regression in the two-program load / name-pairing / comparison pipeline re-surfaces as
    ``ok=False`` (e.g. the throwaway-project load lifecycle breaking) or a spurious non-zero delta.

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
    except subprocess.TimeoutExpired as exc:  # don't hang the suite — fail with what we captured.
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"binary_diff run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"binary_diff reported failure (ADR-067 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    summary = data.get("summary") or {}
    assert int(summary.get("added", -1)) == 0, f"identical programs added a function: {data!r}"
    assert int(summary.get("removed", -1)) == 0, f"identical programs removed a function: {data!r}"
    assert int(summary.get("changed", -1)) == 0, f"identical programs changed a function: {data!r}"
    assert (data.get("added") or []) == [], f"non-empty added list on identical inputs: {data!r}"
    assert (data.get("removed") or []) == [], (
        f"non-empty removed list on identical inputs: {data!r}"
    )
    assert (data.get("changed") or []) == [], (
        f"non-empty changed list on identical inputs: {data!r}"
    )
    # include_unchanged=True: the shared function(s) are name-paired + non-differing, so the
    # correspondence map is non-empty and its honest count matches the returned list.
    assert int(summary.get("unchanged", 0)) >= 1, f"expected >=1 unchanged name-pair: {data!r}"
    assert len(data.get("unchanged") or []) >= 1, (
        f"empty unchanged list despite the count: {data!r}"
    )


# --- ADR-067 bsim (content) pairing --------------------------------------------------------------
# Two tiny freestanding x86-64 ELFs built from the SAME `transform`/`helper` functions, but variant
# B has a leading `pad_lead` function that SHIFTS transform/helper to different addresses. Stripped,
# their names become address-derived (FUN_<addr>) — so NAME-pairing mispairs (B's pad_lead lands at
# A's transform address → same FUN_ name, different content), while BSim pairs by CONTENT:
# A.transform ↔ B.transform score ~1.0 despite the address/name difference. Built with:
#   gcc -Os -fno-pie -no-pie -nostdlib -nostartfiles -e entry{A,B} -Wl,-N,--build-id=none \
#       -Wl,-z,noseparate-code core3{,b}.c -o elf{A,B} && strip elf{A,B}
_ELF_A_HEX = (
    "7f454c4602010100000000000000000002003e00010000002101400000000000400000000000000000020000"
    "00000000000000004000380003004000060005000100000007000000e800000000000000e800400000000000"
    "e800400000000000c400000000000000c400000000000000080000000000000050e574640400000034010000"
    "0000000034014000000000003401400000000000240000000000000024000000000000000400000000000000"
    "51e5746406000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000100000000000000031c031c939c67e116b14870383c20789148701d148ffc0ebeb89c8c389f80faf"
    "c70fafc7ffc00fafc783c0020fafc783c0030fafc783c003c3e8c2ffffff8b3f89c2e8d5ffffff01d0c30000"
    "011b033b2000000003000000b4ffffff3c000000d0ffffff50000000edffffff640000001400000000000000"
    "017a5200017810011b0c070890010000100000001c00000070ffffff1c000000000000001000000030000000"
    "78ffffff1d00000000000000100000004400000081ffffff11000000000000004743433a202844656269616e"
    "2031342e322e302d3139292031342e322e3000002e7368737472746162002e74657874002e65685f6672616d"
    "655f686472002e65685f6672616d65002e636f6d6d656e740000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000b000000010000000700000000000000e800400000000000e8000000000000004a00000000000000"
    "0000000000000000010000000000000000000000000000001100000001000000020000000000000034014000"
    "0000000034010000000000002400000000000000000000000000000004000000000000000000000000000000"
    "1f00000001000000020000000000000058014000000000005801000000000000540000000000000000000000"
    "0000000008000000000000000000000000000000290000000100000030000000000000000000000000000000"
    "ac010000000000001f0000000000000000000000000000000100000000000000010000000000000001000000"
    "0300000000000000000000000000000000000000cb0100000000000032000000000000000000000000000000"
    "01000000000000000000000000000000"
)
_ELF_B_HEX = (
    "7f454c4602010100000000000000000002003e00010000003801400000000000400000000000000048020000"
    "00000000000000004000380003004000060005000100000007000000e800000000000000e800400000000000"
    "e80040000000000008010000000000000801000000000000080000000000000050e57464040000005c010000"
    "000000005c014000000000005c014000000000002c000000000000002c000000000000000400000000000000"
    "51e5746406000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000100000000000000031c031d239f87d0c8d48fd0fafc8ffc001caebf089d0c331c031c939c67e116b"
    "14870383c20789148701d148ffc0ebeb89c8c389f80fafc70fafc7ffc00fafc783c0020fafc783c0030fafc7"
    "83c003c34989f989f7e8a6ffffff4c89cf4189c0e8b2ffffff418b394101c0e8c3ffffff4401c0c3011b033b"
    "28000000040000008cffffff44000000a3ffffff58000000bfffffff6c000000dcffffff8000000014000000"
    "00000000017a5200017810011b0c070890010000100000001c00000040ffffff170000000000000010000000"
    "3000000043ffffff1c0000000000000010000000440000004bffffff1d000000000000001000000058000000"
    "54ffffff24000000000000004743433a202844656269616e2031342e322e302d3139292031342e322e300000"
    "2e7368737472746162002e74657874002e65685f6672616d655f686472002e65685f6672616d65002e636f6d"
    "6d656e7400000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000b0000000100000007000000"
    "00000000e800400000000000e800000000000000740000000000000000000000000000000100000000000000"
    "0000000000000000110000000100000002000000000000005c014000000000005c010000000000002c000000"
    "000000000000000000000000040000000000000000000000000000001f000000010000000200000000000000"
    "8801400000000000880100000000000068000000000000000000000000000000080000000000000000000000"
    "00000000290000000100000030000000000000000000000000000000f0010000000000001f00000000000000"
    "0000000000000000010000000000000001000000000000000100000003000000000000000000000000000000"
    "000000000f020000000000003200000000000000000000000000000001000000000000000000000000000000"
)
_DRIVER_BSIM = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
ELF_A = bytes.fromhex("__ELF_A_HEX__")
ELF_B = bytes.fromhex("__ELF_B_HEX__")


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path_a = os.path.join(project_dir, "a.elf")
    path_b = os.path.join(project_dir, "b.elf")
    with open(path_a, "wb") as h:
        h.write(ELF_A)
    with open(path_b, "wb") as h:
        h.write(ELF_B)

    backend = PyGhidraBackend()
    return backend.binary_diff(
        {
            "program_a": path_a,
            "program_b": path_b,
            "match_by": "bsim",
            "min_similarity": 0.7,
            "include_unchanged": True,
            "max_entries": 100,
        }
    )


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
""".replace("__ELF_A_HEX__", _ELF_A_HEX).replace("__ELF_B_HEX__", _ELF_B_HEX)


def test_binary_diff_bsim_content_pairing_on_real_worker(worker_image: str) -> None:
    """``binary_diff`` with ``match_by="bsim"`` pairs identical functions across shifted addresses.

    Drives the in-container backend: two stripped x86-64 ELFs sharing ``transform``/``helper`` but
    at different addresses (variant B has a leading ``pad_lead``). Under ``bsim`` content-pairing
    they correlate despite the address-derived name difference, so ``transform`` + ``helper`` land
    in the ``unchanged`` correspondence (sim ~1.0) and B's extra ``pad_lead`` is ``added``. A
    regression in
    the sign/greedy-pair/classify path re-surfaces as ``ok=False`` or a missing correspondence.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image, _DRIVER_BSIM)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"binary_diff bsim run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"binary_diff bsim reported failure (ADR-067 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    summary = data.get("summary") or {}
    # transform + helper are identical across the two builds → bsim pairs them (sim ~1.0) as
    # unchanged, DESPITE the shifted addresses that break name-pairing.
    assert int(summary.get("unchanged", 0)) >= 2, (
        f"expected >=2 bsim-paired unchanged functions (transform + helper); got {data!r}"
    )
    # B's extra leading pad_lead has no A counterpart → added.
    assert int(summary.get("added", 0)) >= 1, (
        f"expected >=1 added function (pad_lead); got {data!r}"
    )
