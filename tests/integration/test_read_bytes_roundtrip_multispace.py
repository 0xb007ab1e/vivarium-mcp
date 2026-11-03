"""Integration regression for #372 / #385: `read_bytes` round-trips a `memory_map` address.

#372: `_parse_address` hardcoded the default address space, so an address that lives in a
non-default / overlay space (e.g. a multi-space processor, or an F1 overlay mapped into `:local`)
was read from the default-space offset — returning a different block's bytes or an all-zero /
truncated read. The fix parses via `AddressFactory.getAddress`, which honours both a bare hex
offset AND a **space-qualified** address (`CODE:0100` / `OVL::0100`). `memory_map` *emits*
`str(block.getStart())`, which is space-qualified for a non-default space — so the exact bug is:
an address `memory_map` hands you cannot be fed back to `read_bytes`.

This test asserts that **contract directly**: import a headerless blob with a **multi-space
processor** (8051 — CODE / INTMEM / EXTMEM spaces, so block starts stringify space-qualified),
then for the loaded block feed the start address `memory_map` emitted straight into `read_bytes`
and assert it returns the ACTUAL loaded bytes (not a zero-fill / wrong block). On an unfixed worker
the qualified address fails to parse / reads the wrong space; the fix makes the round-trip hold.

The overlay-via-JieLi reproduction (the original Pocket-T19 symptom) needs a JieLi fixture and
stays tracked in #385; this multi-space variant exercises the same `_parse_address` fix without
one. Gating + in-worker-driver posture mirror `test_import_raw_binary.py`.
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
_RUN_TIMEOUT_SECONDS = 420
_MARKER = "__VIVARIUM_RESULT__"

#: Multi-space processor: 8051 has CODE/INTMEM/EXTMEM/SFR spaces, so a loaded block's start
#: stringifies space-qualified — the format that broke `read_bytes` before #372.
_PROCESSOR = "8051:BE:16:default"
_BASE_ADDR = 0x0100
#: The first 8 bytes of the loaded blob (``bytes(range(16))`` ⇒ 00 01 … 07), as the hex `read_bytes`
#: must return at the block start — any zero-fill / wrong-space read fails this.
_EXPECTED_HEAD = "0001020304050607"

_DRIVER = r"""
import json, os, sys, traceback

MARKER = "__VIVARIUM_RESULT__"
PROCESSOR = os.environ["VIVARIUM_DRIVER_PROCESSOR"]
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x100"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    blob = bytes(range(16)) * 4  # 64 deterministic bytes; head = 00 01 .. 07
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "raw_fw.bin")
    with open(path, "wb") as handle:
        handle.write(blob)

    backend = PyGhidraBackend()
    out = {}
    out["import"] = backend.import_binary(
        {
            "source_ref": path,
            "loader": "binary",
            "processor": PROCESSOR,
            "base_addr": BASE_ADDR,
            "entry": BASE_ADDR,
        }
    )
    mm = backend.memory_map({})
    out["memory_map"] = mm
    # THE #372 contract: feed each emitted block start straight back into read_bytes.
    reads = []
    for block in mm.get("blocks", []):
        start = block.get("start")
        if start is None:
            continue
        reads.append({"start": start, "read": backend.read_bytes({"address": start, "length": 8})})
    out["roundtrip_reads"] = reads
    return out


try:
    result = {"ok": True, "data": main()}
except Exception as exc:  # fail-closed envelope
    result = {"ok": False, "error": "{}: {}".format(type(exc).__name__, exc),
              "traceback": traceback.format_exc()}

sys.stdout.write("\n" + MARKER + json.dumps(result) + "\n")
sys.stdout.flush()
"""


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
        "--env",
        f"VIVARIUM_DRIVER_PROCESSOR={_PROCESSOR}",
        "--env",
        f"VIVARIUM_DRIVER_BASE_ADDR={hex(_BASE_ADDR)}",
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
    assert lines, f"no result marker in worker stdout:\n{stdout[-2000:]}"
    try:
        parsed: dict[str, Any] = json.loads(lines[-1][len(_MARKER) :])
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise AssertionError(f"marker payload not valid JSON: {exc}") from exc
    return parsed


def test_read_bytes_round_trips_a_memory_map_address(worker_image: str) -> None:
    """An address `memory_map` emits must feed straight into `read_bytes` (the #372 fix).

    On a multi-space processor the emitted block start is space-qualified; an unfixed
    `_parse_address` (default-space only) cannot read it. The fix must return the actual loaded
    bytes at that exact emitted address.
    """
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
        pytest.fail(f"run timed out after {_RUN_TIMEOUT_SECONDS}s\n{captured[-2000:]}")

    if proc.returncode != 0:
        pytest.fail(f"worker exited {proc.returncode}\n--- stderr ---\n{proc.stderr[-2000:]}")

    envelope = _parse_marker_json(proc.stdout)
    assert envelope.get("ok") is True, (
        f"import/round-trip reported failure: {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    reads = data.get("roundtrip_reads") or []
    assert reads, f"no memory blocks to round-trip: {data.get('memory_map')!r}"

    # The block holding the loaded image round-trips: read_bytes at the ADDRESS memory_map emitted
    # returns the actual loaded head bytes (not a zero-fill / wrong-space read). This is the fix.
    matched = [r for r in reads if r.get("read", {}).get("data") == _EXPECTED_HEAD]
    assert matched, (
        "read_bytes did not return the loaded bytes at any memory_map-emitted block start "
        f"(#372 space-qualified-address regression); expected {_EXPECTED_HEAD!r} at one of "
        f"{[r['start'] for r in reads]!r}; got "
        f"{[(r['start'], r.get('read', {}).get('data')) for r in reads]!r}"
    )
    # The crux of #372/#385: the round-tripped block start is **space-qualified** (a non-default
    # space on this multi-space processor — e.g. ``CODE:0100``). A bare offset would NOT exercise
    # the fix (the old default-space-only parse handles bare offsets fine); only a qualified address
    # caused the original Pocket-T19 zero-read. ``:`` distinguishes qualified from a bare offset.
    start = matched[0]["start"]
    assert ":" in start, (
        f"expected the round-tripped block start to be SPACE-QUALIFIED (exercising the #372 "
        f"qualified-address path); got a bare offset {start!r}. All emitted starts: "
        f"{[r['start'] for r in reads]!r}"
    )

    # And that read did not silently truncate.
    assert matched[0]["read"].get("truncated") is False, (
        f"read_bytes over mapped memory should not truncate: {matched[0]!r}"
    )
