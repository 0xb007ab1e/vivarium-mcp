"""Integration: cross-binary BSim corpus search on a real worker (ADR-062, v1.8 bsim_search_corpus).

Regression + capability gate for the ``bsim_search_corpus`` tool: BSim compares a target binary's
functions against a corpus of reference binaries loaded fresh in one worker (ephemeral — no
persistent DB). Proven live:

    * a target ELF and a reference ELF sharing a function; ``bsim_search_corpus(target,
      [reference])`` returns that cross-binary function match at high similarity, naming the
      matched reference by index.

Why a gated in-container test (not a unit test): the BSim pipeline (per-binary load + auto-analysis
+ ``GenSignatures`` + cross-program ``LSHVector.compare``) is the JVM/PyGhidra edge (TB3, ADR-001) —
excluded from server unit coverage and only validatable against a real Ghidra worker. Gating +
posture reuse ``test_version_track.py`` verbatim. No real malware — a tiny synthetic ARM ELF used as
both the target and the (separately-loaded) reference, proving the cross-binary compare.

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

#: Generous ceiling for JVM boot + two ELF imports + two auto-analyses + the BSim sign/compare.
_RUN_TIMEOUT_SECONDS = 420

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: A 239-byte synthetic ARM ELF (from ``tests/_fixtures/binaries.synthetic_arm32_elf`` — embedded so
#: the in-container driver is self-contained). Ghidra analyzes it into ``ARM:LE:32`` with one
#: function; used as BOTH the target and a separately-loaded reference, so its function matches
#: itself across the two loads at similarity 1.0.
_ARM_ELF_HEX = (
    "7f454c46010101000000000000000000020028000100000054000100340000007700000000020005340020000100"
    "28000300020001000000000000000000010000000100ef000000ef000000050000000010000000bf00bf00bf00bf"
    "00bf00bf00bf00bf7047002e74657874002e73687374727461620000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000001000000010000000600000054000100540000001200000000"
    "00000000000000020000000000000007000000030000000000000000000000660000001100000000000000000000"
    "000100000000000000"
)

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: write the ELF as a target + a reference,
# bsim_search_corpus the target against the one-reference corpus. Ends with an explicit flush +
# os._exit(0) — the BSim/JVM non-daemon threads otherwise keep the process alive.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
ARM_ELF = bytes.fromhex("__ARM_ELF_HEX__")


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    target = os.path.join(project_dir, "target.elf")
    reference = os.path.join(project_dir, "reference.elf")
    for path in (target, reference):
        with open(path, "wb") as handle:
            handle.write(ARM_ELF)

    backend = PyGhidraBackend()
    return backend.bsim_search_corpus(
        {
            "target_ref": target,
            "reference_refs": [reference],
            "min_similarity": 0.5,
            "limit": 50,
            "max_scan": 100,
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


def _build_command(engine: str, image: str) -> list[str]:
    """Build the container-run argv that drives the BSim corpus search in ``image``.

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


def test_bsim_search_corpus_matches_across_binaries_on_real_worker(worker_image: str) -> None:
    """``bsim_search_corpus`` must find a target function in a separately-loaded reference binary.

    Drives the in-container backend: write the ELF as a target + a reference, then
    ``bsim_search_corpus(target, [reference])``. Asserts a single match, similarity 1.0 (the shared
    function), naming the reference by index 0, with the (identical) target/reference addresses. A
    regression re-surfaces as ``ok=False`` (e.g. vectors not surviving release) or an empty set.

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
            f"bsim_search_corpus run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"bsim_search_corpus reported failure (ADR-062?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    matches = data["matches"]
    assert matches, f"expected a cross-binary match; got {data!r}"
    top = matches[0]
    assert float(top["similarity"]) >= 0.99, f"the shared function must match ~1.0; got {top!r}"
    assert int(top["reference_index"]) == 0, f"the match must name reference 0; got {top!r}"
    assert top["target_address"] == top["reference_address"], (
        f"identical binaries: the matched addresses must agree; got {top!r}"
    )
    assert int(data["corpus_functions_scanned"]) >= 1, f"the reference must be signed; got {data!r}"
