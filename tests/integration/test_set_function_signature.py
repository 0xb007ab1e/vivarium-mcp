"""Integration: ``set_function_signature`` applies against a real worker (ADR-014 happy path).

Regression guard for the JVM-overload bug: ``_gh_set_function_signature`` called Ghidra's
overloaded ``FunctionDB.updateFunction`` with a bare Python ``None`` in the ``String``
calling-convention slot and a raw ``DataType`` where a ``Variable`` (return parameter) is required.
JPype could match no overload → ``TypeError`` → ``_in_transaction`` rolled back → the tool always
failed ``analysis-failed``. The fix passes a ``String``-typed Java null for the unchanged
convention, wraps the return type in a ``ReturnParameterImpl``, and passes an explicit
``Variable[]`` (not Python varargs).

Why this test exists: every OTHER ``set_function_signature`` test either MOCKS the worker (the unit
suite) or asserts REJECTION (the abuse suite), so the real ``updateFunction`` call was never driven
to a SUCCESS — the two JVM-signature bugs shipped undetected. This is the missing happy-path live
gate: it drives the in-container backend to a committed write and asserts the applied prototype.

Why a gated, in-container integration test (not a unit test): the ``updateFunction`` call is the
JVM/PyGhidra edge (TB3, ADR-001) — excluded from server unit coverage and only validatable against a
real Ghidra worker. Gating + fixture posture are reused verbatim from
``test_export_annotations_after_rename.py``: ``integration``-marked (the default unit run SKIPS it),
runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No
real malware — the analyzed input is a benign OS utility already in the image (master §5).

Honored environment (same as ``test_export_annotations_after_rename.py``):
    * ``VIVARIUM_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``VIVARIUM_WORKER_IMAGE`` — the pinned-by-digest worker image ref (conftest fixture).
    * ``VIVARIUM_CONTAINER_ENGINE`` — container CLI to invoke (default ``podman``).
    * ``VIVARIUM_INTEGRATION_TARGET`` — in-image ELF to analyze (default ``/bin/true``).
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

# --- gating / engine constants (mirror test_export_annotations_after_rename.py) -------------------
_ENGINE_ENV = "VIVARIUM_CONTAINER_ENGINE"
_DEFAULT_ENGINE = "podman"
_TARGET_ENV = "VIVARIUM_INTEGRATION_TARGET"
_DEFAULT_TARGET = "/bin/true"
_SRC_MOUNT_ENV = "VIVARIUM_WORKER_SRC_MOUNT"

#: Generous ceiling for JVM boot + Ghidra auto-analysis + the signature write.
_RUN_TIMEOUT_SECONDS = 300
#: In-worker analysis budget hint passed to ``analyze`` (the harness ceiling is the hard wall).
_ANALYZE_TIMEOUT_SECONDS = 180

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: The parameter name applied by the probe — a benign, recognizable identifier the assertion checks
#: for in the re-rendered prototype (proves the write took, not just that the call returned).
_PROBE_PARAM = "vivarium_sig_probe"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: import -> analyze -> list functions -> pick
# the largest (real-body) function -> set_function_signature with an int return + one char* param
# and NO calling_convention (the exact None-convention path that failed). Prints one marker-prefixed
# JSON line and self-reports any failure as a parseable fail-closed envelope.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
TARGET = os.environ.get("VIVARIUM_INTEGRATION_TARGET", "/bin/true")
ANALYZE_TIMEOUT = int(os.environ.get("VIVARIUM_DRIVER_ANALYZE_TIMEOUT", "180"))
PROBE_PARAM = os.environ.get("VIVARIUM_DRIVER_PROBE_PARAM", "vivarium_sig_probe")


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    out = {}

    out["import"] = backend.import_binary({"source_ref": TARGET, "expected_sha256": None})
    out["analyze"] = backend.analyze({"timeout_seconds": ANALYZE_TIMEOUT})

    functions = backend.list_functions({"offset": 0, "limit": 100})
    rows = functions.get("functions") or []
    if not rows:
        raise RuntimeError("no functions found; cannot exercise set_function_signature")

    # Pick the largest function (a real body, not a 0/1-byte thunk or external stub).
    target_fn = max(rows, key=lambda r: int(r.get("size") or 0))["address"]

    # NO 'calling_convention' key -> params.get(...) is None -> the exact path that used to fail
    # JPype overload resolution. int return + one char* parameter exercises ReturnParameterImpl and
    # the Variable[] array assembly.
    out["set_function_signature"] = backend.set_function_signature(
        {
            "function": target_fn,
            "return_type": {"base": "int"},
            "parameters": [{"name": PROBE_PARAM, "type": {"base": "char", "pointer_levels": 1}}],
        }
    )
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
    """Build the container-run argv that drives the signature write in ``image``.

    Mirrors ``test_export_annotations_after_rename.py``'s posture exactly (network-isolated, capped
    memory, read-only rootfs + tmpfs scratch) so the regression is validated under the real deploy
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
        "VIVARIUM_WORKER_PROJECT_DIR=/work/project",
        "--env",
        f"{_TARGET_ENV}={target}",
        "--env",
        f"VIVARIUM_DRIVER_ANALYZE_TIMEOUT={_ANALYZE_TIMEOUT_SECONDS}",
        "--env",
        f"VIVARIUM_DRIVER_PROBE_PARAM={_PROBE_PARAM}",
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


def test_set_function_signature_applies_on_real_worker(worker_image: str) -> None:
    """Setting a function's signature must COMMIT against a live worker (JVM-overload regression).

    Drives the in-container backend: import → analyze → pick the largest function → set its
    signature to ``int fn(char * vivarium_sig_probe)`` with NO calling convention (the exact path
    that used to fail JPype overload resolution). Asserts the write applied and the re-rendered
    prototype carries the probe parameter — a regression re-surfaces here as ``ok=False`` with the
    ``analysis-failed`` / ``No matching overloads`` string instead of silently passing.

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
            f"set_function_signature run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
    assert envelope.get("ok") is True, (
        f"set_function_signature reported failure (JVM-overload regression?): "
        f"{envelope.get('error')!r}\n{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    result = data.get("set_function_signature") or {}
    assert result.get("applied") is True, f"signature did not apply: {result!r}"

    # The re-rendered prototype is a plain string here (the backend returns plain; the SERVER wraps
    # it untrusted). It must carry the applied return type + parameter name — proof the write took.
    new_signature = str(result.get("new_signature") or "")
    assert _PROBE_PARAM in new_signature, (
        f"expected the applied parameter {_PROBE_PARAM!r} in the re-rendered prototype; "
        f"got new_signature={new_signature!r}"
    )
