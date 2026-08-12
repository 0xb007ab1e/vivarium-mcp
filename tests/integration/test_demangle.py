"""Integration: C++ symbol demangling runs against a real worker (ADR-050, v1.8 demangle).

Regression + capability gate for the ``demangle`` tool: Ghidra's GNU/Itanium + MSVC demanglers turn
a mangled symbol into a readable signature — a pure, program-independent string transform (no
program is loaded or mutated; read-only). Three properties are proven live:

    1. **GNU/Itanium** — ``_ZN3foo3barEi`` demangles to ``foo::bar(int)`` (scheme ``gnu``).
    2. **MSVC** — ``?bar@foo@@QAEHH@Z`` demangles to ``foo::bar(int)`` (scheme ``msvc``).
    3. **auto + no-match** — ``auto`` resolves each name to the right scheme, and a non-mangled
       string returns ``demangled=None`` / ``scheme=None`` (a non-mangled input is not an error).

Why a gated in-container test (not a unit test): the demangler classes are the JVM/PyGhidra edge
(TB3, ADR-001) — excluded from server unit coverage and only validatable against a real Ghidra
worker. Gating + fixture posture are reused verbatim from ``test_import_emulate.py``:
``integration``-marked (the default unit run SKIPS it), runs only when ``VIVARIUM_INTEGRATION`` is
truthy AND a real worker image + engine are available. No binary is analyzed — the inputs are a pair
of synthetic mangled strings.

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

#: Generous ceiling for JVM boot + a handful of demangle calls.
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: call `demangle` on a GNU name, an MSVC name
# (forced schemes), both under `auto`, and a non-mangled string. No program is imported — the
# demanglers are pure. Prints one marker-prefixed JSON line and self-reports failures.
_DRIVER = r"""
import json, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    gnu_name = "_ZN3foo3barEi"
    msvc_name = "?bar@foo@@QAEHH@Z"
    return {
        "gnu": backend.demangle({"mangled": gnu_name, "scheme": "gnu"}),
        "msvc": backend.demangle({"mangled": msvc_name, "scheme": "msvc"}),
        "auto_gnu": backend.demangle({"mangled": gnu_name, "scheme": "auto"}),
        "auto_msvc": backend.demangle({"mangled": msvc_name, "scheme": "auto"}),
        "none": backend.demangle({"mangled": "not_a_mangled_name", "scheme": "auto"}),
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
"""


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the container-run argv that drives the demangle calls in ``image``.

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


def test_demangle_resolves_gnu_and_msvc_on_real_worker(worker_image: str) -> None:
    """``demangle`` resolves GNU + MSVC names, honors ``auto``, returns None on no match (ADR-050).

    Drives the in-container backend: demangle a GNU/Itanium name and an MSVC name (forced), both via
    ``auto``, and a non-mangled string. Asserts each demangles to ``foo::bar(int)`` with the right
    ``scheme``, that ``auto`` picks the correct demangler, and that a non-mangled string yields
    ``demangled=None`` / ``scheme=None``. A regression re-surfaces here as ``ok=False`` or a wrong
    signature/scheme.

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
            f"demangle run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"demangle reported failure (ADR-050 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    # GNU/Itanium
    gnu = data.get("gnu", {})
    assert gnu.get("scheme") == "gnu", f"expected scheme 'gnu'; got {gnu.get('scheme')!r}"
    assert "foo::bar(int)" in str(gnu.get("demangled")), f"GNU demangle wrong: {gnu!r}"

    # MSVC
    msvc = data.get("msvc", {})
    assert msvc.get("scheme") == "msvc", f"expected scheme 'msvc'; got {msvc.get('scheme')!r}"
    assert "foo::bar(int)" in str(msvc.get("demangled")), f"MSVC demangle wrong: {msvc!r}"

    # auto picks the right demangler for each name
    assert data.get("auto_gnu", {}).get("scheme") == "gnu", (
        f"auto misrouted GNU: {data.get('auto_gnu')!r}"
    )
    assert data.get("auto_msvc", {}).get("scheme") == "msvc", (
        f"auto misrouted MSVC: {data.get('auto_msvc')!r}"
    )

    # a non-mangled string is not an error — it just does not match any scheme
    none = data.get("none", {})
    assert none.get("demangled") is None, f"expected None for a non-mangled string; got {none!r}"
    assert none.get("scheme") is None, (
        f"expected scheme None for a non-mangled string; got {none!r}"
    )
