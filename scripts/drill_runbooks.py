#!/usr/bin/env python3
"""Dry-run drill harness for the rollback + evict-poisoned-worker runbooks (gap N10).

Validates that each runbook's PRECONDITIONS / recovery levers are present and prints the exact
command plan an operator would run — **without mutating anything**. It never reverts a pin, kills a
container, checks out a tag, or removes a socket dir; it only inspects (read-only) and reports. The
operator uses the printed plan to run the real game-day, then stamps the runbook's "Last validated"
footer. workflow-runbooks mandates that a runbook be DRILLED, not just written — this harness makes
the drill repeatable and surfaces a broken recovery path BEFORE an incident.

Fail closed: a missing lever (e.g. no prior worker digest in git history, no prior release tag, the
container engine absent) is reported as a FAILED precondition and the process exits non-zero.

Structure is functional-core / imperative-shell: the pure plan-builders + parsers below take plain
facts and return the plan (no I/O — unit-tested in tests/unit/test_drill_runbooks.py); the thin I/O
shell at the bottom gathers those facts (git history, ``shutil.which``) and prints the report.

Usage:
    python scripts/drill_runbooks.py --runbook all
    python scripts/drill_runbooks.py --runbook evict --session-id <sid>
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess  # nosec B404 — read-only `git`/`which` fact-gathering with literal arg lists only.
import sys
from dataclasses import dataclass
from pathlib import Path

# The runbook files this harness drills (relative to the repo root).
_PIN_FILE = ".github/worker-image.pin"
_WORKER_CONTAINER_PREFIX = "vivarium-worker-"
_DEFAULT_ENGINE = "podman"
_DEFAULT_SOCKET_DIR = "/run/vivarium"

# A session id is the only operator-supplied value embedded in the printed commands. Even though the
# harness NEVER executes them, the operator copy-pastes the plan into a shell, so an id with shell
# metacharacters would be a command-injection vector at THEIR prompt. Allow-list the real sid shape
# (opaque token, 1..64 of [A-Za-z0-9_-]) and fail closed on anything else (std-owasp-proactive #5).
_SID_RE = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")

# A worker-image pin is a digest reference; recover sha256 tokens from `git log -p` output.
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")


def validate_session_id(session_id: str) -> str:
    """Return ``session_id`` if it is a safe opaque token, else raise ``ValueError`` (fail closed).

    Args:
        session_id: The operator-supplied session id.

    Returns:
        The validated id, unchanged.

    Raises:
        ValueError: If the id is empty or contains anything outside ``[A-Za-z0-9_-]`` (1..64) — it
            must never reach a copy-pasted shell command as an injection vector.
    """
    if not _SID_RE.match(session_id):
        raise ValueError("session id must be 1..64 chars of [A-Za-z0-9_-]")
    return session_id


@dataclass(frozen=True, slots=True)
class DrillStep:
    """One step of a runbook drill: a read-only precondition + the command it would gate.

    Attributes:
        name: Short step label.
        action: What the operator would do at this step (human-readable).
        precondition_ok: Whether the read-only precondition for this step holds (None = not a gating
            precondition, just an informational/manual step).
        detail: Safe detail about the precondition result (no secrets).
        command: The exact command the operator would run (DATA — never executed by this harness),
            or ``None`` for a purely manual/observational step.
    """

    name: str
    action: str
    precondition_ok: bool | None
    detail: str
    command: str | None


def extract_prior_digest(pin_log: str, current_digest: str | None) -> str | None:
    """Find the most-recent worker-image digest in ``git log -p`` output that differs from current.

    The rollback lever is "restore the prior ``sha256:`` in the pin file" — so a drill must confirm
    a DISTINCT earlier digest exists in history. Pure text parse (no git invocation here).

    Args:
        pin_log: The ``git log -p -- .github/worker-image.pin`` output text.
        current_digest: The digest currently pinned (excluded from the result), or ``None``.

    Returns:
        The first digest in the log that differs from ``current_digest``, or ``None`` if history has
        no distinct prior digest (→ the rollback lever is unavailable).
    """
    for digest in _SHA256_RE.findall(pin_log):
        if digest != current_digest:
            return digest
    return None


def build_rollback_plan(
    *, pin_file_exists: bool, prior_digest: str | None, prior_tag: str | None, gh_available: bool
) -> list[DrillStep]:
    """Build the dry-run rollback plan from gathered facts (pure — no I/O).

    Args:
        pin_file_exists: Whether ``.github/worker-image.pin`` is present.
        prior_digest: A distinct earlier worker digest from history (the revert target), or None.
        prior_tag: A previous release tag to relaunch the server at, or ``None``.
        gh_available: Whether the ``gh`` CLI is on PATH (to cancel a running release run).

    Returns:
        The ordered drill steps with their precondition results + the commands that would run.
    """
    return [
        DrillStep(
            name="halt-promotion",
            action="Cancel any in-progress release run; stop merging/tagging the bad release.",
            precondition_ok=gh_available,
            detail="gh CLI present" if gh_available else "gh CLI NOT found — cancel run manually",
            command="gh run cancel <run-id>",
        ),
        DrillStep(
            name="revert-worker-pin",
            action=f"Restore the prior sha256 digest in {_PIN_FILE} (image still in GHCR).",
            precondition_ok=pin_file_exists and prior_digest is not None,
            detail=(
                f"prior digest available: {prior_digest}"
                if (pin_file_exists and prior_digest is not None)
                else "NO distinct prior digest in history — rollback lever unavailable"
            ),
            command=f"git log -p -- {_PIN_FILE}   # find + restore the prior sha256: digest",
        ),
        DrillStep(
            name="revert-server-commit",
            action="Relaunch the server at the previous release tag (python -m vivarium).",
            precondition_ok=prior_tag is not None,
            detail=(
                f"previous release tag: {prior_tag}"
                if prior_tag is not None
                else "NO previous release tag found — cannot pin server to a known-good commit"
            ),
            command=f"git checkout {prior_tag or '<previous-release-tag>'}",
        ),
        DrillStep(
            name="sessions-ephemeral",
            action="In-flight sessions are evicted on old-process exit (workers killed + stores "
            "wiped); clients re-open against the rolled-back version.",
            precondition_ok=None,  # observational; no lever to check (ADR-002 ephemeral sessions)
            detail="no DB/migrations in v1 — image/commit revert is the whole rollback",
            command=None,
        ),
    ]


def build_evict_plan(
    session_id: str, *, engine: str, socket_dir: str, engine_available: bool
) -> list[DrillStep]:
    """Build the dry-run evict-poisoned-worker plan for ``session_id`` (pure — no I/O).

    Args:
        session_id: The (already-validated) session id whose worker would be evicted.
        engine: The container engine (e.g. ``podman``).
        socket_dir: The server-owned RPC socket dir whose per-session subdir must vanish post-evict.
        engine_available: Whether ``engine`` is on PATH.

    Returns:
        The ordered drill steps with the exact (data-only) commands an operator would run.
    """
    container = f"{_WORKER_CONTAINER_PREFIX}{session_id}"
    return [
        DrillStep(
            name="identify-worker",
            action="List live workers; the vivarium-worker-<sid> name carries the session id.",
            precondition_ok=engine_available,
            detail=f"{engine} present" if engine_available else f"{engine} NOT found on PATH",
            command=(
                f'{engine} ps --filter "name={_WORKER_CONTAINER_PREFIX}" '
                "--format '{{.Names}}\\t{{.Status}}\\t{{.RunningFor}}'"
            ),
        ),
        DrillStep(
            name="capture-evidence-if-compromise",
            action="If sandbox-escape is suspected: capture evidence FIRST, then escalate.",
            precondition_ok=None,  # conditional manual step (only on suspected compromise)
            detail="rootfs is read-only (ADR-004) → any podman diff is notable; logs are redacted",
            command=(
                f"{engine} logs {container} > evict-{session_id}.log 2>&1; "
                f"{engine} inspect {container} > evict-{session_id}.inspect.json; "
                f"{engine} diff {container} > evict-{session_id}.diff"
            ),
        ),
        DrillStep(
            name="orchestrator-kill",
            action="Kill + remove the worker container (the poison lever — no session trust). "
            "The server then logs session_evicted with store_wiped: true.",
            precondition_ok=engine_available,
            detail="DRY-RUN: this command is NOT executed by the harness",
            command=f"{engine} kill {container} 2>/dev/null || true; "
            f"{engine} rm -f {container} 2>/dev/null || true",
        ),
        DrillStep(
            name="verify-wipe",
            action="Confirm the per-session socket dir is gone (project store is worker tmpfs — "
            "destroyed with the container by construction, ADR-002).",
            precondition_ok=None,  # verification step run AFTER a real evict, not during the drill
            detail="expect: No such file or directory; store_wiped:false = a confidentiality bug",
            command=f"ls -la {socket_dir}/{session_id}   # expect: No such file or directory",
        ),
    ]


def render_report(title: str, steps: list[DrillStep]) -> tuple[str, bool]:
    """Render a drill plan to a text report and report whether every gating precondition passed.

    Args:
        title: The runbook title.
        steps: The drill steps.

    Returns:
        ``(report_text, all_preconditions_ok)``. A step with ``precondition_ok is None`` is
        informational and never fails the drill.
    """
    lines = [f"=== DRILL (dry-run): {title} ===", ""]
    all_ok = True
    for i, step in enumerate(steps, 1):
        if step.precondition_ok is None:
            mark = "·"
        elif step.precondition_ok:
            mark = "PASS"
        else:
            mark = "FAIL"
            all_ok = False
        lines.append(f"[{mark}] {i}. {step.name} — {step.action}")
        lines.append(f"      precondition: {step.detail}")
        if step.command is not None:
            lines.append(f"      would run:    {step.command}")
        lines.append("")
    lines.append(f"RESULT: {'all preconditions PASS' if all_ok else 'a precondition FAILED'}")
    return "\n".join(lines), all_ok


# --- I/O shell (read-only fact gathering) ---


def _run_git(args: list[str], *, repo_root: Path) -> str:
    """Run a read-only git command and return stdout (empty on failure). Never mutates the repo."""
    try:
        proc = subprocess.run(  # nosec B603 B607  # noqa: S603 — literal arg list, no shell.
            ["git", *args],  # noqa: S607 — `git` from PATH is intended for a dev/ops drill script.
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def gather_rollback_facts(repo_root: Path) -> dict[str, object]:
    """Gather (read-only) the facts the rollback plan needs: pin, prior digest, prior tag."""
    pin_path = repo_root / _PIN_FILE
    pin_file_exists = pin_path.is_file()
    current_digest: str | None = None
    if pin_file_exists:
        match = _SHA256_RE.search(pin_path.read_text(encoding="utf-8", errors="replace"))
        current_digest = match.group(0) if match else None
    pin_log = _run_git(["log", "-p", "--", _PIN_FILE], repo_root=repo_root)
    prior_digest = extract_prior_digest(pin_log, current_digest)
    tags = _run_git(["tag", "--sort=-creatordate"], repo_root=repo_root).split()
    return {
        "pin_file_exists": pin_file_exists,
        "prior_digest": prior_digest,
        "prior_tag": tags[0] if tags else None,
        "gh_available": shutil.which("gh") is not None,
    }


def main(argv: list[str] | None = None) -> int:
    """Run the dry-run drill(s) and exit non-zero if any gating precondition fails."""
    parser = argparse.ArgumentParser(
        description="Dry-run drill harness for vivarium runbooks (N10)."
    )
    parser.add_argument("--runbook", choices=("rollback", "evict", "all"), default="all")
    parser.add_argument(
        "--session-id", default="DRILLSID0000", help="session id for the evict drill"
    )
    parser.add_argument(
        "--engine", default=_DEFAULT_ENGINE, help="container engine (podman/docker)"
    )
    parser.add_argument("--socket-dir", default=_DEFAULT_SOCKET_DIR, help="RPC socket dir")
    ns = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]

    overall_ok = True
    if ns.runbook in ("rollback", "all"):
        facts = gather_rollback_facts(repo_root)
        report, ok = render_report(
            "Rollback",
            build_rollback_plan(
                pin_file_exists=bool(facts["pin_file_exists"]),
                prior_digest=facts["prior_digest"],  # type: ignore[arg-type]
                prior_tag=facts["prior_tag"],  # type: ignore[arg-type]
                gh_available=bool(facts["gh_available"]),
            ),
        )
        print(report + "\n")
        overall_ok = overall_ok and ok
    if ns.runbook in ("evict", "all"):
        try:
            sid = validate_session_id(ns.session_id)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        report, ok = render_report(
            "Evict / rotate a poisoned worker",
            build_evict_plan(
                sid,
                engine=ns.engine,
                socket_dir=ns.socket_dir,
                engine_available=shutil.which(ns.engine) is not None,
            ),
        )
        print(report + "\n")
        overall_ok = overall_ok and ok

    print("DRILL COMPLETE — dry-run only; no rollback performed, no container killed.")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
