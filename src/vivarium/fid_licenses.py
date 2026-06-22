"""Bundled-FID-DB source license allow-list gate (ADR-043 Phase 2 / D5; topic-license-compliance).

A merge-blocking gate over the FID-DB **source set** (``deploy/fid/sources.toml``): every source
library whose code is hashed into a shipped ``.fidbf`` must carry a PERMISSIVE SPDX license.
Copyleft ids (``LGPL-*`` / ``GPL-*`` / ``AGPL-*``) and OpenSSL pre-3.0 (the ``OpenSSL`` id) are
BLOCKED — a
copyleft source cannot enter the build without an explicit, reviewed, time-boxed waiver + counsel
sign-off (SPIKE-2 §5, ``docs/security/fid-database-licensing.md``).

Pure + fail-closed: an unknown/missing SPDX id, or any id outside the allow-list, fails the gate.
The ``.fidbf`` is shipped inside the Apache-2.0 worker image, so its source license must be
outbound-
compatible (permissive). This module is the single source of truth for the allow-list, imported by
both the CI gate (``python -m vivarium.fid_licenses``) and the hermetic test.

Run as a CLI: ``python -m vivarium.fid_licenses [path/to/sources.toml]`` — exits ``0`` when every
source passes, ``1`` (with a listing of the offending entries) otherwise.
"""

from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

#: PERMISSIVE SPDX ids allowed for a bundled-FID-DB source (ADR-043 D5). Outbound-compatible with
#: the Apache-2.0 worker image. The single source of truth — the test and the CLI both import this.
ALLOWED_SPDX: frozenset[str] = frozenset(
    {"Zlib", "MIT", "Apache-2.0", "BSL-1.0", "BSD-2-Clause", "BSD-3-Clause"}
)

#: Default manifest location (repo-relative; resolved from this file so the CLI works from any cwd).
DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "deploy" / "fid" / "sources.toml"


@dataclass(frozen=True, slots=True)
class LicenseViolation:
    """A source whose SPDX license is not in the permissive allow-list (a gate failure).

    Attributes:
        name: The source library name (e.g. ``readline``).
        spdx: The offending SPDX id (e.g. ``GPL-3.0-or-later``), or ``"<missing>"`` if absent.
        reason: A short human reason (``"copyleft/blocked"`` or ``"not in allow-list"`` /
            ``"missing spdx"``).
    """

    name: str
    spdx: str
    reason: str


def _classify(name: str, spdx: str | None) -> LicenseViolation | None:
    """Return a :class:`LicenseViolation` for a source, or ``None`` when it passes (pure).

    Fail-closed: a missing/empty SPDX id is a violation; any id outside :data:`ALLOWED_SPDX` is a
    violation (copyleft / OpenSSL-pre-3.0 / unknown all land here). The allow-list is the gate — we
    never need an explicit deny-list, but we label copyleft ids for a clearer message.

    Args:
        name: The source library name.
        spdx: The declared SPDX id, or ``None``.

    Returns:
        A violation, or ``None`` when the source is allowed.
    """
    if not spdx:
        return LicenseViolation(name=name, spdx="<missing>", reason="missing spdx")
    if spdx in ALLOWED_SPDX:
        return None
    upper = spdx.upper()
    if upper.startswith(("LGPL", "GPL", "AGPL")) or spdx == "OpenSSL":
        return LicenseViolation(name=name, spdx=spdx, reason="copyleft/blocked")
    return LicenseViolation(name=name, spdx=spdx, reason="not in allow-list")


def check_sources(manifest_text: str) -> list[LicenseViolation]:
    """Parse a ``sources.toml`` body and return every license violation (pure; fail-closed).

    Args:
        manifest_text: The TOML manifest body (a ``[[source]]`` array of ``{name, spdx, ...}``).

    Returns:
        A list of :class:`LicenseViolation` (empty when every source passes the allow-list gate).

    Raises:
        ValueError: If the manifest is malformed TOML or has no ``source`` array — a broken gate
            input is itself a failure (fail closed; the gate must not silently pass on bad input).
    """
    try:
        data = tomllib.loads(manifest_text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"FID sources manifest is not valid TOML: {exc}") from exc
    sources = data.get("source")
    if not isinstance(sources, list) or not sources:
        raise ValueError("FID sources manifest has no [[source]] entries")
    violations: list[LicenseViolation] = []
    for entry in sources:
        if not isinstance(entry, dict):
            raise ValueError("FID sources manifest [[source]] entry is not a table")
        name = str(entry.get("name", "<unnamed>"))
        spdx_raw = entry.get("spdx")
        spdx = str(spdx_raw) if isinstance(spdx_raw, str) and spdx_raw.strip() else None
        violation = _classify(name, spdx)
        if violation is not None:
            violations.append(violation)
    return violations


def main(argv: list[str] | None = None) -> int:
    """Run the license gate over the manifest. Returns ``0`` on pass, ``1`` on any violation.

    Args:
        argv: Optional CLI args (``[manifest_path]``); defaults to :data:`DEFAULT_MANIFEST`.

    Returns:
        ``0`` when every source passes; ``1`` on a violation or bad/missing manifest (fail closed).
    """
    args = sys.argv[1:] if argv is None else argv
    manifest = Path(args[0]) if args else DEFAULT_MANIFEST
    try:
        text = manifest.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"fid-license-gate: cannot read manifest {manifest}: {exc}", file=sys.stderr)
        return 1
    try:
        violations = check_sources(text)
    except ValueError as exc:
        print(f"fid-license-gate: {exc}", file=sys.stderr)
        return 1
    if violations:
        print(
            f"fid-license-gate: FAIL — {len(violations)} disallowed FID-DB source license(s):",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  - {v.name}: {v.spdx} ({v.reason})", file=sys.stderr)
        print(
            f"  allowed (permissive only): {', '.join(sorted(ALLOWED_SPDX))}",
            file=sys.stderr,
        )
        return 1
    print("fid-license-gate: PASS — all FID-DB sources are permissively licensed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
