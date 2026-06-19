#!/usr/bin/env python3
r"""On-demand naming-accuracy scorer (v1.5 #7; ADR-010) — advisory, NOT a CI gate.

Promotes the v1.3 blind-acceptance run's one-off debuginfod scoring into a committed, reusable
tool. Given a set of **proposed** function names (e.g. an LLM namer's output over a stripped
binary's decompilation) and a **ground-truth** address→name source, it scores naming accuracy
(strict exact-match rate + a fairer token-set F1) by delegating to the project's own, unit-tested
:func:`vivarium.naming.metrics.score_name_map`, and writes a scorecard.

**Advisory only** (the roadmap calls naming quality a non-deterministic LLM signal): it prints a
summary and writes a scorecard JSON; it always exits 0 on a successful score (a usage/IO error exits
non-zero). It is NOT wired into CI and runs no LLM itself — a human/agent supplies the proposed
names; this tool only scores them.

**No hostile binary, ever (ADR-001 / ADR-016 / master §5):** the tool reads only (a) the proposed
names (text), (b) for the ``debuginfod`` / ``elf`` sources, a binary's **DWARF/build-id metadata via
pyelftools** — it never executes the binary and never parses it through Ghidra. Ground truth comes
from trusted, benign, source-available builds (debuginfod's published debuginfo, or a locally-built
unstripped fixture).

Ground-truth sources (``--source``):
  * ``debuginfod`` — read the GNU build-id from ``--binary`` (a stripped ELF), fetch its debuginfo
    from a debuginfod server (``--debuginfod-url`` / ``$DEBUGINFOD_URLS``; default Debian's), and
    extract function address→name from the fetched DWARF. (This is the v1.3 path — real stripped
    Debian binaries.)
  * ``elf`` — extract address→name directly from ``--elf`` (a locally-built **unstripped** ELF;
    same DWARF approach the OSS-fixture ground truth uses).
  * ``json`` — load a precomputed address→name map from ``--ground-truth`` (e.g. a fixture's
    ``*.groundtruth.json``).

Usage:
    python scripts/naming_eval.py --names names.json --source debuginfod --binary ./gzip \\
        --out scorecard.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# The scorer reuses the project's own unit-tested scoring primitives (DRY — one definition of
# "naming accuracy"). scripts/ is not an installed package, so make src/ importable when run
# directly from a checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vivarium.naming.metrics import (
    NamingAccuracy,
    _normalized,
    _token_f1,
    score_name_map,
)

#: Default debuginfod federation (Debian's public server) when none is configured.
_DEFAULT_DEBUGINFOD_URL = "https://debuginfod.debian.net"
#: Cap on a fetched debuginfo payload (DoS / runaway-download guard). 512 MiB is generous for a
#: single binary's separate debuginfo while bounding a hostile/misconfigured server response.
_MAX_DEBUGINFO_BYTES = 512 * 1024 * 1024


def load_proposed_names(path: Path) -> dict[str, str]:
    """Load proposed function names as an address→name map (PURE given file contents).

    Tolerates the shapes the acceptance harness / namers emit: a flat ``{addr: name}`` object, a
    list of ``{"address": ..., "name"|"new_name": ...}`` rows, or a ``{"functions": [...]}`` wrapper
    of such rows. Entries without both an address and a name are skipped.

    Args:
        path: Path to the proposed-names JSON file.

    Returns:
        A ``{hex_address: proposed_name}`` map.

    Raises:
        ValueError: If the JSON is not one of the accepted shapes.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    rows: list[Any]
    if isinstance(data, dict) and "functions" in data:
        rows = data["functions"]
    elif isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        return {str(addr): str(name) for addr, name in data.items() if addr and name}
    else:
        raise ValueError("proposed names: expected an object or a list of rows")
    out: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        addr = row.get("address") or row.get("addr")
        name = row.get("new_name") or row.get("name") or row.get("proposed")
        if addr and name:
            out[str(addr)] = str(name)
    return out


def build_id_from_elf(elf_path: Path) -> str:
    """Read the GNU build-id (lowercase hex) from an ELF's ``.note.gnu.build-id`` (DWARF-free).

    Args:
        elf_path: Path to the ELF (the stripped binary whose debuginfo we want to locate).

    Returns:
        The build-id as a lowercase hex string.

    Raises:
        ValueError: If the ELF carries no GNU build-id note.
    """
    from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
    from elftools.elf.sections import NoteSection  # type: ignore[import-not-found]

    with open(elf_path, "rb") as handle:  # noqa: PTH123 — binary read of a user-supplied path.
        elf = ELFFile(handle)
        # Prefer the canonical named section, then fall back to scanning any note section (covers
        # ELFs whose build-id note lives under a differently-named/PT_NOTE-only section).
        candidates = [elf.get_section_by_name(".note.gnu.build-id")]
        candidates += [s for s in elf.iter_sections() if isinstance(s, NoteSection)]
        for section in candidates:
            if section is None or not hasattr(section, "iter_notes"):
                continue
            for note in section.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    desc = note["n_desc"]
                    # pyelftools yields the descriptor as a hex string for build-id notes.
                    return desc.lower() if isinstance(desc, str) else desc.hex()
    raise ValueError(f"{elf_path}: no GNU build-id note (cannot locate debuginfo via debuginfod)")


def addr_names_from_dwarf(elf_path: Path) -> dict[str, str]:
    """Extract function entry-address→name from an ELF's DWARF ``DW_TAG_subprogram`` DIEs.

    Mirrors the OSS-fixture ground-truth extractor (``tests/fixtures/oss/extract_ground_truth.py``):
    a subprogram DIE with a concrete ``DW_AT_low_pc`` and a ``DW_AT_name`` contributes
    ``{hex(low_pc): name}``. Reads only DWARF metadata — never executes the binary (ADR-001).

    Args:
        elf_path: Path to an ELF carrying DWARF (an unstripped build or fetched debuginfo).

    Returns:
        A ``{hex_address: function_name}`` ground-truth map.

    Raises:
        ValueError: If the ELF carries no DWARF info.
    """
    from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]

    out: dict[str, str] = {}
    with open(elf_path, "rb") as handle:  # noqa: PTH123 — binary read of a user-supplied path.
        elf = ELFFile(handle)
        if not elf.has_dwarf_info():
            raise ValueError(f"{elf_path}: no DWARF info (need debuginfo / an unstripped build)")
        dwarf = elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                low_pc = die.attributes.get("DW_AT_low_pc")
                name = die.attributes.get("DW_AT_name")
                if low_pc is None or name is None:
                    continue
                addr = low_pc.value
                raw = name.value
                fn_name = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                out[hex(addr)] = fn_name
    return out


def fetch_debuginfo(build_id: str, base_url: str, dest: Path) -> Path:
    """Fetch a build-id's separate debuginfo from a debuginfod server (bounded download).

    Args:
        build_id: The lowercase-hex GNU build-id.
        base_url: The debuginfod base URL (no trailing slash needed).
        dest: Where to write the fetched debuginfo ELF.

    Returns:
        ``dest`` (the written path).

    Raises:
        ValueError: If the URL scheme is not HTTP(S) or the response exceeds
            :data:`_MAX_DEBUGINFO_BYTES`.
        SystemExit: If the server is unreachable or has no debuginfo for this build-id (a clean
            advisory exit, not a traceback).
    """
    url = f"{base_url.rstrip('/')}/buildid/{build_id}/debuginfo"
    # Only debuginfod HTT(S) endpoints are expected; reject other schemes (SSRF/file-read guard).
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"refusing non-HTTP debuginfod URL: {url}")
    request = urllib.request.Request(url, method="GET")  # noqa: S310 — scheme checked above.
    try:
        # dynamic-urllib-use-detected (semgrep) / S310 (ruff): the http(s)-only scheme guard above
        # closes the file:// arbitrary-read vector the rule warns about, and the operator (the
        # trust principal) chooses the debuginfod URL — mitigated, not a vuln.
        with urllib.request.urlopen(request) as response:  # noqa: S310  # nosemgrep
            payload = response.read(_MAX_DEBUGINFO_BYTES + 1)
    except urllib.error.URLError as exc:
        # A missing build-id (404) or unreachable server — fail with a clear advisory message, not a
        # raw traceback. debuginfod coverage is environment-dependent (the exact build may not be
        # published); the operator can switch --source elf/json or another --debuginfod-url.
        raise SystemExit(
            f"debuginfod fetch failed for build-id {build_id} at {base_url}: {exc}"
        ) from exc
    if len(payload) > _MAX_DEBUGINFO_BYTES:
        raise ValueError(f"debuginfo for {build_id} exceeds {_MAX_DEBUGINFO_BYTES} bytes")
    dest.write_bytes(payload)
    return dest


def resolve_ground_truth(args: argparse.Namespace) -> dict[str, str]:
    """Resolve the ground-truth address→name map from the selected ``--source``.

    Args:
        args: Parsed CLI arguments (``source`` + its source-specific inputs).

    Returns:
        The ground-truth ``{hex_address: name}`` map.

    Raises:
        SystemExit: If a required source-specific argument is missing.
    """
    if args.source == "json":
        if not args.ground_truth:
            raise SystemExit("--source json requires --ground-truth <file.json>")
        raw = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))
        return {str(a): str(n) for a, n in raw.items()}
    if args.source == "elf":
        if not args.elf:
            raise SystemExit("--source elf requires --elf <unstripped-binary>")
        return addr_names_from_dwarf(Path(args.elf))
    # debuginfod
    if not args.binary:
        raise SystemExit("--source debuginfod requires --binary <stripped-binary>")
    build_id = build_id_from_elf(Path(args.binary))
    with tempfile.TemporaryDirectory(prefix="gmcp-debuginfo-") as tmp:
        debuginfo = fetch_debuginfo(build_id, args.debuginfod_url, Path(tmp) / "debuginfo")
        return addr_names_from_dwarf(debuginfo)


def build_scorecard(
    proposed: dict[str, str], truth: dict[str, str], accuracy: NamingAccuracy
) -> dict[str, Any]:
    """Assemble the advisory scorecard (PURE): aggregate metrics + per-function joined rows.

    Args:
        proposed: The proposed address→name map.
        truth: The ground-truth address→name map.
        accuracy: The aggregate result from :func:`score_name_map`.

    Returns:
        A JSON-serializable scorecard dict (aggregate + a row per proposed name that joined truth).
    """
    truth_by_int = {int(a, 16): n for a, n in truth.items() if _is_hex(a)}
    rows: list[dict[str, Any]] = []
    for addr, proposed_name in sorted(proposed.items()):
        if not _is_hex(addr):
            continue
        true_name = truth_by_int.get(int(addr, 16))
        if true_name is None:
            continue
        rows.append(
            {
                "address": addr,
                "proposed": proposed_name,
                "truth": true_name,
                "exact": _normalized(proposed_name) == _normalized(true_name),
                "token_f1": round(_token_f1(proposed_name, true_name), 4),
            }
        )
    return {
        "aggregate": {
            "scored": accuracy.scored,
            "unscored": accuracy.unscored,
            "exact_matches": accuracy.exact_matches,
            "exact_match_rate": round(accuracy.exact_match_rate, 4),
            "mean_token_f1": round(accuracy.mean_token_f1, 4),
        },
        "functions": rows,
    }


def _is_hex(value: str) -> bool:
    """Return whether ``value`` parses as a hex integer (defensive address guard)."""
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    """Score proposed names against a ground-truth source and write/print a scorecard.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code (0 on a successful score — it is an advisory metric, not a gate).
    """
    parser = argparse.ArgumentParser(description="Advisory naming-accuracy scorer (v1.5 #7).")
    parser.add_argument("--names", required=True, help="proposed names JSON (address→name)")
    parser.add_argument(
        "--source",
        choices=("debuginfod", "elf", "json"),
        default="debuginfod",
        help="ground-truth source (default: debuginfod)",
    )
    parser.add_argument(
        "--binary", help="[debuginfod] the stripped binary to read the build-id from"
    )
    parser.add_argument("--elf", help="[elf] a locally-built unstripped ELF with DWARF")
    parser.add_argument("--ground-truth", help="[json] a precomputed address→name JSON")
    parser.add_argument(
        "--debuginfod-url",
        default=(os.environ.get("DEBUGINFOD_URLS") or _DEFAULT_DEBUGINFOD_URL).split()[0],
        help="debuginfod base URL (default: $DEBUGINFOD_URLS or Debian's)",
    )
    parser.add_argument("--out", help="write the scorecard JSON here (default: stdout only)")
    args = parser.parse_args(argv)

    proposed = load_proposed_names(Path(args.names))
    truth = resolve_ground_truth(args)
    accuracy = score_name_map(proposed, truth)
    scorecard = build_scorecard(proposed, truth, accuracy)

    if args.out:
        Path(args.out).write_text(json.dumps(scorecard, indent=2) + "\n", encoding="utf-8")

    agg = scorecard["aggregate"]
    print(
        f"naming-eval: scored={agg['scored']} unscored={agg['unscored']} "
        f"exact={agg['exact_match_rate']:.1%} mean_token_f1={agg['mean_token_f1']:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
