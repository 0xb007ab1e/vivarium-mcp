#!/usr/bin/env python3
"""GATED fixtures builder for the ground-truth e2e (WS5) — runs ONLY in the e2e workflow.

For each tool in ``manifest.toml``: fetch the pinned source tarball, **verify its SHA-256 (fail
closed)**, extract, build it WITH DWARF and a non-PIE layout (``-g -no-pie -O0 -fno-inline`` so the
call graph is preserved and symbol addresses equal Ghidra's), extract the call-graph ground truth
(``extract_ground_truth.py``), and STRIP a copy. Emits, per tool, into ``--out``:

  * ``<name>.stripped``        — the binary Ghidra analyzes (no symbols)
  * ``<name>.groundtruth.json``— the truth oracle (functions + edges, absolute addresses)
  * ``<name>.meta.json``       — provenance (version, source sha256, stripped-binary sha256)

This requires network + a toolchain and so is GATED (PLAN §6, std-supplychain) — it never runs in
the hermetic unit/coverage job. The hermetic e2e consumes only the emitted artifact. FAILS CLOSED
on an unresolved ``REPLACE_WITH_SHA256_*`` pin, a checksum mismatch, a build failure, or a missing
target binary.

Usage:
    build_fixtures.py --out <artifact-dir> [--only cjson,coreutils] [--jobs N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_MANIFEST = _HERE / "manifest.toml"
_EXTRACTOR = _HERE / "extract_ground_truth.py"
_PLACEHOLDER_PREFIX = "REPLACE_WITH_SHA256"

#: Fixed build flags: DWARF, no inlining (preserve the call graph), non-PIE (absolute addresses
#: that match Ghidra's view of the stripped copy).
_CFLAGS = "-g -O0 -fno-inline -fno-omit-frame-pointer -no-pie"
_LDFLAGS = "-no-pie"


def _log(msg: str) -> None:
    """Emit a progress line to stderr (stdout is reserved for machine-readable summaries)."""
    sys.stderr.write(f"[build_fixtures] {msg}\n")
    sys.stderr.flush()


def _sha256(path: Path) -> str:
    """Return the hex SHA-256 of a file (streamed)."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _fetch(url: str, dest: Path) -> None:
    """Download ``url`` to ``dest`` (https only; the job's network is the gated boundary)."""
    if not url.startswith("https://"):
        msg = f"refusing non-https source url: {url}"
        raise SystemExit(msg)
    _log(f"fetch {url}")
    with urllib.request.urlopen(url) as resp, dest.open("wb") as out:  # noqa: S310 - https-guarded
        shutil.copyfileobj(resp, out)


def _verify(path: Path, expected: str, tool: str) -> None:
    """Verify ``path``'s SHA-256 against the pinned value; fail closed on placeholder/mismatch."""
    if expected.startswith(_PLACEHOLDER_PREFIX):
        msg = (
            f"{tool}: sha256 is an unresolved GATED placeholder ({expected!r}). "
            "Resolve it in manifest.toml against the upstream release before building."
        )
        raise SystemExit(msg)
    actual = _sha256(path)
    if actual != expected.lower():
        msg = f"{tool}: SHA-256 mismatch — expected {expected}, got {actual} (fail closed)"
        raise SystemExit(msg)
    _log(f"{tool}: sha256 verified")


def _extract_tarball(tarball: Path, into: Path) -> Path:
    """Extract ``tarball`` into ``into`` and return the single top-level source directory."""
    with tarfile.open(tarball) as tf:
        names = tf.getnames()
        tf.extractall(into, filter="data")  # filter='data' (py3.12) blocks path-traversal members
    tops = {n.split("/", 1)[0] for n in names if n and not n.startswith("/")}
    if len(tops) != 1:
        msg = f"expected a single top-level dir in {tarball.name}, found {sorted(tops)}"
        raise SystemExit(msg)
    return into / next(iter(tops))


def _run(cmd: list[str], cwd: Path, env_extra: dict[str, str] | None = None) -> None:
    """Run a build command, streaming output; raise on non-zero (fail closed)."""
    import os

    env = {**os.environ, **(env_extra or {})}
    _log(f"run ({cwd}): {' '.join(cmd)}")
    # Commands are fixed argv lists built from the in-repo manifest + our own constants (no shell,
    # no untrusted input) — this runs only in the gated fixtures-build job.
    subprocess.run(cmd, cwd=cwd, env=env, check=True)  # noqa: S603


def _build_single_file(tool: dict[str, Any], src_root: Path) -> Path:
    """Compile listed sources + the committed driver into one binary; return its path."""
    sources = [src_root / s for s in tool["sources"]]
    driver = _HERE / str(tool["driver"])
    out = src_root / str(tool["target_name"])
    cmd = [
        "gcc",
        *(_CFLAGS.split()),
        f"-I{src_root}",
        *map(str, sources),
        str(driver),
        "-lm",
        "-o",
        str(out),
    ]
    _run(cmd, cwd=src_root)
    return out


def _build_autotools(tool: dict[str, Any], src_root: Path, jobs: int) -> Path:
    """./configure + make with DWARF/non-PIE flags; return the target binary path."""
    _run(["./configure", f"CFLAGS={_CFLAGS}", f"LDFLAGS={_LDFLAGS}"], cwd=src_root)
    _run(["make", f"-j{jobs}"], cwd=src_root)
    target = src_root / str(tool["target"])
    if not target.exists():
        msg = f"{tool['name']}: built target not found at {target}"
        raise SystemExit(msg)
    return target


def _strip(src: Path, dest: Path) -> None:
    """Produce a stripped copy (the binary Ghidra analyzes) via objcopy --strip-all."""
    shutil.copy2(src, dest)
    _run(["objcopy", "--strip-all", str(dest), str(dest)], cwd=dest.parent)


def build_one(tool: dict[str, Any], work: Path, out: Path, jobs: int) -> dict[str, Any]:
    """Build one tool end-to-end; return its meta dict."""
    name = tool["name"]
    _log(f"=== {name} {tool['version']} ===")
    tarball = work / f"{name}.tar"
    _fetch(tool["url"], tarball)
    _verify(tarball, tool["sha256"], name)
    src_root = _extract_tarball(tarball, work / name)

    if tool["build"] == "single-file":
        unstripped = _build_single_file(tool, src_root)
    elif tool["build"] == "autotools":
        unstripped = _build_autotools(tool, src_root, jobs)
    else:
        msg = f"{name}: unknown build kind {tool['build']!r}"
        raise SystemExit(msg)

    truth_path = out / f"{name}.groundtruth.json"
    _run(
        [
            sys.executable,
            str(_EXTRACTOR),
            "--binary",
            str(unstripped),
            "--tool",
            name,
            "--version",
            str(tool["version"]),
            "--out",
            str(truth_path),
        ],
        cwd=out,
    )

    stripped = out / f"{name}.stripped"
    _strip(unstripped, stripped)

    meta = {
        "tool": name,
        "version": tool["version"],
        "source_url": tool["url"],
        "source_sha256": tool["sha256"],
        "stripped_sha256": _sha256(stripped),
        "target_name": tool.get("target_name", name),
    }
    (out / f"{name}.meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    truth = json.loads(truth_path.read_text())
    counts = truth["counts"]
    _log(f"{name}: {counts['functions']} fns / {counts['edges']} edges → {stripped.name}")
    return meta


def main(argv: list[str] | None = None) -> int:
    """CLI: build all (or --only) fixtures into --out; write an index.json summary."""
    ap = argparse.ArgumentParser(description="Build OSS ground-truth fixtures (GATED).")
    ap.add_argument("--out", required=True, help="artifact output directory")
    ap.add_argument("--only", default="", help="comma-separated subset of tool names")
    ap.add_argument("--jobs", type=int, default=2, help="make -j parallelism")
    ns = ap.parse_args(argv)

    manifest = tomllib.loads(_MANIFEST.read_text())
    tools = manifest["tool"]
    if ns.only:
        wanted = {t.strip() for t in ns.only.split(",") if t.strip()}
        tools = [t for t in tools if t["name"] in wanted]
        if not tools:
            raise SystemExit(f"--only matched no tools: {ns.only}")

    out = Path(ns.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    work = out / "_work"
    work.mkdir(exist_ok=True)

    metas = [build_one(t, work, out, ns.jobs) for t in tools]
    (out / "index.json").write_text(
        json.dumps({"schema": "ghidra-mcp/e2e-fixtures-index/1", "tools": metas}, indent=2) + "\n"
    )
    _log(f"built {len(metas)} fixture(s) into {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
