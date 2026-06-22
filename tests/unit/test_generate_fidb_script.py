"""Hermetic unit tests for the PURE helpers of ``scripts/fid/generate_fidb.py`` (ADR-043 D2/D4).

The generator runs INSIDE the worker (PyGhidra) and its generate+pack recipe is a JVM edge
(``# pragma: no cover``, validated by the PM's gated container run + the live test). These tests
cover only the PURE, hermetic parts: arg parsing, the provenance-manifest builder (D4), and the
sibling-path derivation — no Ghidra/JVM involved. Loaded by path (the script is not an installed
module), mirroring ``test_naming_eval_script.py``.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "fid" / "generate_fidb.py"


def _load() -> Any:
    """Import ``scripts/fid/generate_fidb.py`` by path (top-level imports are stdlib only)."""
    spec = importlib.util.spec_from_file_location("generate_fidb", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_fidb"] = module
    spec.loader.exec_module(module)
    return module


_MOD = _load()


def _meta() -> Any:
    """Build a representative LibraryMeta for the zlib vertical slice."""
    return _MOD.LibraryMeta(
        family="zlib",
        version="1.3.1",
        variant="x86-64-static",
        license_spdx="Zlib",
        source_digest="sha256:" + "a" * 64,
        compiler="gcc 13.2.0",
        compiler_flags="-O2 -g -fno-pie",
        source_name="zlib",
    )


def test_manifest_path_for_appends_suffix() -> None:
    """The provenance manifest sits beside the .fidbf as ``<name>.fidbf.provenance.json``."""
    p = _MOD.manifest_path_for(Path("/opt/vivarium/fid/zlib.fidbf"))
    assert p == Path("/opt/vivarium/fid/zlib.fidbf.provenance.json")


def test_build_manifest_shape(tmp_path: Path) -> None:
    """The manifest records source/build/library/artifact + the no-code disclaimer (D4)."""
    fidbf = tmp_path / "zlib.fidbf"
    fidbf.write_bytes(b"packed-bytes")
    fixed = datetime.datetime(2026, 6, 21, 12, 0, tzinfo=datetime.UTC)
    manifest = _MOD.build_manifest(
        _meta(),
        fidbf_path=fidbf,
        ghidra_version="12.1.2",
        language_id="x86:LE:64:default",
        function_count=42,
        now=fixed,
    )
    assert manifest["schema"] == "vivarium.fid.provenance/1"
    assert manifest["source"] == {
        "name": "zlib",
        "version": "1.3.1",
        "digest": "sha256:" + "a" * 64,
        "license_spdx": "Zlib",
    }
    assert manifest["build"]["ghidra_version"] == "12.1.2"
    assert manifest["build"]["generator_version"] == _MOD.GENERATOR_VERSION
    assert manifest["build"]["built_at"] == "2026-06-21T12:00:00+00:00"
    assert manifest["build"]["compiler"] == "gcc 13.2.0"
    assert manifest["library"]["family"] == "zlib"
    assert manifest["library"]["language_id"] == "x86:LE:64:default"
    assert manifest["library"]["function_count"] == 42
    assert manifest["artifact"]["fidbf"] == "zlib.fidbf"
    # The artifact digest is the sha256 of the actual packed bytes.
    assert manifest["artifact"]["fidbf_digest"].startswith("sha256:")
    assert "no library code" in manifest["disclaimer"]
    # The whole manifest is JSON-serializable (it gets written to disk).
    json.dumps(manifest)


def test_build_manifest_optional_fields_default_none(tmp_path: Path) -> None:
    """Optional provenance fields default to None (not omitted) when not supplied."""
    fidbf = tmp_path / "x.fidbf"
    fidbf.write_bytes(b"x")
    meta = _MOD.LibraryMeta(family="x", version="1", variant="v", license_spdx="MIT")
    manifest = _MOD.build_manifest(
        meta,
        fidbf_path=fidbf,
        ghidra_version="12.1.2",
        language_id="x86:LE:64:default",
        function_count=0,
    )
    assert manifest["source"]["digest"] is None
    assert manifest["source"]["name"] == "x"  # falls back to family when source_name unset
    assert manifest["build"]["compiler"] is None
    assert manifest["build"]["compiler_flags"] is None


def test_parse_args_and_meta_roundtrip() -> None:
    """CLI args parse into a LibraryMeta with the expected fields."""
    args = _MOD._parse_args(
        [
            "--input",
            "/build/libz.so",
            "--output",
            "/opt/vivarium/fid/zlib.fidbf",
            "--family",
            "zlib",
            "--version",
            "1.3.1",
            "--variant",
            "x86-64-static",
            "--license-spdx",
            "Zlib",
            "--source-digest",
            "sha256:" + "b" * 64,
            "--compiler",
            "clang 18",
            # A flag VALUE that starts with '-' must use the =form (argparse else reads it as an
            # option); the build invocation passes flags the same way (e.g. --compiler-flags="-O2").
            "--compiler-flags=-O2 -g",
        ]
    )
    assert args.input == "/build/libz.so"
    assert args.output == "/opt/vivarium/fid/zlib.fidbf"
    meta = _MOD._meta_from_args(args)
    assert meta.family == "zlib"
    assert meta.version == "1.3.1"
    assert meta.variant == "x86-64-static"
    assert meta.license_spdx == "Zlib"
    assert meta.source_digest == "sha256:" + "b" * 64
    assert meta.compiler == "clang 18"
    assert meta.compiler_flags == "-O2 -g"
    assert meta.source_name is None  # defaults to family at manifest-build time


def test_parse_args_requires_core_fields() -> None:
    """Missing a required arg exits non-zero (argparse fail-closed)."""
    with pytest.raises(SystemExit):
        _MOD._parse_args(["--input", "/x"])  # missing output/family/version/variant/license


def test_parse_args_include_symbols_optional() -> None:
    """``--include-symbols`` is optional (defaults None) and parses when given."""
    base = [
        "--input",
        "/b",
        "--output",
        "/o.fidbf",
        "--family",
        "zlib",
        "--version",
        "1.3.1",
        "--variant",
        "x86-64",
        "--license-spdx",
        "Zlib",
    ]
    assert _MOD._parse_args(base).include_symbols is None
    parsed = _MOD._parse_args([*base, "--include-symbols", "/opt/zlib.allow"])
    assert parsed.include_symbols == "/opt/zlib.allow"


def test_load_include_symbols_parses_strips_and_dedupes(tmp_path: Path) -> None:
    """The allow-list loader trims whitespace, drops blanks, and dedupes into a frozenset."""
    f = tmp_path / "zlib.allow"
    f.write_text("deflate\ninflate\n\n  crc32  \ndeflate\n", encoding="utf-8")
    got = _MOD._load_include_symbols(f)
    assert got == frozenset({"deflate", "inflate", "crc32"})


def test_load_include_symbols_none_returns_none() -> None:
    """No allow-list path → ``None`` (include every function, back-compat)."""
    assert _MOD._load_include_symbols(None) is None


def test_load_include_symbols_empty_file_raises(tmp_path: Path) -> None:
    """An empty/whitespace-only allow-list fails closed (a silent empty DB would be a footgun)."""
    f = tmp_path / "empty.allow"
    f.write_text("\n   \n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        _MOD._load_include_symbols(f)


def test_sha256_file(tmp_path: Path) -> None:
    """The streaming digest matches hashlib over the file bytes."""
    import hashlib

    f = tmp_path / "blob"
    data = b"deadbeef" * 1000
    f.write_bytes(data)
    assert _MOD._sha256_file(f) == "sha256:" + hashlib.sha256(data).hexdigest()
