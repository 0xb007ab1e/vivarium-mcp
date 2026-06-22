"""Hermetic unit tests for the FID-DB source license allow-list gate (ADR-043 D5).

Verifies the gate PASSES on the permissive v1 set and FAILS on copyleft / unknown / missing SPDX
ids — including a known-bad probe (a copyleft entry) so the gate is proven to go red, not merely
green (topic-testing: prove a guard fails on a known-bad input).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vivarium.fid_licenses import (
    ALLOWED_SPDX,
    DEFAULT_MANIFEST,
    LicenseViolation,
    check_sources,
    main,
)

_PERMISSIVE = """
[[source]]
name = "zlib"
spdx = "Zlib"

[[source]]
name = "musl"
spdx = "MIT"

[[source]]
name = "openssl"
spdx = "Apache-2.0"

[[source]]
name = "boost"
spdx = "BSL-1.0"
"""


def test_committed_manifest_passes() -> None:
    """The committed deploy/fid/sources.toml passes the gate (its sources are all permissive)."""
    assert check_sources(DEFAULT_MANIFEST.read_text(encoding="utf-8")) == []


def test_permissive_set_passes() -> None:
    """Every allowed SPDX id passes; no violations."""
    assert check_sources(_PERMISSIVE) == []


@pytest.mark.parametrize("spdx", sorted(ALLOWED_SPDX))
def test_each_allowed_id_passes(spdx: str) -> None:
    """Each id in the allow-list individually passes the gate."""
    body = f'[[source]]\nname = "lib"\nspdx = "{spdx}"\n'
    assert check_sources(body) == []


@pytest.mark.parametrize(
    "spdx",
    [
        "GPL-3.0-or-later",
        "GPL-2.0-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "AGPL-3.0",
        "OpenSSL",  # pre-3.0 OpenSSL license is BLOCKED (3.0+ is Apache-2.0)
    ],
)
def test_copyleft_and_openssl_fail(spdx: str) -> None:
    """A copyleft / OpenSSL-pre-3.0 source FAILS the gate, classified ``copyleft/blocked``."""
    body = f'[[source]]\nname = "readline"\nspdx = "{spdx}"\n'
    violations = check_sources(body)
    assert len(violations) == 1
    assert violations[0] == LicenseViolation(name="readline", spdx=spdx, reason="copyleft/blocked")


def test_unknown_license_fails() -> None:
    """An unknown/proprietary id (not copyleft, not allowed) FAILS as ``not in allow-list``."""
    body = '[[source]]\nname = "weird"\nspdx = "SomeProprietary-1.0"\n'
    violations = check_sources(body)
    assert len(violations) == 1
    assert violations[0].reason == "not in allow-list"


def test_missing_spdx_fails() -> None:
    """A source with no SPDX id FAILS (fail-closed)."""
    body = '[[source]]\nname = "nolicense"\n'
    violations = check_sources(body)
    assert len(violations) == 1
    assert violations[0].reason == "missing spdx"
    assert violations[0].spdx == "<missing>"


def test_blank_spdx_fails() -> None:
    """A whitespace-only SPDX id is treated as missing (fail-closed)."""
    body = '[[source]]\nname = "blank"\nspdx = "   "\n'
    violations = check_sources(body)
    assert len(violations) == 1
    assert violations[0].reason == "missing spdx"


def test_mixed_set_reports_only_violations() -> None:
    """A mix reports exactly the disallowed entries, leaving permissive ones alone."""
    body = _PERMISSIVE + '\n[[source]]\nname = "qt"\nspdx = "LGPL-3.0"\n'
    violations = check_sources(body)
    assert [v.name for v in violations] == ["qt"]


def test_empty_manifest_raises() -> None:
    """A manifest with no [[source]] entries is itself a failure (fail-closed, no silent pass)."""
    with pytest.raises(ValueError, match="no \\[\\[source\\]\\]"):
        check_sources("# nothing here\n")


def test_malformed_toml_raises() -> None:
    """Invalid TOML is a gate failure (fail-closed)."""
    with pytest.raises(ValueError, match="not valid TOML"):
        check_sources("this = = broken")


def test_non_table_source_raises() -> None:
    """A non-table [[source]] entry is rejected (fail-closed)."""
    with pytest.raises(ValueError, match="not a table"):
        check_sources("source = [1, 2, 3]\n")


def test_main_passes_on_committed_manifest(capsys: pytest.CaptureFixture[str]) -> None:
    """``main()`` returns 0 on the committed (permissive) manifest."""
    assert main([str(DEFAULT_MANIFEST)]) == 0
    assert "PASS" in capsys.readouterr().err


def test_main_defaults_to_committed_manifest() -> None:
    """``main()`` with no args resolves the default committed manifest and passes."""
    assert main([]) == 0


def test_main_fails_on_copyleft(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """``main()`` returns 1 and lists the offending entry on a copyleft manifest (known-bad)."""
    manifest = tmp_path / "bad.toml"
    manifest.write_text('[[source]]\nname = "readline"\nspdx = "GPL-3.0-or-later"\n')
    assert main([str(manifest)]) == 1
    err = capsys.readouterr().err
    assert "FAIL" in err
    assert "readline" in err
    assert "GPL-3.0-or-later" in err


def test_main_fails_on_missing_file(tmp_path: Path) -> None:
    """``main()`` returns 1 when the manifest cannot be read (fail-closed)."""
    assert main([str(tmp_path / "nope.toml")]) == 1


def test_main_fails_on_malformed(tmp_path: Path) -> None:
    """``main()`` returns 1 on a malformed manifest (fail-closed)."""
    manifest = tmp_path / "broken.toml"
    manifest.write_text("= = =")
    assert main([str(manifest)]) == 1
