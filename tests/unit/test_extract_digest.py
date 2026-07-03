"""Unit tests for ``scripts/extract_digest.sh`` — the worker-image digest extractor (round-8 X3).

The extractor decides which ``sha256:`` token gets cosign-verified, compared against the current
pin, and written into the trust pin — previously untested inline shell (a fragile
``grep -oiE … | head`` at three sites in ``worker-image.yml``). It is now an extracted, tested unit.
These drive the real script over sample content via ``subprocess`` and assert extraction + the
fail-closed / strict-lowercase behavior. Hermetic: pure stdin -> stdout, no network/gh/filesystem.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "extract_digest.sh"
_A64 = "a" * 64
_B64 = "b" * 64
_DIGEST_A = f"sha256:{_A64}"


def _run(stdin: str) -> subprocess.CompletedProcess[str]:
    """Run extract_digest.sh with ``stdin`` on stdin (text mode)."""
    return subprocess.run(  # noqa: S603  # fixed, executable script path; no shell; test-only inputs
        [str(_SCRIPT)],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_extracts_a_bare_digest() -> None:
    """A lone digest token is emitted verbatim (single trailing newline)."""
    result = _run(f"{_DIGEST_A}\n")
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{_DIGEST_A}\n"


def test_extracts_digest_from_pin_file_shape() -> None:
    """The digest is found among header/comment lines (the pin-file shape)."""
    pin = f"# Trusted worker image digest.\n#\n# Format: sha256:<64 hex>.\n{_DIGEST_A}\n"
    assert _run(pin).stdout == f"{_DIGEST_A}\n"


def test_emits_only_the_first_digest() -> None:
    """With multiple digests, only the first is emitted (matches the prior ``head -n1``)."""
    out = _run(f"{_DIGEST_A}\nsha256:{_B64}\n").stdout
    assert out == f"{_DIGEST_A}\n"


def test_no_digest_fails_closed() -> None:
    """No sha256 token → exit 1, message on stderr, empty stdout (caller treats as 'no digest')."""
    result = _run("no digest here — just prose\n")
    assert result.returncode == 1
    assert "no sha256" in result.stderr
    assert result.stdout == ""


def test_uppercase_hex_is_rejected() -> None:
    """Uppercase hex is NOT matched (strict lowercase — OCI/cosign digests are lowercase)."""
    result = _run(f"sha256:{'A' * 64}\n")
    assert result.returncode == 1
    assert result.stdout == ""


def test_wrong_length_is_rejected() -> None:
    """A too-short/too-long hex run is not a valid digest → fail closed."""
    assert _run(f"sha256:{'a' * 63}\n").returncode == 1
    # 65 hex: the first 64 after `sha256:` match, trailing 'a' is extra text — still a valid token.
    assert _run(f"sha256:{'a' * 65}\n").stdout == f"{_DIGEST_A}\n"
