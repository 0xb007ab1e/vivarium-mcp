"""Unit tests for ``scripts/bump_pin.sh`` — the worker-image trust-pin rewrite (round-6 V2).

The pin rewrite advances what ``live-regression`` cosign-verifies, and it was previously untested
inline CI shell in ``worker-image.yml`` (a regression in the ``grep``/append transform would
silently emit a malformed pin). It is now an extracted, tested unit. These drive the real script
over ``socket``-free sample content via ``subprocess`` and assert the transform + fail-closed
validation. Hermetic: no network, no ``gh``, no filesystem mutation (pure stdin -> stdout).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "bump_pin.sh"
_A64 = "a" * 64
_B64 = "b" * 64
_DIGEST_A = f"sha256:{_A64}"
_DIGEST_B = f"sha256:{_B64}"
_HEADER = "# Trusted vivarium worker image digest.\n#\n# Format: a single sha256:<64 hex> token.\n"


def _run(digest: str, stdin: str) -> subprocess.CompletedProcess[str]:
    """Run bump_pin.sh with ``digest`` as argv[1] and ``stdin`` on stdin (text mode)."""
    return subprocess.run(  # noqa: S603  # fixed, executable script path; no shell; test-only inputs
        [str(_SCRIPT), digest],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_replaces_digest_and_preserves_header() -> None:
    """The header/comment lines are preserved in order; only the sha256 line is replaced."""
    result = _run(_DIGEST_B, f"{_HEADER}{_DIGEST_A}\n")
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{_HEADER}{_DIGEST_B}\n"


def test_output_has_exactly_one_digest_line() -> None:
    """Exactly one sha256 line remains (the new one) — the old is not left behind or duplicated."""
    out = _run(_DIGEST_B, f"{_HEADER}{_DIGEST_A}\n").stdout
    digest_lines = [ln for ln in out.splitlines() if ln.startswith("sha256:")]
    assert digest_lines == [_DIGEST_B]


def test_idempotent_when_already_at_digest() -> None:
    """Re-running with the digest already present yields identical content (stable transform)."""
    once = _run(_DIGEST_B, f"{_HEADER}{_DIGEST_A}\n").stdout
    twice = _run(_DIGEST_B, once).stdout
    assert once == twice == f"{_HEADER}{_DIGEST_B}\n"


def test_header_only_input_appends_digest() -> None:
    """A pin body with no existing digest line (header only) still gets the digest appended."""
    result = _run(_DIGEST_A, _HEADER)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{_HEADER}{_DIGEST_A}\n"


@pytest.mark.parametrize(
    "bad",
    [
        "",  # empty
        "not-a-digest",
        "sha256:tooshort",
        f"sha256:{_A64}extra",  # too long
        f"sha1:{_A64}",  # wrong algo
        f"SHA256:{_A64}",  # wrong case on the prefix
        f"sha256:{'A' * 64}",  # uppercase hex (frozen format is lowercase)
        f"sha256:{_A64}\nsha256:{_B64}",  # embedded newline (anchor bypass attempt)
    ],
)
def test_invalid_digest_fails_closed(bad: str) -> None:
    """A malformed digest fails closed (exit 2, message on stderr) — no bad pin is ever emitted."""
    result = _run(bad, f"{_HEADER}{_DIGEST_A}\n")
    assert result.returncode == 2
    assert "invalid digest" in result.stderr
    assert result.stdout == ""
