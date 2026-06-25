"""Property/fuzz tests for the import-root path-confinement resolver (G11; TB3, CWE-22).

Complements the example-based ``test_confined_resolver_*`` in ``test_worker_launcher.py`` with a
generated-input INVARIANT over :func:`vivarium.ghidra.launcher.make_confined_resolver`: the server
resolves a client-supplied ``source_ref`` and enforces a size cap BEFORE any worker is contacted,
so the resolver is the CWE-22 boundary.

The load-bearing invariant (asserted over both arbitrary text and root-relative traversal paths):

    **accept ⟹ under-root** — if the resolver RETURNS a size, the resolved real path is strictly
    inside ``import_root``. It must NEVER return a size for a path that escapes the root.

A rejected ``source_ref`` raises (``OSError`` for an escape / missing file; ``ValueError`` for an
embedded null byte — see the OPEN QUESTION in the G11 report re: the documented OSError contract).
Either way no out-of-root path is ever accepted. Hermetic + deterministic; no worker, no I/O beyond
a throwaway ``tmp_path`` root.
"""

from __future__ import annotations

from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")  # skip cleanly if the property-test extra is absent
from hypothesis import HealthCheck, example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from vivarium.ghidra.launcher import make_confined_resolver  # noqa: E402

#: Deterministic + CI-safe (see the framing-property module). The ``confined`` root fixture is
#: READ-ONLY (set up once, reused across examples — only ``source_ref`` varies), so suppressing the
#: function-scoped-fixture health check is correct here, not a latent bug.
_PROFILE = settings(
    max_examples=200,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

#: Path segments that mix benign names with traversal/no-op tokens — composed against the real root
#: to exercise escapes (``..``), no-ops (``.``), the known in-root file, and non-existent siblings.
_SEGMENT = st.sampled_from(["..", ".", "inside.bin", "sub", "x", "etc", "passwd"])


@pytest.fixture
def confined(tmp_path: Path) -> tuple[Path, object]:
    """A real import root containing one known file, plus a resolver confined to it."""
    root = (tmp_path / "root").resolve()
    root.mkdir()
    (root / "inside.bin").write_bytes(b"abc")  # a 3-byte known-good file under the root
    return root, make_confined_resolver(str(root))


def _assert_confined(root: Path, resolver: object, source_ref: str) -> None:
    """The CWE-22 invariant: a returned size implies the resolved path is under ``root``."""
    try:
        size = resolver(source_ref)  # type: ignore[operator]
    except (OSError, ValueError):
        return  # rejected (escape / missing / null byte) — no out-of-root path was accepted
    assert isinstance(size, int) and size >= 0
    # Accepted → the resolver must have confirmed the resolved real path is under the root.
    assert Path(source_ref).resolve().is_relative_to(root)


@_PROFILE
@given(source_ref=st.text(max_size=128))
@example("../etc/passwd")
@example("/etc/passwd")
@example("a/../../b")
@example("foo\x00bar")  # embedded null byte → ValueError (see report OPEN QUESTION)
@example("")
@example(".")
def test_arbitrary_source_ref_never_escapes_root(
    confined: tuple[Path, object], source_ref: str
) -> None:
    """No arbitrary ``source_ref`` string is accepted unless it resolves under the import root."""
    root, resolver = confined
    _assert_confined(root, resolver, source_ref)


@_PROFILE
@given(segments=st.lists(_SEGMENT, max_size=6))
@example(segments=["inside.bin"])  # the real file → ACCEPTED (exercises the success branch)
@example(segments=["..", "etc", "passwd"])  # climbs out of root → rejected
@example(segments=["sub", "..", "..", "x"])  # net escape via traversal → rejected
def test_root_relative_traversal_never_escapes_root(
    confined: tuple[Path, object], segments: list[str]
) -> None:
    """A path built from the root + traversal segments is accepted ONLY when it stays under root."""
    root, resolver = confined
    source_ref = str(root.joinpath(*segments)) if segments else str(root)
    _assert_confined(root, resolver, source_ref)
