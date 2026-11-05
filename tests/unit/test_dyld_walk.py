"""Unit tests for the iterative dyld cache component walk (ADR-086/089 review hardening).

`_dyld_walk_components` enumerates a mounted dyld cache's files via an **explicit stack** (not
recursion) so a hostile cache nesting directories deeper than Python's recursion limit cannot raise
``RecursionError`` (CWE-674), and bounds both the collected files (`_DYLD_MAX_COMPONENTS`) and the
total nodes visited (`_DYLD_MAX_WALK_NODES`, CWE-400). These tests drive it with a fake Ghidra
``GFileSystem`` (no JVM) to prove the traversal, the recursion-safety, and the caps.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vivarium.ghidra._jvm_bridge import (
    _DYLD_MAX_COMPONENTS,
    _DYLD_MAX_WALK_NODES,
    _dyld_walk_components,
)


@dataclass
class _FakeEntry:
    """A fake GFileSystem entry: a file (leaf) or a directory with children."""

    path: str
    is_dir: bool = False
    children: list[_FakeEntry] = field(default_factory=list)

    def isDirectory(self) -> bool:  # noqa: N802 - mirrors the Ghidra GFile API
        """Return whether this entry is a directory."""
        return self.is_dir

    def getPath(self) -> str:  # noqa: N802 - mirrors the Ghidra GFile API
        """Return this entry's path."""
        return self.path


class _FakeFs:
    """A fake GFileSystem: ``getListing(None)`` lists the root; ``getListing(dir)`` its children."""

    def __init__(self, root: list[_FakeEntry]) -> None:
        self._root = root

    def getListing(self, directory: _FakeEntry | None) -> list[_FakeEntry]:  # noqa: N802
        """List the root (``None``) or a directory entry's children."""
        return self._root if directory is None else directory.children


def test_walks_flat_listing() -> None:
    """A flat listing of files returns all their paths."""
    fs = _FakeFs([_FakeEntry("/usr/lib/a.dylib"), _FakeEntry("/usr/lib/b.dylib")])
    assert _dyld_walk_components(fs) == ["/usr/lib/a.dylib", "/usr/lib/b.dylib"]


def test_walks_nested_dirs() -> None:
    """Files inside nested directories are collected (DFS over the explicit stack)."""
    tree = [
        _FakeEntry(
            "/usr",
            is_dir=True,
            children=[
                _FakeEntry("/usr/lib", is_dir=True, children=[_FakeEntry("/usr/lib/c.dylib")]),
            ],
        ),
        _FakeEntry("/top.dylib"),
    ]
    assert set(_dyld_walk_components(_FakeFs(tree))) == {"/usr/lib/c.dylib", "/top.dylib"}


def test_deep_nesting_does_not_recurse() -> None:
    """A directory nested FAR deeper than the recursion limit does not raise (iterative walk).

    A recursive walk would blow the stack (RecursionError); the explicit-stack walk must not.
    """
    import sys

    depth = sys.getrecursionlimit() * 3  # well past what recursion could survive
    leaf = _FakeEntry("/deep/leaf.dylib")
    node = leaf
    for i in range(depth):
        node = _FakeEntry(f"/d{i}", is_dir=True, children=[node])
    # No RecursionError — the leaf is found.
    assert _dyld_walk_components(_FakeFs([node])) == ["/deep/leaf.dylib"]


def test_component_cap_bounds_output() -> None:
    """The collected-file count is capped at _DYLD_MAX_COMPONENTS (CWE-400)."""
    files = [_FakeEntry(f"/lib/f{i}.dylib") for i in range(_DYLD_MAX_COMPONENTS + 100)]
    result = _dyld_walk_components(_FakeFs(files))
    assert len(result) == _DYLD_MAX_COMPONENTS


def test_node_cap_bounds_empty_dir_tree() -> None:
    """A tree of many empty directories (few/no files) is bounded by the node cap, not unbounded."""
    empties = [
        _FakeEntry(f"/d{i}", is_dir=True, children=[]) for i in range(_DYLD_MAX_WALK_NODES + 50)
    ]
    # Must terminate (node cap) and collect no files — the point is it returns, bounded.
    assert _dyld_walk_components(_FakeFs(empties)) == []
