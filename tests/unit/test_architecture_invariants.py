"""Architecture invariant tests — enforce ADR-001 (out-of-process Ghidra) at the import level.

These are cheap static guards that fail CI if a server-side module ever imports the JVM bridge or
references in-process Ghidra/PyGhidra. Defense-in-depth alongside the runtime container boundary.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src" / "ghidra_mcp"

# Server-side packages that MUST NOT touch the JVM/PyGhidra (ADR-001). The worker-only bridge is
# the sole exception and is excluded.
_SERVER_DIRS = ["core", "sessions", "security", "server", "tools"]
_FORBIDDEN_IMPORT_SUBSTRINGS = ("pyghidra", "jpype", "ghidra_mcp.ghidra._jvm_bridge")


def _python_files(rel_dir: str) -> list[Path]:
    return sorted((_SRC / rel_dir).rglob("*.py"))


@pytest.mark.critical
def test_server_packages_do_not_import_jvm_bridge_or_pyghidra() -> None:
    offenders: list[str] = []
    for rel in _SERVER_DIRS:
        for path in _python_files(rel):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    if any(bad in name.lower() for bad in _FORBIDDEN_IMPORT_SUBSTRINGS):
                        offenders.append(f"{path}: imports {name}")
    assert not offenders, "ADR-001 violation (in-process Ghidra import): " + "; ".join(offenders)


@pytest.mark.critical
def test_jvm_bridge_is_marked_worker_only_and_omitted_from_coverage() -> None:
    # The bridge exists, is clearly worker-only, and is the documented coverage omission.
    bridge = _SRC / "ghidra" / "_jvm_bridge.py"
    assert bridge.exists()
    text = bridge.read_text(encoding="utf-8")
    assert "ONLY INSIDE THE WORKER" in text
    pyproject = (_SRC.parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert "_jvm_bridge.py" in pyproject  # listed in [tool.coverage.run] omit
