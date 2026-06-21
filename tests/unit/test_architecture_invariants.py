"""Architecture invariant tests — enforce ADR-001 (out-of-process Ghidra) at the import level.

These are cheap static guards that fail CI if a server-side module ever imports the JVM bridge or
references in-process Ghidra/PyGhidra. Defense-in-depth alongside the runtime container boundary.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src" / "vivarium"

# Server-side packages that MUST NOT touch the JVM/PyGhidra (ADR-001). This INCLUDES the ``ghidra``
# adapter package — ``rpc_client``/``port`` run IN the server process and are the most tempting
# place for an accidental JVM import. The worker-only ``_jvm_bridge`` is the sole exception (the
# only JVM consumer, runs inside the worker), so it is excluded from the scan.
_SERVER_DIRS = ["core", "sessions", "security", "server", "tools", "ghidra", "jobs", "naming"]
_FORBIDDEN_IMPORT_SUBSTRINGS = ("pyghidra", "jpype", "vivarium.ghidra._jvm_bridge")
#: The worker-only JVM bridge legitimately imports PyGhidra/JPype; it is the documented exception.
_WORKER_ONLY_FILES = {"_jvm_bridge.py"}


def _python_files(rel_dir: str) -> list[Path]:
    return sorted(p for p in (_SRC / rel_dir).rglob("*.py") if p.name not in _WORKER_ONLY_FILES)


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
