"""Unit tests for the section-bearing 32-bit ELF fixture builders (v1.8 F5).

Validates that :func:`tests._fixtures.binaries.synthetic_arm32_elf` /
:func:`~tests._fixtures.binaries.synthetic_riscv32_elf` (and the generic
:func:`~tests._fixtures.binaries.build_elf32_exec`) emit **readelf-clean** ELF32 executables — the
structure a real Ghidra worker relies on in ``test_import_synthetic_elf.py``. Parsing them with
pyelftools here is the fast, hermetic guard that the hand-packed headers stay valid (no worker
needed).
"""

from __future__ import annotations

import io

import pytest
from elftools.elf.elffile import ELFFile

from tests._fixtures import binaries

_EM_ARM = 40


@pytest.mark.parametrize(
    ("builder", "machine_name"),
    [
        (binaries.synthetic_arm32_elf, "EM_ARM"),
        (binaries.synthetic_riscv32_elf, "EM_RISCV"),
    ],
)
def test_synthetic_elf_is_readelf_clean(builder: object, machine_name: str) -> None:
    """Each fixture parses as an ELF32 LE executable with the right machine, PT_LOAD, and .text."""
    blob = builder()  # type: ignore[operator]
    ef = ELFFile(io.BytesIO(blob))
    assert ef.elfclass == 32
    assert ef.header["e_ident"]["EI_DATA"] == "ELFDATA2LSB"
    assert ef.header["e_type"] == "ET_EXEC"
    assert ef.header["e_machine"] == machine_name
    assert ef.num_segments() == 1  # the single PT_LOAD
    section_names = {s.name for s in ef.iter_sections()}
    assert ".text" in section_names
    assert ".shstrtab" in section_names
    # The entry point lands inside the mapped image (>= the base vaddr).
    assert ef.header["e_entry"] >= 0x10000


def test_build_elf32_exec_embeds_the_code() -> None:
    """The provided ``code`` bytes land verbatim in the ``.text`` section."""
    code = b"\xde\xad\xbe\xef" * 4
    blob = binaries.build_elf32_exec(_EM_ARM, code)
    ef = ELFFile(io.BytesIO(blob))
    text = ef.get_section_by_name(".text")
    assert text is not None
    assert text.data() == code


def test_synthetic_arm_and_riscv_differ_only_by_machine_and_code() -> None:
    """The two fixtures are distinct blobs (different machine + code), same builder."""
    assert binaries.synthetic_arm32_elf() != binaries.synthetic_riscv32_elf()
