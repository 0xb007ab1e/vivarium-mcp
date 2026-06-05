"""Deterministic synthetic benign-binary builders for the test suite (WS5).

No real malware and no committed binary samples (master §5, PLAN §6). Tests build their own
minimal, valid ELF/PE byte blobs in-process via the pure-Python builders here, plus deliberately
malformed / oversized variants for abuse tests (WS4) and the integration harness.

The builders are byte-for-byte deterministic (no randomness, no clock) so fixtures are
reproducible and hashes are stable. They emit the smallest structure Ghidra/format-sniffers
recognize as a given format — they are NOT runnable programs and contain no payload.
"""

from __future__ import annotations

from .binaries import (
    MALFORMED_ELF,
    TRUNCATED_PE,
    build_elf64,
    build_pe32,
    malformed_elf,
    oversized_blob,
    truncated_pe,
    zeros,
)

__all__ = [
    "MALFORMED_ELF",
    "TRUNCATED_PE",
    "build_elf64",
    "build_pe32",
    "malformed_elf",
    "oversized_blob",
    "truncated_pe",
    "zeros",
]
