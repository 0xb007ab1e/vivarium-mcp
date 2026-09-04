"""Unit tests for ADR-075 `crypto_detect` — pure core + schema boundary + read-only wiring.

The whole detection is the pure ``core.cryptodetect`` (no JVM edge): the adapter merely pulls the
existing ``list_imports`` / ``list_strings`` facts and wraps ``detail`` untrusted. These tests
exercise the core exhaustively (the import / api_name / instruction sources, symbol-likeness gate,
opcode kinds, dedup, ordering, confidence) plus the schema boundary and read-only registration. The
worker opcode scan (``crypto_instructions``) is a JVM edge covered by a gated integration test.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vivarium.core import cryptodetect as cd
from vivarium.core.cryptodetect import detect_crypto, detect_instruction_crypto
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

# --- pure core: import source --------------------------------------------------------------------


def test_import_commoncrypto_is_detected() -> None:
    """The case-02 miss: Apple CommonCrypto AES via `CCCrypt` fires the `import` source."""
    out = detect_crypto([("0x402000", "CCCrypt", "libSystem")], [])
    assert len(out) == 1
    ind = out[0]
    assert ind.kind == "crypto_api"
    assert ind.source == "import"
    assert ind.detail == "CCCrypt"
    assert ind.confidence == 0.9
    assert ind.address == "0x402000"


def test_import_maps_algorithm_kinds() -> None:
    """Algorithm-specific symbols map to their kind, generic APIs to `crypto_api`."""
    out = detect_crypto(
        [
            ("0x1", "AES_encrypt", None),
            ("0x2", "SHA256_Init", None),
            ("0x3", "CryptEncrypt", "advapi32"),
            ("0x4", "RC4_set_key", None),
        ],
        [],
    )
    by_addr = {i.address: i.kind for i in out}
    assert by_addr == {"0x1": "aes", "0x2": "sha", "0x3": "crypto_api", "0x4": "rc4"}
    assert all(i.source == "import" for i in out)


def test_non_crypto_import_ignored() -> None:
    """An ordinary import (no crypto needle) yields nothing."""
    assert (
        detect_crypto([("0x1", "memcpy", "libc"), ("0x2", "GetProcAddress", "kernel32")], []) == []
    )


# --- pure core: api_name source (strings) --------------------------------------------------------


def test_symbol_like_string_fires_api_name() -> None:
    """A resolved crypto symbol NAME in the strings fires `api_name` (lower confidence)."""
    out = detect_crypto([], [("0x5000", "EVP_EncryptInit")])
    assert len(out) == 1
    assert out[0].source == "api_name"
    assert out[0].kind == "crypto_api"
    assert out[0].confidence == 0.6


def test_prose_string_not_matched() -> None:
    """A non-identifier string (spaces/prose) that merely mentions crypto does NOT fire."""
    assert detect_crypto([], [("0x1", "please CryptEncrypt the payload now")]) == []


def test_symbol_like_without_crypto_needle_not_matched() -> None:
    """A symbol-like string with no crypto needle is ignored (precision)."""
    assert detect_crypto([], [("0x1", "encryptButton"), ("0x2", "main")]) == []


# --- pure core: dedup / ordering / bounds --------------------------------------------------------


def test_dedup_same_address_source_detail() -> None:
    """Duplicate (address, kind, source, detail) collapses to one indicator."""
    out = detect_crypto([("0x1", "CCCrypt", None), ("0x1", "CCCrypt", None)], [])
    assert len(out) == 1


def test_deterministic_sort() -> None:
    """Output is sorted by (address, source, kind, detail) — stable across input order."""
    a = detect_crypto([("0x30", "CCCrypt", None), ("0x10", "AES_encrypt", None)], [])
    b = detect_crypto([("0x10", "AES_encrypt", None), ("0x30", "CCCrypt", None)], [])
    assert [(i.address, i.kind) for i in a] == [(i.address, i.kind) for i in b]
    assert [i.address for i in a] == ["0x10", "0x30"]


def test_empty_inputs_empty_output() -> None:
    """No imports and no strings ⇒ no indicators (empty ≠ no crypto, but empty here)."""
    assert detect_crypto([], []) == []


def test_empty_name_and_text_rows_skipped() -> None:
    """Rows with an empty import name or empty string are skipped (no crash, no match)."""
    assert detect_crypto([("0x1", "", "libc")], [("0x2", "")]) == []


def test_oversized_symbol_bounded() -> None:
    """A pathologically long symbol is truncated to MAX_SCAN_LEN before matching (DoS guard)."""
    huge = "CCCrypt" + ("A" * (cd.MAX_SCAN_LEN * 2))
    out = detect_crypto([("0x1", huge, None)], [])
    assert len(out) == 1
    assert len(out[0].detail) == cd.MAX_SCAN_LEN


# --- schema boundary -----------------------------------------------------------------------------


def test_schema_defaults_and_bounds() -> None:
    """CryptoDetectIn is paginated + has a bounded min_length; unknown fields rejected."""
    m = s.CryptoDetectIn(session_id="sess")
    assert m.offset == 0 and m.min_length == 4
    with pytest.raises(ValidationError):
        s.CryptoDetectIn(session_id="s", min_length=0)


def test_indicator_detail_is_untrusted() -> None:
    """The detail field is the untrusted envelope (binary-derived symbol/string)."""
    field = s.CryptoIndicator.model_fields["detail"]
    assert "Untrusted" in str(field.annotation)


# --- registry wiring -----------------------------------------------------------------------------


# --- instruction source (hardware crypto opcodes) ---


def test_instruction_aes_ni() -> None:
    """An AES-NI opcode maps to kind=aes, source=instruction, high confidence."""
    out = detect_instruction_crypto([("0x1000", "aesenc")])
    assert len(out) == 1
    assert out[0].kind == "aes"
    assert out[0].source == "instruction"
    assert out[0].detail == "aesenc"
    assert out[0].confidence == 0.9


def test_instruction_sha_and_pclmul_kinds() -> None:
    """SHA-ext ⇒ sha; carry-less multiply ⇒ crypto_api (generic)."""
    out = detect_instruction_crypto([("0x1", "sha256rnds2"), ("0x2", "pclmulqdq")])
    by_addr = {i.address: i.kind for i in out}
    assert by_addr == {"0x1": "sha", "0x2": "crypto_api"}


def test_instruction_unknown_mnemonic_skipped() -> None:
    """A non-crypto mnemonic (defensive) is skipped, not emitted."""
    assert detect_instruction_crypto([("0x1", "mov"), ("0x2", "add")]) == []


def test_instruction_dedup_and_sort() -> None:
    """Duplicate (address, opcode) collapses; output is deterministically sorted."""
    out = detect_instruction_crypto([("0x20", "aesenc"), ("0x20", "aesenc"), ("0x10", "aesdec")])
    assert len(out) == 2
    assert [i.address for i in out] == ["0x10", "0x20"]


def test_instruction_source_in_vocab() -> None:
    """`instruction` is now part of the closed source vocabulary."""
    assert "instruction" in cd.SOURCES


def test_registered_and_read_only() -> None:
    """crypto_detect is in the frozen allow-list, handled, and NOT a write tool."""
    assert "crypto_detect" in reg.TIER1_TOOL_NAMES
    assert "crypto_detect" in reg._HANDLERS
    assert "crypto_detect" not in reg.WRITE_TOOLS
    assert reg.required_capability("crypto_detect") == reg.required_capability(
        "crypto_constant_scan"
    )
