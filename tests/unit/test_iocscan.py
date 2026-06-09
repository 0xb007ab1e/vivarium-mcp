"""Unit tests for the pure Tier-2 IOC + crypto-signature cores (ADR-008)."""

from __future__ import annotations

import re

from ghidra_mcp.core.iocscan import (
    CRYPTO_SIGNATURES,
    IOC_CATEGORIES,
    MAX_SCAN_LEN,
    CryptoHit,
    CryptoSignature,
    IocHit,
    scan_crypto_constants,
    scan_iocs,
)


def test_each_ioc_category_matches() -> None:
    """Each category fires on a representative string (isolated via the category filter)."""
    cases = {
        "ipv4": "host 192.168.1.1 here",
        "ipv6": "addr fe80::1ff:fe23:4567:890a end",
        "url": "go http://evil.example/x?a=1 now",
        "email": "mail to alice@corp.example please",
        "domain": "beacon to cdn.evil-corp.example daily",
        "sha256": "h " + "a" * 64,
        "sha1": "h " + "b" * 40,
        "md5": "h " + "c" * 32,
        "windows_path": r"open C:\Windows\System32\evil.dll",
        "unc_path": r"copy \\server\share\x.exe",
        "registry_key": r"set HKLM\Software\Run\evil value",
    }
    assert set(cases) == set(IOC_CATEGORIES)
    for category, text in cases.items():
        hits = scan_iocs([("0x1", text)], categories=(category,))
        assert any(h.category == category for h in hits), f"{category} did not match {text!r}"


def test_dedup_and_min_length_and_address() -> None:
    """Duplicate values dedup; short strings skip; source address passes through."""
    rows = [("0x10", "192.168.0.1"), ("0x20", "192.168.0.1"), ("0x30", "ab")]
    hits = scan_iocs(rows, categories=("ipv4",), min_length=4)
    assert len(hits) == 1
    assert hits[0] == IocHit(category="ipv4", value="192.168.0.1", source_address="0x10")


def test_category_filter_and_none_scans_all() -> None:
    """An unknown category yields nothing; categories=None scans every category."""
    assert scan_iocs([("0x1", "192.168.0.1")], categories=("nope",)) == []
    hits = scan_iocs([("0x1", "192.168.0.1 http://a.example/y")], categories=None)
    assert {h.category for h in hits} >= {"ipv4", "url"}


def test_max_scan_len_truncation() -> None:
    """An IOC beyond MAX_SCAN_LEN is not matched (input is length-capped)."""
    payload = ("." * MAX_SCAN_LEN) + "10.0.0.7"
    assert scan_iocs([("0x1", payload)], categories=("ipv4",)) == []
    within = "10.0.0.7" + ("." * MAX_SCAN_LEN)
    assert scan_iocs([("0x1", within)], categories=("ipv4",))[0].value == "10.0.0.7"


def test_none_value_is_skipped() -> None:
    """A None value row is skipped without error."""
    assert scan_iocs([(None, None)], categories=("ipv4",)) == []  # type: ignore[list-item]


def test_deterministic_order() -> None:
    """Hits are ordered by (category scan order, source_address, value)."""
    rows = [("0x2", "8.8.8.8"), ("0x1", "1.1.1.1"), ("0x1", "http://z.example/a")]
    hits = scan_iocs(rows, categories=None, min_length=4)
    cats = [h.category for h in hits]
    # ipv4 (category index 0) before url (index 2)
    assert cats.index("ipv4") < cats.index("url")
    ipv4 = [h for h in hits if h.category == "ipv4"]
    assert [h.source_address for h in ipv4] == ["0x1", "0x2"]  # sorted by address


def test_crypto_signatures_well_formed() -> None:
    """Every crypto signature has valid even-length lowercase hex + closed-vocab labels."""
    assert CRYPTO_SIGNATURES
    kinds = {"sbox", "iv", "magic"}
    for sig in CRYPTO_SIGNATURES:
        assert isinstance(sig, CryptoSignature)
        assert re.fullmatch(r"[0-9a-f]+", sig.pattern_hex), sig
        assert len(sig.pattern_hex) % 2 == 0, sig
        assert sig.kind in kinds
        assert sig.algorithm


def test_crypto_hit_dataclass() -> None:
    """CryptoHit carries closed-vocabulary labels + a bare address."""
    hit = CryptoHit(algorithm="AES", kind="sbox", address="0x4010")
    assert (hit.algorithm, hit.kind, hit.address) == ("AES", "sbox", "0x4010")


def test_scan_crypto_constants_shapes_dedups_and_orders() -> None:
    """scan_crypto_constants maps per-signature addresses to ordered, deduped hits."""
    aes = CryptoSignature("AES", "sbox", "637c")
    sha = CryptoSignature("SHA-256", "iv", "6a09")
    hits = scan_crypto_constants(
        [
            (sha, ["0x9000", "0x9000"]),  # duplicate address collapses
            (aes, ["0x8000"]),
        ]
    )
    # ordered by (algorithm, kind, address): AES before SHA-256; one SHA hit after dedup
    assert [(h.algorithm, h.address) for h in hits] == [
        ("AES", "0x8000"),
        ("SHA-256", "0x9000"),
    ]


def test_scan_crypto_constants_empty() -> None:
    """No matches → no hits."""
    sig = CryptoSignature("AES", "sbox", "637c")
    assert scan_crypto_constants([(sig, [])]) == []
