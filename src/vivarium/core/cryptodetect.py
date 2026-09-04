"""Pure (JVM-free) crypto detection by API / import / symbol name for Tier-2 (ADR-075).

Part of the functional core (ADR-001): operates on already-extracted facts (the existing
``list_imports`` + ``list_strings`` RPCs). No I/O, no JVM — deterministic and 100%-unit-testable.
Mirrors ``core.iocscan`` / ``core.secretscan`` in shape (a pure ``detect_*`` over rows).

**Why this exists (ADR-075 / validation miss M2).** ``crypto_constant_scan`` (ADR-008) finds only
*algorithm constants* (AES S-boxes, round constants). The blind-triage benchmark hit its blind spot
three times — framework crypto (CommonCrypto AES) and bespoke ciphers leave no recognizable
constant, so an empty constant scan risks the false conclusion "no crypto / plaintext C2". This
module detects crypto by the OTHER high-signal signals a static view exposes: a linked/imported
crypto **API** and a dynamically-resolved crypto **symbol name** in the strings.

**MVP scope (ADR-075, ratified 2026-08-25).** Two sources — ``import`` (a crypto symbol in the IAT)
and ``api_name`` (a crypto symbol NAME in the strings, i.e. resolved via ``GetProcAddress`` /
``dlsym``) — both pure over lists the worker already provides. The ``instruction`` (AES-NI/SHA) and
``code_pattern`` (cipher-shaped loops) sources from the ADR need a worker disassembly pass and are a
tracked fast-follow.

**Heuristic, not authoritative (ADR-075 D5 / ADR-008).** ``import``/``api_name`` are high-precision
but an obfuscated/statically-linked-and-stripped crypto routine can evade both — an empty result is
**not** "no crypto" (the same discipline `crypto_constant_scan` needs). ``detail`` is binary-derived
(attacker-controlled) and MUST be wrapped in the untrusted envelope by the adapter (ADR-005).

All matching is plain lowercase substring / a single linear anchored regex (no nested quantifiers —
ReDoS-safe, std-cwe CWE-1333); inputs are length-capped by the caller before matching.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

#: Hard cap on the characters of any single string scanned (pathological-input defense; the caller
#: also paginates the string/import sets).
MAX_SCAN_LEN = 8192

#: The closed source vocabulary (ADR-075 D1). ``code_pattern`` (cipher-shaped loops) is the last
#: fast-follow; ``instruction`` (hardware crypto opcodes) is now implemented.
SOURCES: tuple[str, ...] = ("import", "api_name", "instruction")

#: The closed primitive/family vocabulary a match reports.
KINDS: tuple[str, ...] = ("aes", "sha", "md5", "rc4", "hmac", "crypto_api")

#: Confidence per source (ADR-075 D5). A linked import or a hardware crypto opcode is a strong,
#: unambiguous signal; a symbol-like STRING is weaker (may be an incidental literal) — hence lower.
_CONFIDENCE: dict[str, float] = {"import": 0.9, "api_name": 0.6, "instruction": 0.9}

#: Hardware crypto opcode (lowercased mnemonic) → primitive kind. AES-NI ⇒ aes, SHA-ext ⇒ sha,
#: carry-less multiply (GHASH/AES-GCM) ⇒ crypto_api (generic — not an algorithm by itself).
_OPCODE_KIND: dict[str, str] = {
    "aesenc": "aes",
    "aesenclast": "aes",
    "aesdec": "aes",
    "aesdeclast": "aes",
    "aesimc": "aes",
    "aeskeygenassist": "aes",
    "sha1rnds4": "sha",
    "sha1nexte": "sha",
    "sha1msg1": "sha",
    "sha1msg2": "sha",
    "sha256rnds2": "sha",
    "sha256msg1": "sha",
    "sha256msg2": "sha",
    "pclmulqdq": "crypto_api",
    "vpclmulqdq": "crypto_api",
}

#: Curated crypto-API signal table: ``(pattern_id, kind, needle)``. ``needle`` is matched
#: case-insensitively as a substring of a symbol name. Covers Windows CryptoAPI + CNG, Apple
#: CommonCrypto, OpenSSL/libcrypto, libsodium/NaCl, and mbedTLS/wolfSSL. Extensible — add a row.
_CRYPTO_API: tuple[tuple[str, str, str], ...] = (
    # Windows CryptoAPI (wincrypt / advapi32)
    ("wincrypt", "crypto_api", "cryptencrypt"),
    ("wincrypt", "crypto_api", "cryptdecrypt"),
    ("wincrypt", "crypto_api", "cryptgenkey"),
    ("wincrypt", "crypto_api", "cryptderivekey"),
    ("wincrypt", "crypto_api", "crypthashdata"),
    ("wincrypt", "crypto_api", "cryptacquirecontext"),
    # Windows CNG (bcrypt / ncrypt)
    ("cng", "crypto_api", "bcryptencrypt"),
    ("cng", "crypto_api", "bcryptdecrypt"),
    ("cng", "crypto_api", "bcryptgeneratesymmetrickey"),
    ("cng", "crypto_api", "bcrypthash"),
    ("cng", "crypto_api", "ncryptencrypt"),
    # Apple CommonCrypto (the case-02 / Wirenet miss)
    ("commoncrypto", "crypto_api", "cccrypt"),
    ("commoncrypto", "crypto_api", "cccryptorcreate"),
    ("commoncrypto", "hmac", "cchmac"),
    # OpenSSL / libcrypto
    ("openssl_evp", "crypto_api", "evp_encryptinit"),
    ("openssl_evp", "crypto_api", "evp_decryptinit"),
    ("openssl_evp", "crypto_api", "evp_cipherinit"),
    ("openssl_aes", "aes", "aes_encrypt"),
    ("openssl_aes", "aes", "aes_set_encrypt_key"),
    ("openssl_sha", "sha", "sha256_init"),
    ("openssl_sha", "sha", "sha1_init"),
    ("openssl_md5", "md5", "md5_init"),
    ("openssl_rc4", "rc4", "rc4_set_key"),
    # libsodium / NaCl
    ("libsodium", "crypto_api", "crypto_secretbox"),
    ("libsodium", "crypto_api", "crypto_aead"),
    ("libsodium", "crypto_api", "crypto_stream"),
    ("libsodium", "crypto_api", "crypto_box"),
    ("libsodium", "sha", "crypto_hash_sha"),
    # mbedTLS / wolfSSL
    ("mbedtls", "aes", "mbedtls_aes"),
    ("mbedtls", "crypto_api", "mbedtls_cipher"),
    ("wolfssl", "aes", "wc_aesencrypt"),
)

#: A string is treated as a candidate *symbol name* (``api_name`` source) only when it looks like an
#: identifier — no whitespace, identifier chars, bounded length. This keeps prose/log lines that
#: merely mention "encrypt" from firing while still catching a resolved ``CCCrypt`` / ``EVP_...``.
_SYMBOL_LIKE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,63}$")


@dataclass(frozen=True, slots=True)
class CryptoIndicator:
    """One heuristic crypto indicator — HEURISTIC (a lead, not proof; ADR-075 D5).

    Attributes:
        address: Address of the source import/string (hex) — safe (``None`` if unknown).
        kind: One of :data:`KINDS` — safe (closed vocabulary).
        source: One of :data:`SOURCES` — safe (closed vocabulary).
        detail: The matched symbol/string — binary-derived (UNTRUSTED once wrapped by the adapter).
        confidence: Per-source confidence in ``[0, 1]`` — safe scalar.
    """

    address: str | None
    kind: str
    source: str
    detail: str
    confidence: float


def _matches(name: str) -> list[tuple[str, str]]:
    """Return ``(pattern_id, kind)`` for every crypto-API needle contained in ``name`` (lowered)."""
    lowered = name.lower()
    return [(pid, kind) for (pid, kind, needle) in _CRYPTO_API if needle in lowered]


def detect_crypto(
    imports: Iterable[tuple[str | None, str, str | None]],
    strings: Iterable[tuple[str | None, str]],
) -> list[CryptoIndicator]:
    """Detect crypto by imported API and by resolved symbol NAME (pure; ADR-075 D1).

    Args:
        imports: ``(address, name, library)`` rows from ``list_imports`` (``library`` may be
            ``None``). Each is scanned against the crypto-API table as the ``import`` source.
        strings: ``(address, text)`` rows from ``list_strings``. A string that looks like a bare
            symbol name (``_SYMBOL_LIKE``) and matches the table fires the ``api_name`` source —
            catching dynamically-resolved (``GetProcAddress``/``dlsym``) crypto.

    Returns:
        Deterministic list of :class:`CryptoIndicator`, de-duplicated by
        ``(address, kind, source, detail)`` and sorted by ``(address, source, kind, detail)``. The
        raw ``detail`` stays here until the adapter wraps it untrusted (ADR-005).
    """
    seen: set[tuple[str | None, str, str, str]] = set()
    out: list[CryptoIndicator] = []

    def _emit(address: str | None, kind: str, source: str, detail: str) -> None:
        key = (address, kind, source, detail)
        if key in seen:
            return
        seen.add(key)
        out.append(
            CryptoIndicator(
                address=address,
                kind=kind,
                source=source,
                detail=detail,
                confidence=_CONFIDENCE[source],
            )
        )

    for address, name, _library in imports:
        if not name:
            continue
        for _pid, kind in _matches(name[:MAX_SCAN_LEN]):
            _emit(address, kind, "import", name[:MAX_SCAN_LEN])

    for address, text in strings:
        if not text or not _SYMBOL_LIKE.match(text):
            continue
        for _pid, kind in _matches(text):
            _emit(address, kind, "api_name", text)

    out.sort(key=lambda i: (i.address or "", i.source, i.kind, i.detail))
    return out


def detect_instruction_crypto(
    hits: Iterable[tuple[str | None, str]],
) -> list[CryptoIndicator]:
    """Map hardware crypto-opcode hits to indicators (pure; ADR-075 ``instruction`` source).

    A hit is a ``(address, mnemonic)`` from the worker's ``crypto_instructions`` opcode scan (AES-NI
    / SHA-ext / carry-less multiply — all unambiguous crypto, so high confidence). Unknown mnemonics
    (should not occur — the worker only emits allow-listed opcodes) are skipped defensively.

    Args:
        hits: ``(address, mnemonic)`` rows; ``mnemonic`` is a lowercased opcode.

    Returns:
        Deterministic :class:`CryptoIndicator` list, de-duplicated by ``(address, kind, source,
        detail)`` and sorted — ``source="instruction"``, ``detail`` = the mnemonic.
    """
    seen: set[tuple[str | None, str, str, str]] = set()
    out: list[CryptoIndicator] = []
    for address, mnemonic in hits:
        kind = _OPCODE_KIND.get(mnemonic.lower())
        if kind is None:
            continue
        key = (address, kind, "instruction", mnemonic)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            CryptoIndicator(
                address=address,
                kind=kind,
                source="instruction",
                detail=mnemonic,
                confidence=_CONFIDENCE["instruction"],
            )
        )
    out.sort(key=lambda i: (i.address or "", i.source, i.kind, i.detail))
    return out
