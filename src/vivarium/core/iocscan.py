"""Pure (JVM-free) heuristic IOC + crypto-constant scanning for Tier-2 (ADR-008).

Part of the functional core (ADR-001): operates on already-extracted strings (from the existing
``list_strings`` RPC) and on a static crypto-signature table (consumed by the existing
``search_bytes`` RPC). No I/O, no JVM — deterministic and 100%-unit-testable.

**Heuristic, not authoritative (ADR-008 caveat).** Pattern/signature matching has false positives
and negatives; results are triage leads. Every matched value is binary-derived (attacker-controlled)
and MUST be wrapped in the untrusted envelope by the adapter before reaching the client (ADR-005) —
a matched "URL"/"domain"/"path" can itself be an indirect-prompt-injection payload.

All regexes are linear and bounded (no nested quantifiers / catastrophic backtracking — ReDoS-safe,
std-cwe CWE-1333), and inputs are length-capped by the caller before matching.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

#: Hard cap on the characters of any single string scanned for IOCs (defense against pathological
#: inputs / ReDoS amplification; the caller also paginates the string set).
MAX_SCAN_LEN = 4096

# Linear IOC patterns, kept deliberately simple: precision is traded for safety + determinism
# (heuristic triage, not validation). Order defines the deterministic per-category scan order.
_IOC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("ipv6", re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")),
    ("url", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{0,15}://[^\s\"'<>]{1,512}")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b")),
    ("domain", re.compile(r"\b(?:[A-Za-z0-9\-]{1,63}\.){1,8}[A-Za-z]{2,24}\b")),
    ("sha256", re.compile(r"\b[0-9a-fA-F]{64}\b")),
    ("sha1", re.compile(r"\b[0-9a-fA-F]{40}\b")),
    ("md5", re.compile(r"\b[0-9a-fA-F]{32}\b")),
    ("windows_path", re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,255}\\?){1,64}")),
    ("unc_path", re.compile(r"\\\\[A-Za-z0-9_.$\-]{1,255}\\[^\r\n]{1,255}")),
    ("registry_key", re.compile(r"\bHK(?:LM|CU|CR|U|CC)\\[^\r\n]{1,512}")),
)

#: Curated set of common top-level domains. The bare ``domain`` regex matches ANY dotted token, so
#: binary artifacts like ELF section/symbol names (``note.gnu.property``, ``gnu.hash``) were
#: reported as "domains" on essentially every binary. Requiring the final label to be a real TLD
#: removes that noise. HEURISTIC: obscure ccTLDs are intentionally omitted (precision over recall —
#: a missed exotic domain is cheaper than a section name on every scan).
_DOMAIN_TLDS: frozenset[str] = frozenset(
    {
        # generic
        "com",
        "net",
        "org",
        "info",
        "biz",
        "io",
        "co",
        "dev",
        "app",
        "xyz",
        "online",
        "site",
        "top",
        "live",
        "cloud",
        "tech",
        "ai",
        "me",
        "tv",
        "cc",
        "gov",
        "edu",
        "mil",
        "int",
        "name",
        "pro",
        "mobi",
        "asia",
        "link",
        "click",
        "work",
        "shop",
        "store",
        "blog",
        "game",
        "fun",
        "example",  # example: RFC 2606 reserved documentation TLD
        # country-code (common)
        "us",
        "uk",
        "ca",
        "au",
        "de",
        "fr",
        "es",
        "it",
        "nl",
        "ru",
        "cn",
        "jp",
        "kr",
        "in",
        "br",
        "mx",
        "za",
        "se",
        "no",
        "fi",
        "dk",
        "pl",
        "ch",
        "at",
        "be",
        "ie",
        "nz",
        "sg",
        "hk",
        "tw",
        "ua",
        "tr",
        "ir",
        "kp",
        "eu",
    }
)


def _domain_has_known_tld(text: str) -> bool:
    """Whether a ``domain``-pattern match ends in a curated common TLD (drops ELF-section noise)."""
    _, _, tld = text.rpartition(".")
    return tld.lower() in _DOMAIN_TLDS


#: Per-category acceptance filters applied after the regex (precision the regex can't express).
_IOC_ACCEPT: dict[str, Callable[[str], bool]] = {"domain": _domain_has_known_tld}

#: All IOC category names, in deterministic scan order.
IOC_CATEGORIES: tuple[str, ...] = tuple(name for name, _ in _IOC_PATTERNS)


@dataclass(frozen=True, slots=True)
class IocHit:
    """One IOC match.

    Attributes:
        category: The IOC category (a closed-vocabulary label — safe; see :data:`IOC_CATEGORIES`).
        value: The matched substring — UNTRUSTED (attacker-controlled string content).
        source_address: Address of the string the match came from (hex), or ``None``.
    """

    category: str
    value: str
    source_address: str | None


def scan_iocs(
    strings: Iterable[tuple[str | None, str]],
    *,
    categories: tuple[str, ...] | None = None,
    min_length: int = 4,
) -> list[IocHit]:
    """Scan extracted strings for IOCs (PURE, heuristic).

    Args:
        strings: Iterable of ``(source_address, value)`` rows (address may be ``None``).
        categories: Restrict to these IOC categories; ``None`` scans all. Unknown names are ignored.
        min_length: Skip strings shorter than this (cheap noise filter).

    Returns:
        De-duplicated :class:`IocHit` list, ordered by (category scan order, source_address, value).
    """
    selected = [
        (name, pat) for name, pat in _IOC_PATTERNS if categories is None or name in set(categories)
    ]
    seen: set[tuple[str, str]] = set()
    hits: list[IocHit] = []
    for address, value in strings:
        if value is None or len(value) < min_length:
            continue
        scanned = value[:MAX_SCAN_LEN]
        for name, pat in selected:
            # Every pattern uses only non-capturing groups, so findall yields whole-match strings.
            accept = _IOC_ACCEPT.get(name)
            for text in pat.findall(scanned):
                if accept is not None and not accept(text):
                    continue
                key = (name, text)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(IocHit(category=name, value=text, source_address=address))
    hits.sort(key=lambda h: (IOC_CATEGORIES.index(h.category), h.source_address or "", h.value))
    return hits


@dataclass(frozen=True, slots=True)
class CryptoSignature:
    """A known crypto byte-constant signature to search for (closed-vocabulary metadata).

    Attributes:
        algorithm: The algorithm label (e.g. ``"AES"``, ``"SHA-256"``) — safe.
        kind: What the constant is (``"sbox"``, ``"iv"``, ``"magic"``, ``"table"``) — safe.
        pattern_hex: Lowercase hex of the constant byte sequence, fed to the ``search_bytes`` RPC.
    """

    algorithm: str
    kind: str
    pattern_hex: str


#: Curated, well-known crypto constants. HEURISTIC — a byte match is a *lead*, not proof (the bytes
#: can appear coincidentally or in unrelated tables). Endianness-sensitive constants use the form
#: most common in compiled binaries; misses are expected (ADR-008 caveat).
CRYPTO_SIGNATURES: tuple[CryptoSignature, ...] = (
    # AES forward S-box, first 16 bytes.
    CryptoSignature("AES", "sbox", "637c777bf26b6fc53001672bfed7ab76"),
    # MD5 init state (little-endian in memory): A,B,C,D.
    CryptoSignature("MD5", "iv", "0123456789abcdeffedcba9876543210"),
    # SHA-1 init state (big-endian).
    CryptoSignature("SHA-1", "iv", "67452301efcdab8998badcfe10325476c3d2e1f0"),
    # SHA-256 init H0..H7 (big-endian).
    CryptoSignature(
        "SHA-256",
        "iv",
        "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19",
    ),
    # SHA-512 init H0..H1 prefix (big-endian) — prefix kept short to bound the search.
    CryptoSignature("SHA-512", "iv", "6a09e667f3bcc908bb67ae8584caa73b"),
    # CRC-32 (IEEE, reflected) lookup table entries 1..4, little-endian as stored in memory:
    # 0x77073096 0xEE0E612C 0x990951BA 0x076DC419. Skips entry 0 (all-zero, too generic). This is
    # the table zlib/gzip/PNG and countless others embed. (Adler-32 has no constant table — it is
    # pure arithmetic mod 65521 — so it is not byte-signaturable and is intentionally omitted.)
    CryptoSignature("CRC-32", "table", "963007772c610eeeba51099919c46d07"),
)


@dataclass(frozen=True, slots=True)
class CryptoHit:
    """One crypto-constant match located in the binary.

    Attributes:
        algorithm: Algorithm label (closed vocabulary) — safe.
        kind: Constant kind (``"sbox"``/``"iv"``/``"magic"``/``"table"``) — safe.
        address: Address where the constant was found (hex) — safe.
    """

    algorithm: str
    kind: str
    address: str


def scan_crypto_constants(
    results: Iterable[tuple[CryptoSignature, Sequence[str]]],
) -> list[CryptoHit]:
    """Shape per-signature byte-search match addresses into ordered, deduped hits (PURE).

    The byte search itself is delegated to the worker ``search_bytes`` RPC (the JVM edge); this core
    owns the signature table and the result shaping, so the mapping is deterministic and testable
    with no JVM. All output fields are closed-vocabulary labels or server-normalized addresses
    (safe) — no binary-derived *content* is in a :class:`CryptoHit`.

    Args:
        results: Iterable of ``(signature, [match_address, ...])`` rows, one per signature.

    Returns:
        De-duplicated :class:`CryptoHit` list ordered by (algorithm, kind, address).
    """
    seen: set[tuple[str, str, str]] = set()
    hits: list[CryptoHit] = []
    for signature, addresses in results:
        for address in addresses:
            key = (signature.algorithm, signature.kind, address)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                CryptoHit(algorithm=signature.algorithm, kind=signature.kind, address=address)
            )
    hits.sort(key=lambda h: (h.algorithm, h.kind, h.address))
    return hits
