"""Pure (JVM-free) heuristic firmware-secret scanning for Tier-2 (ADR-072).

Part of the functional core (ADR-001): operates on already-extracted strings (from the existing
``list_strings`` RPC). No I/O, no JVM — deterministic and 100%-unit-testable. Mirrors
``core.iocscan`` in shape (pure ``scan_*`` over string rows) but with a distinct category set and a
**redaction contract** (ADR-072 D3): a finding NEVER carries the raw secret — only a masked preview
and a salted, truncated correlation hash leave this module.

**Heuristic, not authoritative (ADR-072 D4 / ADR-008).** Keyword/entropy/magic matching has false
positives (high-entropy non-secrets) and false negatives (obfuscated/encrypted secrets); results are
triage leads. The masked preview is binary-derived (attacker-controlled) and MUST be wrapped in the
untrusted envelope by the adapter before reaching the client (ADR-005).

All regexes are linear and bounded (no nested quantifiers / catastrophic backtracking — ReDoS-safe,
std-cwe CWE-1333); inputs are length-capped by the caller before matching.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass

#: Hard cap on the characters of any single string scanned (ReDoS / pathological-input defense; the
#: caller also paginates the string set).
MAX_SCAN_LEN = 8192

#: The closed category vocabulary (ADR-072 D1). Order defines the deterministic scan/report order.
CATEGORIES: tuple[str, ...] = (
    "hardcoded_credential",
    "key_material",
    "format_magic",
    "property_secret_name",
)

#: Fixed module salt for the correlation hash. It is NOT a security secret — its only job is to make
#: the truncated digest non-reversible-by-lookup for casual values while staying deterministic, so
#: two findings of the same value correlate within and across scans (ADR-072 D3). Disclosure of the
#: salt does not weaken the redaction contract (the raw value never leaves this module regardless).
_PREVIEW_SALT = b"vivarium/secret_scan/v1"

# Substrings that, appearing in a string, make an *adjacent* literal look credential-like.
_CREDENTIAL_KEYWORDS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "auth",
    "credential",
    "private_key",
    "access_key",
    "session_key",
)

# Key-material headers (PEM + common private-key markers). Matched case-sensitively as they appear.
# Ordered specific-before-generic: the bare ``-----BEGIN `` fallback must come LAST or it would
# shadow the specific PEM/OpenSSH/PGP headers (each of which starts with it).
_KEY_MATERIAL_MARKERS: tuple[tuple[str, str], ...] = (
    ("pem_certificate", "-----BEGIN CERTIFICATE-----"),
    ("openssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("pgp_block", "-----BEGIN PGP "),
    ("ssh_public_key", "ssh-rsa "),
    ("ssh_ed25519", "ssh-ed25519 "),
    ("pem_private_key", "-----BEGIN "),
)

# Firmware/bootloader/container format magic that appears as printable ASCII in a strings dump —
# provenance context (ADR-072 D1 `format_magic`), not a secret. Binary-only magic (uImage's
# 0x27051956) is out of a string-based MVP scan and is deferred to the byte-scan follow-up.
_FORMAT_MAGIC: tuple[tuple[str, str], ...] = (
    ("android_boot", "ANDROID!"),
    ("uboot_legacy", "U-Boot"),
    ("squashfs", "hsqs"),
    ("cramfs", "Compressed ROMFS"),
    ("jffs2", "JFFS2"),
    ("ubi", "UBI#"),
    ("elf", "\x7fELF"),
)

# Property-store / config KEY names whose name implies a secret value (the exact T19 `WIFI_PWD`
# case). Linear, anchored, ReDoS-safe.
_PROPERTY_SECRET_NAME = re.compile(
    r"^[A-Za-z0-9_.\-]{0,64}"
    r"(?:PWD|PASS(?:WORD)?|SECRET|TOKEN|API[_-]?KEY|PRIV(?:ATE)?[_-]?KEY|ACCESS[_-]?KEY)"
    r"[A-Za-z0-9_.\-]{0,64}$",
    re.IGNORECASE,
)

# A run of base64/hex characters long enough to be key material (used with the entropy gate).
_BLOB = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")

#: Default Shannon-entropy floor (bits/byte) for a high-entropy blob to count as a credential.
DEFAULT_ENTROPY_THRESHOLD = 4.0

#: Minimum length for a high-entropy blob to be considered (below this, entropy is not meaningful).
_MIN_BLOB_LEN = 20


@dataclass(frozen=True, slots=True)
class SecretFinding:
    """One heuristic secret finding — REDACTED (ADR-072 D3): never carries the raw value.

    Attributes:
        address: Address of the source string (hex) — safe (``None`` if unknown).
        category: One of :data:`CATEGORIES` — safe (closed vocabulary).
        pattern_id: Which pattern fired (e.g. ``"keyword:password"``, ``"pem_private_key"``) — safe.
        masked_preview: The value with its middle masked (first/last few chars) — binary-derived
            (UNTRUSTED once wrapped by the adapter); still not the raw secret.
        preview_hash: Salted, truncated digest of the raw value — safe (non-disclosing correlation
            handle; ADR-072 D3).
        entropy: Shannon entropy (bits/byte) when entropy drove the match, else ``None`` — safe.
    """

    address: str | None
    category: str
    pattern_id: str
    masked_preview: str
    preview_hash: str
    entropy: float | None = None


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per byte) of ``value``'s UTF-8 bytes (0.0 for empty)."""
    if not value:
        return 0.0
    data = value.encode("utf-8", "ignore")
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask_preview(value: str) -> str:
    """Mask the middle of ``value``, keeping a couple of edge chars for triage (never the raw).

    Short values (<= 8 chars) are fully masked — showing edges of an 8-char secret would disclose
    most of it.
    """
    length = len(value)
    if length <= 8:
        return "*" * length
    keep = 2 if length < 20 else 4
    return f"{value[:keep]}{'*' * (length - 2 * keep)}{value[-keep:]}"


def preview_hash(value: str) -> str:
    """Return a salted, truncated (12-hex) digest of ``value`` — a non-disclosing handle."""
    digest = hashlib.sha256(_PREVIEW_SALT + value.encode("utf-8", "ignore")).hexdigest()
    return digest[:12]


def _finding(
    address: str | None, category: str, pattern_id: str, value: str, entropy: float | None
) -> SecretFinding:
    """Build a redacted :class:`SecretFinding` from a raw ``value`` (the raw value stays local)."""
    return SecretFinding(
        address=address,
        category=category,
        pattern_id=pattern_id,
        masked_preview=mask_preview(value),
        preview_hash=preview_hash(value),
        entropy=entropy,
    )


def scan_secrets(  # noqa: C901 - one linear pass, one independent branch per closed category; splitting hurts readability
    rows: Iterable[tuple[str | None, str]],
    *,
    categories: tuple[str, ...] | None = None,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> list[SecretFinding]:
    """Scan ``(address, value)`` rows for firmware secrets, returning redacted findings.

    Deterministic, side-effect-free. Each row's ``value`` is capped at :data:`MAX_SCAN_LEN` before
    matching. At most one finding per (row, category) is emitted (the first/strongest signal in that
    category) to keep the result bounded and the report readable.

    Args:
        rows: ``(source_address_hex_or_None, string_value)`` pairs (from ``list_strings``).
        categories: Restrict to these categories (subset of :data:`CATEGORIES`); ``None`` = all.
        entropy_threshold: Shannon-entropy floor (bits/byte) for a high-entropy blob to count as a
            ``hardcoded_credential``.

    Returns:
        Redacted :class:`SecretFinding` list — NEVER carrying a raw secret (ADR-072 D3).
    """
    wanted = tuple(c for c in CATEGORIES if c in categories) if categories else CATEGORIES
    findings: list[SecretFinding] = []
    for address, raw in rows:
        value = raw[:MAX_SCAN_LEN]
        low = value.lower()

        if "property_secret_name" in wanted and _PROPERTY_SECRET_NAME.match(value):
            findings.append(
                _finding(address, "property_secret_name", "name_implies_secret", value, None)
            )

        if "key_material" in wanted:
            for pattern_id, marker in _KEY_MATERIAL_MARKERS:
                if marker in value:
                    findings.append(_finding(address, "key_material", pattern_id, value, None))
                    break

        if "format_magic" in wanted:
            for pattern_id, marker in _FORMAT_MAGIC:
                if marker in value:
                    findings.append(_finding(address, "format_magic", pattern_id, value, None))
                    break

        if "hardcoded_credential" in wanted:
            keyword = next((k for k in _CREDENTIAL_KEYWORDS if k in low), None)
            if keyword is not None:
                findings.append(
                    _finding(address, "hardcoded_credential", f"keyword:{keyword}", value, None)
                )
            else:
                blob = _BLOB.search(value)
                if blob is not None and len(blob.group()) >= _MIN_BLOB_LEN:
                    ent = shannon_entropy(blob.group())
                    if ent >= entropy_threshold:
                        findings.append(
                            _finding(
                                address,
                                "hardcoded_credential",
                                "high_entropy_blob",
                                blob.group(),
                                ent,
                            )
                        )
    return findings
