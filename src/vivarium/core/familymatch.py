"""Pure (JVM-free) offline family matching over the bundled corpus (ADR-073 D2/D3).

Part of the functional core (ADR-001): given a program's ``program_fingerprint`` digests (ADR-073
D1) and a parsed corpus, rank candidate malware families by exact digest match. No I/O, no JVM, no
network — deterministic and 100%-unit-testable. The ``family_match`` adapter fetches this program's
digests via ``program_fingerprint`` and the bundled corpus (:mod:`vivarium.data.family_corpus`),
then calls :func:`match` here.

**Offline + read-only (ADR-073 D2, containment).** The corpus is a trusted, in-repo artifact;
matching it is a local lookup — no network trust boundary, no new agency. Corpus curation is
human-gated build-time (D3), NEVER a runtime write (knowledge-poisoning defence — LLM03).

**Heuristic (ADR-073 D4).** ``structure_digest`` (operand-masked whole-program structure) is a
strong same/variant-build signal; ``import_digest`` is a weaker same-import-set signal. An empty
result is NOT "unknown-therefore-benign" — only "not in the corpus". A packer that randomizes
structure/imports evades both; a fuzzy (TLSH) tier is a fast-follow (needs the VT-hash fields, D1).

**MVP scope:** exact-digest lookup over the bundled corpus. TLSH/imphash fuzzy matching and a signed
external corpus artifact are the tracked fast-follow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: A 64-char lowercase hex digest (sha256). Corpus entries + fingerprint digests must match this.
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: Confidence per match basis (ADR-073 D4). ``structure`` >> ``import`` (structure is operand-masked
#: whole-program code; import set is weaker). Both together is near-certain.
_CONF_BOTH = 0.98
_CONF_STRUCTURE = 0.95
_CONF_IMPORT = 0.6


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    """One curated corpus row — a family keyed by one or both fingerprint digests (all SAFE)."""

    family: str
    structure_digest: str | None
    import_digest: str | None


@dataclass(frozen=True, slots=True)
class Corpus:
    """A parsed, validated corpus (SAFE, in-repo trusted data)."""

    version: str
    entries: tuple[CorpusEntry, ...]


@dataclass(frozen=True, slots=True)
class FamilyCandidate:
    """One ranked family candidate — HEURISTIC (a lead, not proof; ADR-073 D4).

    Attributes:
        family: The candidate family label — safe (curated in-repo).
        confidence: ``[0, 1]`` from the match basis — safe scalar.
        basis: Which digest(s) matched — ``["structure"]`` / ``["import"]`` / ``["structure",
            "import"]`` — the evidence, never an opaque score.
    """

    family: str
    confidence: float
    basis: tuple[str, ...]


def _hex64_or_none(value: Any) -> str | None:
    """Return ``value`` lowercased if it is a 64-hex string, else ``None`` (validation helper)."""
    if isinstance(value, str):
        lowered = value.lower()
        if _HEX64.match(lowered):
            return lowered
    return None


def parse_corpus(data: dict[str, Any]) -> Corpus:
    """Parse + validate a raw corpus dict into a :class:`Corpus` (pure; fail-closed per entry).

    A malformed entry (no family, or neither digest a valid 64-hex) is **skipped** honestly rather
    than crashing the whole lookup — a corrupt corpus degrades to fewer/zero candidates, never an
    error at scan time (fail-closed, master §2).

    Args:
        data: The raw corpus mapping (``{"version": str, "entries": [ {...}, ... ]}``).

    Returns:
        The validated :class:`Corpus` (``version`` coerced to ``str``; invalid entries dropped).
    """
    version = str(data.get("version", "unknown"))
    entries: list[CorpusEntry] = []
    for raw in data.get("entries", []):
        if not isinstance(raw, dict):
            continue
        family = raw.get("family")
        if not isinstance(family, str) or not family:
            continue
        structure = _hex64_or_none(raw.get("structure_digest"))
        imports = _hex64_or_none(raw.get("import_digest"))
        if structure is None and imports is None:
            continue
        entries.append(
            CorpusEntry(family=family, structure_digest=structure, import_digest=imports)
        )
    return Corpus(version=version, entries=tuple(entries))


def match(
    structure_digest: str | None,
    import_digest: str | None,
    corpus: Corpus,
    *,
    max_candidates: int = 10,
) -> list[FamilyCandidate]:
    """Rank corpus families by exact digest match against a program's fingerprint (pure; D2).

    For each entry a basis is collected: ``structure`` if its ``structure_digest`` equals the
    program's, ``import`` if its ``import_digest`` equals the program's. An entry with any basis is
    a candidate; confidence follows the basis (structure >> import; both ≈ certain). Candidates are
    deduplicated by family (best confidence kept), sorted by confidence desc then family, capped.

    Args:
        structure_digest: The program's ``program_fingerprint.structure_digest`` (or ``None``).
        import_digest: The program's ``program_fingerprint.import_digest`` (or ``None``).
        corpus: The parsed corpus to match against.
        max_candidates: Cap on returned candidates (bounds the result — CWE-400).

    Returns:
        Ranked, deduplicated, capped :class:`FamilyCandidate` list (empty ⇒ not in the corpus, NOT
        "benign").
    """
    best: dict[str, FamilyCandidate] = {}
    for entry in corpus.entries:
        basis: list[str] = []
        if structure_digest is not None and entry.structure_digest == structure_digest:
            basis.append("structure")
        if import_digest is not None and entry.import_digest == import_digest:
            basis.append("import")
        if not basis:
            continue
        if "structure" in basis and "import" in basis:
            confidence = _CONF_BOTH
        elif "structure" in basis:
            confidence = _CONF_STRUCTURE
        else:
            confidence = _CONF_IMPORT
        candidate = FamilyCandidate(family=entry.family, confidence=confidence, basis=tuple(basis))
        existing = best.get(entry.family)
        if existing is None or candidate.confidence > existing.confidence:
            best[entry.family] = candidate

    ranked = sorted(best.values(), key=lambda c: (-c.confidence, c.family))
    return ranked[:max_candidates]


def load_default_corpus() -> Corpus:
    """Load + parse the bundled offline corpus (:mod:`vivarium.data.family_corpus`); local read.

    Reads the in-repo Python data module (no filesystem/network) and validates it via
    :func:`parse_corpus`. The bundled seed is intentionally small/empty (see the data module); a
    corrupt/empty corpus yields zero candidates, never an error.
    """
    from vivarium.data.family_corpus import FAMILY_CORPUS

    return parse_corpus(FAMILY_CORPUS)
