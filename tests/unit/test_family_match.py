"""Unit tests for ADR-073 D2/D3 `family_match` — pure matcher + corpus parse + wiring.

The whole lookup is the pure ``core.familymatch`` (no JVM edge): the adapter fetches this program's
``program_fingerprint`` digests and the bundled offline corpus, then calls ``match``. These tests
exercise the matcher (structure/import/both bases, confidence ordering, dedup, cap), the corpus
parser (fail-closed per-entry validation), the bundled default corpus, and read-only registration.
"""

from __future__ import annotations

from vivarium.core import familymatch as fm
from vivarium.core.familymatch import Corpus, CorpusEntry, load_default_corpus, match, parse_corpus
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64


def _corpus(*entries: CorpusEntry) -> Corpus:
    return Corpus(version="test-1", entries=tuple(entries))


# --- matcher: bases + confidence ---


def test_structure_match_strong() -> None:
    """A structure_digest hit is a strong, high-confidence candidate."""
    c = _corpus(CorpusEntry("Fam.A", structure_digest=_A, import_digest=_B))
    out = match(_A, None, c)
    assert len(out) == 1
    assert out[0].family == "Fam.A"
    assert out[0].basis == ("structure",)
    assert out[0].confidence == 0.95


def test_import_only_match_weaker() -> None:
    """An import-only hit is a weaker candidate."""
    c = _corpus(CorpusEntry("Fam.A", structure_digest=_A, import_digest=_B))
    out = match(None, _B, c)
    assert out[0].basis == ("import",)
    assert out[0].confidence == 0.6


def test_both_digests_near_certain() -> None:
    """Matching BOTH digests is near-certain and ranks highest."""
    c = _corpus(CorpusEntry("Fam.A", structure_digest=_A, import_digest=_B))
    out = match(_A, _B, c)
    assert out[0].basis == ("structure", "import")
    assert out[0].confidence == 0.98


def test_no_match_is_empty() -> None:
    """A fingerprint absent from the corpus yields no candidates (NOT 'benign')."""
    c = _corpus(CorpusEntry("Fam.A", structure_digest=_A, import_digest=_B))
    assert match(_C, _D, c) == []


def test_ranking_and_dedup() -> None:
    """Candidates rank by confidence desc; a family is deduped to its best basis."""
    c = _corpus(
        CorpusEntry("Weak", structure_digest=None, import_digest=_B),  # import-only 0.6
        CorpusEntry("Strong", structure_digest=_A, import_digest=None),  # structure 0.95
        CorpusEntry("Strong", structure_digest=None, import_digest=_B),  # dup family, weaker
    )
    out = match(_A, _B, c)
    assert [x.family for x in out] == ["Strong", "Weak"]
    strong = next(x for x in out if x.family == "Strong")
    assert strong.confidence == 0.95  # kept the stronger basis for the deduped family


def test_max_candidates_caps() -> None:
    """max_candidates bounds the returned list."""
    c = _corpus(
        CorpusEntry("F1", structure_digest=_A, import_digest=None),
        CorpusEntry("F2", structure_digest=_A, import_digest=None),
        CorpusEntry("F3", structure_digest=_A, import_digest=None),
    )
    assert len(match(_A, None, c, max_candidates=2)) == 2


# --- corpus parse: fail-closed validation ---


def test_parse_skips_malformed_entries() -> None:
    """Entries missing a family or with no valid digest are dropped, not fatal (fail-closed)."""
    raw = {
        "version": "corpus-x",
        "entries": [
            {"family": "Good", "structure_digest": _A},
            {"structure_digest": _B},  # no family → skip
            {"family": "NoDigest"},  # neither digest → skip
            {"family": "BadHex", "structure_digest": "xyz"},  # invalid hex → skip
            "not-a-dict",  # → skip
        ],
    }
    c = parse_corpus(raw)
    assert c.version == "corpus-x"
    assert [e.family for e in c.entries] == ["Good"]


def test_parse_lowercases_hex() -> None:
    """Digest hex is normalized to lowercase so matching is case-insensitive at the source."""
    c = parse_corpus({"version": "v", "entries": [{"family": "F", "import_digest": _A.upper()}]})
    assert c.entries[0].import_digest == _A


def test_default_corpus_loads_and_is_valid() -> None:
    """The bundled corpus loads, parses, and carries a version (seed may be empty)."""
    c = load_default_corpus()
    assert c.version == "corpus-1"
    assert isinstance(c.entries, tuple)  # empty seed is fine


# --- schema + registry wiring ---


def test_schema_bounds_and_basis_safe() -> None:
    """FamilyMatchIn bounds max_candidates; candidate basis is a plain safe list."""
    m = s.FamilyMatchIn(session_id="sess")
    assert m.max_candidates == 10
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        s.FamilyMatchIn(session_id="s", max_candidates=0)
    assert "Untrusted" not in str(s.FamilyCandidate.model_fields["family"].annotation)


def test_registered_and_read_only() -> None:
    """family_match is in the frozen allow-list, handled, and NOT a write tool."""
    assert "family_match" in reg.TIER1_TOOL_NAMES
    assert "family_match" in reg._HANDLERS
    assert "family_match" not in reg.WRITE_TOOLS
    assert reg.required_capability("family_match") == reg.required_capability("program_fingerprint")


def test_rule_pack_free_module_has_confidences() -> None:
    """The confidence tiers are ordered structure(+import) > structure > import (documented)."""
    assert fm._CONF_BOTH > fm._CONF_STRUCTURE > fm._CONF_IMPORT
