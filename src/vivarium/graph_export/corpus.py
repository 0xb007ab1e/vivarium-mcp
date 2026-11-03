"""Pure cross-binary corpus projection (ADR-080 Part A).

Functional core — no I/O, no SDK, no server. Projects one Vivarium session's content-hashed
functions + family-match leads onto a **shared** ``vivarium-corpus`` memory-graph project so clones
across binaries cluster *by construction*: every binary upserts its per-function **occurrence**
nodes plus the **shared hash-class** nodes (named by the operand-masked ``function_hash`` and, for
byte-identical clones, the exact-bytes hash). Because a hash-class node's name is the hash and the
corpus is one project, two binaries' occurrences of the same hash ``SAME_AS``/``EQUIV`` the *same*
class node — the clone cluster forms via upsert idempotency with no cross-binary query and no
pairwise fan-out (ADR-080 §4: bounded by construction).

Clone links are **INFERRED leads, not proof** (ADR-073): an operand-masked hash collision strongly
suggests the same code, byte-equality more so, but neither is certified identity. Family leads are
likewise ``inferred``. The hash names are server-computed digests (safe, not hostile content);
function/family names are binary-derived and stored as inert ``attrs`` tagged by provenance
(ADR-005). No ``SECRET`` ever enters the corpus — functions + families only (ADR-072 preserved).
"""

from __future__ import annotations

from collections.abc import Iterable

from vivarium.graph_export.ports import EdgeSpec, GraphBatch, NodeSpec

#: The one standing cross-binary index project (ADR-080 §Part A).
CORPUS_PROJECT: str = "vivarium-corpus"

#: Max per-binary occurrences projected into the corpus (CWE-400; the driver also caps enrichment,
#: which is where the hashes come from — this is a defence-in-depth second bound).
MAX_CORPUS_OCCURRENCES: int = 50_000


def _occurrence_name(sha256: str, address_hex: str) -> str:
    """A per-(binary, function) occurrence node name — unique so two binaries never collapse."""
    return f"{sha256[:12]}:{address_hex}"


def _norm_addr(value: str) -> str:
    """Normalise a Vivarium hex address to a bare lowercase hex offset (drops a ``0x`` prefix)."""
    text = value.strip()
    return text[2:].lower() if text[:2].lower() == "0x" else text.lower()


def build_corpus_specs(
    *,
    sha256: str,
    fmt: str,
    masked_hashes: dict[str, str],
    byte_hashes: dict[str, str] | None = None,
    function_names: dict[str, str] | None = None,
    families: Iterable[tuple[str, float, list[str], str]] = (),
    max_occurrences: int = MAX_CORPUS_OCCURRENCES,
) -> GraphBatch:
    """Project one session onto the shared corpus project as a pure :class:`GraphBatch`.

    All node local-ids resolve **within this batch** (anchor, occurrences, hash-class, bytes-class,
    family), so the existing ``push_batch`` machinery upserts it with no new sink capability; the
    cross-binary clustering happens in the store because the shared hash-class / family node names
    collide (idempotent) across binaries in the one corpus project.

    Args:
        sha256: The binary's content hash (the corpus anchor name — safe digest).
        fmt: The binary format label (e.g. ``"ELF"``) — safe metadata.
        masked_hashes: ``address_hex -> operand-masked function hash`` (``exact_instructions``,
            ADR-057) — the clone key.
        byte_hashes: ``address_hex -> exact-bytes hash`` (``exact_bytes``) for byte-identical
            ``EQUIV`` links; omitted entries get only the masked ``SAME_AS`` link.
        function_names: ``address_hex -> name`` (hostile; stored as an inert occurrence attr).
        families: ``(label, confidence, basis, corpus_version)`` family-match leads (INFERRED).
        max_occurrences: Hard cap on occurrences projected (CWE-400); extras are dropped.

    Returns:
        A :class:`GraphBatch` of corpus nodes + edges (empty of occurrences when no hashes).
    """
    byte_hashes = byte_hashes or {}
    function_names = function_names or {}
    nodes: list[NodeSpec] = []
    edges: list[EdgeSpec] = []

    anchor = NodeSpec("PROGRAM", sha256, "BINARY", "raw", attrs={"format": fmt})
    nodes.append(anchor)

    for index, (address, masked) in enumerate(sorted(masked_hashes.items())):
        if index >= max_occurrences:
            break
        addr_hex = _norm_addr(address)
        occ_attrs: dict[str, object] = {
            "sha256": sha256,
            "address": addr_hex,
            "masked_hash": masked,
        }
        exact_bytes = byte_hashes.get(address)
        if exact_bytes is not None:
            occ_attrs["exact_bytes"] = exact_bytes
        name = function_names.get(address)
        if name is not None:
            occ_attrs["ghidra_name"] = name  # hostile content — inert attr (ADR-005)
        occ = NodeSpec(
            "FUNCTION", _occurrence_name(sha256, addr_hex), "GHIDRA", "raw", attrs=occ_attrs
        )
        nodes.append(occ)
        # Anchor contains each of its occurrences (navigability back to the per-binary project).
        edges.append(EdgeSpec("CONTAINS", anchor.local_id, occ.local_id, "BINARY"))
        # Shared operand-masked clone-class node (name = hash) → SAME_AS (clone lead, INFERRED).
        klass = NodeSpec("CONSTANT", masked, "INFERRED", "inferred")
        nodes.append(klass)
        edges.append(EdgeSpec("SAME_AS", occ.local_id, klass.local_id, "INFERRED"))
        # Byte-identical clone-class node → EQUIV (stronger lead) when exact bytes are known.
        if exact_bytes is not None:
            bklass = NodeSpec("CONSTANT", f"bytes:{exact_bytes}", "INFERRED", "inferred")
            nodes.append(bklass)
            edges.append(EdgeSpec("EQUIV", occ.local_id, bklass.local_id, "INFERRED"))

    for label, confidence, basis, corpus_version in families:
        fam = NodeSpec(
            "OTHER",
            f"family:{label}",  # label is a curated-corpus string; still tagged INFERRED (ADR-073)
            "INFERRED",
            "inferred",
            attrs={
                "confidence": confidence,
                "basis": list(basis),
                "corpus_version": corpus_version,
            },
        )
        nodes.append(fam)
        edges.append(EdgeSpec("REFERENCES", anchor.local_id, fam.local_id, "INFERRED"))

    return GraphBatch(nodes=nodes, edges=edges)
