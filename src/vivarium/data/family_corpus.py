"""The bundled, offline, versioned family-match corpus (ADR-073 D3).

A curated map from a program's ``program_fingerprint`` digests (ADR-073 D1) to a known malware
**family** label, used by the ``family_match`` tool (ADR-073 D2) to turn "obfuscated variant" into a
named family without any network lookup (containment intact — offline by construction).

Format (validated by :func:`vivarium.core.familymatch.parse_corpus`):

    FAMILY_CORPUS = {
        "version": "corpus-<n>",            # bumped whenever entries change (reproducibility)
        "entries": [
            {
                "family": "Win32.Example",  # required, non-empty
                # at least ONE of the two digests (both is strongest):
                "structure_digest": "<64-hex sha256>",   # program_fingerprint.structure_digest
                "import_digest": "<64-hex sha256>",       # program_fingerprint.import_digest
                "note": "optional provenance",            # ignored by the matcher
            },
            ...
        ],
    }

**Curation is human-gated build-time (ADR-073 D3), NEVER a runtime agent write** — the primary
defence against knowledge poisoning (`workflow-knowledge-base` gated promotion, `std-owasp-llm`
LLM03). To add an entry: analyze a *confirmed*-family sample, read its ``program_fingerprint``
digests, and append a row here in a reviewed PR (bump ``version``).

**Seed status:** intentionally EMPTY. Populating it requires running ``program_fingerprint`` on
confirmed-family samples — the digests are worker-computed (``ExactMnemonics`` hashes / import set),
so seeding needs the ADR-073-D1 worker image, a separate curation task (the 4 validation-benchmark
samples are the obvious first entries). The tool + matcher + format ship now; population is the
ongoing D3 curation loop. A future increment moves this to a signed, external JSON artifact.
"""

from __future__ import annotations

from typing import Any

#: The bundled corpus. Empty seed (see module docstring) — extended by reviewed, human-gated PRs.
FAMILY_CORPUS: dict[str, Any] = {
    "version": "corpus-1",
    "entries": [],
}
