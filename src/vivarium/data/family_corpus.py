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

**Seed status (corpus-2):** seeded with the four confirmed-family validation-benchmark samples
(Kelihos / Wirenet / LuckyCat / BumbleBee), fingerprinted with the pinned worker image (Ghidra
12.1.2, ADR-073 D1) under the DEFAULT analysis profile. The digests are worker-computed
(``ExactMnemonics`` structural hashes + normalized import set). Add further entries via the same
human-gated D3 curation loop (analyze a confirmed sample → read its ``program_fingerprint``
digests → append a row → bump ``version``). A future increment moves this to a signed JSON artifact.
"""

from __future__ import annotations

from typing import Any

#: The bundled corpus — extended by reviewed, human-gated PRs (see module docstring).
#:
#: Seed (corpus-2): the four confirmed-family samples from the blind-triage validation benchmark
#: (`validation/`), fingerprinted with the pinned worker image (Ghidra 12.1.2) under the DEFAULT
#: analysis profile. NOTE the profile caveat: ``structure_digest`` depends on which functions Ghidra
#: discovered, so it matches a ``family_match`` query only when that query's session analyzed with
#: the same (default) profile; ``import_digest`` is profile-stable and the more robust key. Both are
#: seeded so ``family_match`` reports whichever basis hits.
FAMILY_CORPUS: dict[str, Any] = {
    "version": "corpus-2",
    "entries": [
        {
            "family": "Win32.Kelihos",
            "structure_digest": "9e2154e7d40a3fa8ee3b7ee329a775b554eaba2faa9b8d23bc73cf748b5f79e5",
            "import_digest": "581ddc5cd4302f9e6acd557654af93723c54141c96233d0214bb6f79c7cd1f78",
            "note": "theZoo Win32/Kelihos (Hlux); validation case-01; sha256 89c2d370…896bc41",
        },
        {
            "family": "OSX.Wirenet",
            "structure_digest": "7c9d0b08afb30a71bc04c9bfd86b5a77fc8368346489e8370d2b69f7ccccfd42",
            "import_digest": "c8bcea8e0f2b5cc69da080c18fece225c8cee7967afbfcdf269c9b24dafd78a2",
            "note": "theZoo OSX/Wirenet (Mach-O); validation case-02; sha256 257da8c8…f50a1",
        },
        {
            "family": "Win32.LuckyCat",
            "structure_digest": "c211eff68001d3fb768e9e1e19d91f983a1bf6cbc742041a905432abd87333dc",
            "import_digest": "a7dee5761864539b2e52b2fefedf3ea42b89484694e4276bb3d12c6ed023405c",
            "note": "theZoo Win32.LuckyCat (Tibetan-APT DLL RAT); case-03; sha256 e89614e3…add4",
        },
        {
            "family": "Win32.BumbleBee",
            "structure_digest": "4d56ae8dede0f5fec07d47e94c2d4baa6982deeac2a8c2c22da13719c883107f",
            "import_digest": "ea793d71a33c8105e560958cb25257269d261045650bb1e8f56e4df3920e1991",
            "note": "theZoo Win32.BumbleBee (x64 regsvr32 loader); case-04; sha256 c34e5d36…689a",
        },
    ],
}
