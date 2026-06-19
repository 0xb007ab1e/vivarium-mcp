"""Naming-quality eval metrics (ADR-010, decision #3 — MEASURED, not guaranteed).

Scores a :class:`~vivarium.naming.loop.RenamedProgram` on quality signals:

- **name_coverage** — fraction of inferred (non-external) functions that got a *meaningful* name,
  i.e. renamed away from Ghidra's ``FUN_xxxxxxxx`` placeholder. Pure, no compiler needed.
- **compiles / compile_diagnostics** — does the assembled translation unit compile? Requires an
  injected :class:`CompileRunner`. The renamed C is **untrusted-derived** (it came, via the namer,
  from a hostile binary's decompilation), so a real runner MUST compile it **sandboxed** — that
  step is a separate gated increment (ADR-010 §Security); here it is a port with fakes in tests.
- **behavioral_equivalence** — does the rebuilt artifact behave like the original on test inputs?
  Realized by the ADR-016 differential harness: it compares two **builds** on shared **synthetic**
  inputs — (A) a build from the fixture's **trusted known source** (e.g. cJSON) and (B) the
  **recompiled renamed-decompiled-C** — and NEVER runs the hostile sample (ADR-001 / D1). The metric
  is the fraction of input vectors whose ``(exit_code, stdout)`` match **byte-exactly** (D2,
  measured-not-guaranteed). It is computable **only** for ground-truth fixtures carrying trusted
  source + inputs; otherwise it stays ``None`` (honest unavailability). This module's core only
  *compares* inert captured run-results (:class:`RunResult`) — it executes nothing; the sandboxed
  build+run+capture lives in the ``ExecRunner`` adapter (ADR-016 §Architecture / TB5). ADR-022
  refines this: ``behavioral_equivalence_normalized`` reports the **same** oracle but compares
  ``stdout`` after a conservative, pure ``normalize_output`` (masks volatile pointers/timestamps/
  PIDs, canonicalizes whitespace) so behaviorally-equivalent builds that differ only in volatile
  output aren't penalized — reported **alongside** (never instead of) the strict byte-exact number
  (strict stays the conservative truth; normalized only loosens, so ``normalized >= strict``). The
  same ADR adds ``generate_fuzz_vectors`` — pure, deterministic, bounded synthetic stdin vectors
  fed to both builds to broaden coverage.
- **naming_accuracy** — how close are the proposed names to a known *ground truth* (e.g. the DWARF
  symbol names from an unstripped build)? Pure, given an injected ``ground_truth`` address→name map.
  Reports a strict ``exact_match_rate`` (normalized identifier equality) and a fairer
  ``mean_token_f1`` (token-set F1 — credits ``get_array_size`` ≈ ``cJSON_GetArraySize``). Only the
  *client* namer (the LLM, decision #1) produces a meaningful number; the eval's stub namer scores
  ~0 by design. The fixtures already carry the truth (``*.groundtruth.json``), so the gated e2e can
  track it; this module just does the (hermetic, deterministic) comparison.

Compilability and behavioral equivalence are honest *metrics to track*, never guarantees: turning
decompiler pseudo-C into a recompilable, equivalent program is not solvable in general (decision 3).
This module is pure given its ports — the compiler/runner are injected, so scoring is hermetic.
The behavioral-equivalence *core* never executes anything; it only compares the inert
``(exit_code, stdout)`` run-results an injected (sandboxed) ``ExecRunner`` already captured.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from vivarium.naming.loop import RenamedProgram

#: Ghidra's default placeholder names for un-named functions/data. A function whose assigned name
#: still matches one of these was NOT meaningfully renamed (does not count toward coverage).
_PLACEHOLDER = re.compile(r"^(FUN|SUB|LAB|DAT|UNK)_[0-9a-fA-F]+$")


@dataclass(frozen=True, slots=True)
class CompileResult:
    """Outcome of compiling a translation unit.

    Attributes:
        ok: Whether compilation succeeded.
        diagnostics: Compiler stderr/notes, truncated + safe (no host paths/secrets) — for triage.
    """

    ok: bool
    diagnostics: str = ""


#: A compile runner takes C source and returns a :class:`CompileResult`. THE INPUT IS UNTRUSTED
#: (binary-derived); a real implementation MUST sandbox the compiler (no network, read-only, dropped
#: caps — worker-style isolation, ADR-004/ADR-010 §Security). Tests inject a deterministic fake.
CompileRunner = Callable[[str], CompileResult]


@dataclass(frozen=True, slots=True)
class RunResult:
    """One captured outcome of building + running a translation unit on a single input vector.

    The (bounded) observable behavior the differential oracle compares (ADR-016 D2): the process
    **exit code** and its **captured stdout bytes** (size-capped at the sandbox edge — anti
    output-flood DoS). ``stdout`` is **inert, untrusted-derived data** (it came, via the candidate
    build, from a hostile binary's decompilation, ADR-005) — it is **compared, never executed or
    rendered**. ``ok=False`` means the build itself failed to produce a runnable artifact (a stub
    or a non-recompiling TU) — an honest non-match, never a guess.

    Attributes:
        ok: Whether the TU built AND ran (vs. a build/spawn failure). A failed build scores as a
            non-match for every input vector (keeps low/zero scores honest).
        exit_code: The process exit status for this input vector (``None`` if it never ran).
        stdout: The captured, size-capped stdout bytes for this input vector (``b""`` if none).
    """

    ok: bool
    exit_code: int | None = None
    stdout: bytes = b""


#: An exec runner builds a translation unit and runs it on each synthetic input vector under
#: worker-style isolation, returning one :class:`RunResult` per vector. THE TU IS UNTRUSTED
#: (binary-derived); the real adapter MUST sandbox build+run+capture (no network, read-only, dropped
#: caps, resource caps, kill-on-timeout, output-size cap — ADR-004/ADR-016 TB5). Tests inject a
#: deterministic fake. ``inputs`` are author-controlled synthetic vectors (stdin bytes), not
#: attacker-controlled (ADR-016 D3).
ExecRunner = Callable[[str, "list[bytes]"], "list[RunResult]"]


def behavioral_equivalence(
    runs_a: list[RunResult] | None, runs_b: list[RunResult] | None
) -> float | None:
    """Fraction of input vectors whose ``(exit_code, stdout)`` match byte-exactly across two builds.

    The pure differential oracle (ADR-016 D2). ``runs_a`` is the **trusted reference** build's
    captured run-results (build A — from the fixture's known source), ``runs_b`` the **candidate**
    build's (build B — the recompiled renamed-decompiled-C), one :class:`RunResult` per shared
    synthetic input vector, in the same order. This function **executes nothing** — it compares the
    already-captured, inert results (ADR-005); the sandboxed build+run lives in the
    :data:`ExecRunner` adapter.

    A vector matches iff **both** sides ran (``ok`` true), exited with the same ``exit_code``, AND
    produced byte-identical ``stdout`` (no normalization — D2). A failed/stub build therefore
    matches nothing, so a low/zero score is honest signal (D2), never a crash.

    Args:
        runs_a: The reference build's per-vector run-results, or ``None`` when no trusted reference
            is available (e.g. an arbitrary hostile binary with no known source — D1).
        runs_b: The candidate build's per-vector run-results, or ``None``.

    Returns:
        The matching fraction in ``[0, 1]``, or ``None`` (honest *unavailable*) when either side is
        absent/empty or the two run-lists differ in length (no shared vector set to compare over).
    """
    if not runs_a or not runs_b or len(runs_a) != len(runs_b):
        # No trusted reference, no inputs, or a misaligned vector set → unavailable, not fabricated.
        return None
    matches = sum(1 for a, b in zip(runs_a, runs_b, strict=True) if _runs_match(a, b))
    return matches / len(runs_a)


def _runs_match(a: RunResult, b: RunResult) -> bool:
    """Whether two run-results agree on the byte-exact (exit_code, stdout) oracle (D2).

    Both must have actually run; a build/spawn failure on either side is a non-match (honest).
    """
    return a.ok and b.ok and a.exit_code == b.exit_code and a.stdout == b.stdout


#: Pointer-like / hex tokens, e.g. ``0x401286`` — a build's printed addresses vary run-to-run and
#: build-to-build without any behavioral difference. Masked to a constant so two behaviorally
#: equivalent builds aren't penalized for a volatile address. Anchored on ``0x`` so it does NOT
#: touch ordinary decimal numbers (conservative — only the obviously-volatile form is masked).
_PTR = re.compile(rb"0x[0-9a-fA-F]+")
#: Clock-style timestamps, e.g. ``12:34:56`` (HH:MM:SS, with an optional ``.fff`` fraction). Masked
#: because wall-clock output is volatile yet behaviorally irrelevant. Conservative: requires the
#: full colon-delimited HH:MM:SS shape, so it won't strike arbitrary colon-separated text.
_TIME = re.compile(rb"\d{2}:\d{2}:\d{2}(?:\.\d+)?")
#: ISO-8601 date (optionally with a ``T``/space + the HH:MM:SS time above), e.g.
#: ``2026-06-15T12:34:56``. The date half is masked first so the residual time is then ``_TIME``-
#: masked uniformly. Conservative: requires the ``YYYY-MM-DD`` shape.
_ISO_DATE = re.compile(rb"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)?")
#: A clearly-delimited PID, e.g. ``pid=1234`` / ``pid: 1234`` / ``[pid 1234]`` — a label
#: ``pid`` (case-insensitive) followed by an ``=``/``:``/space separator then digits. Masked
#: because a process id is volatile yet behaviorally irrelevant. Conservative: only the labelled
#: form is masked (a bare number is NEVER treated as a PID — that would over-strip ordinary text).
_PID = re.compile(rb"(?i)\bpid\b\s*[=:]?\s*\d+")

#: The placeholder a masked volatile token is replaced with (a fixed, inert marker).
_MASK = b"<X>"


def normalize_output(stdout: bytes) -> bytes:
    r"""Conservatively canonicalize inert captured stdout for the *looser* equivalence compare (D1).

    A **pure** transform over already-captured, inert bytes (ADR-005) — it **executes nothing**,
    only rewrites the byte string. It is deliberately **conservative**: it masks only obviously
    *volatile* output (which varies run-to-run / build-to-build without any behavioral meaning) and
    canonicalizes whitespace, so it can only ever *loosen* the match (``normalized >= strict``).
    Over-normalizing risks false positives, so the masks target narrow, well-delimited shapes and
    leave ordinary text untouched.

    Rules applied (in order):

    1. **Line endings** — CRLF / lone CR → LF (``\\r\\n``/``\\r`` → ``\\n``).
    2. **Volatile token masks** → :data:`_MASK` (``b"<X>"``):

       - ISO-8601 dates/datetimes (``2026-06-15`` / ``2026-06-15T12:34:56``) — masked first so the
         residual clock time is then handled uniformly by the time rule;
       - clock timestamps ``HH:MM:SS`` (optionally ``.fff``);
       - clearly-labelled PIDs (``pid=1234`` / ``pid: 1234`` — the ``pid`` label is required);
       - pointer-like hex tokens (``0x[0-9a-fA-F]+``).
    3. **Trailing whitespace** — stripped from the end of every line (spaces/tabs before each
       ``\\n`` and at end of output).

    A bare decimal number, an ordinary colon (``key:value``), and arbitrary words are **not**
    masked — only the specific volatile shapes above. Masking is idempotent and order-stable.

    Args:
        stdout: The captured, size-capped stdout bytes for one input vector (inert, untrusted —
            ADR-005). Never executed or rendered.

    Returns:
        The normalized bytes, suitable for the *normalized* (looser) equivalence compare. The
        strict oracle (:func:`behavioral_equivalence`) compares the raw bytes and is unaffected.
    """
    # 1. Canonicalize line endings (CRLF and lone CR → LF) before any other rule.
    out = stdout.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    # 2. Mask volatile tokens. ISO dates first (so a trailing HH:MM:SS in a datetime is absorbed by
    #    the date rule), then bare clock times, labelled PIDs, then pointer-like hex.
    out = _ISO_DATE.sub(_MASK, out)
    out = _TIME.sub(_MASK, out)
    out = _PID.sub(_MASK, out)
    out = _PTR.sub(_MASK, out)
    # 3. Strip trailing whitespace from each line (and end-of-output).
    out = re.sub(rb"[ \t]+(?=\n)", b"", out)
    out = re.sub(rb"[ \t]+$", b"", out)
    return out


def behavioral_equivalence_normalized(
    runs_a: list[RunResult] | None, runs_b: list[RunResult] | None
) -> float | None:
    """Match-rate over ``(exit_code, normalize_output(stdout))`` — the *looser* signal (D1).

    The **same** differential oracle as :func:`behavioral_equivalence` — both sides must have run
    (``ok`` true), ``exit_code`` is compared **exactly** (never normalized), the same ``None`` /
    empty / mismatched-length unavailability rules hold — **except** ``stdout`` is compared
    **after** :func:`normalize_output`. Because normalization only ever loosens the compare, this
    score is ``>=`` the strict :func:`behavioral_equivalence` over the same runs (the *equivalent
    modulo volatile output* signal). Strict stays the conservative truth; this is reported beside
    it, never *instead* of it. Pure — it **executes nothing**, only compares inert bytes (ADR-005).

    Args:
        runs_a: The reference build's per-vector run-results, or ``None`` when unavailable (D1).
        runs_b: The candidate build's per-vector run-results, or ``None``.

    Returns:
        The matching fraction in ``[0, 1]``, or ``None`` (honest *unavailable*) under the same rules
        as :func:`behavioral_equivalence` (either side absent/empty, or lengths differ).
    """
    if not runs_a or not runs_b or len(runs_a) != len(runs_b):
        # Same unavailability rule as the strict oracle — no shared vector set → not fabricated.
        return None
    matches = sum(1 for a, b in zip(runs_a, runs_b, strict=True) if _runs_match_normalized(a, b))
    return matches / len(runs_a)


def _runs_match_normalized(a: RunResult, b: RunResult) -> bool:
    """Like :func:`_runs_match` but compares ``stdout`` after :func:`normalize_output` (D1).

    ``ok`` and ``exit_code`` must still match exactly; only the stdout compare is loosened.
    """
    return (
        a.ok
        and b.ok
        and a.exit_code == b.exit_code
        and normalize_output(a.stdout) == normalize_output(b.stdout)
    )


def generate_fuzz_vectors(seed: int, count: int, max_len: int) -> list[bytes]:
    """Generate ``count`` deterministic, bounded synthetic stdin vectors from ``seed`` (D2).

    **Pure + deterministic + hermetic** (``topic-testing``): a fixed ``seed`` always yields the
    identical list of vectors, using a *local* :class:`random.Random` instance — **no module-level
    random and no wall-clock**. Broadens behavioral coverage beyond the few committed fixed vectors;
    the same generated vectors are fed to **both** builds A and B through the sandboxed
    :data:`ExecRunner` (TB5, unchanged exec model). The vectors are **author-generated synthetic
    bytes** (not attacker-controlled) and are **bounded** in count and per-vector length (CWE-400):
    each vector is ``0..max_len`` bytes drawn from the full byte range, so they exercise binary,
    empty, and printable inputs without driving the host.

    This function only *produces* inert byte strings — it **executes nothing** (ADR-005). Bounds are
    validated up front and the function fails closed on a non-positive ``count``/``max_len`` or a
    negative ``count``.

    Args:
        seed: The PRNG seed. A fixed seed → fixed vectors (reproducible). Different seeds → (with
            overwhelming probability) different vectors.
        count: How many vectors to generate (must be ``>= 0``; ``0`` yields an empty list).
        max_len: The inclusive upper bound on each vector's length in bytes (must be ``>= 0``;
            ``0`` yields all-empty vectors).

    Returns:
        A list of exactly ``count`` byte strings, each ``0..max_len`` bytes long, fully determined
        by ``seed``.

    Raises:
        ValueError: If ``count`` or ``max_len`` is negative (fail closed — defensive bound).
    """
    if count < 0:
        raise ValueError("count must be >= 0")
    if max_len < 0:
        raise ValueError("max_len must be >= 0")
    rng = random.Random(seed)  # noqa: S311  # nosec B311 - synthetic fuzz inputs, not security RNG
    vectors: list[bytes] = []
    for _ in range(count):
        length = rng.randint(0, max_len)
        vectors.append(bytes(rng.randrange(256) for _ in range(length)))
    return vectors


@dataclass(frozen=True, slots=True)
class NamingMetrics:
    """Measured quality of a naming pass (best-effort signals; see module docstring).

    Attributes:
        total_functions: All functions in the pass (inferred + external + skipped externals).
        inferred_functions: Functions a namer actually named (the coverage denominator).
        external_functions: Imported/external functions (kept their known name, not inferred).
        named_functions: Inferred functions whose assigned name is meaningful (not a placeholder).
        name_coverage: ``named_functions / inferred_functions`` (``0.0`` when none inferred).
        compiles: Whether the translation unit compiled, or ``None`` if no compiler was run.
        compile_diagnostics: Compiler diagnostics when a runner ran, else ``None``.
        behavioral_equivalence: Measured byte-exact (exit_code, stdout) match-rate between the
            trusted reference build (A) and the candidate build (B) over shared synthetic inputs
            (ADR-016 — the conservative, primary signal), or ``None`` when no trusted reference +
            inputs were supplied (honest unavailability).
        behavioral_equivalence_normalized: The same match-rate but with ``stdout`` compared after
            :func:`normalize_output` (ADR-022 D1 — *equivalent modulo volatile output*; looser, so
            always ``>=`` ``behavioral_equivalence`` over the same runs). Reported **alongside**
            (never instead of) the strict number; ``None`` under the same unavailability rules.
        naming_accuracy: Proposed-vs-ground-truth name accuracy, or ``None`` if no ground truth
            was supplied.
    """

    total_functions: int
    inferred_functions: int
    external_functions: int
    named_functions: int
    name_coverage: float
    compiles: bool | None = None
    compile_diagnostics: str | None = None
    behavioral_equivalence: float | None = None
    behavioral_equivalence_normalized: float | None = None
    naming_accuracy: NamingAccuracy | None = None


def _is_meaningful(name: str) -> bool:
    """Whether ``name`` is a real semantic identifier (not a Ghidra ``FUN_``-style placeholder)."""
    return bool(name) and _PLACEHOLDER.match(name) is None


def name_coverage(program: RenamedProgram) -> float:
    """Fraction of inferred functions renamed to a meaningful (non-placeholder) identifier.

    Args:
        program: The naming pass result.

    Returns:
        ``named / inferred`` in ``[0, 1]``; ``0.0`` when no functions were inferred.
    """
    inferred = [f for f in program.functions if f.inferred]
    if not inferred:
        return 0.0
    named = sum(1 for f in inferred if _is_meaningful(f.assigned_name))
    return named / len(inferred)


@dataclass(frozen=True, slots=True)
class NamingAccuracy:
    """Proposed names scored against a known ground truth (e.g. DWARF symbols).

    Attributes:
        scored: Inferred functions that HAD a ground-truth name to compare against (denominator).
        unscored: Inferred functions with no ground-truth entry (e.g. compiler-synthesized helpers
            absent from the truth) — reported, not counted against accuracy.
        exact_matches: Functions whose normalized identifier equals the truth's (strict).
        exact_match_rate: ``exact_matches / scored`` in ``[0, 1]`` (``0.0`` when none scored).
        mean_token_f1: Mean token-set F1 over scored functions — the fair *semantic* measure, giving
            partial credit (``get_array_size`` vs ``cJSON_GetArraySize`` ≈ 0.75) where the strict
            exact rate gives none. ``0.0`` when none scored.
    """

    scored: int
    unscored: int
    exact_matches: int
    exact_match_rate: float
    mean_token_f1: float


#: Identifier token boundaries: lower/digit→Upper (camelCase) and letter→digit.
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Za-z])(?=[0-9])")


def _tokens(identifier: str) -> frozenset[str]:
    """Split an identifier into a lowercase token set (camelCase + ``_``/non-alnum + digit splits).

    ``cJSON_GetArraySize`` → ``{c, json, get, array, size}``; ``parse_hex4`` → ``{parse, hex, 4}``.
    """
    spaced = _CAMEL.sub("_", identifier)
    return frozenset(t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t)


def _normalized(identifier: str) -> str:
    """Lowercased, alphanumeric-only form for strict exact comparison.

    ``cJSON_Parse`` → ``cjsonparse`` — so case/underscore differences don't count as a mismatch.
    """
    return re.sub(r"[^a-z0-9]", "", identifier.lower())


def _token_f1(proposed: str, truth: str) -> float:
    """Token-set F1 between two identifiers in ``[0, 1]`` (1.0 = same token set, 0.0 = disjoint)."""
    pt, tt = _tokens(proposed), _tokens(truth)
    if not pt or not tt:
        return 1.0 if pt == tt else 0.0
    overlap = len(pt & tt)
    if overlap == 0:
        return 0.0
    precision = overlap / len(pt)
    recall = overlap / len(tt)
    return 2 * precision * recall / (precision + recall)


def _addr_key(address: str) -> int | None:
    """Canonicalize a hex entry address to an int for joining (``0x401286``/``00401286`` → same).

    Returns ``None`` for an unparseable address (defensive — a bad address simply doesn't join).
    """
    try:
        return int(address, 16)
    except ValueError:
        return None


def score_name_map(proposed: Mapping[str, str], ground_truth: Mapping[str, str]) -> NamingAccuracy:
    """Score a proposed address→name map against a ground-truth address→name map (PURE).

    The reusable core of :func:`naming_accuracy`, decoupled from the naming-loop's program model so
    an out-of-band scorer (``scripts/naming_eval.py``, ADR-010 / v1.5) can score names from any
    source — e.g. a client LLM's proposals vs. **debuginfod** ground truth — without constructing a
    :class:`RenamedProgram`. Addresses join by integer value (``0x401286``/``00401286``/``401286``
    are the same key). A proposed entry whose address is absent from ``ground_truth`` is
    ``unscored`` (honest denominator — we neither credit nor penalize names we can't check).

    Args:
        proposed: Map of function entry address (hex) → the proposed/inferred name.
        ground_truth: Map of function entry address (hex) → the true name.

    Returns:
        A :class:`NamingAccuracy` over the proposed names that join the ground truth.
    """
    truth_by_int: dict[int, str] = {}
    for addr, name in ground_truth.items():
        key = _addr_key(addr)
        if key is not None:
            truth_by_int[key] = name

    scored = 0
    exact = 0
    f1_total = 0.0
    unscored = 0
    for addr, proposed_name in proposed.items():
        key = _addr_key(addr)
        truth = truth_by_int.get(key) if key is not None else None
        if truth is None:
            unscored += 1
            continue
        scored += 1
        if _normalized(proposed_name) == _normalized(truth):
            exact += 1
        f1_total += _token_f1(proposed_name, truth)

    return NamingAccuracy(
        scored=scored,
        unscored=unscored,
        exact_matches=exact,
        exact_match_rate=(exact / scored) if scored else 0.0,
        mean_token_f1=(f1_total / scored) if scored else 0.0,
    )


def naming_accuracy(program: RenamedProgram, ground_truth: Mapping[str, str]) -> NamingAccuracy:
    """Score the pass's inferred names against a ground-truth address→name map.

    Projects the program's **inferred** functions to a proposed address→name map and delegates to
    the pure :func:`score_name_map` (externals are not scored — their names are known, not
    inferred).

    Args:
        program: The naming pass result.
        ground_truth: Map of function entry address (hex; any of ``0x401286``/``00401286``/
            ``401286`` — normalized by value, not string form) to the true name.

    Returns:
        A :class:`NamingAccuracy`. Only inferred functions present in ``ground_truth`` are scored;
        the rest are counted as ``unscored`` (honest denominator — we don't credit or penalize names
        we can't check).
    """
    proposed = {fn.address: fn.assigned_name for fn in program.functions if fn.inferred}
    return score_name_map(proposed, ground_truth)


def score(
    program: RenamedProgram,
    *,
    compile_runner: CompileRunner | None = None,
    ground_truth: Mapping[str, str] | None = None,
    behavioral_runs: tuple[list[RunResult], list[RunResult]] | None = None,
) -> NamingMetrics:
    """Compute :class:`NamingMetrics` for a naming pass.

    Args:
        program: The naming pass result to score.
        compile_runner: Optional SANDBOXED compiler (ADR-010 §Security). When ``None`` (default,
            hermetic), compilability is not measured (``compiles=None``) — name coverage still is.
        ground_truth: Optional address→name map (e.g. DWARF symbols). When supplied, naming accuracy
            is measured; when ``None`` (default), ``naming_accuracy`` is ``None``.
        behavioral_runs: Optional ``(reference_runs, candidate_runs)`` — the per-input-vector
            :class:`RunResult` lists for build A (trusted reference source) and build B (the
            candidate recompiled C), already captured by a SANDBOXED :data:`ExecRunner` (ADR-016).
            When supplied, ``behavioral_equivalence`` is the byte-exact match-rate **and**
            ``behavioral_equivalence_normalized`` the looser *modulo volatile output* match-rate
            (ADR-022 D1 — both reported, strict primary); when ``None`` (default — no trusted
            reference + inputs), both stay ``None`` (honest unavailability, D1). This core
            *compares* inert results only — it never executes anything.

    Returns:
        The measured (best-effort) metrics.
    """
    inferred = [f for f in program.functions if f.inferred]
    externals = [f for f in program.functions if f.is_external]
    named = sum(1 for f in inferred if _is_meaningful(f.assigned_name))

    compiles: bool | None = None
    diagnostics: str | None = None
    if compile_runner is not None:
        result = compile_runner(program.translation_unit)
        compiles, diagnostics = result.ok, result.diagnostics

    accuracy = naming_accuracy(program, ground_truth) if ground_truth is not None else None

    behavioral: float | None = None
    behavioral_normalized: float | None = None
    if behavioral_runs is not None:
        runs_a, runs_b = behavioral_runs
        behavioral = behavioral_equivalence(runs_a, runs_b)
        behavioral_normalized = behavioral_equivalence_normalized(runs_a, runs_b)

    return NamingMetrics(
        total_functions=len(program.functions),
        inferred_functions=len(inferred),
        external_functions=len(externals),
        named_functions=named,
        name_coverage=(named / len(inferred)) if inferred else 0.0,
        compiles=compiles,
        compile_diagnostics=diagnostics,
        behavioral_equivalence=behavioral,
        behavioral_equivalence_normalized=behavioral_normalized,
        naming_accuracy=accuracy,
    )
