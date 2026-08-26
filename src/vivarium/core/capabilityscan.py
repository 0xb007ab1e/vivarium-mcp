"""Pure (JVM-free) capability detection mapped to MITRE ATT&CK for Tier-2 (ADR-074).

Part of the functional core (ADR-001): operates on already-extracted facts (the existing
``list_imports`` / ``list_strings`` / ``list_exports`` RPCs). No I/O, no JVM — deterministic and
100%-unit-testable. Mirrors ``core.iocscan`` / ``core.secretscan`` / ``core.cryptodetect`` in shape.

**Why this exists (ADR-074 / validation benchmark).** On the benchmark the analyst reached the
highest-value triage call — "obfuscated modular **loader**, regsvr32-run, reflective-load,
named-pipe C2, anti-debug" (BumbleBee) — BY HAND from imports + one decompile. A rule-based detector
emits exactly that, mechanically, as named capabilities each mapped to a MITRE ATT&CK technique.

**MVP scope (ADR-074, ratified 2026-08-25).** A **curated, built-in** rule pack matched over the
imports/exports/strings the worker already provides — enough to auto-tag the benchmark's samples.
The ADR's full **capa-rules ecosystem** (a bundled, signed, versioned external rule pack — D2) and
disassembly/const-based rules are a tracked fast-follow; this module's ``RULE_PACK_VERSION`` +
``rule_id`` per match make that migration additive.

**Heuristic, not authoritative (ADR-074 D5 / ADR-008).** A rule fires on *observed* imports/strings;
packing/obfuscation hides behaviour (a packed sample's real capabilities live in its encoded stage),
so a thin/empty result on a packed input is expected — combine with ``program_fingerprint`` /
``crypto_detect``. Evidence ``detail`` is binary-derived (attacker-controlled) and MUST be wrapped
in the untrusted envelope by the adapter (ADR-005).

All matching is plain lowercase substring (no regex / no backtracking — ReDoS-safe); inputs are
length-capped by the caller before matching.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

#: Version of the built-in rule pack — bumped when rules change; surfaced per response for
#: reproducibility and to make the future external-rule-pack migration (ADR-074 D2) legible.
RULE_PACK_VERSION = "builtin-1"

#: Hard cap on the characters of any single fact scanned (pathological-input defense; the caller
#: also paginates the fact sets).
MAX_SCAN_LEN = 8192


@dataclass(frozen=True, slots=True)
class _Signal:
    """One matcher: a lowercased ``needle`` looked for in facts of kind ``where`` (substring)."""

    where: str
    needle: str


@dataclass(frozen=True, slots=True)
class _Rule:
    """A capability rule (capa-style, built-in).

    Attributes:
        rule_id: Stable id (namespace-scoped) — safe.
        name: Human-readable capability — safe.
        namespace: Coarse grouping (roughly an ATT&CK tactic) — safe.
        attack: ``(tactic, technique_id)`` pairs this capability maps to — safe.
        mode: ``"all"`` (every signal), ``"any"`` (≥1), or ``"n_of"`` (≥ ``n``).
        n: Threshold for ``"n_of"``.
        signals: The matchers.
        confidence: ``[0, 1]`` — multi-signal rules are higher-confidence than single ``any`` ones.
    """

    rule_id: str
    name: str
    namespace: str
    attack: tuple[tuple[str, str], ...]
    mode: str
    signals: tuple[_Signal, ...]
    confidence: float
    n: int = 1


def _s(where: str, needle: str) -> _Signal:
    return _Signal(where=where, needle=needle.lower())


#: The built-in rule pack. Curated + high-signal, grounded in the validation benchmark. Extensible —
#: add a rule; the future signed external pack (ADR-074 D2) supersedes this additively.
RULES: tuple[_Rule, ...] = (
    _Rule(
        "execution/regsvr32",
        "executed via regsvr32 (DllRegisterServer)",
        "execution",
        (("defense-evasion", "T1218.010"),),
        "any",
        (_s("export", "dllregisterserver"),),
        0.8,
    ),
    _Rule(
        "defense-evasion/reflective-load",
        "reflectively / dynamically load code",
        "defense-evasion",
        (("defense-evasion", "T1620"),),
        "all",
        (_s("import", "loadlibrary"), _s("import", "getprocaddress"), _s("import", "virtualalloc")),
        0.8,
    ),
    _Rule(
        "defense-evasion/process-injection",
        "inject into another process",
        "defense-evasion",
        (("defense-evasion", "T1055"),),
        "n_of",
        (
            _s("import", "virtualallocex"),
            _s("import", "writeprocessmemory"),
            _s("import", "createremotethread"),
            _s("import", "ntcreatethreadex"),
            _s("import", "queueuserapc"),
        ),
        0.85,
        n=2,
    ),
    _Rule(
        "c2/named-pipe",
        "communicate over a named pipe",
        "command-and-control",
        (("command-and-control", "T1559.001"),),
        "n_of",
        (
            _s("import", "createnamedpipe"),
            _s("import", "transactnamedpipe"),
            _s("import", "connectnamedpipe"),
            _s("import", "waitnamedpipe"),
        ),
        0.8,
        n=2,
    ),
    _Rule(
        "defense-evasion/anti-debug",
        "check for a debugger (anti-analysis)",
        "defense-evasion",
        (("defense-evasion", "T1622"),),
        "any",
        (
            _s("import", "isdebuggerpresent"),
            _s("import", "checkremotedebuggerpresent"),
            _s("import", "ntqueryinformationprocess"),
        ),
        0.7,
    ),
    _Rule(
        "persistence/run-key",
        "persist via a registry Run key",
        "persistence",
        (("persistence", "T1547.001"),),
        "all",
        (_s("import", "regsetvalue"), _s("string", "currentversion\\run")),
        0.85,
    ),
    _Rule(
        "collection/keylog",
        "log keystrokes",
        "collection",
        (("collection", "T1056.001"),),
        "any",
        (
            _s("import", "setwindowshookex"),
            _s("import", "getasynckeystate"),
            _s("import", "registerrawinputdevices"),
        ),
        0.75,
    ),
    _Rule(
        "collection/screen-capture",
        "capture the screen",
        "collection",
        (("collection", "T1113"),),
        "any",
        (
            _s("import", "bitblt"),
            _s("import", "cgwindowlistcreateimage"),
            _s("import", "cgdisplaycreateimage"),
        ),
        0.75,
    ),
    _Rule(
        "credential-access/browser",
        "steal browser / mail credentials",
        "credential-access",
        (("credential-access", "T1555.003"),),
        "any",
        (
            _s("string", "signons.sqlite"),
            _s("string", "moz_logins"),
            _s("string", "login data"),
            _s("string", "wand.dat"),
            _s("import", "pk11sdr_decrypt"),
        ),
        0.85,
    ),
    _Rule(
        "credential-access/sniff",
        "sniff network traffic",
        "credential-access",
        (("credential-access", "T1040"),),
        "any",
        (
            _s("import", "pcap_open"),
            _s("import", "packetopenadapter"),
            _s("string", "wpcap.dll"),
        ),
        0.8,
    ),
    _Rule(
        "c2/network",
        "communicate over the network (C2)",
        "command-and-control",
        (("command-and-control", "T1071"),),
        "any",
        (
            _s("import", "wsasocket"),
            _s("import", "internetopen"),
            _s("import", "winhttpconnect"),
            _s("import", "getaddrinfo"),
        ),
        0.6,
    ),
    _Rule(
        "execution/shell",
        "execute a command shell with redirected I/O",
        "execution",
        (("execution", "T1059"),),
        "all",
        (_s("import", "createprocess"), _s("import", "createpipe")),
        0.7,
    ),
    _Rule(
        "discovery/system-info",
        "fingerprint the host",
        "discovery",
        (("discovery", "T1082"),),
        "n_of",
        (
            _s("import", "getcomputername"),
            _s("import", "getvolumeinformation"),
            _s("import", "getnativesysteminfo"),
            _s("import", "globalmemorystatus"),
        ),
        0.6,
        n=2,
    ),
)


@dataclass(frozen=True, slots=True)
class Evidence:
    """One matched signal backing a capability — ``detail`` is binary-derived (adapter wraps it)."""

    address: str | None
    where: str
    detail: str


@dataclass(frozen=True, slots=True)
class CapabilityMatch:
    """One detected capability — HEURISTIC (a lead, not proof; ADR-074 D5).

    Attributes:
        rule_id: Which built-in rule fired — safe.
        name: The capability — safe.
        namespace: Coarse grouping — safe.
        attack: ``(tactic, technique_id)`` pairs — safe.
        evidence: The matched signals (each ``detail`` binary-derived → wrapped by the adapter).
        confidence: ``[0, 1]`` — safe scalar.
    """

    rule_id: str
    name: str
    namespace: str
    attack: tuple[tuple[str, str], ...]
    evidence: tuple[Evidence, ...]
    confidence: float


def _fact_hits(signal: _Signal, facts: list[tuple[str | None, str]]) -> list[Evidence]:
    """Return one :class:`Evidence` per fact whose (lowercased) value contains ``signal.needle``."""
    hits: list[Evidence] = []
    for address, value in facts:
        if signal.needle in value.lower():
            hits.append(Evidence(address=address, where=signal.where, detail=value[:MAX_SCAN_LEN]))
    return hits


def detect_capabilities(
    imports: Iterable[tuple[str | None, str]],
    exports: Iterable[tuple[str | None, str]],
    strings: Iterable[tuple[str | None, str]],
) -> list[CapabilityMatch]:
    """Detect capabilities by matching the built-in rule pack over facts (pure; ADR-074 D1).

    Args:
        imports: ``(address, name)`` rows from ``list_imports``.
        exports: ``(address, name)`` rows from ``list_exports``.
        strings: ``(address, text)`` rows from ``list_strings``.

    Returns:
        Deterministic list of :class:`CapabilityMatch` (one per fired rule, in ``RULES`` order —
        rules are curated deterministically). Evidence ``detail`` stays raw here until the adapter
        wraps it untrusted (ADR-005).
    """
    by_where: dict[str, list[tuple[str | None, str]]] = {
        "import": [(a, n[:MAX_SCAN_LEN]) for a, n in imports if n],
        "export": [(a, n[:MAX_SCAN_LEN]) for a, n in exports if n],
        "string": [(a, t[:MAX_SCAN_LEN]) for a, t in strings if t],
    }

    out: list[CapabilityMatch] = []
    for rule in RULES:
        satisfied_signals = 0
        evidence: list[Evidence] = []
        for signal in rule.signals:
            hits = _fact_hits(signal, by_where[signal.where])
            if hits:
                satisfied_signals += 1
                evidence.extend(hits)
        needed = len(rule.signals) if rule.mode == "all" else (rule.n if rule.mode == "n_of" else 1)
        if satisfied_signals >= needed:
            out.append(
                CapabilityMatch(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    namespace=rule.namespace,
                    attack=rule.attack,
                    evidence=tuple(evidence),
                    confidence=rule.confidence,
                )
            )
    return out
