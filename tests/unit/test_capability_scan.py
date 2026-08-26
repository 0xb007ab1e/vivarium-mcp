"""Unit tests for ADR-074 `capability_scan` — the pure `core.capabilityscan` rule engine.

The whole detection is the pure core (no JVM edge): the adapter merely pulls the existing
``list_imports`` / ``list_exports`` / ``list_strings`` facts and wraps evidence ``detail`` as
untrusted. These tests exercise the rule engine — each match mode (all / any / n_of), ATT&CK
mapping, evidence, ordering, and benchmark-grounded capabilities (regsvr32 loader, pipe C2, creds).

The server-side wiring (schema / registry / adapter) is added + tested in the same increment once
the shared-file counts settle; this file is deliberately dependency-free (imports only the core).
"""

from __future__ import annotations

from vivarium.core import capabilityscan as cap
from vivarium.core.capabilityscan import detect_capabilities
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

# --- match modes ---


def _ids(matches: list[cap.CapabilityMatch]) -> set[str]:
    return {m.rule_id for m in matches}


def test_any_mode_single_signal() -> None:
    """`any` mode fires on one matching signal (anti-debug via IsDebuggerPresent)."""
    out = detect_capabilities([("0x1", "IsDebuggerPresent")], [], [])
    assert "defense-evasion/anti-debug" in _ids(out)


def test_all_mode_requires_every_signal() -> None:
    """`all` mode (reflective load) needs LoadLibrary AND GetProcAddress AND VirtualAlloc."""
    partial = detect_capabilities([("0x1", "LoadLibraryW"), ("0x2", "GetProcAddress")], [], [])
    assert "defense-evasion/reflective-load" not in _ids(partial)
    full = detect_capabilities(
        [("0x1", "LoadLibraryW"), ("0x2", "GetProcAddress"), ("0x3", "VirtualAlloc")], [], []
    )
    assert "defense-evasion/reflective-load" in _ids(full)


def test_n_of_mode_threshold() -> None:
    """`n_of` mode (process injection, n=2) needs at least two of the injection primitives."""
    one = detect_capabilities([("0x1", "VirtualAllocEx")], [], [])
    assert "defense-evasion/process-injection" not in _ids(one)
    two = detect_capabilities([("0x1", "VirtualAllocEx"), ("0x2", "WriteProcessMemory")], [], [])
    assert "defense-evasion/process-injection" in _ids(two)


# --- benchmark-grounded capabilities ---


def test_bumblebee_shape() -> None:
    """BumbleBee-like facts light up regsvr32 + reflective-load + named-pipe + anti-debug."""
    out = detect_capabilities(
        [
            ("0x1", "LoadLibraryExW"),
            ("0x2", "GetProcAddress"),
            ("0x3", "VirtualAlloc"),
            ("0x4", "CreateNamedPipeA"),
            ("0x5", "TransactNamedPipe"),
            ("0x6", "IsDebuggerPresent"),
        ],
        [("0x100", "DllRegisterServer")],
        [],
    )
    ids = _ids(out)
    assert {
        "execution/regsvr32",
        "defense-evasion/reflective-load",
        "c2/named-pipe",
        "defense-evasion/anti-debug",
    } <= ids


def test_browser_credential_theft_string_signal() -> None:
    """A `moz_logins` string alone fires the browser-credential capability (Wirenet)."""
    out = detect_capabilities([], [], [("0x900", "select * from moz_logins")])
    m = next(x for x in out if x.rule_id == "credential-access/browser")
    assert m.attack == (("credential-access", "T1555.003"),)


def test_run_key_persistence_needs_both_signals() -> None:
    """Run-key persistence (`all`) needs RegSetValue AND the Run-key string."""
    reg_only = detect_capabilities([("0x1", "RegSetValueExW")], [], [])
    assert "persistence/run-key" not in _ids(reg_only)
    both = detect_capabilities(
        [("0x1", "RegSetValueExW")],
        [],
        [("0x2", "Software\\Microsoft\\Windows\\CurrentVersion\\Run")],
    )
    assert "persistence/run-key" in _ids(both)


# --- evidence / mapping / determinism ---


def test_evidence_anchors_and_attack_mapping() -> None:
    """Each match carries evidence (address + where + detail) and an ATT&CK technique id."""
    out = detect_capabilities([], [("0x100", "DllRegisterServer")], [])
    m = next(x for x in out if x.rule_id == "execution/regsvr32")
    assert m.attack == (("defense-evasion", "T1218.010"),)
    assert m.evidence[0].where == "export"
    assert m.evidence[0].detail == "DllRegisterServer"
    assert m.evidence[0].address == "0x100"
    assert 0.0 <= m.confidence <= 1.0


def test_deterministic_rule_order() -> None:
    """Matches come back in RULES order regardless of fact order (stable output)."""
    facts = [("0x1", "IsDebuggerPresent"), ("0x2", "BitBlt")]
    a = [m.rule_id for m in detect_capabilities(facts, [], [])]
    b = [m.rule_id for m in detect_capabilities(list(reversed(facts)), [], [])]
    assert a == b


def test_no_facts_no_matches() -> None:
    """Empty facts ⇒ no capabilities (empty ≠ benign on a packed input — documented)."""
    assert detect_capabilities([], [], []) == []


def test_empty_names_skipped_and_bounded() -> None:
    """Empty fact values are skipped; an oversized value is truncated before match (DoS guard)."""
    assert detect_capabilities([("0x1", "")], [("0x2", "")], [("0x3", "")]) == []
    huge = "IsDebuggerPresent" + ("A" * (cap.MAX_SCAN_LEN * 2))
    out = detect_capabilities([("0x1", huge)], [], [])
    ev = next(x for x in out if x.rule_id == "defense-evasion/anti-debug").evidence[0]
    assert len(ev.detail) == cap.MAX_SCAN_LEN


def test_rule_pack_version_present() -> None:
    """A rule-pack version is exposed for reproducibility + the future external-pack migration."""
    assert cap.RULE_PACK_VERSION == "builtin-1"


# --- schema + registry wiring ---


def test_schema_evidence_detail_untrusted_and_paginated() -> None:
    """CapabilityScanIn is paginated; evidence detail is the untrusted envelope."""
    m = s.CapabilityScanIn(session_id="sess")
    assert m.offset == 0 and m.limit >= 1
    field = s.CapabilityEvidence.model_fields["detail"]
    assert "Untrusted" in str(field.annotation)


def test_registered_and_read_only() -> None:
    """capability_scan is in the frozen allow-list, handled, and NOT a write tool."""
    assert "capability_scan" in reg.TIER1_TOOL_NAMES
    assert "capability_scan" in reg._HANDLERS
    assert "capability_scan" not in reg.WRITE_TOOLS
    assert reg.required_capability("capability_scan") == reg.required_capability("ioc_scan")
