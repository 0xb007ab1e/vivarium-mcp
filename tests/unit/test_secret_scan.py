"""Unit tests for ADR-072 `secret_scan` — pure redacted core + the adapter over `list_strings`.

Two layers, both JVM-free (the only worker hop is the already-proven `list_strings`):
  * the pure `core.secretscan` heuristics + the REDACTION contract (no raw secret ever emitted);
  * the `RpcGhidraAdapter.secret_scan` wiring (pure scan over a canned `list_strings`, BINARY-wrap
    of the masked preview, pagination/truncation).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.secretscan import (
    CATEGORIES,
    SecretFinding,
    mask_preview,
    preview_hash,
    scan_secrets,
    shannon_entropy,
)
from vivarium.ghidra import rpc_client as rc
from vivarium.tools import schemas as s

_SID = "sess-secret"

# --- pure core: redaction contract ---------------------------------------------------------------


def test_mask_never_reveals_full_value() -> None:
    """A masked preview drops the middle; short values are fully masked (edges would leak them)."""
    assert mask_preview("hunter2") == "*******"  # <= 8 chars -> fully masked
    assert mask_preview("supersecretvalue123") == "su***************23"  # keep 2 (len < 20)
    long = mask_preview("A" * 40)
    assert long.startswith("AAAA") and long.endswith("AAAA") and "*" in long
    assert long.count("*") == 32  # keep 4 each end


def test_preview_hash_is_stable_and_non_raw() -> None:
    """The correlation hash is deterministic, 12-hex, and not the raw value."""
    h1 = preview_hash("s3cr3t-token-value")
    h2 = preview_hash("s3cr3t-token-value")
    assert h1 == h2 and len(h1) == 12 and all(c in "0123456789abcdef" for c in h1)
    assert "s3cr3t" not in h1


def test_finding_never_carries_raw_secret() -> None:
    """No SecretFinding field equals the raw value (ADR-072 D3)."""
    raw = "AKIAIOSFODNN7EXAMPLEKEYMATERIAL12345"
    findings = scan_secrets([("0x1", f"api_key={raw}")])
    assert findings
    for f in findings:
        assert raw not in f.masked_preview
        assert raw not in f.preview_hash


def test_entropy_of_uniform_is_low_random_is_high() -> None:
    """Shannon entropy separates a repetitive string from a mixed one."""
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("Ab3xZ9-Qw7pLmR2") > 3.0


# --- pure core: categories -----------------------------------------------------------------------


def _cats(findings: list[SecretFinding]) -> set[str]:
    return {f.category for f in findings}


def test_property_secret_name_matches_wifi_pwd() -> None:
    """The T19 case: a key name implying a secret is flagged (name only, no value needed)."""
    findings = scan_secrets(
        [("0x10", "WIFI_PWD"), ("0x11", "device_api_key"), ("0x12", "hostname")]
    )
    props = [f for f in findings if f.category == "property_secret_name"]
    assert {f.address for f in props} == {"0x10", "0x11"}


def test_key_material_pem_header() -> None:
    """A PEM/OpenSSH header is flagged as key_material with the right pattern id."""
    findings = scan_secrets([("0x20", "-----BEGIN OPENSSH PRIVATE KEY-----")])
    assert any(
        f.category == "key_material" and f.pattern_id == "openssh_private_key" for f in findings
    )


def test_hardcoded_credential_keyword_and_entropy() -> None:
    """A credential keyword fires directly; a bare high-entropy blob fires on entropy."""
    kw = scan_secrets([("0x30", "password = letmein")])
    assert any(
        f.category == "hardcoded_credential" and f.pattern_id == "keyword:password" for f in kw
    )
    blob = scan_secrets([("0x31", "Zm9vYmFyYmF6cXV4Y29ycmVjdGhvcnNl9+/Ab")], entropy_threshold=3.5)
    hi = [f for f in blob if f.pattern_id == "high_entropy_blob"]
    assert hi and hi[0].entropy is not None and hi[0].entropy >= 3.5


def test_low_entropy_blob_not_flagged() -> None:
    """A long but repetitive blob stays below threshold and is not a credential."""
    assert not [
        f
        for f in scan_secrets([("0x32", "abcabcabcabcabcabcabcabc")])
        if f.category == "hardcoded_credential"
    ]


def test_format_magic() -> None:
    """A container/bootloader magic string is surfaced as provenance context."""
    findings = scan_secrets([("0x40", "ANDROID!")])
    assert any(f.category == "format_magic" and f.pattern_id == "android_boot" for f in findings)


def test_category_filter_restricts() -> None:
    """`categories` restricts the scan to the requested subset."""
    rows = [("0x1", "WIFI_PWD"), ("0x2", "-----BEGIN CERTIFICATE-----")]
    only_props = scan_secrets(rows, categories=("property_secret_name",))
    assert _cats(only_props) == {"property_secret_name"}
    assert set(CATEGORIES) >= _cats(scan_secrets(rows))


# --- adapter over list_strings -------------------------------------------------------------------


class _DeadWorker:
    def kill(self) -> None:
        return None

    def is_alive(self) -> bool:
        return False

    def exit_diagnosis(self) -> str:
        return "dead"


class _FakeAdapter(rc.RpcGhidraAdapter):
    responses: dict[str, Callable[[dict[str, Any]], dict[str, Any]]]
    calls: list[tuple[str, dict[str, Any]]]

    def _tool_call(self, sid: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, params))
        return self.responses[method](params)


def _make(responses: dict[str, Callable[[dict[str, Any]], dict[str, Any]]]) -> _FakeAdapter:
    adapter = _FakeAdapter(
        launcher=lambda _sid, _path: _DeadWorker(),
        socket_dir="/run/x",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=1 << 20,
    )
    adapter.responses = responses
    adapter.calls = []
    return adapter


def _strings(
    *rows: tuple[str, str], truncated: bool = False
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    return lambda _p: {
        "strings": [{"address": a, "value": v, "length": len(v)} for a, v in rows],
        "total": len(rows),
        "truncated": truncated,
    }


def test_adapter_scans_wraps_and_redacts() -> None:
    """`secret_scan` scans strings, wraps the masked preview BINARY, hides the raw value."""
    adapter = _make({"list_strings": _strings(("0x1", "WIFI_PWD"), ("0x2", "password=hunter2xyz"))})
    out = adapter.secret_scan(_SID, s.SecretScanIn(session_id=_SID))
    cats = {f.category for f in out.findings}
    assert "property_secret_name" in cats and "hardcoded_credential" in cats
    for f in out.findings:
        assert isinstance(f.masked_preview, Untrusted)
        assert f.masked_preview.origin is DataOrigin.BINARY
        assert "hunter2xyz" not in f.masked_preview.value  # redacted
    assert adapter.calls[0][0] == "list_strings"


def test_adapter_paginates_and_propagates_truncation() -> None:
    """`offset`/`limit` paginate; string-set truncation propagates to the result."""
    # single-category strings (format_magic only) so the count is unambiguous — one finding each.
    adapter = _make(
        {"list_strings": _strings(("0x1", "ANDROID!"), ("0x2", "U-Boot"), ("0x3", "JFFS2"))}
    )
    out = adapter.secret_scan(_SID, s.SecretScanIn(session_id=_SID, offset=1, limit=1))
    assert out.total == 3
    assert len(out.findings) == 1
    assert out.truncated is True  # offset+limit < total
