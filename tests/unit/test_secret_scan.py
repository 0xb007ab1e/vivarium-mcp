"""Unit tests for ADR-072 `secret_scan` — pure redacted core + the adapter over `list_strings`.

Two layers, both JVM-free (the only worker hop is the already-proven `list_strings`):
  * the pure `core.secretscan` heuristics + the REDACTION contract (no raw secret ever emitted);
  * the `RpcGhidraAdapter.secret_scan` wiring (pure scan over a canned `list_strings`, BINARY-wrap
    of the masked preview, pagination/truncation).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.secretscan import (
    CATEGORIES,
    MAX_MAGIC_SCAN_LEN,
    SecretFinding,
    mask_preview,
    preview_hash,
    scan_byte_magic,
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


# --- pure core: byte magic (ADR-072 byte-scan follow-up, #371) ------------------------------------

_UIMAGE = b"\x27\x05\x19\x56"  # U-Boot legacy uImage header


def test_byte_magic_finds_uimage_the_string_scan_misses() -> None:
    """uImage's 0x27051956 is binary-only — invisible to the string scan, found by the byte scan."""
    data = b"\x00\x00" + _UIMAGE + b"rest-of-header"
    # The string scan over the same bytes-as-text sees no uImage magic.
    assert not [
        f for f in scan_secrets([("0x1000", data.decode("latin-1"))]) if "uimage" in f.pattern_id
    ]
    found = scan_byte_magic([("00001000", data)])
    assert len(found) == 1
    f = found[0]
    assert f.category == "format_magic" and f.pattern_id == "byte:uimage"
    # Address is base + the magic's offset (2 bytes in), hex.
    assert f.address == "00001002"
    # Redaction contract holds even for inert magic: masked, hashed, no raw bytes str leaked.
    assert set(f.masked_preview) == {"*"} and len(f.preview_hash) == 12


def test_byte_magic_preserves_overlay_qualifier_in_address() -> None:
    """A space-qualified base keeps its prefix + pad width so the address round-trips (#372)."""
    found = scan_byte_magic([("ram1::00001000", _UIMAGE + b"xx")])  # magic at offset 0
    assert found and found[0].address == "ram1::00001000"
    found2 = scan_byte_magic([("ram1::00001000", b"\x00\x00" + _UIMAGE)])  # offset 2
    assert found2 and found2[0].address == "ram1::00001002"


def test_byte_magic_category_gate_and_empty() -> None:
    """A category set without format_magic yields nothing; clean bytes yield nothing."""
    assert scan_byte_magic([("0x0", _UIMAGE)], categories=("key_material",)) == []
    assert scan_byte_magic([("0x0", b"nothing-to-see-here-plain-ascii")]) == []


def test_byte_magic_non_hex_base_returned_unchanged() -> None:
    """A non-hex base can't be offset — it's returned as-is (honest fallback), never raising."""
    found = scan_byte_magic([("weird-base", _UIMAGE)])  # magic at offset 0 anyway
    assert found and found[0].address == "weird-base"
    found2 = scan_byte_magic([("weird-base", b"\x00" + _UIMAGE)])  # offset 1, un-offsettable base
    assert found2 and found2[0].address == "weird-base"


def test_byte_magic_is_bounded_to_scan_window() -> None:
    """Magic past MAX_MAGIC_SCAN_LEN is not scanned (CWE-400 bound)."""
    past = b"\x00" * MAX_MAGIC_SCAN_LEN + _UIMAGE
    assert scan_byte_magic([("0x0", past)]) == []
    at_edge = b"\x00" * (MAX_MAGIC_SCAN_LEN - 4) + _UIMAGE
    assert len(scan_byte_magic([("0x0", at_edge)])) == 1


# Realistic bases only: a bare zero-padded hex offset, or an overlay-qualified one — exactly what
# ``memory_map`` emits (``str(Address)``). The *data* is arbitrary binary (the fuzz surface).
_BASE_STRAT = st.one_of(
    st.none(),
    st.integers(min_value=0, max_value=2**32 - 1).map(lambda n: format(n, "08x")),
    st.integers(min_value=0, max_value=2**16 - 1).map(lambda n: f"ram1::{n:08x}"),
)


@given(st.binary(max_size=4096), _BASE_STRAT)
def test_byte_magic_fuzz_total_and_typed(data: bytes, base: str | None) -> None:
    """Arbitrary bytes + realistic base: never raises, only typed/bounded format_magic findings."""
    out = scan_byte_magic([(base, data)])
    assert isinstance(out, list)
    assert len(out) <= 5  # at most one per signature in _BYTE_MAGIC
    for f in out:
        assert isinstance(f, SecretFinding)
        assert f.category == "format_magic" and f.pattern_id.startswith("byte:")
        # Redaction holds: hashed handle + masked preview (every signature >= 4 bytes -> masked).
        assert len(f.preview_hash) == 12 and "*" in f.masked_preview
        # Address, when present, is a parseable hex offset (optionally overlay-qualified).
        if f.address is not None:
            int(f.address.rpartition("::")[2], 16)


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
    adapter = _make(
        {
            "list_strings": _strings(("0x1", "WIFI_PWD"), ("0x2", "password=hunter2xyz")),
            "memory_map": _mem(),  # no blocks -> byte-magic pass is a no-op
        }
    )
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
        {
            "list_strings": _strings(("0x1", "ANDROID!"), ("0x2", "U-Boot"), ("0x3", "JFFS2")),
            "memory_map": _mem(),  # no blocks -> count stays unambiguous
        }
    )
    out = adapter.secret_scan(_SID, s.SecretScanIn(session_id=_SID, offset=1, limit=1))
    assert out.total == 3
    assert len(out.findings) == 1
    assert out.truncated is True  # offset+limit < total


# --- adapter: byte-magic sub-pass over memory_map + read_bytes (#371) -----------------------------


def _mem(*blocks: dict[str, Any]) -> Callable[[dict[str, Any]], dict[str, Any]]:
    return lambda _p: {"blocks": list(blocks)}


def _block(start: str, data: bytes, *, initialized: bool = True) -> dict[str, Any]:
    return {
        "name": "seg",
        "start": start,
        "end": start,
        "size": len(data),
        "permissions": "r-x",
        "initialized": initialized,
        "_data": data,  # test-only side channel for the read_bytes responder
    }


def _reads(*blocks: dict[str, Any]) -> Callable[[dict[str, Any]], dict[str, Any]]:
    by_start = {b["start"]: b["_data"] for b in blocks}

    def respond(p: dict[str, Any]) -> dict[str, Any]:
        data = by_start.get(p["address"], b"")[: int(p["length"])]
        return {
            "address": p["address"],
            "data": data.hex(),
            "length": len(data),
            "truncated": False,
        }

    return respond


def test_adapter_byte_magic_finds_uimage_in_initialized_block() -> None:
    """The adapter reads an initialized block head and surfaces its binary-only uImage magic."""
    hot = _block("00001000", b"\x00\x27\x05\x19\x56\xff\xff")
    cold = _block("00002000", b"\x27\x05\x19\x56", initialized=False)  # skipped: uninitialized
    adapter = _make(
        {"list_strings": _strings(), "memory_map": _mem(hot, cold), "read_bytes": _reads(hot, cold)}
    )
    out = adapter.secret_scan(_SID, s.SecretScanIn(session_id=_SID))
    byte = [f for f in out.findings if f.pattern_id == "byte:uimage"]
    assert len(byte) == 1
    assert byte[0].address == "00001001"
    assert isinstance(byte[0].masked_preview, Untrusted)
    assert byte[0].masked_preview.origin is DataOrigin.BINARY
    methods = [c[0] for c in adapter.calls]
    assert methods.count("read_bytes") == 1  # only the initialized block was read


def test_adapter_byte_magic_skipped_when_category_excluded() -> None:
    """Excluding format_magic skips the memory_map/read_bytes hops entirely (no wasted RPC)."""
    adapter = _make({"list_strings": _strings(("0x1", "WIFI_PWD"))})
    out = adapter.secret_scan(
        _SID, s.SecretScanIn(session_id=_SID, categories=["property_secret_name"])
    )
    assert out.findings  # the string hit is still there
    assert [c[0] for c in adapter.calls] == ["list_strings"]  # no memory_map / read_bytes


def test_adapter_byte_magic_skips_uninit_and_empty_and_bounds_blocks() -> None:
    """Uninitialized / zero-size / start-less blocks are skipped; the block count is capped."""
    many = [
        _block(format(0x1000 * (i + 1), "08x"), _UIMAGE)
        for i in range(rc._SECRET_MAGIC_MAX_BLOCKS + 3)
    ]
    noise = [
        _block("0000a000", _UIMAGE, initialized=False),  # uninitialized -> skipped
        {"name": "z", "start": "0000b000", "size": 0, "initialized": True, "_data": b""},  # size 0
        {"name": "n", "start": None, "size": 8, "initialized": True, "_data": _UIMAGE},  # no start
    ]
    blocks = noise + many
    adapter = _make(
        {"list_strings": _strings(), "memory_map": _mem(*blocks), "read_bytes": _reads(*many)}
    )
    out = adapter.secret_scan(_SID, s.SecretScanIn(session_id=_SID, limit=1000))
    reads = [c for c in adapter.calls if c[0] == "read_bytes"]
    assert len(reads) == rc._SECRET_MAGIC_MAX_BLOCKS  # capped; noise never read
    assert out.truncated is True  # more initialized blocks than the cap


def test_adapter_byte_magic_propagates_read_truncation() -> None:
    """A truncated block-head read propagates to the result's `truncated` flag."""
    hot = _block("00001000", _UIMAGE)

    def truncating_read(_p: dict[str, Any]) -> dict[str, Any]:
        return {"address": "00001000", "data": _UIMAGE.hex(), "length": 4, "truncated": True}

    adapter = _make(
        {"list_strings": _strings(), "memory_map": _mem(hot), "read_bytes": truncating_read}
    )
    out = adapter.secret_scan(_SID, s.SecretScanIn(session_id=_SID))
    assert any(f.pattern_id == "byte:uimage" for f in out.findings)
    assert out.truncated is True
