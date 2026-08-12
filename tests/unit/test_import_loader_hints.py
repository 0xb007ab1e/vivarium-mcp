"""Unit tests for ADR-045 (F1) `session_import` loader hints — raw/headerless binary import.

Covers the three server-side layers the feature adds (the worker `BinaryLoader` edge is
`# pragma: no cover - JVM` and validated by the gated integration test):

1. the curated LanguageID allow-list (`vivarium.core.languages`),
2. the `SessionImportIn` cross-field validation boundary (fail-closed rejects), and
3. the `rpc_client` param construction — proving the auto path stays a **byte-for-byte no-op** and
   the binary path threads exactly the opted-in hints.
"""

from __future__ import annotations

import socket

import pytest
from pydantic import ValidationError

from vivarium.core import languages
from vivarium.tools import schemas as s

# --- 1. allow-list (vivarium.core.languages) -----------------------------------------------------


def test_supported_language_ids_are_sorted_and_nonempty() -> None:
    """The public id tuple mirrors the mapping, is sorted, and covers the full installed set."""
    assert languages.SUPPORTED_LANGUAGE_IDS
    assert list(languages.SUPPORTED_LANGUAGE_IDS) == sorted(languages.SUPPORTED_LANGUAGE_IDS)
    # The full installed set is broad (>100 languages) — spanning embedded + desktop families.
    assert len(languages.SUPPORTED_LANGUAGE_IDS) > 100
    ids = set(languages.SUPPORTED_LANGUAGE_IDS)
    # Real installed LanguageIDs across families (grounded against the pinned Ghidra).
    assert {"ARM:LE:32:Cortex", "ARM:BE:32:Cortex"} <= ids  # embedded ARM
    assert {"AARCH64:LE:64:v8A", "AARCH64:BE:64:v8A"} <= ids  # 64-bit ARM
    assert {"RISCV:LE:32:default", "RISCV:LE:64:default"} <= ids  # RISC-V (real ids, not RV32GC)
    assert {"x86:LE:32:default", "x86:LE:64:default"} <= ids  # desktop x86
    assert {"MIPS:BE:32:default", "PowerPC:BE:32:default"} <= ids  # router/embedded
    assert "Xtensa:LE:32:default" in ids  # ESP32/IoT


def test_is_supported_language_is_exact_match_only() -> None:
    """Membership is exact/case-sensitive — a near-miss must fail closed, not be coerced."""
    assert languages.is_supported_language("ARM:LE:32:Cortex")
    assert not languages.is_supported_language("arm:le:32:cortex")  # case matters
    assert not languages.is_supported_language("ARM:LE:32:Cortex ")  # trailing space
    assert not languages.is_supported_language("X86:LE:64:default")  # wrong case (real id is `x86`)
    assert not languages.is_supported_language("TotallyMadeUp:LE:32:nope")  # not a real LanguageID
    assert not languages.is_supported_language("")


@pytest.mark.parametrize(
    ("language_id", "bits"),
    [
        ("ARM:LE:32:Cortex", 32),
        ("AARCH64:LE:64:v8A", 64),
        ("RISCV:LE:32:default", 32),
        ("x86:LE:64:default", 64),
        ("z80:LE:16:default", 16),
        ("dsPIC30F:LE:24:default", 24),
    ],
)
def test_address_bits(language_id: str, bits: int) -> None:
    """Address width comes from the mapping (used to bound base_addr/entry)."""
    assert languages.address_bits(language_id) == bits


def test_address_bits_rejects_unlisted() -> None:
    """Asking the width of a non-allow-listed id is a programmer error (KeyError)."""
    with pytest.raises(KeyError):
        languages.address_bits("TotallyMadeUp:LE:32:nope")


# --- 2. SessionImportIn validation boundary ------------------------------------------------------


def _binary(**over: object) -> dict[str, object]:
    """A valid loader='binary' kwargs baseline; override individual fields per test."""
    base: dict[str, object] = {
        "session_id": "s",
        "source_ref": "fw.bin",
        "loader": "binary",
        "processor": "ARM:LE:32:Cortex",
        "base_addr": 0x10000000,
    }
    base.update(over)
    return base


def test_default_is_auto_with_no_hints() -> None:
    """Absent loader hints → loader='auto' and every hint None (the no-op default)."""
    m = s.SessionImportIn(session_id="s", source_ref="prog.elf")
    assert m.loader == "auto"
    assert m.processor is None and m.base_addr is None and m.entry is None


def test_valid_binary_import_accepted() -> None:
    """A complete binary import (with an in-range entry) validates."""
    m = s.SessionImportIn.model_validate(_binary(entry=0x10000100))
    assert m.loader == "binary"
    assert m.processor == "ARM:LE:32:Cortex"
    assert m.base_addr == 0x10000000
    assert m.entry == 0x10000100


def test_binary_requires_processor_and_base_addr() -> None:
    """loader='binary' without processor or without base_addr is rejected."""
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_binary(processor=None))
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_binary(base_addr=None))


def test_auto_forbids_any_loader_hint() -> None:
    """A hint set under loader='auto' is ambiguous → rejected (no silent ignore)."""
    with pytest.raises(ValidationError):
        s.SessionImportIn(session_id="s", source_ref="p", processor="ARM:LE:32:Cortex")
    with pytest.raises(ValidationError):
        s.SessionImportIn(session_id="s", source_ref="p", base_addr=0x1000)
    with pytest.raises(ValidationError):
        s.SessionImportIn(session_id="s", source_ref="p", entry=0x1000)


def test_unsupported_processor_rejected() -> None:
    """A processor outside the curated allow-list fails closed."""
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_binary(processor="X86:LE:64:default"))


def test_base_addr_beyond_address_width_rejected() -> None:
    """A 32-bit language cannot carry a base_addr >= 2**32."""
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_binary(processor="ARM:LE:32:Cortex", base_addr=1 << 32))
    # The same numeric base is fine on a 64-bit language.
    m = s.SessionImportIn.model_validate(_binary(processor="AARCH64:LE:64:v8A", base_addr=1 << 32))
    assert m.base_addr == 1 << 32


def test_entry_out_of_range_or_below_base_rejected() -> None:
    """entry must fit the address width and be >= base_addr."""
    with pytest.raises(ValidationError):  # entry past 32-bit width
        s.SessionImportIn.model_validate(_binary(entry=1 << 32))
    with pytest.raises(ValidationError):  # entry below base_addr
        s.SessionImportIn.model_validate(_binary(base_addr=0x2000, entry=0x1000))


def test_negative_base_addr_rejected_by_field() -> None:
    """base_addr/entry are non-negative (Field ge=0)."""
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_binary(base_addr=-1))


# --- 2b. hex loaders (ADR-046: intel-hex / motorola-hex) -----------------------------------------


def _hex(loader: str, **over: object) -> dict[str, object]:
    """A loader='<hex>' kwargs baseline (source_ref + processor); override per test.

    Uses a dict + ``model_validate`` (not the typed constructor) so a parametrized ``str`` loader
    doesn't trip mypy's ``Literal`` arg-type check — same pattern as ``_binary``.
    """
    base: dict[str, object] = {
        "session_id": "s",
        "source_ref": "fw.hex",
        "loader": loader,
        "processor": "ARM:LE:32:Cortex",
    }
    base.update(over)
    return base


@pytest.mark.parametrize("loader", ["intel-hex", "motorola-hex"])
def test_hex_loader_requires_processor_only(loader: str) -> None:
    """A hex loader with just a supported processor validates (addresses come from the records)."""
    m = s.SessionImportIn.model_validate(_hex(loader))
    assert m.loader == loader
    assert m.processor == "ARM:LE:32:Cortex"
    assert m.base_addr is None and m.entry is None


@pytest.mark.parametrize("loader", ["intel-hex", "motorola-hex"])
def test_hex_loader_missing_processor_rejected(loader: str) -> None:
    """A hex loader without a processor is rejected (hex carries no arch)."""
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_hex(loader, processor=None))


@pytest.mark.parametrize("loader", ["intel-hex", "motorola-hex"])
def test_hex_loader_forbids_base_addr_and_entry(loader: str) -> None:
    """base_addr/entry are meaningless for hex (records are absolute) → rejected, not ignored."""
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_hex(loader, base_addr=0x1000))
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_hex(loader, entry=0x1000))


@pytest.mark.parametrize("loader", ["intel-hex", "motorola-hex"])
def test_hex_loader_unsupported_processor_rejected(loader: str) -> None:
    """A hex loader with an unknown processor fails closed."""
    with pytest.raises(ValidationError):
        s.SessionImportIn.model_validate(_hex(loader, processor="Nope:LE:32:x"))


# --- 3. rpc_client param construction (byte-for-byte no-op + hint threading) ----------------------


def _adapter_capturing_call() -> tuple[object, list[dict[str, object]]]:
    """Build an RpcGhidraAdapter whose `_call` is stubbed to capture the params dict.

    Size/pre-flight are neutralized (tiny resolved size) so `import_binary` reaches the RPC step.
    """
    from tests.unit.test_rpc_adapter import _FakeWorker, _make_adapter

    srv, _client = socket.socketpair()
    adapter = _make_adapter(srv, _FakeWorker())
    captured: list[dict[str, object]] = []

    def _fake_call(
        session_id: str, method: str, params: dict[str, object], **_kw: object
    ) -> dict[str, object]:
        captured.append(params)
        # Minimal valid SessionInfo-shaped reply so `_validate(SessionInfo, …)` succeeds.
        return {
            "session_id": session_id,
            "state": "importing",
            "created_at": 0,
            "expires_at": 0,
        }

    adapter._source_resolver = lambda _ref: 16
    adapter._call = _fake_call  # type: ignore[method-assign]
    return adapter, captured


def test_auto_import_params_are_byte_for_byte_noop() -> None:
    """loader='auto' sends ONLY {source_ref, expected_sha256} — no loader-hint key on the wire."""
    adapter, captured = _adapter_capturing_call()
    args = s.SessionImportIn(session_id="s", source_ref="prog.elf")
    adapter.import_binary("s", args)  # type: ignore[attr-defined]
    assert captured == [{"source_ref": "prog.elf", "expected_sha256": None}]


def test_binary_import_params_thread_the_hints() -> None:
    """loader='binary' attaches loader/processor/base_addr (+entry only when set)."""
    adapter, captured = _adapter_capturing_call()
    args = s.SessionImportIn(
        session_id="s",
        source_ref="fw.bin",
        loader="binary",
        processor="RISCV:LE:32:default",
        base_addr=0x0,
        entry=0x80,
    )
    adapter.import_binary("s", args)  # type: ignore[attr-defined]
    assert captured == [
        {
            "source_ref": "fw.bin",
            "expected_sha256": None,
            "loader": "binary",
            "processor": "RISCV:LE:32:default",
            "base_addr": 0x0,
            "entry": 0x80,
        }
    ]


def test_binary_import_omits_entry_when_absent() -> None:
    """No `entry` key is sent when the client did not supply one."""
    adapter, captured = _adapter_capturing_call()
    args = s.SessionImportIn(
        session_id="s",
        source_ref="fw.bin",
        loader="binary",
        processor="ARM:LE:32:Cortex",
        base_addr=0x10000000,
    )
    adapter.import_binary("s", args)  # type: ignore[attr-defined]
    assert "entry" not in captured[0]
    assert captured[0]["loader"] == "binary"


@pytest.mark.parametrize("loader", ["intel-hex", "motorola-hex"])
def test_hex_import_params_thread_only_loader_and_processor(loader: str) -> None:
    """ADR-046: a hex loader sends ONLY {source_ref, expected_sha256, loader, processor}."""
    adapter, captured = _adapter_capturing_call()
    args = s.SessionImportIn.model_validate(_hex(loader))
    adapter.import_binary("s", args)  # type: ignore[attr-defined]
    assert captured == [
        {
            "source_ref": "fw.hex",
            "expected_sha256": None,
            "loader": loader,
            "processor": "ARM:LE:32:Cortex",
        }
    ]
