"""Shared pytest fixtures for the ghidra-mcp test suite (WS5 — QA infrastructure).

This module provides the test doubles and helpers that depend ONLY on the frozen contracts
(``docs/contracts/*`` and their pydantic source of truth in ``src/ghidra_mcp/``), so the suite
is buildable while the implementation workstreams (WS1/WS2/WS4) are still reserved stubs.

Provided fixtures and helpers:

- :class:`FakeGhidraPort` — a complete, deterministic, schema-valid implementation of the frozen
  :class:`ghidra_mcp.ghidra.port.GhidraPort` Protocol, with a ``failure`` switch to simulate
  timeout / worker crash / oversized-frame / poison conditions for abuse and reliability tests.
- :class:`FrozenClock` — an injectable, monotonic-and-wall-clock test clock (no wall-clock
  dependence; TTL/idle eviction tests advance it explicitly — topic-numeric-correctness).
- :class:`FakeSessionManager` — an in-memory session manager honoring the frozen
  :class:`ghidra_mcp.sessions.manager.SessionManager` surface, driven by the frozen clock.
- Assertion helpers for the error-envelope and untrusted-data envelope shapes.

Everything here is deterministic and hermetic: no real network, no wall-clock, no unseeded
randomness, no real/malware data (master §4, topic-testing). The fakes return synthetic,
benign, structurally-valid data only.
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

import pytest

from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from ghidra_mcp.tools import schemas as s

if TYPE_CHECKING:
    from ghidra_mcp.ghidra.port import GhidraPort

# ---------------------------------------------------------------------------------------------
# Failure injection
# ---------------------------------------------------------------------------------------------


class PortFailure(enum.Enum):
    """Failure modes the :class:`FakeGhidraPort` can simulate on the next call.

    These mirror the worker-fault taxonomy in ``docs/contracts/rpc-protocol.md`` §6 so reliability
    and abuse tests can drive every kill-and-evict path without a real worker.
    """

    NONE = "none"
    """Healthy worker; return deterministic valid data."""

    TIMEOUT = "timeout"
    """Per-call deadline elapsed → ``TIMEOUT`` error (server kills the worker)."""

    CRASH = "crash"
    """Worker crashed / closed the socket mid-call → ``WORKER_UNAVAILABLE`` + eviction."""

    OVERSIZED_FRAME = "oversized_frame"
    """Worker declared a frame larger than ``max_response_bytes`` → protocol error; the server
    closes the socket and kills the worker (TB2 framing defense)."""

    POISON = "poison"
    """Worker is suspected poisoned (e.g. anomalous/hostile behavior) → ``WORKER_UNAVAILABLE``
    and the session is evicted and the store verified-wiped (ADR-002)."""

    ANALYSIS_FAILED = "analysis_failed"
    """Ghidra could not analyze the input (corrupt/unrecognized format) → ``ANALYSIS_FAILED``."""


def _error(
    error_type: ErrorType, *, retryable: bool = False, status: int | None = None
) -> GhidraMcpError:
    """Build a :class:`GhidraMcpError` carrying a safe, contract-valid envelope.

    The envelope contents are generic and leak-free (no paths, stacks, or binary content),
    matching the security contract of ``core.errors`` so tests assert against realistic shapes.
    """
    titles = {
        ErrorType.TIMEOUT: "Operation timed out",
        ErrorType.WORKER_UNAVAILABLE: "Worker unavailable",
        ErrorType.ANALYSIS_FAILED: "Analysis failed",
        ErrorType.LIMIT_EXCEEDED: "Limit exceeded",
        ErrorType.SESSION_INVALID: "Invalid session",
        ErrorType.VALIDATION: "Invalid arguments",
        ErrorType.NOT_FOUND: "Not found",
        ErrorType.INTERNAL: "Internal error",
    }
    env = ErrorEnvelope(
        type=error_type,
        title=titles[error_type],
        detail=f"The {error_type.value} condition was simulated by the test double.",
        status=status,
        correlation_id="test-correlation-id",
        retryable=retryable,
    )
    return GhidraMcpError(env)


def _u(value: Any, *, encoding: str | None = None) -> Untrusted[Any]:
    """Wrap a value in the untrusted-data envelope directly (production ``wrap()`` is a WS4 stub).

    The test double constructs :class:`Untrusted` directly so it does not depend on the
    not-yet-implemented normalization chokepoint. The shape is identical to the frozen contract.
    """
    return Untrusted(value=value, origin=DataOrigin.BINARY, encoding=encoding)


def _ug(value: Any) -> Untrusted[Any]:
    """Wrap a value as ghidra-generated untrusted content (decompiler output, recovered names)."""
    return Untrusted(value=value, origin=DataOrigin.GHIDRA)


# ---------------------------------------------------------------------------------------------
# FakeGhidraPort — full Protocol implementation
# ---------------------------------------------------------------------------------------------


class FakeGhidraPort:
    """A deterministic, schema-valid fake implementing the entire frozen ``GhidraPort`` Protocol.

    Every method returns the frozen output schema populated with synthetic, benign, structurally
    valid data with binary-derived fields already wrapped in :class:`Untrusted` (as the real
    adapter contract requires the server to do). The fake is fully deterministic — no clock, no
    randomness — so assertions are stable.

    Failure injection:
        Set :attr:`failure` to a :class:`PortFailure` (or call :meth:`fail_next`) and the next
        Ghidra-touching call raises the corresponding :class:`GhidraMcpError`, simulating a worker
        timeout / crash / oversized-frame / poison / analysis failure without a real worker. The
        fake records which worker lifecycle calls happened in :attr:`events` so tests can assert
        kill-on-timeout and verified-wipe-on-evict orderings.

    This is the single test double WS4's abuse tests and the (skipped-by-default) integration
    harness can share for unit-level coverage of the server shell against the contract.
    """

    def __init__(self) -> None:
        """Initialize a healthy fake with an empty event log."""
        self.failure: PortFailure = PortFailure.NONE
        self.events: list[tuple[str, str]] = []
        self.killed: list[str] = []
        self.started: list[str] = []

    def fail_next(self, mode: PortFailure) -> None:
        """Arm the fake to fail the next Ghidra-touching call with ``mode``."""
        self.failure = mode

    def _maybe_fail(self) -> None:
        """Raise the armed failure (if any) and disarm, mapping each mode to its envelope."""
        mode = self.failure
        if mode is PortFailure.NONE:
            return
        self.failure = PortFailure.NONE
        if mode is PortFailure.TIMEOUT:
            raise _error(ErrorType.TIMEOUT, retryable=True, status=504)
        if mode is PortFailure.CRASH:
            raise _error(ErrorType.WORKER_UNAVAILABLE, retryable=True, status=503)
        if mode is PortFailure.OVERSIZED_FRAME:
            # Protocol violation: server kills the worker. Surfaced as worker-unavailable.
            raise _error(ErrorType.WORKER_UNAVAILABLE, status=503)
        if mode is PortFailure.POISON:
            raise _error(ErrorType.WORKER_UNAVAILABLE, status=503)
        if mode is PortFailure.ANALYSIS_FAILED:
            raise _error(ErrorType.ANALYSIS_FAILED, status=422)

    # --- worker/session lifecycle ---
    def start_worker(self, session_id: str) -> None:
        """Record a worker-start event (no JVM in a fake)."""
        self.events.append(("start_worker", session_id))
        self.started.append(session_id)

    def import_binary(self, session_id: str, args: s.SessionImportIn) -> s.SessionInfo:
        """Return a deterministic post-import :class:`SessionInfo`."""
        self._maybe_fail()
        self.events.append(("import_binary", session_id))
        return s.SessionInfo(
            session_id=session_id,
            state="importing",
            created_at=1_700_000_000,
            expires_at=1_700_003_600,
            binary_sha256="a" * 64,
        )

    def analyze(self, session_id: str, args: s.SessionAnalyzeIn) -> s.SessionInfo:
        """Return a deterministic post-analysis :class:`SessionInfo` (or simulated failure)."""
        self._maybe_fail()
        self.events.append(("analyze", session_id))
        return s.SessionInfo(
            session_id=session_id,
            state="ready",
            created_at=1_700_000_000,
            expires_at=1_700_003_600,
            binary_sha256="a" * 64,
        )

    def kill_worker(self, session_id: str) -> None:
        """Record a worker-kill event (the universal failure handler — rpc-protocol §6)."""
        self.events.append(("kill_worker", session_id))
        self.killed.append(session_id)

    # --- read-only tool operations ---
    def decompile_function(self, sid: str, a: s.DecompileFunctionIn) -> s.DecompiledFunction:
        """Return deterministic decompiler output with untrusted fields wrapped."""
        self._maybe_fail()
        return s.DecompiledFunction(
            address="0x00401000",
            name=_ug("FUN_00401000"),
            c_code=_ug("int FUN_00401000(void) {\n  return 0;\n}\n"),
            signature=_ug("int FUN_00401000(void)"),
        )

    def disassemble(self, sid: str, a: s.DisassembleIn) -> s.DisassembleOut:
        """Return a bounded, deterministic instruction list."""
        self._maybe_fail()
        count = min(a.max_instructions, 2)
        instrs = [
            s.Instruction(
                address=f"0x0040{1000 + i:04x}",
                mnemonic=_u("MOV"),
                operands=_u("EAX, 0x1"),
                bytes_hex=_u("b801000000", encoding="hex"),
            )
            for i in range(count)
        ]
        return s.DisassembleOut(instructions=instrs, truncated=a.max_instructions < 2)

    def list_functions(self, sid: str, a: s.ListFunctionsIn) -> s.FunctionListOut:
        """Return a bounded, deterministic function summary page."""
        self._maybe_fail()
        funcs = [
            s.FunctionSummary(address="0x00401000", name=_ug("entry"), size=42),
            s.FunctionSummary(address="0x00401100", name=_ug("FUN_00401100"), size=16),
        ][a.offset : a.offset + a.limit]
        return s.FunctionListOut(functions=funcs, total=2, truncated=False)

    def get_function(self, sid: str, a: s.GetFunctionIn) -> s.FunctionDetail:
        """Return deterministic function detail."""
        self._maybe_fail()
        return s.FunctionDetail(
            address="0x00401000",
            name=_ug("entry"),
            signature=_ug("void entry(void)"),
            size=42,
            is_thunk=False,
            calling_convention=_ug("__cdecl"),
        )

    def xrefs_to(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """Return deterministic inbound cross-references."""
        self._maybe_fail()
        return s.XrefsOut(
            xrefs=[s.Xref(from_address="0x00401100", to_address="0x00401000", ref_type="CALL")],
            total=1,
            truncated=False,
        )

    def xrefs_from(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """Return deterministic outbound cross-references."""
        self._maybe_fail()
        return s.XrefsOut(
            xrefs=[s.Xref(from_address="0x00401000", to_address="0x00402000", ref_type="READ")],
            total=1,
            truncated=False,
        )

    def list_strings(self, sid: str, a: s.ListStringsIn) -> s.StringListOut:
        """Return a bounded, deterministic defined-string page (untrusted values)."""
        self._maybe_fail()
        return s.StringListOut(
            strings=[s.DefinedString(address="0x00403000", value=_u("hello world"), length=11)],
            total=1,
            truncated=False,
        )

    def list_symbols(self, sid: str, a: s.ListSymbolsIn) -> s.SymbolListOut:
        """Return a bounded, deterministic symbol page (untrusted names)."""
        self._maybe_fail()
        return s.SymbolListOut(
            symbols=[
                s.Symbol(
                    address="0x00401000", name=_u("entry"), kind="FUNCTION", namespace=_u("global")
                )
            ],
            total=1,
            truncated=False,
        )

    def get_symbol(self, sid: str, a: s.GetSymbolIn) -> s.Symbol:
        """Return a single deterministic symbol."""
        self._maybe_fail()
        return s.Symbol(address="0x00401000", name=_u("entry"), kind="FUNCTION", namespace=None)

    def list_data(self, sid: str, a: s.ListDataIn) -> s.DataListOut:
        """Return a bounded, deterministic defined-data page (untrusted reprs)."""
        self._maybe_fail()
        return s.DataListOut(
            data=[
                s.DefinedData(
                    address="0x00403000",
                    data_type=_u("char[12]"),
                    value_repr=_u('"hello world"'),
                    length=12,
                )
            ],
            total=1,
            truncated=False,
        )

    def get_data_type(self, sid: str, a: s.GetDataTypeIn) -> s.DataType:
        """Return a single deterministic data-type definition (untrusted name/definition)."""
        self._maybe_fail()
        return s.DataType(
            name=_u("MyStruct"),
            kind="struct",
            size=8,
            definition=_u("struct MyStruct { int a; int b; };"),
        )

    def get_comments(self, sid: str, a: s.GetCommentsIn) -> s.CommentListOut:
        """Return a bounded, deterministic comment page (untrusted text)."""
        self._maybe_fail()
        return s.CommentListOut(
            comments=[
                s.Comment(address="0x00401000", comment_type="PLATE", text=_u("entry point"))
            ],
            total=1,
            truncated=False,
        )

    def memory_map(self, sid: str, a: s.MemoryMapIn) -> s.MemoryMapOut:
        """Return a deterministic memory map (untrusted block names)."""
        self._maybe_fail()
        return s.MemoryMapOut(
            blocks=[
                s.MemoryBlock(
                    name=_u(".text"),
                    start="0x00401000",
                    end="0x00402000",
                    size=4096,
                    permissions="r-x",
                    initialized=True,
                )
            ]
        )

    def read_bytes(self, sid: str, a: s.ReadBytesIn) -> s.ReadBytesOut:
        """Return deterministic bounded bytes (hex-encoded, untrusted)."""
        self._maybe_fail()
        return s.ReadBytesOut(
            address=a.address, data=_u("deadbeef", encoding="hex"), length=4, truncated=False
        )

    def search_bytes(self, sid: str, a: s.SearchBytesIn) -> s.SearchBytesOut:
        """Return deterministic bounded byte-search matches (untrusted context)."""
        self._maybe_fail()
        return s.SearchBytesOut(
            matches=[
                s.ByteMatch(address="0x00401000", context_hex=_u("90deadbeef90", encoding="hex"))
            ],
            total=1,
            truncated=False,
        )

    def search_strings(self, sid: str, a: s.SearchStringsIn) -> s.SearchStringsOut:
        """Return deterministic bounded string-search matches (untrusted values)."""
        self._maybe_fail()
        return s.SearchStringsOut(
            strings=[s.DefinedString(address="0x00403000", value=_u("hello world"), length=11)],
            total=1,
            truncated=False,
        )

    def program_metadata(self, sid: str, a: s.ProgramMetadataIn) -> s.ProgramMetadata:
        """Return deterministic high-level program metadata."""
        self._maybe_fail()
        return s.ProgramMetadata(
            sha256="a" * 64,
            size_bytes=4096,
            format="ELF",
            architecture="x86:LE:64:default",
            endianness="little",
            compiler=_u("gcc"),
            entry_point="0x00401000",
            function_count=2,
            analysis_complete=True,
        )

    # --- call-graph / semantic-naming operations (v1.1 — ADR-007; deterministic fakes) ---
    def call_graph(self, sid: str, a: s.CallGraphIn) -> s.CallGraphOut:
        """Return a deterministic 2-node call graph (one resolved edge, no unresolved)."""
        self._maybe_fail()
        return s.CallGraphOut(
            nodes=[
                s.CallGraphNode(
                    address="0x00401000",
                    name=_u("main"),
                    is_external=False,
                    has_unresolved_calls=False,
                ),
                s.CallGraphNode(
                    address="0x00401100",
                    name=_u("puts"),
                    is_external=True,
                    has_unresolved_calls=False,
                ),
            ],
            edges=[s.CallEdge(from_address="0x00401000", to_address="0x00401100")],
            unresolved_callers=[],
            truncated=False,
        )

    def callees(self, sid: str, a: s.CalleesIn) -> s.CallNeighborsOut:
        """Return a deterministic one-hop callee list."""
        self._maybe_fail()
        return s.CallNeighborsOut(
            neighbors=[
                s.CallGraphNode(
                    address="0x00401100",
                    name=_u("puts"),
                    is_external=True,
                    has_unresolved_calls=False,
                )
            ],
            total=1,
            unresolved=False,
            truncated=False,
        )

    def callers(self, sid: str, a: s.CallersIn) -> s.CallNeighborsOut:
        """Return a deterministic one-hop caller list."""
        self._maybe_fail()
        return s.CallNeighborsOut(
            neighbors=[
                s.CallGraphNode(
                    address="0x00401000",
                    name=_u("main"),
                    is_external=False,
                    has_unresolved_calls=False,
                )
            ],
            total=1,
            unresolved=False,
            truncated=False,
        )

    def analysis_order(self, sid: str, a: s.AnalysisOrderIn) -> s.AnalysisOrderOut:
        """Return a deterministic leaf-first order (callee before caller)."""
        self._maybe_fail()
        return s.AnalysisOrderOut(
            components=[
                s.OrderedComponent(members=["0x00401100"], is_recursive=False),
                s.OrderedComponent(members=["0x00401000"], is_recursive=False),
            ],
            unresolved_callers=[],
            self_recursive=[],
            truncated=False,
        )

    def function_context(self, sid: str, a: s.FunctionContextIn) -> s.FunctionContext:
        """Return a deterministic per-function naming/synthesis context bundle."""
        self._maybe_fail()
        return s.FunctionContext(
            address="0x00401000",
            name=_u("main"),
            signature=_ug("int main(int argc, char **argv)"),
            is_external=False,
            decompilation=(
                _ug('int main(int argc, char **argv){ puts("hi"); return 0; }')
                if a.include_decompilation
                else None
            ),
            callees=[
                s.CallGraphNode(
                    address="0x00401100",
                    name=_u("puts"),
                    is_external=True,
                    has_unresolved_calls=False,
                )
            ],
            callers=[],
            referenced_strings=[_u("hi")],
            has_unresolved_calls=False,
            truncated=False,
        )

    # --- Tier-2 reporting / metrics (v1.1 — ADR-008; reserved doubles matching the adapter) ---
    def cyclomatic_complexity(
        self, sid: str, a: s.CyclomaticComplexityIn
    ) -> s.CyclomaticComplexity:
        """Reserved Tier-2 stub (mirrors the reserved adapter — built in the fan-out)."""
        raise NotImplementedError("RESERVED (v1.1 ADR-008): cyclomatic_complexity")

    def list_imports(self, sid: str, a: s.ListImportsIn) -> s.ImportListOut:
        """Reserved Tier-2 stub."""
        raise NotImplementedError("RESERVED (v1.1 ADR-008): list_imports")

    def list_exports(self, sid: str, a: s.ListExportsIn) -> s.ExportListOut:
        """Reserved Tier-2 stub."""
        raise NotImplementedError("RESERVED (v1.1 ADR-008): list_exports")

    def coverage(self, sid: str, a: s.CoverageIn) -> s.CoverageOut:
        """Reserved Tier-2 stub."""
        raise NotImplementedError("RESERVED (v1.1 ADR-008): coverage")

    def ioc_scan(self, sid: str, a: s.IocScanIn) -> s.IocScanOut:
        """Reserved Tier-2 stub."""
        raise NotImplementedError("RESERVED (v1.1 ADR-008): ioc_scan")

    def crypto_constant_scan(self, sid: str, a: s.CryptoConstantScanIn) -> s.CryptoConstantScanOut:
        """Reserved Tier-2 stub."""
        raise NotImplementedError("RESERVED (v1.1 ADR-008): crypto_constant_scan")

    def call_graph_metrics(self, sid: str, a: s.CallGraphMetricsIn) -> s.CallGraphMetricsOut:
        """Reserved Tier-2 stub."""
        raise NotImplementedError("RESERVED (v1.1 ADR-008): call_graph_metrics")

    def program_summary(self, sid: str, a: s.ProgramSummaryIn) -> s.ProgramSummary:
        """Reserved Tier-2 stub."""
        raise NotImplementedError("RESERVED (v1.1 ADR-008): program_summary")

    def rename_function(self, sid: str, a: s.RenameFunctionIn) -> s.RenameResult:
        """Reserved mutation stub (ADR-012; mutation tests use a dedicated fake port)."""
        raise NotImplementedError("RESERVED (v1.1 ADR-012): rename_function")

    def rename_symbol(self, sid: str, a: s.RenameSymbolIn) -> s.RenameSymbolResult:
        """Reserved mutation stub (ADR-012)."""
        raise NotImplementedError("RESERVED (v1.1 ADR-012): rename_symbol")

    def set_comment(self, sid: str, a: s.SetCommentIn) -> s.SetCommentResult:
        """Reserved mutation stub (ADR-012)."""
        raise NotImplementedError("RESERVED (v1.1 ADR-012): set_comment")

    def undo(self, sid: str, a: s.SessionUndoIn) -> s.SessionUndoOut:
        """Reserved mutation stub (ADR-012)."""
        raise NotImplementedError("RESERVED (v1.1 ADR-012): undo")

    def rename_local_variable(
        self, sid: str, a: s.RenameLocalVariableIn
    ) -> s.StructuralRenameResult:
        """Reserved structural-mutation stub (ADR-013; mutation tests use a dedicated fake port)."""
        raise NotImplementedError("RESERVED (v1.1 ADR-013): rename_local_variable")

    def rename_parameter(self, sid: str, a: s.RenameParameterIn) -> s.StructuralRenameResult:
        """Reserved structural-mutation stub (ADR-013)."""
        raise NotImplementedError("RESERVED (v1.1 ADR-013): rename_parameter")


@pytest.fixture
def fake_port() -> FakeGhidraPort:
    """Provide a fresh, healthy :class:`FakeGhidraPort` for a test."""
    return FakeGhidraPort()


if TYPE_CHECKING:
    # Structural conformance gate (mypy --strict): if FakeGhidraPort ever drifts from the frozen
    # GhidraPort Protocol (a renamed/retyped method), this assignment fails to type-check — proving
    # the fake stays a drop-in for the real adapter rather than asserting it vacuously.
    _port_conforms: GhidraPort = FakeGhidraPort()


# ---------------------------------------------------------------------------------------------
# FrozenClock — injectable deterministic time
# ---------------------------------------------------------------------------------------------


@dataclass
class FrozenClock:
    """An injectable test clock with no wall-clock dependence (topic-numeric-correctness).

    Sessions track absolute TTL and idle timeouts; tests advance time explicitly rather than
    sleeping, so eviction logic is deterministic and fast (topic-testing: inject the clock).

    Attributes:
        now_s: Current wall-clock value (Unix epoch seconds), advanced by :meth:`advance`.
        mono_s: Current monotonic value (seconds); advances in lockstep with ``now_s`` but is
            used for durations/timeouts where a wall-clock jump would be wrong.
    """

    now_s: int = 1_700_000_000
    mono_s: float = 0.0

    def time(self) -> int:
        """Return the current wall-clock epoch seconds (for ``created_at``/``expires_at``)."""
        return self.now_s

    def monotonic(self) -> float:
        """Return the current monotonic seconds (for elapsed/timeout measurement)."""
        return self.mono_s

    def advance(self, seconds: int) -> None:
        """Advance both clocks by ``seconds`` (drives TTL/idle eviction tests)."""
        self.now_s += seconds
        self.mono_s += float(seconds)


@pytest.fixture
def clock() -> FrozenClock:
    """Provide a fresh :class:`FrozenClock` anchored at a fixed epoch."""
    return FrozenClock()


# ---------------------------------------------------------------------------------------------
# FakeSessionManager — in-memory, honoring the frozen SessionManager surface
# ---------------------------------------------------------------------------------------------


@dataclass
class _Session:
    """Internal in-memory session record used only by :class:`FakeSessionManager`."""

    info: s.SessionInfo
    last_active_s: int
    evicted: bool = False


@dataclass
class FakeSessionManager:
    """In-memory test double matching the frozen :class:`SessionManager` method surface.

    Provides deterministic ``create`` / ``authorize`` / ``evict`` / ``reap_expired`` / ``shutdown``
    semantics driven by an injected :class:`FrozenClock`, with **deterministic (non-CSPRNG) ids**
    — explicitly a TEST double, never production. It models the security-relevant behaviors the
    suite asserts:

    - opaque-id lookup with a BOLA-safe ``SESSION_INVALID`` for unknown/expired/evicted ids
      (the response never reveals whether *another* session exists);
    - a concurrency cap with ``LIMIT_EXCEEDED`` backpressure;
    - TTL + idle eviction via the injected clock;
    - idempotent eviction returning a verified-wipe flag.

    The real WS2 manager generates ids with ``secrets`` and owns real workers; this double exists
    so the server shell and abuse tests can run before WS2 lands.
    """

    clock: FrozenClock
    ttl_s: int = 3600
    idle_s: int = 600
    max_sessions: int = 4
    _sessions: dict[str, _Session] = field(default_factory=dict)
    _counter: int = 0

    def _live(self) -> dict[str, _Session]:
        """Return only non-evicted sessions."""
        return {k: v for k, v in self._sessions.items() if not v.evicted}

    def create(self, *, label: str | None = None) -> s.SessionInfo:
        """Open a session with a deterministic opaque id; enforce the concurrency cap.

        Raises:
            GhidraMcpError: ``LIMIT_EXCEEDED`` when the live-session cap is reached (backpressure).
        """
        if len(self._live()) >= self.max_sessions:
            raise _error(ErrorType.LIMIT_EXCEEDED, status=429)
        self._counter += 1
        sid = f"sess-{self._counter:08d}"  # deterministic; TEST-ONLY (real uses CSPRNG)
        now = self.clock.time()
        info = s.SessionInfo(
            session_id=sid,
            state="open",
            created_at=now,
            expires_at=now + self.ttl_s,
            binary_sha256=None,
        )
        self._sessions[sid] = _Session(info=info, last_active_s=now)
        return info

    def authorize(self, session_id: str) -> s.SessionInfo:
        """Authorize a live session and refresh its idle clock; fail closed (BOLA-safe).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted ids — identical
                response whether or not other sessions exist (no existence oracle).
        """
        rec = self._sessions.get(session_id)
        now = self.clock.time()
        if (
            rec is None
            or rec.evicted
            or now >= rec.info.expires_at
            or (now - rec.last_active_s) >= self.idle_s
        ):
            raise _error(ErrorType.SESSION_INVALID, status=404)
        rec.last_active_s = now
        return rec.info

    def evict(self, session_id: str, *, reason: str) -> bool:
        """Evict a session idempotently; return the verified-wipe flag.

        A real manager kills the worker first, then verified-wipes the store. The fake records the
        eviction and reports ``store_wiped=True`` deterministically.
        """
        rec = self._sessions.get(session_id)
        if rec is None:
            return True  # idempotent: nothing to wipe
        rec.evicted = True
        return True

    def reap_expired(self) -> int:
        """Evict all sessions past TTL or idle timeout; return the count evicted."""
        now = self.clock.time()
        evicted = 0
        for sid, rec in list(self._sessions.items()):
            if rec.evicted:
                continue
            if now >= rec.info.expires_at or (now - rec.last_active_s) >= self.idle_s:
                self.evict(sid, reason="ttl")
                evicted += 1
        return evicted

    def shutdown(self) -> None:
        """Evict all live sessions (graceful shutdown drain)."""
        for sid in list(self._live()):
            self.evict(sid, reason="close")


class _SessionManagerLike(Protocol):
    """The session-manager surface the suite (and tool handlers) depend on (structural).

    Mirrors the public methods of the frozen :class:`ghidra_mcp.sessions.manager.SessionManager`
    that the server shell and abuse/e2e tests exercise. :class:`FakeSessionManager` is asserted
    to satisfy this below so its signatures cannot silently drift from the real manager.
    """

    def create(self, *, label: str | None = ...) -> s.SessionInfo:
        """Open a new session."""
        ...

    def authorize(self, session_id: str) -> s.SessionInfo:
        """Authorize a live session (BOLA chokepoint)."""
        ...

    def evict(self, session_id: str, *, reason: str) -> bool:
        """Evict a session; return the verified-wipe flag."""
        ...

    def reap_expired(self) -> int:
        """Evict expired/idle sessions; return the count."""
        ...

    def shutdown(self) -> None:
        """Drain and evict all live sessions."""
        ...


@pytest.fixture
def session_manager(clock: FrozenClock) -> FakeSessionManager:
    """Provide a :class:`FakeSessionManager` wired to the frozen test clock."""
    return FakeSessionManager(clock=clock)


if TYPE_CHECKING:
    # Structural conformance gates (mypy --strict): the fakes must remain drop-in for the frozen
    # collaborator surfaces. A retyped/renamed method on either fake (or a drift in the real
    # SessionManager's clock injection contract) fails to type-check here rather than at runtime.
    _sessions_conforms: _SessionManagerLike = FakeSessionManager(clock=FrozenClock())
    _mono_clock: Callable[[], float] = FrozenClock().monotonic
    _wall_clock: Callable[[], int] = FrozenClock().time


# ---------------------------------------------------------------------------------------------
# Envelope assertion helpers (importable + as fixtures)
# ---------------------------------------------------------------------------------------------


def assert_error_envelope(env: object, *, expected_type: ErrorType | None = None) -> ErrorEnvelope:
    """Assert ``env`` is a contract-valid, leak-free :class:`ErrorEnvelope`.

    Verifies the frozen shape and the security contract (no obvious internals leaked: no stack
    markers, no absolute paths). Returns the envelope for further assertions.

    Args:
        env: The object to check.
        expected_type: If given, the envelope ``type`` must equal it.

    Returns:
        The validated :class:`ErrorEnvelope`.
    """
    assert isinstance(env, ErrorEnvelope), f"not an ErrorEnvelope: {type(env)!r}"
    assert isinstance(env.type, ErrorType)
    assert env.title and len(env.title) <= 120
    assert env.detail and len(env.detail) <= 2048
    if env.status is not None:
        assert 400 <= env.status <= 599
    # Leak-free contract (core.errors security note): no stack traces / absolute paths in detail.
    lowered = env.detail.lower()
    assert "traceback" not in lowered
    assert "/home/" not in env.detail and "/usr/" not in env.detail
    if expected_type is not None:
        assert env.type == expected_type
    return env


def assert_untrusted(value: object, *, expected_origin: DataOrigin | None = None) -> Untrusted[Any]:
    """Assert ``value`` is a frozen :class:`Untrusted` wrapper (binary-derived → hostile origin).

    Args:
        value: The object to check.
        expected_origin: If given, the wrapper ``origin`` must equal it.

    Returns:
        The validated :class:`Untrusted` wrapper.
    """
    assert isinstance(value, Untrusted), f"binary-derived field not wrapped: {type(value)!r}"
    assert isinstance(value.origin, DataOrigin)
    assert isinstance(value.truncated, bool)
    assert isinstance(value.notes, list) and len(value.notes) <= 16
    if expected_origin is not None:
        assert value.origin == expected_origin
    return value


@pytest.fixture
def assert_error() -> Iterator[Any]:
    """Expose :func:`assert_error_envelope` as a fixture for tests that prefer injection."""
    yield assert_error_envelope


@pytest.fixture
def assert_wrapped() -> Iterator[Any]:
    """Expose :func:`assert_untrusted` as a fixture for tests that prefer injection."""
    yield assert_untrusted
