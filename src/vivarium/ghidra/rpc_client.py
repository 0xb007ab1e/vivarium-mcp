"""RPC adapter: spawns hardened workers and speaks the internal protocol (WS2).

Concrete :class:`vivarium.ghidra.port.GhidraPort` implementation. It:

- Spawns/kills the worker as a hardened container (non-root, ro-rootfs, all caps dropped, seccomp,
  **no network**, gVisor runtime, CPU/mem/pids limits — ADR-004; the concrete runtime flags are
  injected by WS3/deploy via the :data:`WorkerLauncher` callable, so this module stays runtime-
  agnostic and unit-testable).
- Connects to the worker over the internal RPC transport (JSON-RPC 2.0 over a per-session Unix
  domain socket — ``docs/contracts/rpc-protocol.md``) with 4-byte big-endian length-prefixed
  framing.
- Enforces per-call timeouts and **SIGKILLs the worker** on expiry (no graceful wait for a hung
  JVM — rpc-protocol.md §6).
- Treats the worker as a fault domain: an oversized frame, protocol violation, timeout, or crash
  all resolve to **kill + ``worker-unavailable``/``timeout``** and signal eviction. It never
  destabilizes the server.

This module runs IN THE SERVER process and MUST NOT import the JVM bridge (ADR-001). It only ever
sends/receives bytes over the socket; the framing/JSON-RPC codec lives in the JVM-free
:mod:`vivarium.ghidra.rpc_framing`.

**Untrusted-data wrap chokepoint (PM #9, ADR-005).** The worker returns *plain* JSON (rpc-protocol
§4: "the worker returns plain structured data"). This adapter is the single server-side place that
turns those plain values into typed ``*Out`` models, calling :func:`vivarium.core.envelope.wrap`
on every binary-derived field as it constructs each model — ``DataOrigin.BINARY`` for content
*extracted* from the binary (strings, bytes, names, comments) and ``DataOrigin.GHIDRA`` for content
*synthesized* by the decompiler/analysis over hostile input (pseudo-C, signatures, recovered
mnemonics/types). Nothing binary-derived leaves this adapter un-wrapped.
"""

from __future__ import annotations

import contextlib
import functools
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from pydantic import BaseModel, ValidationError

from vivarium.core.envelope import DataOrigin, Untrusted, wrap
from vivarium.core.errors import ErrorType
from vivarium.ghidra import _errors, port, rpc_framing
from vivarium.ghidra.rpc_framing import (
    FramingError,
    RpcCallError,
    RpcProtocolError,
)
from vivarium.jobs import streaming as st
from vivarium.jobs.streaming import StreamingJobManager
from vivarium.logging import get_logger
from vivarium.security.limits import (
    DEFAULT_PREFLIGHT_MODE,
    DEFAULT_WORKER_MEM_MIB,
    PREFLIGHT_MODES,
    Limits,
    check_binary_size,
    plausible_max_bytes,
)
from vivarium.tools import schemas as s


class WorkerProcess(Protocol):
    """A spawned worker process/container handle the adapter can SIGKILL (injected by WS3).

    Abstracted so the adapter is independent of the concrete runtime (podman/runsc). The launcher
    returns one of these per session.
    """

    def kill(self) -> None:
        """Forcibly terminate the worker (SIGKILL the container/process). Idempotent."""
        ...

    def is_alive(self) -> bool:
        """Whether the worker is still running."""
        ...

    def exit_diagnosis(self) -> str:
        """Classify why the worker exited: ``"oom"`` / ``"other"`` / ``"unknown"`` (ADR-023 / F1).

        A server-side container-engine metadata query only (NO binary parsing — ADR-001). The
        adapter uses it on a transport failure to distinguish a memory-cap OOM (→
        ``resource-exhausted``) from a generic crash (→ ``worker-unavailable``). Fails closed to
        ``"unknown"`` (treated as a generic crash) on any engine error.
        """
        ...


#: A launcher takes a session id and the socket path and returns a running worker process. WS3
#: supplies the concrete container command (arg list — never ``shell=True``); tests supply a fake.
WorkerLauncher = Callable[[str, str], WorkerProcess]

#: Resolves a (server-confined) ``source_ref`` to the byte size of the candidate input, so the
#: server can enforce the binary-size cap BEFORE a single byte reaches the worker (CWE-22 path
#: confinement + DoS cap, both server-side and pre-Ghidra). WS3/deploy injects the concrete,
#: allow-list-confined resolver; the built-in default stats a path under the OS (used only when the
#: composition root wires no resolver). It returns a non-negative ``int`` size.
#:
#: **Failure contract:** signal an unresolvable/rejected ``source_ref`` by raising ``OSError`` (the
#: default's stat failures) or ``ValueError`` (e.g. a confined resolver rejecting a path outside its
#: allow-list root). :meth:`RpcClient.import_binary` maps BOTH to a fail-closed ``VALIDATION`` error
#: with a fixed, content-free detail — the resolver's exception is chained server-side only, never
#: forwarded to the client (master §5). Any OTHER exception is treated as a wiring/programmer bug
#: and propagates (fail fast — ``topic-error-handling``), not masked as input validation.
SourceResolver = Callable[[str], int]


class SourceRefError(OSError):
    """A ``source_ref`` the resolver rejected, tagged with a category-safe ``reason`` (F4).

    Subclasses :class:`OSError` so the existing ``except (OSError, ValueError)`` in
    :meth:`RpcGhidraAdapter.import_binary` still catches it; the ``reason`` selects a specific,
    content-free ``VALIDATION`` detail (see :data:`_SOURCE_REF_DETAILS`) so the client can tell
    *outside-the-root* from *not-found* from *malformed* — actionable without leaking the resolved
    root path or the ``source_ref`` value (master §5, ADR-005).
    """

    def __init__(self, reason: str, message: str) -> None:
        """Initialize with a category ``reason`` and a server-side (log-only) ``message``.

        Args:
            reason: One of ``escapes-root`` / ``not-found`` / ``malformed`` — selects the safe
                client detail; an unknown reason falls back to the generic detail.
            message: The server-side exception text (chained, never forwarded to the client).
        """
        super().__init__(message)
        self.reason = reason


#: Category-safe ``VALIDATION`` detail per resolver reject reason. Deliberately references only the
#: documented env-var name (safe operator guidance), NEVER the resolved root path or the client's
#: ``source_ref`` value (master §5 redaction). An unknown reason falls back to the generic detail.
_SOURCE_REF_DETAILS: dict[str, str] = {
    "escapes-root": "source_ref must be a path under the import root (VIVARIUM_IMPORT_ROOT)",
    "not-found": "source_ref was not found under the import root (VIVARIUM_IMPORT_ROOT)",
    "malformed": "source_ref is not a valid path",
}
#: Fallback when the resolver signalled a reject without a recognized reason (e.g. the default
#: built-in resolver's bare stat failure) — the original pre-F4 content-free detail.
_DEFAULT_SOURCE_REF_DETAIL = "input reference could not be resolved"


# --- Tier-2 internal scan budgets (ADR-008; bounded BEFORE the worker — std-cwe CWE-400) -----
#: How many defined strings ``ioc_scan`` pulls in one bounded page before scanning (the worker also
#: clamps; ``truncated`` is honest when more exist). Sized to a generous-but-bounded triage window.
#: Hard ceiling on a decompressed container payload (ADR-070 D3 zip-bomb defense). The worker
#: streams the decompress against this and aborts on overflow — a bomb never materializes a large
#: buffer. Paired with the ratio cap (whichever binds first).
_MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024  # 512 MiB
#: Hard ceiling on output ÷ input for a container decompress (ADR-070 D3). A stream exceeding this
#: ratio is a bomb → aborted, fail closed.
_MAX_DECOMPRESSION_RATIO = 200
_IOC_STRING_BUDGET = 10_000
#: Max strings pulled for the ``secret_scan`` pass (ADR-072); bounds the scanned set + feeds
#: ``truncated`` when the program has more strings than the budget.
_SECRET_STRING_BUDGET = 10_000
#: Max ``search_bytes`` matches requested per crypto signature (each search is already bounded; this
#: caps the per-signature contribution to the aggregate and feeds ``truncated``).
_CRYPTO_MATCH_BUDGET = 1_000
#: Max imports + strings pulled for the ``crypto_detect`` pass (ADR-075); bounds the scanned sets
#: and feeds ``truncated`` when either the imports or the strings exceed the budget.
_CRYPTO_DETECT_IMPORT_BUDGET = 10_000
_CRYPTO_DETECT_STRING_BUDGET = 10_000
#: Max hardware crypto-opcode hits pulled for the ``crypto_detect`` ``instruction`` source
#: (ADR-075); bounds the worker's opcode scan and feeds ``truncated`` when the cap binds.
_CRYPTO_DETECT_OPCODE_BUDGET = 10_000
#: Max imports + exports + strings pulled for the ``capability_scan`` rule pass (ADR-074); bounds
#: the scanned fact sets and feeds ``truncated`` when any of them exceeds its budget.
_CAPABILITY_IMPORT_BUDGET = 10_000
_CAPABILITY_EXPORT_BUDGET = 10_000
_CAPABILITY_STRING_BUDGET = 10_000
#: Hard cap on FID match candidates the adapter ever returns from ``identify_functions`` (ADR-042;
#: bounds the result BEFORE shaping — std-cwe CWE-400). Mirrors the worker-side cap; the per-call
#: ``limit`` (schema-bounded) further narrows it, and ``truncated`` is honest when more matched.
_IDENTIFY_MATCH_BUDGET = 10_000
#: Poll interval between worker-socket connect attempts while the worker is still binding/warming
#: up (bounded overall by ``connect_timeout_s``). Small enough for a snappy first call, large
#: enough not to busy-spin.
_CONNECT_RETRY_INTERVAL_S = 0.1

#: Length of the per-session socket *directory* token (a prefix of the session id). Keeps the
#: AF_UNIX host path well under the ~107-byte limit while staying collision-free for the small
#: live-session set (the full id is still the socket filename + the server-side identity). See
#: :meth:`RpcGhidraAdapter._socket_path`.
_SOCKET_DIR_TOKEN_LEN = 16

#: The analyzer profile that is a byte-for-byte no-op: when this is selected the analyze RPC carries
#: NO ``profile`` param at all, so the worker takes the exact same code path as before ADR-029 B
#: (the default-is-no-op guarantee — see :func:`_analyze_params`).
_DEFAULT_PROFILE = "default"

# --- $/progress flood bounds (ADR-030 Phase 1; worker is potentially hostile — TB2/TB3) --------
#: Hard cap on ``$/progress`` notification frames accepted per opted-in ``analyze`` call. Exceeding
#: this is a protocol violation handled FAIL-CLOSED: the worker is killed + the session evicted (the
#: same universal kill handler as any TB2 violation — rpc-protocol.md §6). A finite cap prevents a
#: hostile worker from streaming progress forever to keep the read-loop busy (the un-extended
#: deadline already bounds wall-clock; this bounds frame COUNT independently).
_MAX_PROGRESS_FRAMES = 10_000
#: Minimum spacing between progress frames the server will RELAY to the log; a frame arriving sooner
#: than this after the last relayed one is COALESCED (dropped — not logged) but still counts toward
#: :data:`_MAX_PROGRESS_FRAMES`. Bounds log volume from a chatty (or hostile) worker without killing
#: it for mere chattiness; only exceeding the hard frame count is fatal.
_MIN_PROGRESS_INTERVAL_S = 0.5

#: Hard cap on ``$/chunk`` frames accepted per streaming call (ADR-040; worker is potentially
#: hostile — TB2/TB3). A bulk decompile is bounded by the decompile total cap (10 000), so a worker
#: emitting MORE chunks than that is a protocol violation → kill + evict (fail closed). Independent
#: of the per-frame size cap (§3) and the server-side per-job buffer cap (which applies backpressure
#: rather than killing); this bounds the TOTAL frame count across one call.
_MAX_STREAM_CHUNKS = 10_000

#: Module logger. RPC-layer failures are logged SERVER-SIDE with the underlying exception
#: (socket/framing errors — no binary content or secrets) before being mapped to the
#: boundary-safe public envelope, so operability does not depend on the client-facing message
#: (topic-logging-observability; master §5).
_log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _TopComplex:
    """Bounded top-by-complexity result for ``program_summary`` (helper return type).

    Attributes:
        functions: The examined functions, sorted by descending cyclomatic complexity.
        truncated: Whether more functions existed than were examined (honesty for the summary).
    """

    functions: list[s.CyclomaticComplexity]
    truncated: bool


def _default_source_size(source_ref: str) -> int:
    """Default ``SourceResolver``: byte size of a filesystem ``source_ref`` (server-side, no JVM).

    This is a conservative built-in used only when no confined resolver is injected; WS3/deploy
    supplies the real allow-list/path-confinement resolver. It performs NO read of the bytes into
    memory — it only stats the size so the cap can be enforced before the worker is fed.

    Args:
        source_ref: The server-resolved reference to the input.

    Returns:
        The size of the referenced input in bytes.
    """
    return Path(source_ref).stat().st_size


def _analyze_params(
    timeout_seconds: int | None, profile: str, *, progress: bool = False
) -> dict[str, Any]:
    """Shape the ``analyze`` RPC params, preserving the default-is-no-op guarantee (ADR-029/030).

    Pure (no I/O) so it is unit-testable. When ``profile`` is the default AND ``progress`` is
    ``False`` the returned params are IDENTICAL to the pre-ADR-029 shape
    (``{"timeout_seconds": ...}`` only) — both additive keys are OMITTED, so the unchanged path
    routes the worker down the exact same code as before these increments. ``light``/``deep`` add
    the explicit ``profile`` key; ``progress=True`` adds the explicit ``progress`` key (opt-in to
    ``$/progress`` frames, ADR-030).

    Args:
        timeout_seconds: The (already server-clamped) in-worker budget hint, or ``None``.
        profile: The validated analyzer-depth preset (``default``/``light``/``deep``).
        progress: Whether the caller opted into worker→server progress frames (ADR-030 Phase 1).

    Returns:
        The JSON-serializable params dict for the ``analyze`` RPC.
    """
    params: dict[str, Any] = {"timeout_seconds": timeout_seconds}
    if profile != _DEFAULT_PROFILE:
        params["profile"] = profile
    if progress:
        params["progress"] = True
    return params


def _progress_log_payload(progress: rpc_framing.RpcProgress) -> dict[str, Any]:
    """Build the redacted, log-only ``extra`` payload for a relayed progress frame (master §5).

    Carries the SAFE percent + closed-vocabulary phase ONLY. There is no field here that could hold
    binary-derived ``TaskMonitor`` text — :class:`rpc_framing.RpcProgress` cannot even represent
    one, so the redaction is structural (the type, not a scrub pass). Keyed so it never trips the
    logger's sensitive-key redactor.

    Args:
        progress: The validated progress notification.

    Returns:
        A dict of safe structured-log fields (``percent`` + ``phase`` only).
    """
    return {"percent": progress.percent, "phase": progress.phase}


def _should_relay_progress(
    last_relayed_at: float | None, now: float, min_interval_s: float
) -> bool:
    """Decide whether to RELAY (log) a progress frame given the last relayed time (pure; ADR-030).

    Rate-limits log volume from a chatty/hostile worker: the first frame is always relayed; a later
    frame is relayed only if at least ``min_interval_s`` has elapsed since the last RELAYED one,
    otherwise it is coalesced (dropped from the log — but the caller still counts it toward the hard
    frame cap). Pure (monotonic ``now`` passed in) so it is unit-testable without a clock.

    Args:
        last_relayed_at: Monotonic time of the last relayed frame, or ``None`` if none yet.
        now: The current monotonic time.
        min_interval_s: Minimum spacing between relayed frames.

    Returns:
        ``True`` to relay (log) this frame; ``False`` to coalesce it.
    """
    if last_relayed_at is None:
        return True
    return (now - last_relayed_at) >= min_interval_s


class _Session:
    """Per-session worker + socket state owned by the adapter.

    Attributes:
        worker: The spawned worker process/container handle.
        sock: The connected UDS stream socket, or ``None`` before connect / after close.
        socket_path: Filesystem path of the per-session UDS.
        active_stream_id: The request id of the in-flight ``start_decompile_stream`` call (ADR-041),
            or ``None`` when no stream is producing. Set (under :attr:`lock`) when the streaming
            generator sends its RPC and cleared when it terminates. It doubles as the **socket-owner
            flag** (gap N1): while it is set, a plain :meth:`RpcGhidraAdapter._call` refuses to use
            the socket (the stream's reader holds no lock, so the flag — not a lock — is what
            excludes a concurrent call). ``cancel_job`` sends a ``$/cancel`` targeting THIS id, so
            worker stops the right call between functions.
        lock: Serializes **short, same-thread** socket sections (gap N1): the whole request→response
            transaction in :meth:`RpcGhidraAdapter._call`, and the brief connect+send+set-flag at a
            stream's start. It is NOT held across the streaming read — the generator is resumed by
            different pump threads and a thread-owned lock must be released by its acquiring thread,
            so the stream uses the ``active_stream_id`` flag for exclusion instead. Reentrant
            (``RLock``). ``kill_worker``/``_send_cancel`` deliberately do NOT take it: closing the
            socket is the mechanism that interrupts a hung read, and a ``$/cancel`` is the sole
            writer concurrent with the (lock-free) streamer read (full-duplex-safe).
    """

    __slots__ = ("active_stream_id", "lock", "sock", "socket_path", "worker")

    def __init__(self, worker: WorkerProcess, socket_path: str) -> None:
        """Initialize per-session state.

        Args:
            worker: The spawned worker handle.
            socket_path: Path of the per-session UDS.
        """
        self.worker = worker
        self.sock: socket.socket | None = None
        self.socket_path = socket_path
        self.active_stream_id: str | None = None
        self.lock = threading.RLock()


class RpcGhidraAdapter:
    """JSON-RPC-over-UDS adapter to per-session Ghidra workers (concrete ``GhidraPort``).

    Construction takes its collaborators by injection (dependency inversion — topic-dependency-
    injection): a :data:`WorkerLauncher` (WS3 container spawn), the socket directory, the per-call
    timeout, the analysis timeout, and the hard frame cap. No I/O happens at construction.
    """

    def __init__(
        self,
        *,
        launcher: WorkerLauncher,
        socket_dir: str,
        tool_timeout_s: float,
        analysis_timeout_s: float,
        max_response_bytes: int,
        limits: Limits | None = None,
        source_resolver: SourceResolver | None = None,
        connect_timeout_s: float = 30.0,
        worker_mem_mib: int = DEFAULT_WORKER_MEM_MIB,
        preflight_mode: str = DEFAULT_PREFLIGHT_MODE,
        stream_jobs: StreamingJobManager | None = None,
    ) -> None:
        """Initialize the adapter with injected runtime collaborators.

        Args:
            launcher: Callable that spawns a hardened worker bound to a session + socket path.
            socket_dir: Directory under which per-session UDS files live (``<dir>/<sid>.sock``).
            tool_timeout_s: Default per-tool-call wall-clock deadline.
            analysis_timeout_s: Per-analysis wall-clock deadline (kills worker on expiry).
            max_response_bytes: Hard frame cap; a declared length above this kills the worker.
            limits: Resolved resource limits; the binary-size cap is enforced from these BEFORE the
                worker is fed (defaults to built-in safe :class:`Limits`).
            source_resolver: Maps a (confined) ``source_ref`` to its byte size for the pre-Ghidra
                size check (defaults to :func:`_default_source_size`).
            connect_timeout_s: How long to wait for the worker to bind/accept on its socket.
            worker_mem_mib: Configured worker memory (MiB) — used ONLY for the OOM pre-flight
                (ADR-023 / F1, :func:`plausible_max_bytes`); defaults to the built-in worker memory
                default.
            preflight_mode: Over-plausible-size pre-flight behaviour (ADR-029 C; one of
                :data:`PREFLIGHT_MODES`): ``warn`` (log + proceed — the v1.3 default), ``reject``
                (fail closed with ``resource-exhausted`` before the worker is contacted), or ``off``
                (skip the check). Defaults to :data:`DEFAULT_PREFLIGHT_MODE`. The caller (config) is
                responsible for validating the value against the allow-list; an unrecognized value
                is treated as ``warn`` here (fail safe — never silently disables the heads-up).
            stream_jobs: Optional :class:`~vivarium.jobs.streaming.StreamingJobManager` that owns
                streaming-decompile jobs (ADR-040). Injected at the composition root so it shares
                the server's session-ownership authorizer + limits. ``None`` (the default) means
                streaming is not wired (the four stream methods then fail closed with a clear
                ``worker-unavailable``) — used by the non-streaming code paths/tests.
        """
        self._launcher = launcher
        self._socket_dir = socket_dir
        self._tool_timeout_s = tool_timeout_s
        self._analysis_timeout_s = analysis_timeout_s
        self._max_response_bytes = max_response_bytes
        self._limits = limits if limits is not None else Limits()
        self._source_resolver = source_resolver or _default_source_size
        self._connect_timeout_s = connect_timeout_s
        self._worker_mem_mib = worker_mem_mib
        # Defense in depth: config already allow-lists this, but if a bad value reaches us, fall
        # back to the safe warn mode rather than the silent ``off`` (never weaken the guard).
        self._preflight_mode = preflight_mode if preflight_mode in PREFLIGHT_MODES else "warn"
        self._stream_jobs = stream_jobs
        self._sessions: dict[str, _Session] = {}
        # Guards the _sessions dict STRUCTURE (add/pop/get) + the brief detached worker spawn (gap
        # N1). NEVER held across a request/stream socket transaction — that long socket I/O is
        # serialized per session by each _Session.lock, so distinct sessions stay fully concurrent.
        self._sessions_lock = threading.Lock()

    # --- worker/session lifecycle -----------------------------------------------------------
    def start_worker(self, session_id: str) -> None:
        """Spawn a hardened worker bound to ``session_id`` (no binary yet).

        Args:
            session_id: The opaque session id (also names the per-session socket).
        """
        with self._sessions_lock:
            if session_id in self._sessions:
                return  # idempotent: a worker already exists for this session
            sock_path = self._socket_path(session_id)
            worker = self._launcher(session_id, sock_path)
            self._sessions[session_id] = _Session(worker, sock_path)

    def kill_worker(self, session_id: str) -> None:
        """Forcibly terminate the session's worker and drop its socket. Idempotent.

        Args:
            session_id: The session whose worker to kill.
        """
        with self._sessions_lock:
            sess = self._sessions.pop(session_id, None)
        if sess is None:
            return
        # Close the socket WITHOUT taking sess.lock: a hung in-flight call/stream is holding that
        # lock blocked in recv(), and closing the fd from outside is precisely what unblocks it
        # (its recv raises → that path kills+evicts). Taking the lock here would deadlock (gap N1).
        self._close_socket(sess)
        # Best-effort kill: a launcher/runtime hiccup must not stop eviction (fail closed → drop).
        with contextlib.suppress(Exception):
            sess.worker.kill()

    def _resolve_and_cap(self, source_ref: str) -> int:
        """Confine + size-cap a ``source_ref`` server-side, pre-Ghidra (ADR-001 / CWE-22 / CWE-400).

        Resolves the ref through the injected confined resolver, maps a rejected/unresolvable ref to
        a category-SAFE ``VALIDATION`` (F4 reason: escapes-root / not-found / malformed — never the
        root path or the ref value, master §5), then enforces the hard binary-size cap and the OOM
        pre-flight. No byte reaches the JVM until the ref has passed all three. Shared by
        ``import_binary`` and ``version_track`` so both confine identically.

        Args:
            source_ref: The (server-side) reference to resolve and cap.

        Returns:
            The resolved input byte size (past the hard cap + pre-flight).

        Raises:
            GhidraMcpError: ``VALIDATION`` if the ref cannot be resolved; ``LIMIT_EXCEEDED`` if over
                the hard size cap; ``RESOURCE_EXHAUSTED`` if the reject-mode pre-flight trips.
        """
        try:
            size_bytes = self._source_resolver(source_ref)
        except (OSError, ValueError) as exc:
            # Fail closed: the resolver signalled an unresolvable/rejected ref (OSError from a
            # stat, or ValueError from a confined resolver rejecting a path outside its allow-list
            # root). Map to VALIDATION with a category-SAFE detail naming the specific reason (F4:
            # outside-root vs not-found vs malformed) so the client can self-correct — WITHOUT the
            # resolved root path or the source_ref value (master §5). The underlying exception is
            # chained SERVER-SIDE only. Any other exception type is a wiring/programmer bug and
            # propagates unmasked (fail fast — topic-error-handling).
            raw_reason = getattr(exc, "reason", None)
            if isinstance(raw_reason, str):
                reason = raw_reason
            elif isinstance(exc, FileNotFoundError):
                reason = "not-found"  # the built-in resolver's bare stat miss
            else:
                reason = ""
            detail = _SOURCE_REF_DETAILS.get(reason, _DEFAULT_SOURCE_REF_DETAIL)
            raise _errors.make_error(ErrorType.VALIDATION, detail) from exc
        # Fail closed BEFORE the worker: an over-cap binary is rejected pre-Ghidra (TB3 DoS).
        check_binary_size(size_bytes, self._limits)
        # OOM pre-flight (ADR-023 D3 + ADR-029 C): may warn, reject, or be skipped per the mode.
        self._preflight_check(size_bytes)
        return size_bytes

    def import_binary(  # noqa: C901 - one branch per loader kind + the ADR-065 region resolution
        self, session_id: str, args: s.SessionImportIn
    ) -> s.SessionInfo:
        """Import the binary into the session's worker, enforcing the size cap FIRST.

        The binary-size cap is checked server-side and pre-Ghidra (DoS first line — PLAN §3 F7,
        ADR-001: no byte reaches the JVM until it has passed the cap). The ``source_ref`` is
        resolved by the injected confined resolver; an over-cap input raises ``LIMIT_EXCEEDED``
        before the worker is contacted, and an unresolvable/rejected ref (resolver raising
        ``OSError`` or ``ValueError`` — see :data:`SourceResolver`) fails closed as ``VALIDATION``.

        After the hard cap, the configurable OOM pre-flight (ADR-029 C) runs: in ``reject`` mode an
        input above the OOM-plausible threshold fails closed with ``resource-exhausted`` BEFORE the
        worker is contacted; ``warn`` logs + proceeds (v1.3 behaviour); ``off`` skips the check.

        Args:
            session_id: The session.
            args: Import arguments (digest verification happens in the worker).

        Returns:
            Updated :class:`SessionInfo` (server-computed fields only — no binary-derived content),
            carrying the server-resolved ``binary_size`` overlaid onto the worker's reply.

        Raises:
            GhidraMcpError: ``VALIDATION`` if the ref cannot be resolved (resolver raised
                ``OSError`` or ``ValueError``); ``LIMIT_EXCEEDED`` if over the hard size cap;
                ``RESOURCE_EXHAUSTED`` if the pre-flight is in ``reject`` mode and the input
                exceeds the OOM-plausible threshold.
        """
        size_bytes = self._resolve_and_cap(args.source_ref)
        params: dict[str, object] = {
            "source_ref": args.source_ref,
            "expected_sha256": args.expected_sha256,
        }
        # ADR-065: a multi-region (scatter-load) raw import. Resolve + confine + size-cap EACH
        # region BEFORE the worker (per-region CWE-22/CWE-400), reject overlapping ranges with the
        # full known lengths, then thread a resolved region list. The schema already enforced
        # loader='binary', the shared processor, the mutual-exclusion with base_addr/entry, the
        # per-region address-width, and slice-region overlap; here we add the source_ref-region
        # size resolution + the full overlap check. `regions=None` skips this branch entirely.
        if args.regions is not None:
            params["loader"] = "binary"
            params["processor"] = args.processor
            resolved_regions: list[dict[str, object]] = []
            spans: list[tuple[int, int]] = []
            # AA7 (round-11) + AB8/AB9 (round-12): enforce an AGGREGATE byte budget across all
            # regions, not just the per-region cap — the worker loads every region into ONE program,
            # so N regions each at the single-binary cap would resident ~Nx the cap. Two refinements
            # over the round-11 cut: (AB9) a slice region is carved from the PARENT source_ref,
            # which the worker materializes whole to slice, so the parent's full size is added ONCE
            # to the peak when any slice is present (the round-11 total omitted it → real peak was
            # ~2x cap, not "<= single binary"); (AB8) the aggregate is run through the SAME OOM
            # `_preflight_check` (reject-mode) as the per-ref path, which the round-11 cut skipped.
            total_region_bytes = 0
            uses_parent_slice = False
            for region in args.regions:
                if region.source_ref is not None:
                    region_size = self._resolve_and_cap(region.source_ref)
                    region_path, region_offset, region_length = region.source_ref, 0, region_size
                else:
                    # A slice of the (already resolved + capped) parent source_ref.
                    region_offset = int(region.offset or 0)
                    region_length = int(region.length or 0)
                    if region_offset + region_length > size_bytes:
                        raise _errors.make_error(
                            ErrorType.VALIDATION, "a region slice exceeds the source length"
                        )
                    region_path = args.source_ref
                    uses_parent_slice = True
                total_region_bytes += region_length
                check_binary_size(total_region_bytes, self._limits)
                resolved_regions.append(
                    {
                        "source_ref": region_path,
                        "offset": region_offset,
                        "length": region_length,
                        "base_addr": region.base_addr,
                        "entry": region.entry,
                    }
                )
                spans.append((region.base_addr, region.base_addr + region_length))
            # AB9: account for the whole-parent materialization (once) that slice regions cause.
            peak_bytes = total_region_bytes + (size_bytes if uses_parent_slice else 0)
            check_binary_size(peak_bytes, self._limits)
            # AB8: the aggregate gets the same OOM reject-mode pre-flight as every per-ref import.
            self._preflight_check(peak_bytes)
            spans.sort()
            for (_a0, a_end), (b_start, _b1) in pairwise(spans):
                if b_start < a_end:
                    raise _errors.make_error(ErrorType.VALIDATION, "region address ranges overlap")
            params["regions"] = resolved_regions
        # Loader hints: only attach when explicitly opted in (loader != 'auto'). When loader='auto'
        # (the default) NO extra key crosses the wire — params are byte-for-byte identical to the
        # pre-ADR-045 auto path (the ADR-029/030 no-op guarantee). The schema has already validated
        # the hint combination + the processor allow-list server-side.
        elif args.loader == "binary":
            params["loader"] = args.loader
            params["processor"] = args.processor
            params["base_addr"] = args.base_addr
            if args.entry is not None:
                params["entry"] = args.entry
        elif args.loader in ("intel-hex", "motorola-hex"):
            # ADR-046: hex loaders take addresses from the records — only loader + processor cross.
            params["loader"] = args.loader
            params["processor"] = args.processor
        elif args.loader in ("dex", "apk"):
            # ADR-047: self-describing formats — force the loader; the format supplies everything.
            params["loader"] = args.loader
        elif args.loader == "macho":
            # ADR-047 force + ADR-048 optional fat-slice selection via `processor`.
            params["loader"] = args.loader
            if args.processor is not None:
                params["processor"] = args.processor
        # ADR-061 companion PDB (opt-in; loader='auto' only, enforced by the schema): confine +
        # size-cap the PDB with the SAME resolver/cap/pre-flight as the binary (no byte reaches the
        # JVM until it passes), then thread it. Absent → no key crosses (byte-for-byte no-op).
        if args.pdb_ref is not None:
            self._resolve_and_cap(args.pdb_ref)
            params["pdb_ref"] = args.pdb_ref
        # ADR-071 companion debug info (opt-in; loader='auto' only, enforced by the schema): confine
        # + size-cap the debug file with the SAME resolver/cap/pre-flight as the binary, then thread
        # it with its format. Absent → no key crosses (byte-for-byte no-op).
        if args.debug_ref is not None:
            self._resolve_and_cap(args.debug_ref)
            params["debug_ref"] = args.debug_ref
            params["debug_format"] = args.debug_format
        # ADR-070 container unwrap (opt-in): the compressed input already passed the standard size
        # cap above (as source_ref). Thread the token + the two zip-bomb caps (absolute output +
        # ratio); the WORKER streams the decompress against them and fails closed on overflow (the
        # server never parses container bytes — ADR-001/D4). Absent → no key crosses (no-op).
        if args.container is not None:
            params["container"] = args.container
            params["max_decompressed_bytes"] = _MAX_DECOMPRESSED_BYTES
            params["max_decompression_ratio"] = _MAX_DECOMPRESSION_RATIO
        result = self._call(
            session_id,
            "import_binary",
            params,
            timeout_s=self._tool_timeout_s,
        )
        info = _validate(s.SessionInfo, result)
        # Overlay the server-resolved input byte size onto the worker's reply (ADR-018 provenance).
        # The size is known here from the confined resolver — computed BEFORE any byte reached the
        # JVM (ADR-001: no binary parse) — and the worker does not report it. Advisory provenance
        # only, surfaced on ``SessionInfo`` like ``binary_sha256`` (server-computed, safe).
        return info.model_copy(update={"binary_size": size_bytes})

    def _preflight_check(self, size_bytes: int) -> None:
        """Apply the over-plausible-size pre-flight per the configured mode (ADR-029 C).

        Runs AFTER the hard binary-size cap, BEFORE the worker is contacted. ``off`` skips entirely;
        otherwise an input above :func:`plausible_max_bytes` either logs a heads-up and proceeds
        (``warn``) or fails closed with ``resource-exhausted`` (``reject``). The log and error carry
        ONLY the size + configured memory — never content/path (master §5 redaction; the error
        detail is the fixed safe hint from :func:`_errors.resource_exhausted`).

        Args:
            size_bytes: The resolved candidate input size (already past the hard cap).

        Raises:
            GhidraMcpError: ``RESOURCE_EXHAUSTED`` when in ``reject`` mode and the input exceeds the
                OOM-plausible threshold.
        """
        if self._preflight_mode == "off":
            return
        if size_bytes <= plausible_max_bytes(self._worker_mem_mib):
            return
        if self._preflight_mode == "reject":
            # Fail closed pre-Ghidra: an input this large would very likely OOM-kill the worker;
            # reject it now with the actionable, content-free hint rather than burn a worker on it.
            _log.warning(
                "worker.preflight_rejected",
                extra={"size_bytes": size_bytes, "worker_mem_mib": self._worker_mem_mib},
            )
            raise _errors.resource_exhausted(self._worker_mem_mib)
        # warn: emit a heads-up (size + configured memory ONLY) and PROCEED — the hard size cap and
        # the worker's memory cgroup remain the enforcing controls.
        _log.warning(
            "worker.preflight_oversized",
            extra={"size_bytes": size_bytes, "worker_mem_mib": self._worker_mem_mib},
        )

    def analyze(
        self,
        session_id: str,
        args: s.SessionAnalyzeIn,
        *,
        on_progress: port.OnProgress | None = None,
    ) -> s.SessionInfo:
        """Run Ghidra auto-analysis, bounded by the analysis timeout (kills worker on expiry).

        The additive ``profile`` (ADR-029 B) selects the analyzer-depth preset. When it is the
        default the analyze RPC params are IDENTICAL to today's (no ``profile`` key — the worker
        takes the unchanged code path); ``light``/``deep`` add the explicit preset.

        Progress emission (ADR-030) is driven by two independent inputs, OR-ed into one decision:
        ``args.progress`` (the Phase-1 explicit opt-in, log-only) and ``on_progress`` (the Phase-2
        client relay). The worker is told to emit ``$/progress`` frames iff EITHER is set; when it
        is, the call enters the bounded read-loop, which always relays each frame to the SERVER LOG
        and — when ``on_progress`` is present — ALSO invokes it (the server forwards to the MCP
        client via ``Context.report_progress``). When NEITHER is set the params and read path are
        byte-for-byte today's single-frame call. The deadline below is computed ONCE and bounds the
        WHOLE loop — progress frames never extend it (ADR-002 SIGKILL still fires on a hung/chatty
        worker).

        Args:
            session_id: The session.
            args: Analysis arguments (optional timeout override, already clamped by the server; the
                analyzer profile; the Phase-1 progress opt-in).
            on_progress: Optional Phase-2 client-relay callback (``None`` on stdio / no token).

        Returns:
            Updated :class:`SessionInfo`.
        """
        # Clamp the client override DOWN to the configured analysis ceiling (defense-in-depth DoS:
        # the schema bounds timeout_seconds to <=3600, but the deployment's configured max may be
        # lower — never let a per-call arg exceed it). No override → use the configured ceiling.
        # NOTE: this deadline is the ONE-SHOT analysis deadline (ADR-030: NOT extended by progress).
        deadline = (
            min(float(args.timeout_seconds), self._analysis_timeout_s)
            if args.timeout_seconds
            else self._analysis_timeout_s
        )
        # Emit iff EITHER the Phase-1 opt-in OR the Phase-2 client relay is requested. A client
        # progressToken (→ on_progress) implies "I want progress", so we force worker emission on
        # without requiring the caller to ALSO pass progress=true (ADR-030 Phase 2 D1).
        emit_progress = bool(args.progress) or on_progress is not None
        result = self._call(
            session_id,
            "analyze",
            _analyze_params(args.timeout_seconds, args.profile, progress=emit_progress),
            timeout_s=deadline,
            expect_progress=emit_progress,
            on_progress=on_progress,
        )
        return _validate(s.SessionInfo, result)

    # --- read-only tool operations ----------------------------------------------------------
    # Each method takes the worker's PLAIN result dict and builds the typed ``*Out`` via a module-
    # level builder that wraps every binary-derived field at the right provenance (PM #9, ADR-005).
    def decompile_function(self, sid: str, a: s.DecompileFunctionIn) -> s.DecompiledFunction:
        """Decompile one function (decompiler output → GHIDRA-origin untrusted)."""
        return _build_decompiled(
            self._tool_call(sid, "decompile_function", {"function": a.function})
        )

    # --- streaming-decompile (ADR-040) -----------------------------------------------------------
    def decompile_stream(
        self, sid: str, a: st.DecompileStreamIn, *, terminal: st.StreamTerminal | None = None
    ) -> Iterator[s.DecompiledFunction]:
        """Stream decompiled functions incrementally from the worker (ADR-040 — increment 2b).

        Returns a **lazy iterator** (generator): nothing is sent until the first ``next()``. On that
        first pull it issues the ``start_decompile_stream`` RPC, then reads the interleaved
        ``$/progress`` + ``$/chunk`` + terminal-response frames within the call deadline,
        classifying each (rpc-protocol.md §4):

        - ``$/progress`` → relayed to the server log (redacted — percent + closed phase only) and
          skipped (the job buffers results, not heartbeats);
        - ``$/chunk`` → parsed + the **gap-free, monotonic ``seq`` asserted** against the next
          expected value; the per-chunk binary-derived fields are wrapped at the ADR-005 chokepoint
          and yielded as a :class:`DecompiledFunction`;
        - the terminal response → ends the stream (``done``); its ``{total, truncated}`` is recorded
          on ``terminal`` (when supplied) so the server can surface ``truncated`` honestly;
        - a worker ``error`` response or any protocol/framing violation → kills the worker + evicts
          (the universal fault handler) and **raises** so the job ends in a terminal ``error``
          (never an ambiguous early ``done`` — ADR-005).

        A non-monotonic / gapped ``seq`` or an out-of-vocabulary ``kind`` is a protocol violation
        (``parse_chunk`` enforces the per-frame shape; the gap-free invariant ACROSS frames is
        asserted here) → kill + evict.

        Args:
            sid: The session id.
            a: The stream-start arguments (explicit function set or a bounded window).
            terminal: Optional out-parameter the generator fills with the worker's terminal
                ``{total, truncated}`` when the stream completes cleanly (lets the job report
                ``truncated`` — the iterator interface itself cannot return it).

        Returns:
            A lazy iterator of decompiled functions, one per worker ``$/chunk``.

        Raises:
            GhidraMcpError: ``WORKER_UNAVAILABLE`` / ``TIMEOUT`` / a mapped worker error on any
                failure (raised lazily from within the generator on the relevant ``next()``).
        """
        return self._decompile_stream_gen(sid, a, terminal)

    def _decompile_stream_gen(
        self, sid: str, a: st.DecompileStreamIn, terminal: st.StreamTerminal | None
    ) -> Iterator[s.DecompiledFunction]:
        """Generator backing :meth:`decompile_stream` (lazy: sends the RPC on first ``next()``).

        Kept as a separate generator function so :meth:`decompile_stream` returns immediately while
        production stays lazy. See :meth:`decompile_stream` for the full protocol.

        Args:
            sid: The session id.
            a: The stream-start arguments.
            terminal: Optional terminal out-parameter (filled on clean completion).

        Yields:
            One :class:`DecompiledFunction` per worker ``$/chunk``.
        """
        with self._sessions_lock:
            sess = self._sessions.get(sid)
        if sess is None:
            raise _errors.make_error(ErrorType.WORKER_UNAVAILABLE, "no worker for session")
        request_id = uuid.uuid4().hex
        params = _stream_start_params(a)
        frame = rpc_framing.encode_frame(
            rpc_framing.build_request(request_id, "start_decompile_stream", params),
            max_frame_bytes=self._max_response_bytes,
        )
        # A bulk decompile is a long operation; bound it by the analysis deadline (kill-on-expiry,
        # NOT extended by chunks — ADR-002). The job lives inside the worker's bounded lifetime.
        deadline = time.monotonic() + self._analysis_timeout_s
        # gap N1: a concurrent same-session _call must not read frames off this socket while a
        # produces (it would steal chunks). We do NOT hold sess.lock across the stream — the
        # generator is resumed by different pump threads, and a thread-owned lock must be freed by
        # the SAME thread that took it. Instead, briefly hold sess.lock (same thread) to connect,
        # send the start, and set the active_stream_id FLAG atomically against a concurrent _call;
        # then release. The read loop below holds NO lock: _call refuses while active_stream_id is
        # set, only one pump runs at a time (job-manager lock), and _send_cancel is the sole writer
        # concurrent with our read (full-duplex). The flag is cleared in the finally.
        try:
            with sess.lock:
                # W1 (round-7): refuse if a stream already owns this session's socket — symmetric
                # with the plain-_call guard (gap N1). The flag stays set for a just-cancelled
                # stream's *drain* window too (V1 reap_cancelled; the producer finally is its only
                # clearer). Without this guard a concurrent cancel+start on one session (HTTP
                # thread pool) could open a 2nd stream on the same UDS while the old drain still
                # reads → the two read loops steal each other's frames → desync → kill_worker.
                # Checked under sess.lock: atomic vs a concurrent _call or another stream-start.
                if sess.active_stream_id is not None:
                    raise _errors.make_error(
                        ErrorType.WORKER_UNAVAILABLE, "session busy (a stream is in progress)"
                    )
                # Q4: connect + send share the stream's absolute analysis deadline (connect gives up
                # at the earlier of connect_timeout_s or the deadline), so warm-up can't overrun it.
                sock = self._ensure_connected(sess, deadline=deadline)
                self._send_all_with_timeout(sock, frame, max(0.0, deadline - time.monotonic()))
                # Set only after the start RPC is on the wire so a cancel before the worker sees the
                # start cannot mis-target an unsent id (ADR-041).
                sess.active_stream_id = request_id
            yield from self._read_stream_chunks(
                sock, sid, expected_id=request_id, deadline=deadline, terminal=terminal
            )
        except RpcCallError as exc:
            # A method-level worker failure mid-stream: the worker is healthy, do NOT kill. Map the
            # slug; the job manager turns the raised GhidraMcpError into a terminal error chunk.
            # Q8: the worker's free-form message is LOG-ONLY (never the client envelope) — it is
            # untrusted worker output (TB2/TB3) that would bypass the envelope normalization.
            _log.warning(
                "stream.worker_error",
                extra={
                    "code": exc.error.code,
                    "slug": exc.error.type_slug,
                    "detail": exc.error.detail,
                    "worker_message": exc.error.message,
                },
            )
            raise _errors.worker_method_error_from(exc.error.code, exc.error.type_slug) from exc
        except TimeoutError as exc:
            _log.warning("stream.rpc_failed", extra={"cause": "timeout", "detail": str(exc)[:300]})
            self.kill_worker(sid)
            raise _errors.make_error(ErrorType.TIMEOUT, "stream exceeded its time limit") from exc
        except (FramingError, RpcProtocolError) as exc:
            # Hostile/buggy worker: protocol/framing/seq violation → kill + evict.
            _log.warning(
                "stream.rpc_failed",
                extra={"cause": "protocol", "exc": type(exc).__name__, "detail": str(exc)[:300]},
            )
            self.kill_worker(sid)
            raise _errors.make_error(
                ErrorType.WORKER_UNAVAILABLE, "worker protocol violation"
            ) from exc
        except (ConnectionError, EOFError, OSError) as exc:
            diagnosis = self._diagnose_worker_exit(sess)
            _log.warning(
                "stream.rpc_failed",
                extra={
                    "cause": "resource-exhausted" if diagnosis == "oom" else "transport",
                    "exc": type(exc).__name__,
                    "detail": str(exc)[:300],
                },
            )
            self.kill_worker(sid)
            if diagnosis == "oom":
                raise _errors.resource_exhausted(self._worker_mem_mib) from exc
            raise _errors.make_error(ErrorType.WORKER_UNAVAILABLE, "worker unavailable") from exc
        finally:
            # The stream is no longer producing (clean completion, error, or generator close): clear
            # the active id so a later cancel_job does not target a finished call (ADR-041 D6 — a
            # $/cancel for a finished id is a worker no-op anyway, but not sending one is cleaner).
            # Re-fetch by sid: the session may have been evicted/replaced during the stream.
            with self._sessions_lock:
                live = self._sessions.get(sid)
            if live is sess and live.active_stream_id == request_id:
                live.active_stream_id = None

    def _relay_stream_progress(
        self,
        frame: dict[str, Any],
        *,
        expected_id: str,
        progress_count: int,
        last_relayed_at: float | None,
    ) -> float | None:
        """Enforce the ``$/progress`` flood cap and coalesce the relay log for one stream frame.

        X9 (round-8): ``progress_count`` (already incremented) over :data:`_MAX_PROGRESS_FRAMES`
        is a hostile-worker flood → raise (mapped to kill+evict); the deadline bounds wall-clock
        but a worker emitting endless progress frames is a protocol violation, not a slow one.

        Y7 (round-9): the relay LOG is coalesced to :data:`_MIN_PROGRESS_INTERVAL_S` (symmetric
        with the analyze path) so a chatty worker can't flood the log — the cap above stays
        UNCONDITIONAL, so coalescing never weakens the flood bound. Returns the new
        ``last_relayed_at``.
        """
        if progress_count > _MAX_PROGRESS_FRAMES:
            raise RpcProtocolError("stream progress-frame flood exceeded the per-call cap")
        progress = rpc_framing.parse_progress(frame, expected_id=expected_id)
        now = time.monotonic()
        if _should_relay_progress(last_relayed_at, now, _MIN_PROGRESS_INTERVAL_S):
            _log.info("stream.progress", extra=_progress_log_payload(progress))
            return now
        return last_relayed_at

    def _read_stream_chunks(
        self,
        sock: socket.socket,
        sid: str,
        *,
        expected_id: str,
        deadline: float,
        terminal: st.StreamTerminal | None,
    ) -> Iterator[s.DecompiledFunction]:
        """Read interleaved ``$/progress``/``$/chunk`` then the terminal response (ADR-040 loop).

        Each iteration reads one frame within the SHRINKING remaining time of the one-shot stream
        deadline (chunks NEVER extend it — ADR-002), classifies it, and either relays progress,
        yields a chunk, or returns on the terminal response. Enforces the gap-free monotonic ``seq``
        invariant across frames and a per-call chunk-count flood cap (TB2/TB3).

        Args:
            sock: The connected worker socket.
            sid: The session id (for safe log context — length only, never the opaque id value).
            expected_id: The streaming request id every frame must correlate to.
            deadline: The monotonic wall-clock deadline for the whole stream.
            terminal: Optional out-parameter filled with ``{total, truncated}`` on clean completion.

        Yields:
            One :class:`DecompiledFunction` per ``$/chunk`` frame, in ``seq`` order.

        Raises:
            RpcProtocolError: On a gapped/non-monotonic ``seq`` or a chunk flood over the cap.
            RpcCallError: When the terminal frame is a worker ``error`` response.
            TimeoutError: If the deadline elapses before the terminal response arrives.
        """
        next_seq = 0
        chunk_count = 0
        progress_count = 0
        last_relayed_at: float | None = None  # Y7: coalesce the progress LOG (not the count/cap)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("stream deadline elapsed during chunk read-loop")
            # _read_frame re-arms the socket timeout to the shrinking remaining time before EACH
            # recv (slow-loris hardening), so the whole frame is bounded by the same deadline.
            frame = self._read_frame(sock, deadline)
            if rpc_framing.is_progress_notification(frame):
                progress_count += 1
                last_relayed_at = self._relay_stream_progress(
                    frame,
                    expected_id=expected_id,
                    progress_count=progress_count,
                    last_relayed_at=last_relayed_at,
                )
                continue
            if rpc_framing.is_chunk_notification(frame):
                chunk_count += 1
                if chunk_count > _MAX_STREAM_CHUNKS:
                    raise RpcProtocolError("stream chunk flood exceeded the per-call cap")
                chunk = rpc_framing.parse_chunk(frame, expected_id=expected_id)
                if chunk.seq != next_seq:
                    # Gap-free, monotonic seq is the resume/ordering invariant (ADR-040 D7); a
                    # mismatch is a hostile/buggy worker → kill + evict (the caller maps it).
                    raise RpcProtocolError("stream chunk seq is not gap-free monotonic")
                next_seq += 1
                yield _build_decompiled(chunk.payload)
                continue
            # Not a notification → the terminal response. parse_response validates id/result/error;
            # a worker error raises RpcCallError (→ terminal error chunk). On success, record the
            # honest {total, truncated} for the server and end the stream (StopIteration → done).
            result = rpc_framing.parse_response(frame, expected_id=expected_id)
            if terminal is not None:
                # V9 (defense-in-depth, LLM02): the worker-reported `total` is untrusted (TB2) and
                # feeds ONLY the server-side ETA. Bound it so a hostile/garbage value can't yield a
                # nonsensical ETA (or crash the read path via a non-int). A stream emits at most
                # _MAX_STREAM_CHUNKS (the flood cap above) and never fewer than the `next_seq`
                # already produced → clamp to [next_seq, _MAX_STREAM_CHUNKS]; a non-numeric total
                # falls back to the produced count (fail closed to a safe, honest value).
                # W6 (round-7, accepted): this clamp lives in rpc_client — NOT one of the 7
                # 100%-critical + mutation-scoped modules — BY DESIGN. It is a non-boundary ETA
                # hint, not a security invariant (the streaming trust boundary — BOLA/replay/seq —
                # is in the 100%-gated jobs/streaming.py). Unit-tested (test_streaming_adapter.py:
                # huge + non-numeric cases); a helper in a mutated module would be over-engineering.
                try:
                    reported_total = int(result.get("total", next_seq))
                except (TypeError, ValueError):
                    reported_total = next_seq
                terminal.total = max(next_seq, min(reported_total, _MAX_STREAM_CHUNKS))
                terminal.truncated = bool(result.get("truncated", False))
            return

    def attach_stream_jobs(self, manager: StreamingJobManager) -> None:
        """Inject the streaming-job manager after construction (ADR-040; composition-root wiring).

        Resolves the composition cycle: the manager needs the session manager's authorizer, the
        session manager needs this port, so the manager is built last and bound here. Idempotent
        replace.

        Args:
            manager: The constructed :class:`~vivarium.jobs.streaming.StreamingJobManager`.
        """
        self._stream_jobs = manager

    def _require_stream_jobs(self) -> StreamingJobManager:
        """Return the wired streaming-job manager or fail closed if streaming is not configured.

        Returns:
            The injected :class:`StreamingJobManager`.

        Raises:
            GhidraMcpError: ``WORKER_UNAVAILABLE`` when no manager was injected (streaming off).
        """
        if self._stream_jobs is None:
            raise _errors.make_error(
                ErrorType.WORKER_UNAVAILABLE,
                "streaming is not enabled on this server",
            )
        return self._stream_jobs

    def start_decompile_stream(self, sid: str, a: st.DecompileStreamIn, *, caller: str) -> str:
        """Start a bounded bulk-decompile streaming job, returning its opaque handle (ADR-040).

        Delegates to the injected :class:`StreamingJobManager`, feeding it the worker-streaming
        producer (:meth:`decompile_stream`) bounded to ``a.limit`` functions. The manager
        authorizes the session (BOLA), enforces one-active-job-per-session, and pumps the first
        batch under the bounded buffer.

        Args:
            sid: The session id.
            a: The stream-start arguments.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            The opaque job handle.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe), ``LIMIT_EXCEEDED`` (already active), or
                ``WORKER_UNAVAILABLE`` (streaming off).
        """
        jobs = self._require_stream_jobs()
        # A shared terminal holder: the producer fills {total, truncated} from the worker's
        # terminal response; the job reads it to report ``truncated`` honestly (ADR-040 D8). Passing
        # the SAME object to both the producer and the job is the decoupling seam (the iterator
        # interface cannot itself return the job-level summary).
        terminal = st.StreamTerminal()
        producer = self.decompile_stream(sid, a, terminal=terminal)
        return jobs.start_job(
            sid, producer=producer, total=a.limit, caller=caller, terminal=terminal
        )

    def fetch_job_results(
        self, sid: str, a: st.FetchJobResultsIn, *, caller: str
    ) -> st.StreamFetchResult:
        """Pull the next bounded, ordered batch of chunks from a job (cursor resume — ADR-040).

        Args:
            sid: The session id.
            a: The fetch arguments (job handle, optional cursor, batch limit).
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            The :class:`~vivarium.jobs.streaming.StreamFetchResult` batch + resume cursor + state.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe), ``VALIDATION`` (bad cursor/limit), or
                ``WORKER_UNAVAILABLE`` (streaming off).
        """
        jobs = self._require_stream_jobs()
        return jobs.fetch(sid, a.job_id, cursor=a.cursor, limit=a.limit, caller=caller)

    def job_status(self, sid: str, a: st.JobHandleIn, *, caller: str) -> st.StreamJobStatus:
        """Return a job's server-authored status (counts/state/ETA; no binary content — ADR-040).

        Args:
            sid: The session id.
            a: The job-handle arguments.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            The :class:`~vivarium.jobs.streaming.StreamJobStatus` snapshot.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) or ``WORKER_UNAVAILABLE`` (no stream).
        """
        jobs = self._require_stream_jobs()
        return jobs.status(sid, a.job_id, caller=caller)

    def cancel_job(self, sid: str, a: st.JobHandleIn, *, caller: str) -> st.StreamJobStatus:
        """Cancel a job (free the worker early), returning its terminal status (ADR-040 D6).

        The manager authorizes (BOLA) + marks the job cancelled + drops its buffer FIRST (so an
        unauthorized caller never causes a worker side effect). On a successful cancel of a job that
        was still producing, a best-effort ``$/cancel`` notification (ADR-041) is sent to the worker
        targeting the in-flight streaming call's request id, freeing worker capacity promptly: the
        worker polls for it BETWEEN functions and stops production at the next function boundary,
        rather than decompiling the whole bounded set after the client has cancelled.

        The send is best-effort — wrapped so a worker hiccup never fails the (already applied)
        server-side cancel, which is the authoritative state change. The §6 deadline + eviction
        remain the backstop if the notification is never observed.

        Args:
            sid: The session id.
            a: The job-handle arguments.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            The job's terminal :class:`~vivarium.jobs.streaming.StreamJobStatus`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) or ``WORKER_UNAVAILABLE`` (no stream).
        """
        jobs = self._require_stream_jobs()
        status = jobs.cancel(sid, a.job_id, caller=caller)
        # Best-effort worker-side early stop: only attempt it for a session we still have a worker
        # for, and never let it raise (the server-side cancel above is authoritative + done).
        if sid in self._sessions:
            with contextlib.suppress(Exception):
                self._send_cancel(sid)
            # V1: the cancelled job's producer is otherwise abandoned mid-stream — its generator
            # never resumes, so its finally (the sole clearer of active_stream_id) never runs and
            # the session stays "session busy" for every plain call until eviction. Drain it now
            # (AFTER $/cancel so the worker stops promptly): this consumes the worker's residual
            # chunks + terminal frame — leaving the socket byte-clean so the next call does not
            # desync — and runs the generator finally, which clears the flag and frees the session.
            # Best-effort: the server-side cancel above is already authoritative.
            with contextlib.suppress(Exception):
                jobs.reap_cancelled(sid, a.job_id, caller=caller)
        return status

    def _send_cancel(self, sid: str) -> None:
        """Send a best-effort ``$/cancel`` notification to a session's worker (ADR-041).

        Targets the session's in-flight ``start_decompile_stream`` request id (``active_stream_id``)
        so the worker — polling between functions — stops the right call at the next boundary. A
        notification, NOT a request: it adds no request/response pair to the streaming socket
        (ADR-041 D1). Best-effort — the caller suppresses failures; when no stream is active or no
        connection exists there is nothing to signal (a no-op). **Deliberately lock-free** (gap N1):
        it only fires when ``active_stream_id`` is set, i.e. while a stream owns the socket and its
        reader is *reading* (the reader holds no lock — exclusion is the flag). This is therefore
        the sole writer concurrent with that read (full-duplex-safe), and a plain ``_call``
        refuses the socket while the flag is set, so none is mid-transaction.

        The mutable ``sess.sock`` is **snapshotted once** into a local: a concurrent lock-free
        ``kill_worker`` → ``_close_socket`` may null it, and re-reading after the ``None`` guard was
        a check-then-use TOCTOU (``AttributeError`` on ``None.sendall`` — R11/round-5). Operating on
        the snapshot removes that window; the send is still best-effort (a send on a just-closed fd
        is caught by the caller's suppression).

        Args:
            sid: The session id whose worker to signal.
        """
        sess = self._sessions.get(sid)
        if sess is None:
            return  # no such session — nothing to signal
        sock = sess.sock  # snapshot once (a concurrent kill may null sess.sock — see docstring)
        stream_id = sess.active_stream_id
        if sock is None or stream_id is None:
            return  # no live connection / no in-flight stream to target (a no-op)
        frame = rpc_framing.encode_frame(
            rpc_framing.build_cancel(stream_id),
            max_frame_bytes=self._max_response_bytes,
        )
        sock.sendall(frame)

    def disassemble(self, sid: str, a: s.DisassembleIn) -> s.DisassembleOut:
        """Disassemble a bounded range or function."""
        return _build_disassemble(
            self._tool_call(
                sid,
                "disassemble",
                {"start": a.start, "function": a.function, "max_instructions": a.max_instructions},
            )
        )

    def get_pcode(self, sid: str, a: s.GetPcodeIn) -> s.GetPcodeOut:
        """List lifted low p-code for a bounded range or function (ADR-052)."""
        return _build_get_pcode(
            self._tool_call(
                sid,
                "get_pcode",
                {"start": a.start, "function": a.function, "max_instructions": a.max_instructions},
            )
        )

    def get_high_pcode(self, sid: str, a: s.GetHighPcodeIn) -> s.GetHighPcodeOut:
        """Return a function's decompiler-refined high (SSA) p-code (ADR-053)."""
        return _build_get_high_pcode(
            self._tool_call(sid, "get_high_pcode", {"function": a.function, "max_ops": a.max_ops})
        )

    def data_flow_slice(self, sid: str, a: s.DataFlowSliceIn) -> s.DataFlowSliceOut:
        """Return a bounded intra-function def-use slice from a seed (ADR-064)."""
        return _build_data_flow_slice(
            self._tool_call(
                sid,
                "data_flow_slice",
                {
                    "function": a.function,
                    "seed": a.seed,
                    "direction": a.direction,
                    "max_nodes": a.max_nodes,
                    "max_depth": a.max_depth,
                },
            )
        )

    def recover_struct(self, sid: str, a: s.RecoverStructIn) -> s.RecoverStructOut:
        """Propose a struct layout from access patterns off a base pointer (ADR-069)."""
        return _build_recover_struct(
            self._tool_call(
                sid,
                "recover_struct",
                {
                    "function": a.function,
                    "base": a.base,
                    "max_fields": a.max_fields,
                    "max_accesses": a.max_accesses,
                },
            )
        )

    def deobfuscate_strings(self, sid: str, a: s.DeobfuscateStringsIn) -> s.DeobfuscateStringsOut:
        """Recover hidden (stack-string) strings from a function/program scan (ADR-068)."""
        return _build_deobfuscate_strings(
            self._tool_call(
                sid,
                "deobfuscate_strings",
                {
                    "function": a.function,
                    "techniques": a.techniques,
                    "min_length": a.min_length,
                    "max_results": a.max_results,
                    "max_bytes": a.max_bytes,
                    "max_steps": a.max_steps,
                },
            )
        )

    def stack_frame(self, sid: str, a: s.StackFrameIn) -> s.StackFrameOut:
        """Return a function's recovered stack-frame layout (ADR-054)."""
        return _build_stack_frame(self._tool_call(sid, "stack_frame", {"function": a.function}))

    def basic_blocks(self, sid: str, a: s.BasicBlocksIn) -> s.BasicBlocksOut:
        """Return a function's basic blocks + successor edges (ADR-055)."""
        return _build_basic_blocks(
            self._tool_call(
                sid, "basic_blocks", {"function": a.function, "max_blocks": a.max_blocks}
            )
        )

    def list_data_types(self, sid: str, a: s.ListDataTypesIn) -> s.DataTypeListOut:
        """List the program's data types, paginated (ADR-056)."""
        return _build_data_type_list(
            self._tool_call(
                sid,
                "list_data_types",
                {"offset": a.offset, "limit": a.limit, "name_contains": a.name_contains},
            )
        )

    def function_hash(self, sid: str, a: s.FunctionHashIn) -> s.FunctionHashOut:
        """Return a function's Ghidra match-hash fingerprints (ADR-057)."""
        return _build_function_hash(self._tool_call(sid, "function_hash", {"function": a.function}))

    def program_fingerprint(self, sid: str, a: s.ProgramFingerprintIn) -> s.ProgramFingerprintOut:
        """Return whole-program pivot digests (ADR-073 D1)."""
        return _build_program_fingerprint(self._tool_call(sid, "program_fingerprint", {}))

    def family_match(self, sid: str, a: s.FamilyMatchIn) -> s.FamilyMatchOut:
        """Rank candidate families by fingerprint vs the offline corpus (PURE core; ADR-073 D2).

        Computes this program's digests via ``program_fingerprint`` (D1; no new worker verb),
        loads the bundled offline corpus (no network — containment intact), and runs the pure
        :func:`core.familymatch.match`. HEURISTIC: an empty result means "not in the corpus", NOT
        "benign". All fields SAFE (curated family labels + scalars).
        """
        from vivarium.core import familymatch

        fingerprint = self.program_fingerprint(sid, s.ProgramFingerprintIn(session_id=a.session_id))
        corpus = familymatch.load_default_corpus()
        hits = familymatch.match(
            fingerprint.structure_digest,
            fingerprint.import_digest,
            corpus,
            max_candidates=a.max_candidates,
        )
        return s.FamilyMatchOut(
            candidates=[
                s.FamilyCandidate(family=h.family, confidence=h.confidence, basis=list(h.basis))
                for h in hits
            ],
            corpus_version=corpus.version,
            truncated=len(hits) >= a.max_candidates,
        )

    def bsim_similarity(self, sid: str, a: s.BsimSimilarityIn) -> s.BsimSimilarityOut:
        """Return the BSim cosine similarity between two functions (ADR-058)."""
        return _build_bsim_similarity(
            self._tool_call(
                sid, "bsim_similarity", {"function_a": a.function_a, "function_b": a.function_b}
            )
        )

    def find_similar_functions(
        self, sid: str, a: s.FindSimilarFunctionsIn
    ) -> s.FindSimilarFunctionsOut:
        """Rank the program's functions by BSim similarity to a target (ADR-059)."""
        return _build_find_similar_functions(
            self._tool_call(
                sid,
                "find_similar_functions",
                {
                    "function": a.function,
                    "min_similarity": a.min_similarity,
                    "limit": a.limit,
                    "max_scan": a.max_scan,
                },
            )
        )

    def version_track(self, sid: str, a: s.VersionTrackIn) -> s.VersionTrackOut:
        """Correlate functions between two confined binaries via Ghidra VT (ADR-060).

        Both refs are confined + size-capped server-side BEFORE the worker is contacted (ADR-001: no
        byte reaches the JVM until it passes the cap), reusing the same resolver/cap/pre-flight as
        ``import_binary`` (:meth:`_resolve_and_cap`). The worker loads both fresh, analyzes both,
        runs the (allow-listed) correlator, and wipes them — the session program is untouched. The
        call is bounded by the (longer) analysis timeout: two imports + two analyses + a correlation
        cost far more than a single read-only tool call.

        Args:
            sid: The session (supplies auth/scoping + the worker; not a program).
            a: Validated ``version_track`` arguments (correlator is a closed ``Literal``).

        Returns:
            The VT matches (addresses + scores, all SAFE) with a total ``match_count`` +
            ``truncated``.

        Raises:
            GhidraMcpError: ``VALIDATION`` / ``LIMIT_EXCEEDED`` / ``RESOURCE_EXHAUSTED`` if a ref
                fails confinement/cap/pre-flight (per :meth:`_resolve_and_cap`).
        """
        # Confine + cap BOTH refs pre-Ghidra (fail closed before the worker touches either byte).
        self._resolve_and_cap(a.source_ref_a)
        self._resolve_and_cap(a.source_ref_b)
        return _build_version_track(
            self._call(
                sid,
                "version_track",
                {
                    "source_ref_a": a.source_ref_a,
                    "source_ref_b": a.source_ref_b,
                    "correlator": a.correlator,
                    "min_confidence": a.min_confidence,
                    "limit": a.limit,
                },
                timeout_s=self._analysis_timeout_s,
            )
        )

    def binary_diff(self, sid: str, a: s.BinaryDiffIn) -> s.BinaryDiffOut:
        """Function-granularity diff of two confined binaries (session read-only — ADR-067).

        Both refs are confined + size-capped server-side BEFORE the worker (reusing the
        ``import_binary`` resolver/cap/pre-flight); the worker loads both fresh, analyzes both,
        diffs, and wipes them. Bounded by the (longer) analysis timeout (two loads + two
        analyses).
        """
        self._resolve_and_cap(a.program_a)
        self._resolve_and_cap(a.program_b)
        return _build_binary_diff(
            self._call(
                sid,
                "binary_diff",
                {
                    "program_a": a.program_a,
                    "program_b": a.program_b,
                    "match_by": a.match_by,
                    "min_similarity": a.min_similarity,
                    "include_unchanged": a.include_unchanged,
                    "max_entries": a.max_entries,
                },
                timeout_s=self._analysis_timeout_s,
            )
        )

    def bsim_search_corpus(self, sid: str, a: s.BsimSearchCorpusIn) -> s.BsimSearchCorpusOut:
        """Cross-binary BSim search over an ephemeral reference corpus (ADR-062).

        Confines + size-caps the target AND every reference ref (the same resolver/cap/pre-flight as
        ``import_binary`` — no byte reaches the JVM until it passes) BEFORE the worker is contacted,
        then issues the RPC bounded by the (longer) analysis timeout: N+1 loads + analyses + the
        BSim comparison cost far more than one read-only tool call.

        Args:
            sid: The session (supplies auth/scoping + the worker; not a program).
            a: Validated ``bsim_search_corpus`` arguments.

        Returns:
            The per-target best cross-binary matches (names Untrusted; addresses/scores SAFE) with
            scan counts + ``truncated``.

        Raises:
            GhidraMcpError: ``VALIDATION`` / ``LIMIT_EXCEEDED`` / ``RESOURCE_EXHAUSTED`` if the
                target or a reference fails confinement/cap/pre-flight (:meth:`_resolve_and_cap`).
        """
        # Confine + cap the target and EVERY reference pre-Ghidra (fail closed before the worker).
        self._resolve_and_cap(a.target_ref)
        for ref in a.reference_refs:
            self._resolve_and_cap(ref)
        return _build_bsim_search_corpus(
            self._call(
                sid,
                "bsim_search_corpus",
                {
                    "target_ref": a.target_ref,
                    "reference_refs": list(a.reference_refs),
                    "min_similarity": a.min_similarity,
                    "limit": a.limit,
                    "max_scan": a.max_scan,
                },
                timeout_s=self._analysis_timeout_s,
            )
        )

    def list_functions(self, sid: str, a: s.ListFunctionsIn) -> s.FunctionListOut:
        """List functions (paginated/bounded)."""
        return _build_function_list(
            self._tool_call(
                sid,
                "list_functions",
                {"offset": a.offset, "limit": a.limit, "name_contains": a.name_contains},
            )
        )

    def get_function(self, sid: str, a: s.GetFunctionIn) -> s.FunctionDetail:
        """Get one function's detail."""
        return _build_function_detail(
            self._tool_call(sid, "get_function", {"function": a.function})
        )

    def xrefs_to(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References TO a target (addresses/ref-types are server-safe — no wrap needed)."""
        return _validate(s.XrefsOut, self._tool_call(sid, "xrefs_to", _xrefs_params(a)))

    def xrefs_from(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References FROM a target (addresses/ref-types are server-safe — no wrap needed)."""
        return _validate(s.XrefsOut, self._tool_call(sid, "xrefs_from", _xrefs_params(a)))

    def list_strings(self, sid: str, a: s.ListStringsIn) -> s.StringListOut:
        """List defined strings (paginated/bounded)."""
        return _build_string_list(
            self._tool_call(
                sid,
                "list_strings",
                {"offset": a.offset, "limit": a.limit, "min_length": a.min_length},
            )
        )

    def list_symbols(self, sid: str, a: s.ListSymbolsIn) -> s.SymbolListOut:
        """List symbols (paginated/bounded)."""
        return _build_symbol_list(
            self._tool_call(
                sid,
                "list_symbols",
                {"offset": a.offset, "limit": a.limit, "name_contains": a.name_contains},
            )
        )

    def get_symbol(self, sid: str, a: s.GetSymbolIn) -> s.Symbol:
        """Resolve one symbol."""
        return _build_symbol(self._tool_call(sid, "get_symbol", {"identifier": a.identifier}))

    def list_data(self, sid: str, a: s.ListDataIn) -> s.DataListOut:
        """List defined data (paginated/bounded)."""
        return _build_data_list(
            self._tool_call(sid, "list_data", {"offset": a.offset, "limit": a.limit})
        )

    def get_data_type(self, sid: str, a: s.GetDataTypeIn) -> s.DataType:
        """Resolve one data type."""
        return _build_data_type(self._tool_call(sid, "get_data_type", {"name": a.name}))

    def get_comments(self, sid: str, a: s.GetCommentsIn) -> s.CommentListOut:
        """Read comments (paginated/bounded)."""
        return _build_comment_list(
            self._tool_call(
                sid,
                "get_comments",
                {"offset": a.offset, "limit": a.limit, "address": a.address},
            )
        )

    def memory_map(self, sid: str, a: s.MemoryMapIn) -> s.MemoryMapOut:
        """List memory blocks/segments."""
        return _build_memory_map(self._tool_call(sid, "memory_map", {}))

    def read_bytes(self, sid: str, a: s.ReadBytesIn) -> s.ReadBytesOut:
        """Bounded raw byte read."""
        return _build_read_bytes(
            self._tool_call(sid, "read_bytes", {"address": a.address, "length": a.length})
        )

    def emulate(self, sid: str, a: s.EmulateIn) -> s.EmulateOut:
        """Bounded p-code emulation (ADR-049)."""
        return _build_emulate(
            self._tool_call(
                sid,
                "emulate",
                {
                    "start": a.start,
                    "set_registers": a.set_registers,
                    "write_memory": [
                        {"address": w.address, "data_hex": w.data_hex}
                        for w in (a.write_memory or [])
                    ],
                    "max_steps": a.max_steps,
                    "stop_at": a.stop_at,
                    "read_registers": a.read_registers,
                    "read_memory": [
                        {"address": r.address, "length": r.length} for r in (a.read_memory or [])
                    ],
                    "call": a.call,
                    "stubs": [{"target": st.target, "action": st.action} for st in (a.stubs or [])],
                    "args": a.args,
                },
            )
        )

    def demangle(self, sid: str, a: s.DemangleIn) -> s.DemangleOut:
        """Resolve a mangled C++ symbol to a readable name (ADR-050)."""
        return _build_demangle(
            self._tool_call(sid, "demangle", {"mangled": a.mangled, "scheme": a.scheme})
        )

    def search_bytes(self, sid: str, a: s.SearchBytesIn) -> s.SearchBytesOut:
        """Bounded byte-pattern search."""
        return _build_search_bytes(
            self._tool_call(
                sid,
                "search_bytes",
                {"pattern_hex": a.pattern_hex, "offset": a.offset, "limit": a.limit},
            )
        )

    def search_strings(self, sid: str, a: s.SearchStringsIn) -> s.SearchStringsOut:
        """Bounded defined-string search (same shape as ``list_strings``)."""
        base = _build_string_list(
            self._tool_call(
                sid,
                "search_strings",
                {"query": a.query, "offset": a.offset, "limit": a.limit},
            )
        )
        return s.SearchStringsOut(strings=base.strings, total=base.total, truncated=base.truncated)

    def program_metadata(self, sid: str, a: s.ProgramMetadataIn) -> s.ProgramMetadata:
        """High-level program metadata."""
        return _build_program_metadata(self._tool_call(sid, "program_metadata", {}))

    # --- call-graph / semantic-naming operations (v1.1 — ADR-007) ---------------------------
    # The worker exposes exactly two extraction primitives for this feature (ADR-001):
    # ``call_graph`` (resolved adjacency) and ``referenced_strings``. Everything else is computed
    # HERE, JVM-free: ``analysis_order`` runs the PURE ordering core (core.callgraph) over the
    # adjacency; ``callees``/``callers`` are one-hop projections of ``call_graph``;
    # ``function_context`` aggregates existing read-only RPCs. All output-only (no DB mutation).
    def call_graph(self, sid: str, a: s.CallGraphIn) -> s.CallGraphOut:
        """Extract the bounded call adjacency (resolved edges + unresolved callers)."""
        return _build_call_graph(
            self._tool_call(
                sid,
                "call_graph",
                {
                    "root": a.root,
                    "max_depth": a.max_depth,
                    "max_nodes": a.max_nodes,
                    "max_edges": a.max_edges,
                },
            )
        )

    def callees(self, sid: str, a: s.CalleesIn) -> s.CallNeighborsOut:
        """List the functions ``a.function`` directly calls (one hop over a depth-1 call graph)."""
        entry = self._resolve_entry(sid, a.function)
        graph = self.call_graph(sid, s.CallGraphIn(session_id=sid, root=a.function, max_depth=1))
        return _one_hop(graph, entry, direction="out", offset=a.offset, limit=a.limit)

    def callers(self, sid: str, a: s.CallersIn) -> s.CallNeighborsOut:
        """List the functions that directly call ``a.function`` (reverse one hop).

        There is no reverse-rooted extraction primitive (ADR-001 keeps graph walking in the worker),
        so this projects the bounded **whole-program** call graph and reverses it; ``truncated``
        honestly reflects a node/edge cap clipping the view (ADR-005).
        """
        entry = self._resolve_entry(sid, a.function)
        graph = self.call_graph(sid, s.CallGraphIn(session_id=sid))
        return _one_hop(graph, entry, direction="in", offset=a.offset, limit=a.limit)

    def analysis_order(self, sid: str, a: s.AnalysisOrderIn) -> s.AnalysisOrderOut:
        """Leaf-first reverse-topological order over the call graph (pure core — ADR-001/ADR-007).

        Extracts the adjacency via the worker ``call_graph`` RPC, then computes the ordering with
        the PURE :func:`vivarium.core.callgraph.compute_analysis_order` and shapes it via
        :func:`_build_analysis_order`. No JVM on this path — only the extraction hop touched Ghidra.
        """
        return _build_analysis_order(self.call_graph(sid, a))

    def function_context(self, sid: str, a: s.FunctionContextIn) -> s.FunctionContext:
        """Assemble the per-function naming/synthesis context bundle (server-side aggregation).

        Aggregates existing read-only facts — signature (``get_function``), the function's own
        call-graph node + direct callees (a depth-1 ``call_graph``), direct callers (reverse hop),
        decompiled pseudo-C (``decompile_function``), and referenced strings
        (``referenced_strings``) — wrapping every binary-derived field at the ADR-005 chokepoint.
        NO naming or C synthesis
        (no server-side LLM — locked decision #1); the client does that.
        """
        detail = self.get_function(sid, s.GetFunctionIn(session_id=sid, function=a.function))
        entry = detail.address
        graph = self.call_graph(sid, s.CallGraphIn(session_id=sid, root=a.function, max_depth=1))
        own = next((n for n in graph.nodes if n.address == entry), None)

        callees_page = _one_hop(graph, entry, direction="out", offset=0, limit=a.max_callees)
        callers_nodes: list[s.CallGraphNode] = []
        callers_trunc = False
        if a.max_callers:
            callers_page = self.callers(
                sid, s.CallersIn(session_id=sid, function=a.function, limit=a.max_callers)
            )
            callers_nodes = callers_page.neighbors
            callers_trunc = callers_page.truncated

        decompilation = None
        if a.include_decompilation:
            decompilation = self.decompile_function(
                sid, s.DecompileFunctionIn(session_id=sid, function=a.function)
            ).c_code

        referenced_strings: list[Untrusted[str]] = []
        strings_trunc = False
        if a.max_strings:
            rs = self._tool_call(
                sid,
                "referenced_strings",
                {"function": a.function, "max_strings": a.max_strings},
            )
            referenced_strings, strings_trunc = _build_referenced_strings(rs)

        # The function's own attributes come from its graph node when present (``is_external`` /
        # ``has_unresolved_calls`` are graph-only facts); fall back to ``get_function`` otherwise.
        name = own.name if own is not None else detail.name
        is_external = own.is_external if own is not None else detail.is_thunk
        has_unresolved = own.has_unresolved_calls if own is not None else False
        return s.FunctionContext(
            address=entry,
            name=name,
            signature=detail.signature,
            is_external=is_external,
            decompilation=decompilation,
            callees=callees_page.neighbors,
            callers=callers_nodes,
            referenced_strings=referenced_strings,
            has_unresolved_calls=has_unresolved,
            truncated=graph.truncated or callees_page.truncated or callers_trunc or strings_trunc,
        )

    def _resolve_entry(self, sid: str, function: str) -> str:
        """Resolve a function (name or hex) to its server-normalized entry address (via worker)."""
        return self.get_function(sid, s.GetFunctionIn(session_id=sid, function=function)).address

    # --- Tier-2 reporting / metrics (v1.1 — ADR-008; READ-ONLY) ------------------------------
    # The worker exposes four new extraction primitives (ADR-001): ``function_cfg``, ``imports``,
    # ``exports``, ``coverage``. The metric DERIVATION is JVM-free here: ``cyclomatic_complexity``
    # and ``call_graph_metrics`` run the PURE ``core.metrics`` over extracted counts/adjacency;
    # ``ioc_scan`` / ``crypto_constant_scan`` run the PURE ``core.iocscan`` over the existing
    # ``list_strings`` / ``search_bytes`` RPCs; ``program_summary`` aggregates the others. Every
    # binary-derived field is wrapped at the ADR-005 chokepoint; addresses/counts/ratios/labels are
    # safe scalars. NO naming or synthesis (no server-side LLM — locked decision #1).
    def cyclomatic_complexity(
        self, sid: str, a: s.CyclomaticComplexityIn
    ) -> s.CyclomaticComplexity:
        """McCabe complexity of one function (worker CFG counts → pure ``E - N + 2``)."""
        return _build_cyclomatic_complexity(
            self._tool_call(sid, "function_cfg", {"function": a.function})
        )

    def list_imports(self, sid: str, a: s.ListImportsIn) -> s.ImportListOut:
        """List imported symbols/functions (paginated/bounded)."""
        return _build_import_list(
            self._tool_call(sid, "imports", {"offset": a.offset, "limit": a.limit})
        )

    def list_exports(self, sid: str, a: s.ListExportsIn) -> s.ExportListOut:
        """List exported symbols/entry points (paginated/bounded)."""
        return _build_export_list(
            self._tool_call(sid, "exports", {"offset": a.offset, "limit": a.limit})
        )

    def coverage(self, sid: str, a: s.CoverageIn) -> s.CoverageOut:
        """Defined-code/data byte coverage (worker byte counts → pure ratios; no wrap needed)."""
        return _build_coverage(self._tool_call(sid, "coverage", {}))

    def ioc_scan(self, sid: str, a: s.IocScanIn) -> s.IocScanOut:
        """Heuristic IOC scan over defined strings (PURE core over the ``list_strings`` RPC).

        Fetches a bounded page of defined strings, runs the pure :func:`core.iocscan.scan_iocs`,
        then paginates the matches by ``offset``/``limit``. Each matched ``value`` is
        attacker-controlled and wrapped BINARY-origin (ADR-005) — a prime injection vector.
        ``truncated`` reflects either the scanned-string cap or a matches-page cap (honesty).
        """
        from vivarium.core import iocscan

        strings = _build_string_list(
            self._tool_call(
                sid,
                "list_strings",
                {"offset": 0, "limit": _IOC_STRING_BUDGET, "min_length": a.min_length},
            )
        )
        rows = [(ds.address, ds.value.value) for ds in strings.strings]
        categories = tuple(a.categories) if a.categories else None
        hits = iocscan.scan_iocs(rows, categories=categories, min_length=a.min_length)
        total = len(hits)
        page = hits[a.offset : a.offset + a.limit]
        truncated = strings.truncated or (a.offset + a.limit < total)
        return s.IocScanOut(
            matches=[
                s.IocMatch(
                    category=h.category,
                    value=_w(h.value, DataOrigin.BINARY),
                    source_address=h.source_address,
                )
                for h in page
            ],
            total=total,
            truncated=truncated,
        )

    def crypto_constant_scan(self, sid: str, a: s.CryptoConstantScanIn) -> s.CryptoConstantScanOut:
        """Heuristic crypto-constant search (PURE signature table over the ``search_bytes`` RPC).

        Issues one bounded ``search_bytes`` per known signature (reusing the fail-closed
        :meth:`search_bytes` adapter method, so a malformed worker result is already mapped), then
        shapes the addresses with the pure :func:`core.iocscan.scan_crypto_constants` and paginates.
        All output fields are safe (closed-vocabulary labels + server addresses). HEURISTIC — a
        match is a lead, not proof.
        """
        from vivarium.core import iocscan

        per_signature: list[tuple[iocscan.CryptoSignature, list[str]]] = []
        search_truncated = False
        for signature in iocscan.CRYPTO_SIGNATURES:
            found = self.search_bytes(
                sid,
                s.SearchBytesIn(
                    session_id=a.session_id,
                    pattern_hex=signature.pattern_hex,
                    limit=_CRYPTO_MATCH_BUDGET,
                ),
            )
            search_truncated = search_truncated or found.truncated
            per_signature.append((signature, [m.address for m in found.matches]))
        hits = iocscan.scan_crypto_constants(per_signature)
        total = len(hits)
        page = hits[a.offset : a.offset + a.limit]
        truncated = search_truncated or (a.offset + a.limit < total)
        return s.CryptoConstantScanOut(
            findings=[
                s.CryptoConstantFinding(algorithm=h.algorithm, kind=h.kind, address=h.address)
                for h in page
            ],
            total=total,
            truncated=truncated,
        )

    def crypto_detect(self, sid: str, a: s.CryptoDetectIn) -> s.CryptoDetectOut:
        """Detect crypto by imported API / resolved symbol name / hardware opcode (ADR-075).

        Complements ``crypto_constant_scan``: fetches imports (``import`` source), strings
        (``api_name`` source), and the worker's hardware crypto-opcode hits (``instruction`` source,
        AES-NI/SHA-ext/pclmulqdq), runs the pure :func:`core.cryptodetect` matchers, merges, then
        paginates. Each ``detail`` (a matched symbol/string/mnemonic) is binary-derived and wrapped
        BINARY-origin (ADR-005) — inert data. HEURISTIC: a match is a lead; an empty result is NOT
        proof of "no crypto" (an obfuscated / statically-linked routine can evade all sources).
        ``truncated`` reflects the import/string/opcode budgets or a matches-page cap (honesty). The
        ``code_pattern`` (cipher-shaped loops) source remains a tracked fast-follow.
        """
        from vivarium.core import cryptodetect

        imports = self.list_imports(
            sid,
            s.ListImportsIn(session_id=a.session_id, offset=0, limit=_CRYPTO_DETECT_IMPORT_BUDGET),
        )
        strings = _build_string_list(
            self._tool_call(
                sid,
                "list_strings",
                {"offset": 0, "limit": _CRYPTO_DETECT_STRING_BUDGET, "min_length": a.min_length},
            )
        )
        opcode_result = self._tool_call(
            sid, "crypto_instructions", {"max_hits": _CRYPTO_DETECT_OPCODE_BUDGET}
        )
        import_rows = [
            (im.address, im.name.value, im.library.value if im.library else None)
            for im in imports.imports
        ]
        string_rows = [(ds.address, ds.value.value) for ds in strings.strings]
        opcode_rows = [
            (str(h["address"]), str(h["mnemonic"])) for h in opcode_result.get("hits", [])
        ]
        opcode_truncated = bool(opcode_result.get("truncated", False))
        hits = cryptodetect.detect_crypto(import_rows, string_rows) + (
            cryptodetect.detect_instruction_crypto(opcode_rows)
        )
        total = len(hits)
        page = hits[a.offset : a.offset + a.limit]
        truncated = (
            imports.truncated
            or strings.truncated
            or opcode_truncated
            or (a.offset + a.limit < total)
        )
        return s.CryptoDetectOut(
            indicators=[
                s.CryptoIndicator(
                    address=h.address,
                    kind=h.kind,
                    source=h.source,
                    detail=_w(h.detail, DataOrigin.BINARY),
                    confidence=h.confidence,
                )
                for h in page
            ],
            total=total,
            truncated=truncated,
        )

    def capability_scan(self, sid: str, a: s.CapabilityScanIn) -> s.CapabilityScanOut:
        """Detect capabilities + MITRE ATT&CK by the built-in rule pack (PURE core; ADR-074).

        Fetches bounded pages of imports, exports, and strings, runs the pure
        :func:`core.capabilityscan.detect_capabilities`, then paginates the matches. Each evidence
        ``detail`` (a matched symbol/string) is binary-derived and wrapped BINARY-origin (ADR-005) —
        inert data. HEURISTIC: a match is a lead; a thin/empty result on a packed sample is expected
        (its real capabilities live in the encoded stage). ``truncated`` reflects any fact budget or
        a matches-page cap (honesty).
        """
        from vivarium.core import capabilityscan

        imports = self.list_imports(
            sid, s.ListImportsIn(session_id=a.session_id, offset=0, limit=_CAPABILITY_IMPORT_BUDGET)
        )
        exports = self.list_exports(
            sid, s.ListExportsIn(session_id=a.session_id, offset=0, limit=_CAPABILITY_EXPORT_BUDGET)
        )
        strings = _build_string_list(
            self._tool_call(sid, "list_strings", {"offset": 0, "limit": _CAPABILITY_STRING_BUDGET})
        )
        import_rows = [(im.address, im.name.value) for im in imports.imports]
        export_rows = [(ex.address, ex.name.value) for ex in exports.exports]
        string_rows = [(ds.address, ds.value.value) for ds in strings.strings]
        hits = capabilityscan.detect_capabilities(import_rows, export_rows, string_rows)
        total = len(hits)
        page = hits[a.offset : a.offset + a.limit]
        truncated = (
            imports.truncated
            or exports.truncated
            or strings.truncated
            or (a.offset + a.limit < total)
        )
        return s.CapabilityScanOut(
            capabilities=[
                s.CapabilityMatch(
                    rule_id=h.rule_id,
                    name=h.name,
                    namespace=h.namespace,
                    attack=[s.AttackTechnique(tactic=t, technique_id=tid) for (t, tid) in h.attack],
                    evidence=[
                        s.CapabilityEvidence(
                            address=e.address, where=e.where, detail=_w(e.detail, DataOrigin.BINARY)
                        )
                        for e in h.evidence
                    ],
                    confidence=h.confidence,
                )
                for h in page
            ],
            total=total,
            truncated=truncated,
            rule_pack_version=capabilityscan.RULE_PACK_VERSION,
        )

    def secret_scan(self, sid: str, a: s.SecretScanIn) -> s.SecretScanOut:
        """Heuristic firmware-secret scan over defined strings (PURE core over ``list_strings``).

        Fetches a bounded page of strings, runs the pure REDACTED
        :func:`core.secretscan.scan_secrets` (ADR-072 D3 — no raw secret leaves that core), then
        paginates. Only the masked preview is binary-derived and wrapped BINARY-origin (ADR-005);
        ``preview_hash``/``address``/``category``
        are safe. Redaction is first-class: this adapter logs NOTHING about the values (no raw, no
        full preview) — the pure core already reduced each value to a masked preview + hash.
        """
        from vivarium.core import secretscan

        strings = _build_string_list(
            self._tool_call(
                sid,
                "list_strings",
                {"offset": 0, "limit": _SECRET_STRING_BUDGET, "min_length": a.min_length},
            )
        )
        rows = [(ds.address, ds.value.value) for ds in strings.strings]
        categories = tuple(a.categories) if a.categories else None
        hits = secretscan.scan_secrets(
            rows, categories=categories, entropy_threshold=a.entropy_threshold
        )
        total = len(hits)
        page = hits[a.offset : a.offset + a.limit]
        truncated = strings.truncated or (a.offset + a.limit < total)
        return s.SecretScanOut(
            findings=[
                s.SecretFinding(
                    address=h.address,
                    category=h.category,
                    pattern_id=h.pattern_id,
                    masked_preview=_w(h.masked_preview, DataOrigin.BINARY),
                    preview_hash=h.preview_hash,
                    entropy=h.entropy,
                )
                for h in page
            ],
            total=total,
            truncated=truncated,
        )

    def call_graph_metrics(self, sid: str, a: s.CallGraphMetricsIn) -> s.CallGraphMetricsOut:
        """Structural call-graph metrics (PURE ``core.metrics`` over the ``call_graph`` RPC).

        Extracts the bounded adjacency via the worker ``call_graph`` RPC (the only Ghidra hop), then
        computes fan-in/out, leaf/root, and recursion stats with the pure
        :func:`core.metrics.compute_call_graph_metrics` (which reuses the ADR-007 ordering core).
        Hotspot ``name`` fields are taken from the (already-wrapped) graph nodes; addresses/counts
        are safe. ``truncated`` reflects the underlying graph node/edge cap.
        """
        from vivarium.core.metrics import compute_call_graph_metrics

        graph = self.call_graph(
            sid,
            s.CallGraphIn(
                session_id=a.session_id,
                root=a.root,
                max_depth=a.max_depth,
                max_nodes=a.max_nodes,
                max_edges=a.max_edges,
            ),
        )
        adjacency, unresolved = _adjacency_from_graph(graph)
        result = compute_call_graph_metrics(adjacency, unresolved=tuple(unresolved), top_n=a.top_n)
        names = {node.address: node.name for node in graph.nodes}

        def _rank(entries: tuple[Any, ...]) -> list[s.FanRanking]:
            """Map pure ``FanEntry`` ranks to :class:`FanRanking`, reusing wrapped node names."""
            ranked: list[s.FanRanking] = []
            for entry in entries:
                name = names.get(entry.address)
                if name is None:  # an edge target outside the emitted node set (boundary clip)
                    name = _w(entry.address, DataOrigin.BINARY)
                ranked.append(s.FanRanking(address=entry.address, name=name, count=entry.count))
            return ranked

        return s.CallGraphMetricsOut(
            function_count=result.function_count,
            edge_count=result.edge_count,
            leaf_count=result.leaf_count,
            root_count=result.root_count,
            recursive_component_count=result.recursive_component_count,
            self_recursive_count=result.self_recursive_count,
            unresolved_caller_count=result.unresolved_caller_count,
            top_fan_in=_rank(result.top_fan_in),
            top_fan_out=_rank(result.top_fan_out),
            truncated=graph.truncated,
        )

    def program_summary(self, sid: str, a: s.ProgramSummaryIn) -> s.ProgramSummary:
        """One-shot aggregate triage report (server-side aggregation of Tier-1 + Tier-2).

        Composes bounded sub-results — program metadata, import/export/string totals, coverage, the
        optional call-graph metrics, the top functions by complexity (over a bounded examined set),
        an IOC category histogram, and the detected crypto-algorithm set — wrapping every
        binary-derived field at the ADR-005 chokepoint. NO naming or C synthesis (ADR-008). The
        heavy per-item lists stay in their dedicated tools; ``truncated`` is the OR of any capped
        sub-result so the client never mistakes a bounded view for the whole program.
        """
        sess = a.session_id
        metadata = self.program_metadata(sid, s.ProgramMetadataIn(session_id=sess))
        import_count = self.list_imports(sid, s.ListImportsIn(session_id=sess, limit=1)).total
        export_count = self.list_exports(sid, s.ListExportsIn(session_id=sess, limit=1)).total
        string_count = self.list_strings(sid, s.ListStringsIn(session_id=sess, limit=1)).total
        coverage = self.coverage(sid, s.CoverageIn(session_id=sess))
        truncated = False

        call_graph_metrics: s.CallGraphMetricsOut | None = None
        if a.include_call_graph:
            call_graph_metrics = self.call_graph_metrics(sid, s.CallGraphMetricsIn(session_id=sess))
            truncated = truncated or call_graph_metrics.truncated

        top_complex = self._top_complex_functions(sid, sess, a.max_complex_functions)
        truncated = truncated or top_complex.truncated

        ioc_counts: list[s.IocCategoryCount] = []
        if a.max_iocs:
            scan = self.ioc_scan(sid, s.IocScanIn(session_id=sess, limit=a.max_iocs))
            truncated = truncated or scan.truncated
            counts: dict[str, int] = {}
            for match in scan.matches:
                counts[match.category] = counts.get(match.category, 0) + 1
            ioc_counts = [
                s.IocCategoryCount(category=cat, count=n) for cat, n in sorted(counts.items())
            ]

        crypto = self.crypto_constant_scan(
            sid, s.CryptoConstantScanIn(session_id=sess, limit=_CRYPTO_MATCH_BUDGET)
        )
        truncated = truncated or crypto.truncated
        crypto_algorithms = sorted({f.algorithm for f in crypto.findings})

        return s.ProgramSummary(
            metadata=metadata,
            function_count=metadata.function_count,
            import_count=import_count,
            export_count=export_count,
            string_count=string_count,
            coverage=coverage,
            call_graph_metrics=call_graph_metrics,
            top_complex_functions=top_complex.functions,
            ioc_counts=ioc_counts,
            crypto_algorithms=crypto_algorithms,
            truncated=truncated,
        )

    def _top_complex_functions(self, sid: str, session_id: str, max_functions: int) -> _TopComplex:
        """Return the highest-complexity functions over a bounded examined set (helper for summary).

        Examines the first ``max_functions`` functions (one bounded ``list_functions`` page),
        computes each one's cyclomatic complexity, and returns them sorted descending. ``truncated``
        is set when more functions exist than were examined — so the summary never implies it ranked
        the whole program. With ``max_functions == 0`` it does no work.

        Args:
            sid: The session id.
            session_id: The same session id for sub-call argument models.
            max_functions: Cap on functions examined and returned.

        Returns:
            A :class:`_TopComplex` (sorted functions + truncation flag).
        """
        if max_functions <= 0:
            return _TopComplex(functions=[], truncated=False)
        listing = self.list_functions(
            sid, s.ListFunctionsIn(session_id=session_id, limit=max_functions)
        )
        measured = [
            self.cyclomatic_complexity(
                sid, s.CyclomaticComplexityIn(session_id=session_id, function=fn.address)
            )
            for fn in listing.functions
        ]
        measured.sort(key=lambda c: c.complexity, reverse=True)
        return _TopComplex(functions=measured[:max_functions], truncated=listing.truncated)

    # --- Function ID library-match identification (ADR-042 Phase 1; READ-ONLY) ---
    def identify_functions(self, sid: str, a: s.IdentifyFunctionsIn) -> s.IdentifyFunctionsOut:
        """Match functions against library FID databases (best-effort, untrusted hints — ADR-042).

        Issues the worker ``identify_functions`` RPC (the only Ghidra hop — the worker runs the FID
        service, filters candidates below the effective score threshold, and bounds its own result),
        then enforces the caller's ``limit`` server-side: if more matches survive than ``limit``,
        the list is clipped and ``truncated`` is set (honest — ADR-005), OR-ing in any worker clip.
        Each candidate's ``matched_name`` + ``library`` are binary-derived → wrapped ``Untrusted``
        (BINARY origin) by :func:`_build_identified_functions`; the address + score are safe.

        Args:
            sid: The session id.
            a: The validated tool arguments (``limit`` / ``min_score``).

        Returns:
            The bounded :class:`vivarium.tools.schemas.IdentifyFunctionsOut`.
        """
        params: dict[str, Any] = {"limit": _IDENTIFY_MATCH_BUDGET}
        if a.min_score is not None:
            params["min_score"] = a.min_score
        result = _build_identified_functions(self._tool_call(sid, "identify_functions", params))
        worker_truncated = result.truncated
        matches = result.matches
        truncated = worker_truncated or len(matches) > a.limit
        bounded = matches[: a.limit]
        return s.IdentifyFunctionsOut(matches=bounded, total=len(bounded), truncated=truncated)

    # --- mutation / write operations (v1.1 — ADR-012; transaction-wrapped in the worker) ---
    # The server has already checked write consent (sessions.require_write_consent) and validated
    # the attacker-influenced inputs (validate_write_name / validate_comment_text). Here the adapter
    # issues the write RPC and turns the worker's PLAIN result into the typed ``*Out``, wrapping
    # only binary-derived field, the prior ``old_name``, as ``Untrusted`` (ADR-005 chokepoint).
    def rename_function(self, sid: str, a: s.RenameFunctionIn) -> s.RenameResult:
        """Rename one function (write — ADR-012)."""
        return _build_rename_result(
            self._tool_call(
                sid, "rename_function", {"function": a.function, "new_name": a.new_name}
            )
        )

    def rename_symbol(self, sid: str, a: s.RenameSymbolIn) -> s.RenameSymbolResult:
        """Rename one data/label/global symbol (write — ADR-012)."""
        return _build_rename_symbol_result(
            self._tool_call(
                sid, "rename_symbol", {"identifier": a.identifier, "new_name": a.new_name}
            )
        )

    def set_comment(self, sid: str, a: s.SetCommentIn) -> s.SetCommentResult:
        """Set or clear one comment at an address (write — ADR-012)."""
        return _build_set_comment_result(
            self._tool_call(
                sid,
                "set_comment",
                {"address": a.address, "comment_type": a.comment_type, "text": a.text},
            )
        )

    def undo(self, sid: str, a: s.SessionUndoIn) -> s.SessionUndoOut:
        """Undo the last committed mutation transaction in the session (convenience — ADR-012)."""
        return _build_undo_out(sid, self._tool_call(sid, "undo", {}))

    def rename_local_variable(
        self, sid: str, a: s.RenameLocalVariableIn
    ) -> s.StructuralRenameResult:
        """Rename one function-local variable (structural, name-only — ADR-013)."""
        return _build_structural_rename_result(
            self._tool_call(
                sid,
                "rename_local_variable",
                {"function": a.function, "variable": a.variable, "new_name": a.new_name},
            )
        )

    def rename_parameter(self, sid: str, a: s.RenameParameterIn) -> s.StructuralRenameResult:
        """Rename one function parameter (structural, name-only — ADR-013)."""
        return _build_structural_rename_result(
            self._tool_call(
                sid,
                "rename_parameter",
                {"function": a.function, "parameter": a.parameter, "new_name": a.new_name},
            )
        )

    # --- structural type-aware writes (v1.1 — ADR-014 Phase B; structured TypeRef params) ---
    # The server has already checked structural consent and validated the structured payload
    # (validate_signature / validate_type_ref / validate_calling_convention). Here the adapter
    # serializes the typed schema into plain RPC params (the TypeRef/ParamSpec are dumped to plain
    # dicts) and wraps the binary-derived result fields as ``Untrusted`` (ADR-005 chokepoint).
    def set_function_signature(
        self, sid: str, a: s.SetFunctionSignatureIn
    ) -> s.SetFunctionSignatureResult:
        """Set a function's structured signature (resolved types — ADR-014)."""
        return _build_set_function_signature_result(
            self._tool_call(
                sid,
                "set_function_signature",
                {
                    "function": a.function,
                    "return_type": _type_ref_params(a.return_type),
                    "parameters": [
                        {"name": p.name, "type": _type_ref_params(p.type)} for p in a.parameters
                    ],
                    "calling_convention": a.calling_convention,
                },
            )
        )

    def apply_data_type(self, sid: str, a: s.ApplyDataTypeIn) -> s.ApplyDataTypeResult:
        """Apply a resolvable type at an address (resolved type — ADR-014)."""
        return _build_apply_data_type_result(
            self._tool_call(
                sid,
                "apply_data_type",
                {
                    "address": a.address,
                    "type": _type_ref_params(a.type),
                    "clear_existing": a.clear_existing,
                },
            )
        )

    def apply_type_archive(self, sid: str, a: s.ApplyTypeArchiveIn) -> s.ApplyTypeArchiveResult:
        """Apply a bundled Ghidra Data Type archive (structural — ADR-051)."""
        return _build_apply_type_archive_result(
            self._tool_call(sid, "apply_type_archive", {"archive": a.archive})
        )

    # --- composite-type creation (v1.1 — ADR-015 Phase C; structured FieldSpec params) ---
    # The server has already checked structural consent and validated the composite payload
    # (validate_composite: bounded FieldSpec list of resolved TypeRefs, no duplicate/self-embed).
    # Here the adapter serializes each field's TypeRef to plain RPC params (one composite per call)
    # and builds the typed result — every field is server/worker-controlled (no Untrusted echo).
    def define_struct(self, sid: str, a: s.DefineStructIn) -> s.DefineStructResult:
        """Create a new struct from a resolved field list (one composite — ADR-015)."""
        return _build_define_struct_result(
            self._tool_call(
                sid,
                "define_struct",
                {
                    "name": a.name,
                    "fields": [_field_spec_params(f) for f in a.fields],
                    "packed": a.packed,
                },
            )
        )

    def define_union(self, sid: str, a: s.DefineUnionIn) -> s.DefineUnionResult:
        """Create a new union from a resolved field list (one composite — ADR-015)."""
        return _build_define_union_result(
            self._tool_call(
                sid,
                "define_union",
                {
                    "name": a.name,
                    "fields": [_field_spec_params(f) for f in a.fields],
                },
            )
        )

    def delete_type(self, sid: str, a: s.DeleteTypeIn) -> s.DeleteTypeResult:
        """Delete a session-authored composite by name (one transaction — ADR-031).

        The server has already validated the name and confirmed it is session-authored (ADR-031 D2);
        the adapter only forwards the name. Every result field is a server/worker-controlled scalar.
        """
        return _build_delete_type_result(self._tool_call(sid, "delete_type", {"name": a.name}))

    # --- multi-type composite batch (v1.2 — ADR-021; structured FieldSpec params) ---
    # The server has already checked structural consent and validated the batch
    # (validate_types_batch: per-type validate_composite, intra-batch dup-name, and the by-value
    # cycle detector). Here the adapter serializes each entry to plain RPC params (one batch == one
    # transaction) and builds the typed result — every field server/worker-controlled (no echo).
    def define_types(self, sid: str, a: s.DefineTypesIn) -> s.DefineTypesResult:
        """Create a batch of interdependent composites in one transaction (ADR-021)."""
        return _build_define_types_result(
            self._tool_call(
                sid,
                "define_types",
                {"types": [_composite_spec_params(spec) for spec in a.types]},
            )
        )

    # --- cross-session annotation persistence (v1.2 — ADR-018; export read-out) ----------------
    # The worker enumerates ONLY USER_DEFINED annotations (not auto-analysis), dependency-ordered,
    # bounded (over the cap → limit-exceeded — no silent truncation). This adapter turns the plain
    # worker result into the typed ExportedAnnotationDocument, wrapping every binary-derived string
    # at the ADR-005 chokepoint. The server overlays the authoritative binary.sha256. IMPORT is NOT
    # here — it is server-side orchestration (registry) replaying the existing write methods above.
    def export_annotations(
        self,
        sid: str,
        a: s.SessionExportAnnotationsIn,
        *,
        targets: s.ExportTargets,
    ) -> s.SessionExportAnnotationsOut:
        """Read out the session's USER_DEFINED annotations (read-only — ADR-018/ADR-027).

        The server-supplied ``targets`` (the session change-log: comments + composites this session
        authored) ride the worker RPC as an additive ``targets`` parameter so the worker reads ONLY
        those for comments/composites instead of blind-enumerating (the F7 fix). Symbols/signatures
        stay source-type-enumerated worker-side.
        """
        params = _export_annotations_params(targets)
        return _build_exported_annotation_document(
            self._tool_call(sid, "export_annotations", params)
        )

    # --- internal: call orchestration -------------------------------------------------------
    def _tool_call(self, sid: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Issue a read-only tool RPC bounded by the per-tool timeout.

        Args:
            sid: The session id.
            method: The RPC method name.
            params: Method parameters (already validated by the schema/core.validation).

        Returns:
            The worker's ``result`` object.
        """
        return self._call(sid, method, params, timeout_s=self._tool_timeout_s)

    @staticmethod
    def _diagnose_worker_exit(sess: _Session) -> str:
        """Ask the worker handle why it exited (``"oom"`` / ``"other"`` / ``"unknown"``).

        Wraps :meth:`WorkerProcess.exit_diagnosis` so a flaky engine query can never destabilize the
        adapter: any exception fails closed to ``"unknown"`` (treated as a generic crash → the
        existing ``worker-unavailable`` path), never spuriously to ``"oom"``.

        Args:
            sess: The per-session state whose worker just failed on the transport.

        Returns:
            The diagnosis string, or ``"unknown"`` if the query raises.
        """
        try:
            return sess.worker.exit_diagnosis()
        except Exception:
            # Diagnosis is best-effort; a flaky engine query must never mask the underlying failure
            # nor spuriously report an OOM the engine did not confirm (fail closed → generic crash).
            return "unknown"

    def _call(
        self,
        session_id: str,
        method: str,
        params: dict[str, Any],
        *,
        timeout_s: float,
        expect_progress: bool = False,
        on_progress: port.OnProgress | None = None,
    ) -> dict[str, Any]:
        """Send one JSON-RPC request and read its response, enforcing kill-on-failure semantics.

        Failure handling (rpc-protocol.md §3/§6):

        - deadline expiry → SIGKILL worker, ``timeout`` error;
        - oversized declared frame / protocol violation → SIGKILL worker, ``worker-unavailable``;
        - worker crash / closed socket mid-call → SIGKILL worker, ``worker-unavailable``;
        - worker JSON-RPC ``error`` response → map ``data.type`` slug → public error type.

        When ``expect_progress`` is set (only the opted-in ``analyze`` path — ADR-030 Phase 1) the
        single read is replaced by a bounded read-loop (:meth:`_read_response_with_progress`) that
        relays ``$/progress`` notifications to the log and returns the final response. ``timeout_s``
        bounds the WHOLE loop (computed once by the caller; NOT extended per frame). When unset the
        path is byte-for-byte today's single-frame read — IDENTICAL behaviour for every non-opted-in
        call.

        Args:
            session_id: The session whose worker handles the call.
            method: The RPC method name.
            params: Method parameters.
            timeout_s: Wall-clock deadline for this call (and for the whole progress loop).
            expect_progress: Whether to run the progress-aware read-loop (opted-in ``analyze``
                only).
            on_progress: Optional Phase-2 client-relay callback forwarded to the read-loop (``None``
                ⇒ log-only / unchanged path).

        Returns:
            The worker's ``result`` object.

        Raises:
            GhidraMcpError: On any failure, mapped to the public error envelope.
        """
        with self._sessions_lock:
            sess = self._sessions.get(session_id)
        if sess is None:
            raise _errors.make_error(ErrorType.WORKER_UNAVAILABLE, "no worker for session")

        request_id = uuid.uuid4().hex
        frame = rpc_framing.encode_frame(
            rpc_framing.build_request(request_id, method, params),
            max_frame_bytes=self._max_response_bytes,
        )
        # gap N1: serialize this session's socket transaction (connect→send→read) so two concurrent
        # same-session requests (HTTP threadpool) cannot interleave frames / steal each other's
        # response on the one UDS. RLock ⇒ same-thread reentrant; released in the finally below.
        # kill_worker/_send_cancel intentionally do NOT take this lock (see _Session.lock).
        # BOUNDED acquire (gap N1 review): fail closed on the per-call deadline rather than block
        # indefinitely if the lock is briefly held; the caller gets a retryable worker-unavailable.
        # Q4: ONE absolute deadline for the WHOLE call (lock acquire + connect + send + read). Every
        # bounded sub-step below is charged against it, so total call time never exceeds timeout_s —
        # previously connect (up to connect_timeout_s) + a fresh read timeout could overrun it.
        deadline = time.monotonic() + timeout_s
        if not sess.lock.acquire(timeout=timeout_s):
            raise _errors.make_error(
                ErrorType.WORKER_UNAVAILABLE, "session busy (another call or stream holds it)"
            )
        try:
            # A streaming job owns the socket between its start and terminal (the reader holds no
            # lock, only this flag — gap N1). A plain call must NOT read off the socket then or it
            # would steal the stream's chunks; refuse fast (retryable) instead.
            if sess.active_stream_id is not None:
                raise _errors.make_error(
                    ErrorType.WORKER_UNAVAILABLE, "session busy (a stream is in progress)"
                )
            sock = self._ensure_connected(sess, deadline=deadline)
            # Q4: send + read share the ONE call deadline (connect may have consumed part of it), so
            # the remaining budget — not a fresh full timeout — bounds each subsequent step.
            self._send_all_with_timeout(sock, frame, max(0.0, deadline - time.monotonic()))
            if expect_progress:
                # Bounded progress read-loop: relay $/progress to the log, return the response.
                # The deadline bounds the WHOLE loop and is NOT extended by progress frames (ADR-030
                # / ADR-002): a worker emitting progress forever still hits the un-extended SIGKILL.
                response_obj = self._read_response_with_progress(
                    sock,
                    expected_id=request_id,
                    method=method,
                    total_timeout_s=max(0.0, deadline - time.monotonic()),
                    on_progress=on_progress,
                )
            else:
                # Single-frame path. Bound the WHOLE frame read by the absolute call deadline (not a
                # per-recv timeout) so a dribbling worker can't hold it open (slow-loris — N11).
                response_obj = self._read_frame(sock, deadline)
            return rpc_framing.parse_response(response_obj, expected_id=request_id)
        except RpcCallError as exc:
            # A method-level failure: the worker is healthy; do NOT kill. Map the slug.
            # Log the worker's redacted, log-only diagnostic (slug + optional class-name detail —
            # ADR-024 PR-1) so a real worker fault (e.g. a JVM NullPointerException behind the
            # generic "internal worker error") is diagnosable server-side. SAFE keys only
            # (``method``/``slug``/``detail`` carry no sensitive substring); the value is the
            # worker-scrubbed class-name template, never binary-derived text. The client envelope
            # is UNCHANGED — detail is never placed on it.
            # Q8: the worker's free-form message is LOG-ONLY (never the client envelope) — it is
            # untrusted worker output (TB2/TB3) that would bypass the envelope normalization.
            _log.warning(
                "worker.method_error",
                extra={
                    "method": method,
                    "code": exc.error.code,
                    "slug": exc.error.type_slug,
                    "detail": exc.error.detail,
                    "worker_message": exc.error.message,
                },
            )
            raise _errors.worker_method_error_from(exc.error.code, exc.error.type_slug) from exc
        except TimeoutError as exc:
            _log.warning(
                "worker.rpc_failed",
                extra={"method": method, "cause": "timeout", "detail": str(exc)[:300]},
            )
            self.kill_worker(session_id)
            raise _errors.make_error(
                ErrorType.TIMEOUT, "operation exceeded its time limit"
            ) from exc
        except (FramingError, RpcProtocolError) as exc:
            # Hostile/buggy worker: protocol/framing violation → kill + evict.
            _log.warning(
                "worker.rpc_failed",
                extra={
                    "method": method,
                    "cause": "protocol",
                    "exc": type(exc).__name__,
                    "detail": str(exc)[:300],
                },
            )
            self.kill_worker(session_id)
            raise _errors.make_error(
                ErrorType.WORKER_UNAVAILABLE, "worker protocol violation"
            ) from exc
        except (ConnectionError, EOFError, OSError) as exc:
            # Crash / closed socket mid-call → kill + evict. Before killing, ask the engine WHY the
            # worker died (server-side metadata query only — OOMKilled / exit 137; NO binary
            # parsing, ADR-001): an OOM-killed worker (blew its memory cap on a hostile input) is
            # surfaced as the distinct, actionable ``resource-exhausted`` (ADR-023 / F1); everything
            # else stays the generic ``worker-unavailable``. Diagnosis fails closed to "unknown" →
            # treated as a generic crash. The underlying socket error is logged server-side
            # (boundary-safe: errno/type only, no binary content) for diagnosability.
            diagnosis = self._diagnose_worker_exit(sess)
            cause = "resource-exhausted" if diagnosis == "oom" else "transport"
            _log.warning(
                "worker.rpc_failed",
                extra={
                    "method": method,
                    "cause": cause,
                    "exc": type(exc).__name__,
                    "detail": str(exc)[:300],
                },
            )
            self.kill_worker(session_id)
            if diagnosis == "oom":
                # Safe, actionable detail with the configured cap (ADR-037 §3 sizing hint) — no
                # binary content / host paths. Covers both the cgroup OOM-kill (137/OOMKilled) and
                # the JVM ExitOnOutOfMemoryError heap-OOM self-exit (ExitCode 3, ADR-037 §D1).
                raise _errors.resource_exhausted(self._worker_mem_mib) from exc
            raise _errors.make_error(ErrorType.WORKER_UNAVAILABLE, "worker unavailable") from exc
        finally:
            sess.lock.release()  # gap N1: paired with the acquire() above; releases on every exit

    def _ensure_connected(self, sess: _Session, *, deadline: float) -> socket.socket:
        """Connect (lazily) to the session's UDS, returning a stream socket.

        Args:
            sess: The per-session state.
            deadline: The caller's absolute (monotonic) deadline for the WHOLE call. Connect gives
                up at the EARLIER of ``connect_timeout_s`` from now OR this deadline (gap round-4
                Q4), so a worker slow to bind its UDS cannot make connect — which runs while
                ``sess.lock`` is held — push the total call time past the caller's budget.

        Returns:
            The connected stream socket.

        Raises:
            OSError: If the worker socket cannot be reached before the connect budget elapses
                (→ ``worker-unavailable``).
        """
        if sess.sock is not None:
            return sess.sock
        # The worker binds its per-session UDS only AFTER its container starts (and the backend
        # warms up), but the spawn (`podman run --detach`) returns before that. A single connect
        # would lose the race and fail closed as worker-unavailable, so retry until the worker is
        # bound and accepting or the connect budget elapses. The two expected transient conditions
        # are ENOENT (socket file not created yet) and ECONNREFUSED (created but not yet
        # listening); any other OSError is non-transient and propagates immediately (fail fast).
        # Q4: the budget is the EARLIER of connect_timeout_s or the call deadline, and each
        # attempt's socket timeout is capped by the remaining budget — connect never overruns.
        connect_deadline = min(deadline, time.monotonic() + self._connect_timeout_s)
        while True:
            remaining = connect_deadline - time.monotonic()
            if remaining <= 0:
                raise ConnectionError("worker connect budget elapsed before the call deadline")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(remaining)
            try:
                sock.connect(sess.socket_path)
            except (FileNotFoundError, ConnectionRefusedError):
                sock.close()
                if time.monotonic() >= connect_deadline:
                    raise
                nap = min(_CONNECT_RETRY_INTERVAL_S, max(0.0, connect_deadline - time.monotonic()))
                time.sleep(nap)
                continue
            sess.sock = sock
            return sock

    @staticmethod
    def _send_all(sock: socket.socket, data: bytes) -> None:
        """Write a full frame to the socket.

        Args:
            sock: The connected stream socket.
            data: The complete frame bytes.
        """
        sock.sendall(data)

    @staticmethod
    def _send_all_with_timeout(sock: socket.socket, data: bytes, timeout_s: float) -> None:
        """Write a full frame under the call deadline (sets the socket timeout, then sends).

        Factored out of :meth:`_call` so both the unchanged and the progress paths arm the write
        with the same deadline before the read phase reuses/shrinks it.

        Args:
            sock: The connected stream socket.
            data: The complete frame bytes.
            timeout_s: The send deadline.
        """
        sock.settimeout(timeout_s)
        sock.sendall(data)

    def _read_response_with_progress(
        self,
        sock: socket.socket,
        *,
        expected_id: str,
        method: str,
        total_timeout_s: float,
        on_progress: port.OnProgress | None = None,
    ) -> dict[str, Any]:
        """Read frames until the final response, relaying ``$/progress`` to the log (ADR-030 §1).

        Bounded read-loop for an opted-in ``analyze`` call. Each iteration reads one frame within
        the SHRINKING remaining time of the ONE-SHOT deadline (``total_timeout_s`` from call start —
        progress frames NEVER extend it, ADR-002), then classifies it:

        - ``$/progress`` notification → validate + bound (count + coalesce) + relay percent/phase to
          the log, then continue waiting for the response;
        - anything else → return it for :func:`rpc_framing.parse_response` to validate as the
          response (a malformed/mis-correlated frame fails closed there → kill + evict).

        Flood bounds (worker is potentially hostile — TB2/TB3): more than
        :data:`_MAX_PROGRESS_FRAMES` progress frames is a protocol violation → raise
        :class:`RpcProtocolError` (the caller maps it to kill + ``worker-unavailable``). A frame
        arriving sooner than :data:`_MIN_PROGRESS_INTERVAL_S` after the last RELAYED one is
        coalesced (not logged) but still counts toward the hard cap. The per-frame size cap is
        enforced by
        :meth:`_read_frame` (shared §3 cap). NO unbounded server-side buffering — frames are
        processed and discarded one at a time.

        Args:
            sock: The connected stream socket.
            expected_id: The ``analyze`` request id progress + the response must correlate to.
            method: The RPC method name (for log context only — always ``"analyze"`` here).
            total_timeout_s: The one-shot deadline for the whole loop (from call start).
            on_progress: Optional Phase-2 client-relay callback invoked (best-effort) for each
                relayed frame, in addition to the log. ``None`` ⇒ log-only (Phase 1).

        Returns:
            The decoded final response frame (success or error envelope), for the caller to parse.

        Raises:
            RpcProtocolError: On a progress flood (count cap) or a malformed progress notification.
            FramingError: On a short/oversized frame (per-frame size cap).
            TimeoutError: If the deadline elapses before the response arrives.
            EOFError: If the worker closes the socket mid-stream.
        """
        deadline = time.monotonic() + total_timeout_s
        progress_count = 0
        last_relayed_at: float | None = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # Deadline elapsed inside the loop → behave exactly like a single-read timeout
                # (caller kills the worker + returns the TIMEOUT envelope). Deadline NOT extended.
                raise TimeoutError("analysis deadline elapsed during progress read-loop")
            frame = self._read_frame(sock, deadline)
            if not rpc_framing.is_progress_notification(frame):
                return frame  # the response (or error) frame — let the caller validate it
            progress_count += 1
            if progress_count > _MAX_PROGRESS_FRAMES:
                # A worker streaming endless progress is a protocol violation (fail closed → kill).
                raise RpcProtocolError("progress frame flood exceeded the per-call cap")
            progress = rpc_framing.parse_progress(frame, expected_id=expected_id)
            now = time.monotonic()
            if _should_relay_progress(last_relayed_at, now, _MIN_PROGRESS_INTERVAL_S):
                last_relayed_at = now
                # Redacted, log-only relay (percent + closed-vocabulary phase ONLY — master §5).
                _log.info(
                    "analyze.progress",
                    extra={"method": method, **_progress_log_payload(progress)},
                )
                # Phase 2: ALSO relay to the MCP client when a callback is wired (a progressToken
                # was sent). SAFE fields only — percent + closed-vocabulary phase, never any
                # binary-derived text (RpcProgress structurally cannot carry it). The callback is
                # the SAME coalesced + bounded stream the log sees, so the client cadence is bounded
                # too. It is best-effort: a relay failure (client gone, loop unavailable) must NEVER
                # fail the analysis, so the server-side callback swallows its own errors; we still
                # guard here as defense in depth so a buggy callback can't break the read-loop.
                if on_progress is not None:
                    try:
                        on_progress(progress.percent, progress.phase)
                    except Exception:
                        _log.warning("analyze.progress_relay_failed", extra={"method": method})
            # else: coalesced (too-soon since the last relayed frame) — counted but not logged.

    def _read_frame(self, sock: socket.socket, deadline: float) -> dict[str, Any]:
        """Read exactly one length-prefixed JSON-RPC frame from the socket under a deadline.

        Bounds the declared length BEFORE allocating the body buffer (no large-allocation DoS), and
        threads ``deadline`` through BOTH reads (prefix + body) so the whole frame — not merely each
        individual ``recv`` — is bounded in time (slow-loris hardening, see :meth:`_recv_exact`).

        Args:
            sock: The connected stream socket.
            deadline: Absolute :func:`time.monotonic` time by which the full frame must arrive.

        Returns:
            The decoded JSON object.

        Raises:
            FramingError: On a short/oversized frame.
            RpcProtocolError: On malformed JSON.
            EOFError: If the worker closed the socket mid-frame.
            TimeoutError: If the deadline elapses before the full frame arrived.
        """
        prefix = self._recv_exact(sock, rpc_framing.LENGTH_PREFIX_BYTES, deadline)
        n = rpc_framing.decode_length_prefix(prefix, max_frame_bytes=self._max_response_bytes)
        body = self._recv_exact(sock, n, deadline) if n else b""
        return rpc_framing.decode_body(body)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
        """Receive exactly ``n`` bytes under an ABSOLUTE deadline, raising on EOF/timeout.

        Re-arms the socket timeout to the REMAINING time before every ``recv`` so the TOTAL time
        to read the frame is bounded by ``deadline`` no matter how the peer paces the bytes. A
        worker dribbling one byte just under a fixed per-``recv`` timeout previously kept the read
        open indefinitely (a per-recv ``settimeout`` resets its clock on each call); threading the
        absolute deadline closes that slow-loris hole (the worker is potentially hostile — TB2;
        CWE-400 resource exhaustion). ``socket.timeout`` is a ``TimeoutError`` subclass (Py3.10+),
        so a recv that blocks past the remaining budget surfaces as ``TimeoutError`` too.

        Args:
            sock: The connected stream socket.
            n: Number of bytes to read.
            deadline: Absolute :func:`time.monotonic` time by which all ``n`` bytes must arrive.

        Returns:
            Exactly ``n`` bytes.

        Raises:
            EOFError: If the peer closed the connection before ``n`` bytes arrived.
            TimeoutError: If the deadline elapses before ``n`` bytes arrived.
        """
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            time_left = deadline - time.monotonic()
            if time_left <= 0:
                raise TimeoutError("frame read deadline elapsed")
            sock.settimeout(time_left)
            chunk = sock.recv(remaining)
            if not chunk:
                raise EOFError("worker closed connection mid-frame")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _close_socket(sess: _Session) -> None:
        """Close and drop the session's socket if open. Never raises.

        Args:
            sess: The per-session state.
        """
        if sess.sock is not None:
            with contextlib.suppress(OSError):
                sess.sock.close()
            sess.sock = None

    def _socket_path(self, session_id: str) -> str:
        """Compute the per-session UDS path (``<socket_dir>/<token>/<sid>.sock`` — ADR-009).

        The socket lives in a **per-session subdirectory** so the launcher can bind-mount only
        that dir into the worker — a hostile worker therefore sees no sibling sessions' sockets
        (rpc-protocol.md §2; reconciled with the WS3 launcher mount scheme).

        The directory is a SHORT prefix of the session id, not the full id: ``AF_UNIX`` paths are
        capped (~107 bytes on Linux), and the 43-char (256-bit) session id already appears in the
        ``<sid>.sock`` filename — using it for the directory too overflowed the limit on realistic
        socket dirs (the default ``/run/vivarium`` alone reached 108 → ``AF_UNIX path too long``).
        The prefix stays unique per live session (small concurrency cap, high-entropy id), the dir
        is ``0700``, and the full id remains both the socket filename and the server-side identity,
        so isolation/BOLA are unchanged. The in-container path the worker binds is still
        ``/run/vivarium/<session_id>.sock`` (rpc-protocol §2 unchanged).

        Args:
            session_id: The opaque session id (CSPRNG-generated; safe as a filename component).

        Returns:
            The socket path string.
        """
        base = self._socket_dir.rstrip("/")
        return f"{base}/{session_id[:_SOCKET_DIR_TOKEN_LEN]}/{session_id}.sock"


def _xrefs_params(a: s.XrefsIn) -> dict[str, Any]:
    """Build the params dict for ``xrefs_to`` / ``xrefs_from``.

    Args:
        a: The xrefs input model.

    Returns:
        The RPC params dict.
    """
    return {"target": a.target, "offset": a.offset, "limit": a.limit}


def _stream_start_params(a: st.DecompileStreamIn) -> dict[str, Any]:
    """Build the ``start_decompile_stream`` RPC params from the server-side start shape (ADR-040).

    When an explicit ``functions`` set was named (the real name-filtering wired this increment) it
    is forwarded so the worker decompiles exactly those; the worker treats the list as the bound and
    ignores the window. When no set is named the worker windows the program's functions by
    ``offset``/``limit`` (the existing decompile total cap). Pure (no I/O).

    Args:
        a: The server-side stream-start arguments.

    Returns:
        The JSON-serializable params dict for the streaming RPC.
    """
    params: dict[str, Any] = {"offset": a.offset, "limit": a.limit}
    if a.functions is not None:
        params["functions"] = list(a.functions)
    return params


# =====================================================================================
# Untrusted-data wrap builders (PM #9, ADR-005)
# =====================================================================================
# These turn a worker's PLAIN result dict into the typed ``*Out`` model, wrapping every
# binary-derived field via :func:`core.envelope.wrap`. They are the single, auditable map of
# field → provenance. Provenance rule (envelope spec): BINARY = *extracted* from the binary
# (strings, raw/searched bytes, symbol/function/section names, comments, format-reported metadata);
# GHIDRA = *synthesized* by the decompiler/analysis over hostile input (pseudo-C, signatures,
# recovered mnemonics/operands, calling conventions, resolved type names/definitions). Server-
# computed scalars (addresses we normalized, counts, sizes, booleans, ref-types) stay bare.
#
# These builders are pure (dict in → model out, no I/O) and trivially unit-testable. They read
# fields defensively with ``.get`` so a missing optional collapses to ``None``/empty rather than a
# ``KeyError`` crossing the boundary; structural shape is still enforced by the frozen ``*Out``
# models on construction (a bad type fails closed via pydantic).


def _w(value: str, origin: DataOrigin, *, encoding: str | None = None) -> Untrusted[str]:
    """Wrap a required string field at ``origin`` (the chokepoint normalizes/annotates it).

    Args:
        value: The plain, binary-derived string from the worker.
        origin: Provenance (:class:`DataOrigin`).
        encoding: Optional byte-representation tag (e.g. ``"hex"``) for byte payloads.

    Returns:
        The :class:`Untrusted` wrapper.
    """
    return wrap(str(value), origin=origin, encoding=encoding)


def _w_opt(value: object, origin: DataOrigin) -> Untrusted[str] | None:
    """Wrap an OPTIONAL string field, passing ``None`` through unwrapped.

    Args:
        value: The plain value or ``None``.
        origin: Provenance to apply when present.

    Returns:
        The wrapper, or ``None`` if ``value`` is ``None``.
    """
    if value is None:
        return None
    return wrap(str(value), origin=origin)


def _fail_closed[**P, R](builder: Callable[P, R]) -> Callable[P, R]:
    """Map a malformed-worker-result exception in a builder to a safe ``WORKER_UNAVAILABLE``.

    The builders turn the worker's *plain* result dict into a typed ``*Out`` model. A worker that
    returns a structurally-malformed result (a missing required key, a wrong-typed value) would
    otherwise raise a raw ``KeyError``/``ValueError``/``TypeError`` or a pydantic
    ``ValidationError`` out of the adapter — the server shell would then catch it as a *generic*
    ``internal-error``,
    misclassifying a worker fault as a server bug. This decorator catches exactly those shaping
    failures and re-raises the adapter's own ``WORKER_UNAVAILABLE`` (the adapter owns the worker
    fault domain — rpc-protocol.md §6; topic-error-handling fail-closed). It deliberately does NOT
    catch :class:`GhidraMcpError` (an inner builder's already-mapped fault propagates unchanged) or
    any other exception class (a genuine server bug still surfaces as ``internal-error``). The
    untrusted worker detail is never forwarded — only a safe, generic message.

    Args:
        builder: A pure ``dict -> *Out`` (or ``dict -> model``) shaping function.

    Returns:
        The builder wrapped so a malformed-result exception becomes a safe mapped error.
    """

    @functools.wraps(builder)
    def _wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return builder(*args, **kwargs)
        except (KeyError, ValueError, TypeError, ValidationError) as exc:
            raise _errors.make_error(
                ErrorType.WORKER_UNAVAILABLE, "worker returned a malformed result"
            ) from exc

    return _wrapped


@_fail_closed
def _validate[ModelT: BaseModel](model: type[ModelT], result: dict[str, Any]) -> ModelT:
    """Validate a worker result into ``model``, failing closed on a malformed/incomplete result.

    The fail-closed counterpart of a bare ``model.model_validate(result)`` for the few adapter
    methods whose worker result maps 1:1 to a frozen model with no field-wrapping builder
    (lifecycle ``SessionInfo``; ``XrefsOut`` — addresses/ref-types are server-safe). A malformed
    result raises ``ValidationError`` here, which :func:`_fail_closed` maps to a safe envelope.

    Args:
        model: The frozen output model to validate into.
        result: The worker's plain result dict.

    Returns:
        The validated model instance.
    """
    return model.model_validate(result)


@_fail_closed
def _build_decompiled(r: dict[str, Any]) -> s.DecompiledFunction:
    """Build :class:`DecompiledFunction`: name=BINARY; c_code/signature=GHIDRA."""
    return s.DecompiledFunction(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        c_code=_w(r["c_code"], DataOrigin.GHIDRA),
        signature=_w(r["signature"], DataOrigin.GHIDRA),
    )


@_fail_closed
def _build_instruction(r: dict[str, Any]) -> s.Instruction:
    """Build one :class:`Instruction`: mnemonic/operands=GHIDRA; bytes_hex=BINARY (hex)."""
    return s.Instruction(
        address=str(r["address"]),
        mnemonic=_w(r["mnemonic"], DataOrigin.GHIDRA),
        operands=_w(r["operands"], DataOrigin.GHIDRA),
        bytes_hex=_w(r["bytes_hex"], DataOrigin.BINARY, encoding="hex"),
    )


@_fail_closed
def _build_disassemble(r: dict[str, Any]) -> s.DisassembleOut:
    """Build :class:`DisassembleOut` from a plain result."""
    return s.DisassembleOut(
        instructions=[_build_instruction(i) for i in r.get("instructions", [])],
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_pcode_instruction(r: dict[str, Any]) -> s.PcodeInstruction:
    """Build a :class:`PcodeInstruction`: mnemonic + p-code ops are GHIDRA-lifted (untrusted)."""
    return s.PcodeInstruction(
        address=str(r["address"]),
        mnemonic=_w(r["mnemonic"], DataOrigin.GHIDRA),
        pcode=[_w(op, DataOrigin.GHIDRA) for op in r.get("pcode", [])],
    )


@_fail_closed
def _build_get_pcode(r: dict[str, Any]) -> s.GetPcodeOut:
    """Build :class:`GetPcodeOut` (ADR-052) from a plain result."""
    return s.GetPcodeOut(
        instructions=[_build_pcode_instruction(i) for i in r.get("instructions", [])],
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_high_pcode_op(r: dict[str, Any]) -> s.HighPcodeOp:
    """Build one :class:`HighPcodeOp`: the rendered op is decompiler-derived (untrusted)."""
    return s.HighPcodeOp(address=str(r["address"]), op=_w(r["op"], DataOrigin.GHIDRA))


@_fail_closed
def _build_get_high_pcode(r: dict[str, Any]) -> s.GetHighPcodeOut:
    """Build :class:`GetHighPcodeOut` (ADR-053) from a plain result."""
    return s.GetHighPcodeOut(
        ops=[_build_high_pcode_op(o) for o in r.get("ops", [])],
        truncated=bool(r.get("truncated", False)),
    )


def _build_slice_node(r: dict[str, Any]) -> s.SliceNode:
    """Build one :class:`SliceNode` (ADR-064): the rendered op / var name is decompiler-derived."""
    raw_op = r.get("pcode_op")
    addr = r.get("address")
    return s.SliceNode(
        address=None if addr is None else str(addr),
        pcode_op=None if raw_op is None else _w(str(raw_op), DataOrigin.GHIDRA),
        role=r["role"],
    )


@_fail_closed
def _build_data_flow_slice(r: dict[str, Any]) -> s.DataFlowSliceOut:
    """Build :class:`DataFlowSliceOut` (ADR-064) from a plain result."""
    return s.DataFlowSliceOut(
        seed=str(r["seed"]),
        direction=r["direction"],
        nodes=[_build_slice_node(n) for n in r.get("nodes", [])],
        truncated=bool(r.get("truncated", False)),
    )


def _build_proposed_field(r: dict[str, Any]) -> s.ProposedField:
    """Build one :class:`ProposedField` (ADR-069): ``inferred_type`` is decompiler-derived."""
    raw_type = r.get("inferred_type")
    return s.ProposedField(
        offset=int(r["offset"]),
        size=int(r.get("size") or 0),
        inferred_type=None if raw_type is None else _w(str(raw_type), DataOrigin.GHIDRA),
        access=r["access"],
        confidence=r.get("confidence", "observed"),
    )


@_fail_closed
def _build_recover_struct(r: dict[str, Any]) -> s.RecoverStructOut:
    """Build :class:`RecoverStructOut` (ADR-069) — a proposed layout, never applied."""
    return s.RecoverStructOut(
        base=str(r["base"]),
        fields=[_build_proposed_field(f) for f in r.get("fields", [])],
        total_span=int(r.get("total_span") or 0),
        truncated=bool(r.get("truncated", False)),
    )


def _build_recovered_string(r: dict[str, Any]) -> s.RecoveredString:
    """Build one :class:`RecoveredString` (ADR-068): the recovered text + key are binary-derived."""
    decode_key = r.get("decode_key")
    return s.RecoveredString(
        address=str(r["address"]),
        technique=r["technique"],
        text=_w(str(r["text"]), DataOrigin.BINARY),
        length=int(r["length"]),
        encoding=r.get("encoding"),
        decode_key=None if decode_key is None else _w(str(decode_key), DataOrigin.BINARY),
    )


@_fail_closed
def _build_deobfuscate_strings(r: dict[str, Any]) -> s.DeobfuscateStringsOut:
    """Build :class:`DeobfuscateStringsOut` (ADR-068); each recovered text is UNTRUSTED."""
    return s.DeobfuscateStringsOut(
        strings=[_build_recovered_string(x) for x in r.get("strings", [])],
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_stack_variable(r: dict[str, Any]) -> s.StackVariable:
    """Build one :class:`StackVariable`: name + data_type are binary/Ghidra-derived (untrusted)."""
    return s.StackVariable(
        name=_w(r["name"], DataOrigin.GHIDRA),
        stack_offset=int(r["stack_offset"]),
        data_type=_w(r["data_type"], DataOrigin.BINARY),
        size=int(r["size"]),
        is_parameter=bool(r["is_parameter"]),
    )


@_fail_closed
def _build_stack_frame(r: dict[str, Any]) -> s.StackFrameOut:
    """Build :class:`StackFrameOut` (ADR-054) from a plain result."""
    return s.StackFrameOut(
        frame_size=int(r["frame_size"]),
        variables=[_build_stack_variable(v) for v in r.get("variables", [])],
    )


@_fail_closed
def _build_basic_block(r: dict[str, Any]) -> s.BasicBlock:
    """Build one :class:`BasicBlock`: all fields are server-normalized addresses/counts (safe)."""
    return s.BasicBlock(
        address=str(r["address"]),
        end_address=str(r["end_address"]),
        size=int(r["size"]),
        successors=[str(sx) for sx in r.get("successors", [])],
    )


@_fail_closed
def _build_basic_blocks(r: dict[str, Any]) -> s.BasicBlocksOut:
    """Build :class:`BasicBlocksOut` (ADR-055) from a plain result."""
    return s.BasicBlocksOut(
        blocks=[_build_basic_block(b) for b in r.get("blocks", [])],
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_data_type_summary(r: dict[str, Any]) -> s.DataTypeSummary:
    """Build one :class:`DataTypeSummary`: the type name is binary/library-derived (untrusted)."""
    return s.DataTypeSummary(
        name=_w(r["name"], DataOrigin.BINARY), kind=str(r["kind"]), size=int(r["size"])
    )


@_fail_closed
def _build_data_type_list(r: dict[str, Any]) -> s.DataTypeListOut:
    """Build :class:`DataTypeListOut` (ADR-056) from a plain result."""
    return s.DataTypeListOut(
        data_types=[_build_data_type_summary(d) for d in r.get("data_types", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_function_hash(r: dict[str, Any]) -> s.FunctionHashOut:
    """Build :class:`FunctionHashOut` (ADR-057) — all fields SAFE (opaque digests / scalars)."""
    return s.FunctionHashOut(
        address=str(r["address"]),
        exact_bytes=str(r["exact_bytes"]),
        exact_instructions=str(r["exact_instructions"]),
        exact_mnemonics=str(r["exact_mnemonics"]),
        instruction_count=int(r["instruction_count"]),
    )


@_fail_closed
def _build_program_fingerprint(r: dict[str, Any]) -> s.ProgramFingerprintOut:
    """Build :class:`ProgramFingerprintOut` (ADR-073 D1) — all fields SAFE (digests / scalars).

    The digests are server-safe scalars the worker computed over binary-derived facts; ``coverage``
    ratios are computed here (pure) from the worker's byte counts, reusing :func:`_build_coverage`.

    Args:
        r: The worker's plain ``program_fingerprint`` result.

    Returns:
        The typed :class:`ProgramFingerprintOut`.
    """
    import_digest = r.get("import_digest")
    return s.ProgramFingerprintOut(
        structure_digest=str(r["structure_digest"]),
        import_digest=str(import_digest) if import_digest is not None else None,
        function_count=int(r["function_count"]),
        import_count=int(r["import_count"]),
        coverage=_build_coverage(r["coverage"]),
    )


@_fail_closed
def _build_bsim_similarity(r: dict[str, Any]) -> s.BsimSimilarityOut:
    """Build :class:`BsimSimilarityOut` (ADR-058) — addresses + a computed score, all SAFE."""
    return s.BsimSimilarityOut(
        address_a=str(r["address_a"]),
        address_b=str(r["address_b"]),
        similarity=float(r["similarity"]),
    )


@_fail_closed
def _build_similar_function(r: dict[str, Any]) -> s.SimilarFunction:
    """Build one :class:`SimilarFunction`: name is binary-derived (untrusted); score/addr safe."""
    return s.SimilarFunction(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        similarity=float(r["similarity"]),
    )


@_fail_closed
def _build_find_similar_functions(r: dict[str, Any]) -> s.FindSimilarFunctionsOut:
    """Build :class:`FindSimilarFunctionsOut` (ADR-059) from a plain result."""
    return s.FindSimilarFunctionsOut(
        target_address=str(r["target_address"]),
        matches=[_build_similar_function(m) for m in r.get("matches", [])],
        functions_scanned=int(r["functions_scanned"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_version_match(r: dict[str, Any]) -> s.VersionMatch:
    """Build one :class:`VersionMatch` (ADR-060) — addresses + computed scores, all SAFE."""
    return s.VersionMatch(
        source_address=str(r["source_address"]),
        destination_address=str(r["destination_address"]),
        similarity=float(r["similarity"]),
        confidence=float(r["confidence"]),
    )


@_fail_closed
def _build_version_track(r: dict[str, Any]) -> s.VersionTrackOut:
    """Build :class:`VersionTrackOut` (ADR-060) from a plain result — all fields SAFE."""
    return s.VersionTrackOut(
        matches=[_build_version_match(m) for m in r.get("matches", [])],
        match_count=int(r["match_count"]),
        truncated=bool(r.get("truncated", False)),
    )


def _build_diff_function(r: dict[str, Any]) -> s.DiffFunction:
    """Build one added/removed :class:`DiffFunction` (ADR-067): the name is binary-derived."""
    return s.DiffFunction(address=str(r["address"]), name=_w(str(r["name"]), DataOrigin.BINARY))


def _build_changed_function(r: dict[str, Any]) -> s.ChangedFunction:
    """Build one :class:`ChangedFunction` (ADR-067): the shared name is binary-derived."""
    return s.ChangedFunction(
        address_a=str(r["address_a"]),
        address_b=str(r["address_b"]),
        name=_w(str(r["name"]), DataOrigin.BINARY),
        change=r["change"],
    )


@_fail_closed
def _build_binary_diff(r: dict[str, Any]) -> s.BinaryDiffOut:
    """Build :class:`BinaryDiffOut` (ADR-067); names are UNTRUSTED, addresses/counts SAFE."""
    summary = r["summary"]
    return s.BinaryDiffOut(
        added=[_build_diff_function(f) for f in r.get("added", [])],
        removed=[_build_diff_function(f) for f in r.get("removed", [])],
        changed=[_build_changed_function(f) for f in r.get("changed", [])],
        unchanged=[_build_diff_function(f) for f in r.get("unchanged", [])],
        summary=s.DiffSummary(
            added=int(summary["added"]),
            removed=int(summary["removed"]),
            changed=int(summary["changed"]),
            unchanged=int(summary.get("unchanged", 0)),
        ),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_corpus_match(r: dict[str, Any]) -> s.CorpusMatch:
    """Build one :class:`CorpusMatch` (ADR-062): names are binary-derived (untrusted); rest safe."""
    return s.CorpusMatch(
        target_address=str(r["target_address"]),
        target_name=_w(r["target_name"], DataOrigin.BINARY),
        reference_index=int(r["reference_index"]),
        reference_address=str(r["reference_address"]),
        reference_name=_w(r["reference_name"], DataOrigin.BINARY),
        similarity=float(r["similarity"]),
    )


@_fail_closed
def _build_bsim_search_corpus(r: dict[str, Any]) -> s.BsimSearchCorpusOut:
    """Build :class:`BsimSearchCorpusOut` (ADR-062) from a plain result."""
    return s.BsimSearchCorpusOut(
        matches=[_build_corpus_match(m) for m in r.get("matches", [])],
        target_functions_scanned=int(r["target_functions_scanned"]),
        corpus_functions_scanned=int(r["corpus_functions_scanned"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_function_summary(r: dict[str, Any]) -> s.FunctionSummary:
    """Build one :class:`FunctionSummary`: name=BINARY; size is safe."""
    return s.FunctionSummary(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        size=int(r["size"]),
    )


@_fail_closed
def _build_function_list(r: dict[str, Any]) -> s.FunctionListOut:
    """Build :class:`FunctionListOut` from a plain result."""
    return s.FunctionListOut(
        functions=[_build_function_summary(f) for f in r.get("functions", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_function_detail(r: dict[str, Any]) -> s.FunctionDetail:
    """Build :class:`FunctionDetail`: name=BINARY; signature/calling_convention=GHIDRA."""
    return s.FunctionDetail(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        signature=_w(r["signature"], DataOrigin.GHIDRA),
        size=int(r["size"]),
        is_thunk=bool(r["is_thunk"]),
        calling_convention=_w_opt(r.get("calling_convention"), DataOrigin.GHIDRA),
    )


@_fail_closed
def _build_defined_string(r: dict[str, Any]) -> s.DefinedString:
    """Build one :class:`DefinedString`: value=BINARY (extracted, utf-8-replace)."""
    return s.DefinedString(
        address=str(r["address"]),
        value=_w(r["value"], DataOrigin.BINARY, encoding="utf-8-replace"),
        length=int(r["length"]),
    )


@_fail_closed
def _build_string_list(r: dict[str, Any]) -> s.StringListOut:
    """Build :class:`StringListOut` from a plain result."""
    return s.StringListOut(
        strings=[_build_defined_string(x) for x in r.get("strings", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_symbol(r: dict[str, Any]) -> s.Symbol:
    """Build one :class:`Symbol`: name/namespace=BINARY (extracted); kind is safe."""
    return s.Symbol(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        kind=str(r["kind"]),
        namespace=_w_opt(r.get("namespace"), DataOrigin.BINARY),
    )


@_fail_closed
def _build_symbol_list(r: dict[str, Any]) -> s.SymbolListOut:
    """Build :class:`SymbolListOut` from a plain result."""
    return s.SymbolListOut(
        symbols=[_build_symbol(x) for x in r.get("symbols", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_defined_data(r: dict[str, Any]) -> s.DefinedData:
    """Build one :class:`DefinedData`: data_type=GHIDRA (resolved); value_repr=BINARY."""
    return s.DefinedData(
        address=str(r["address"]),
        data_type=_w(r["data_type"], DataOrigin.GHIDRA),
        value_repr=_w(r["value_repr"], DataOrigin.BINARY),
        length=int(r["length"]),
    )


@_fail_closed
def _build_data_list(r: dict[str, Any]) -> s.DataListOut:
    """Build :class:`DataListOut` from a plain result."""
    return s.DataListOut(
        data=[_build_defined_data(x) for x in r.get("data", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_data_type(r: dict[str, Any]) -> s.DataType:
    """Build :class:`DataType`: name/definition=GHIDRA (resolved over hostile input)."""
    return s.DataType(
        name=_w(r["name"], DataOrigin.GHIDRA),
        kind=str(r["kind"]),
        size=int(r["size"]),
        definition=_w(r["definition"], DataOrigin.GHIDRA),
    )


@_fail_closed
def _build_comment(r: dict[str, Any]) -> s.Comment:
    """Build one :class:`Comment`: text=BINARY (extracted; planted-comment injection vector)."""
    return s.Comment(
        address=str(r["address"]),
        comment_type=str(r["comment_type"]),
        text=_w(r["text"], DataOrigin.BINARY),
    )


@_fail_closed
def _build_comment_list(r: dict[str, Any]) -> s.CommentListOut:
    """Build :class:`CommentListOut` from a plain result."""
    return s.CommentListOut(
        comments=[_build_comment(x) for x in r.get("comments", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_memory_block(r: dict[str, Any]) -> s.MemoryBlock:
    """Build one :class:`MemoryBlock`: name=BINARY (section header); rest are safe."""
    return s.MemoryBlock(
        name=_w(r["name"], DataOrigin.BINARY),
        start=str(r["start"]),
        end=str(r["end"]),
        size=int(r["size"]),
        permissions=str(r["permissions"]),
        initialized=bool(r["initialized"]),
    )


@_fail_closed
def _build_memory_map(r: dict[str, Any]) -> s.MemoryMapOut:
    """Build :class:`MemoryMapOut` from a plain result."""
    return s.MemoryMapOut(blocks=[_build_memory_block(b) for b in r.get("blocks", [])])


@_fail_closed
def _build_read_bytes(r: dict[str, Any]) -> s.ReadBytesOut:
    """Build :class:`ReadBytesOut`: data=BINARY (raw bytes, hex-encoded)."""
    return s.ReadBytesOut(
        address=str(r["address"]),
        data=_w(r["data"], DataOrigin.BINARY, encoding="hex"),
        length=int(r["length"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_emulate(r: dict[str, Any]) -> s.EmulateOut:
    """Build :class:`EmulateOut` (ADR-049): register/memory VALUES are BINARY (emulation output)."""
    sr = str(r["stop_reason"])
    if sr not in ("stop-address", "max-steps", "halted", "fault", "stub-limit"):
        sr = "fault"  # fail closed on an unexpected worker stop_reason
    stop_reason = cast('Literal["stop-address", "max-steps", "halted", "fault", "stub-limit"]', sr)
    return s.EmulateOut(
        steps_executed=int(r["steps_executed"]),
        stop_reason=stop_reason,
        registers=[
            s.RegisterValue(
                name=str(x["name"]), value=_w(x["value"], DataOrigin.BINARY, encoding="hex")
            )
            for x in r.get("registers", [])
        ],
        memory=[
            s.MemoryRegion(
                address=str(x["address"]),
                data=_w(x["data"], DataOrigin.BINARY, encoding="hex"),
                length=int(x["length"]),
            )
            for x in r.get("memory", [])
        ],
        return_value=(
            None
            if r.get("return_value") is None
            else _w(str(r["return_value"]), DataOrigin.BINARY, encoding="hex")
        ),
    )


@_fail_closed
def _build_demangle(r: dict[str, Any]) -> s.DemangleOut:
    """Build :class:`DemangleOut` (ADR-050): the demangled name is BINARY-derived → UNTRUSTED."""
    demangled = r.get("demangled")
    scheme = r.get("scheme")
    if scheme not in ("gnu", "msvc", None):
        scheme = None  # fail closed on an unexpected worker scheme
    return s.DemangleOut(
        demangled=(None if demangled is None else _w(str(demangled), DataOrigin.BINARY)),
        scheme=cast('Literal["gnu", "msvc"] | None', scheme),
    )


@_fail_closed
def _build_byte_match(r: dict[str, Any]) -> s.ByteMatch:
    """Build one :class:`ByteMatch`: context_hex=BINARY (raw bytes, hex-encoded)."""
    return s.ByteMatch(
        address=str(r["address"]),
        context_hex=_w(r["context_hex"], DataOrigin.BINARY, encoding="hex"),
    )


@_fail_closed
def _build_search_bytes(r: dict[str, Any]) -> s.SearchBytesOut:
    """Build :class:`SearchBytesOut` from a plain result."""
    return s.SearchBytesOut(
        matches=[_build_byte_match(m) for m in r.get("matches", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_call_graph(r: dict[str, Any]) -> s.CallGraphOut:
    """Build :class:`CallGraphOut`: node ``name`` is BINARY-untrusted; addresses/flags are safe.

    Args:
        r: The worker's plain ``call_graph`` result dict.

    Returns:
        The typed, wrapped :class:`CallGraphOut`.
    """
    return s.CallGraphOut(
        nodes=[_build_call_graph_node(n) for n in r.get("nodes", [])],
        edges=[
            s.CallEdge(from_address=str(e["from_address"]), to_address=str(e["to_address"]))
            for e in r.get("edges", [])
        ],
        unresolved_callers=[str(c) for c in r.get("unresolved_callers", [])],
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_call_graph_node(r: dict[str, Any]) -> s.CallGraphNode:
    """Build one :class:`CallGraphNode`: name=BINARY (extracted symbol); address/flags safe.

    Args:
        r: One plain node dict.

    Returns:
        The typed node with its name untrusted-wrapped.
    """
    return s.CallGraphNode(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        is_external=bool(r.get("is_external", False)),
        has_unresolved_calls=bool(r.get("has_unresolved_calls", False)),
    )


@_fail_closed
def _build_referenced_strings(rs: dict[str, Any]) -> tuple[list[Untrusted[str]], bool]:
    """Shape a ``referenced_strings`` RPC result into (BINARY-wrapped values, truncation flag).

    Used by ``function_context`` (ADR-007). Each referenced string VALUE is attacker-controlled and
    BINARY-origin wrapped (ADR-005). Failing closed here keeps the worker-fault mapping uniform: a
    malformed result (e.g. a non-iterable ``strings``) maps to ``WORKER_UNAVAILABLE`` rather than
    surfacing as a generic internal error.

    Args:
        rs: The worker's plain ``referenced_strings`` result.

    Returns:
        A ``(referenced_strings, truncated)`` tuple.
    """
    values = [_w(str(v), DataOrigin.BINARY) for v in rs.get("strings", [])]
    return values, bool(rs.get("truncated", False))


def _adjacency_from_graph(graph: s.CallGraphOut) -> tuple[dict[str, list[str]], list[str]]:
    """Project a :class:`CallGraphOut` into a plain adjacency map + unresolved-caller list.

    Pure shaping helper (no I/O) feeding the pure ordering core: every node becomes a key (so
    disconnected/leaf nodes are represented), and each resolved edge appends its callee.

    Args:
        graph: The extracted call graph.

    Returns:
        ``(adjacency, unresolved)`` for :func:`vivarium.core.callgraph.compute_analysis_order`.
    """
    adjacency: dict[str, list[str]] = {node.address: [] for node in graph.nodes}
    for edge in graph.edges:
        adjacency.setdefault(edge.from_address, []).append(edge.to_address)
    return adjacency, list(graph.unresolved_callers)


def _build_analysis_order(graph: s.CallGraphOut) -> s.AnalysisOrderOut:
    """Compute + shape the leaf-first analysis order from an extracted call graph (PURE, no JVM).

    Delegates the ordering to the pure server-side core
    (:func:`vivarium.core.callgraph.compute_analysis_order`) — the algorithmic heart of ADR-007 —
    and maps its result to the frozen :class:`AnalysisOrderOut`. No binary-derived *content* is in
    this result (only server-normalized addresses + structural flags), so nothing needs wrapping.

    Args:
        graph: The extracted :class:`CallGraphOut`.

    Returns:
        The leaf-first :class:`AnalysisOrderOut` (sinks first, entry roots last).
    """
    from vivarium.core.callgraph import compute_analysis_order

    adjacency, unresolved = _adjacency_from_graph(graph)
    order = compute_analysis_order(adjacency, unresolved=unresolved)
    return s.AnalysisOrderOut(
        components=[
            s.OrderedComponent(members=list(c.members), is_recursive=c.is_recursive)
            for c in order.components
        ],
        unresolved_callers=list(order.unresolved_callers),
        self_recursive=list(order.self_recursive),
        truncated=graph.truncated,
    )


def _one_hop(
    graph: s.CallGraphOut, entry: str, *, direction: str, offset: int, limit: int
) -> s.CallNeighborsOut:
    """Project a call graph into one function's one-hop neighbors (PURE, no JVM, no I/O).

    Builds the direct callees (``direction="out"`` — edges *from* ``entry``) or callers
    (``direction="in"`` — edges *to* ``entry``) from the graph's edges, de-duplicated by address
    (a function may call/​be-called-by another at several sites) and paginated. The ``unresolved``
    honesty flag is set for the callee direction when ``entry`` itself has unresolved outgoing calls
    (it is not meaningful for callers — schema). ``truncated`` reflects the underlying graph cap or
    a page cap.

    Args:
        graph: The extracted call graph (whole-program for callers; depth-1-rooted for callees).
        entry: The target function's server-normalized entry address.
        direction: ``"out"`` for callees or ``"in"`` for callers.
        offset: Zero-based pagination offset.
        limit: Maximum neighbors to return in the page.

    Returns:
        The bounded, de-duplicated :class:`CallNeighborsOut`.
    """
    by_addr = {node.address: node for node in graph.nodes}
    if direction == "out":
        neighbor_addrs = [e.to_address for e in graph.edges if e.from_address == entry]
        unresolved = any(n.address == entry and n.has_unresolved_calls for n in graph.nodes)
    else:
        neighbor_addrs = [e.from_address for e in graph.edges if e.to_address == entry]
        unresolved = False
    ordered: list[s.CallGraphNode] = []
    seen: set[str] = set()
    for addr in neighbor_addrs:
        node = by_addr.get(addr)
        if node is None or addr in seen:
            continue
        seen.add(addr)
        ordered.append(node)
    total = len(ordered)
    page = ordered[offset : offset + limit]
    truncated = graph.truncated or (offset + limit < total)
    return s.CallNeighborsOut(
        neighbors=page, total=total, unresolved=unresolved, truncated=truncated
    )


@_fail_closed
def _build_program_metadata(r: dict[str, Any]) -> s.ProgramMetadata:
    """Build :class:`ProgramMetadata`: compiler=BINARY (format-reported); rest are safe."""
    return s.ProgramMetadata(
        sha256=str(r["sha256"]),
        size_bytes=int(r["size_bytes"]),
        format=str(r["format"]),
        architecture=str(r["architecture"]),
        endianness=str(r["endianness"]),
        compiler=_w_opt(r.get("compiler"), DataOrigin.BINARY),
        entry_point=(str(r["entry_point"]) if r.get("entry_point") is not None else None),
        function_count=int(r["function_count"]),
        analysis_complete=bool(r["analysis_complete"]),
    )


# --- Tier-2 builders (v1.1 — ADR-008) --------------------------------------------------------
@_fail_closed
def _build_imported_symbol(r: dict[str, Any]) -> s.ImportedSymbol:
    """Build one :class:`ImportedSymbol`: name/library=BINARY (extracted); address safe-optional."""
    return s.ImportedSymbol(
        name=_w(r["name"], DataOrigin.BINARY),
        library=_w_opt(r.get("library"), DataOrigin.BINARY),
        address=(str(r["address"]) if r.get("address") is not None else None),
    )


@_fail_closed
def _build_import_list(r: dict[str, Any]) -> s.ImportListOut:
    """Build :class:`ImportListOut` from a plain result."""
    return s.ImportListOut(
        imports=[_build_imported_symbol(x) for x in r.get("imports", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_exported_symbol(r: dict[str, Any]) -> s.ExportedSymbol:
    """Build one :class:`ExportedSymbol`: name=BINARY (extracted); address safe."""
    return s.ExportedSymbol(
        name=_w(r["name"], DataOrigin.BINARY),
        address=str(r["address"]),
    )


@_fail_closed
def _build_export_list(r: dict[str, Any]) -> s.ExportListOut:
    """Build :class:`ExportListOut` from a plain result."""
    return s.ExportListOut(
        exports=[_build_exported_symbol(x) for x in r.get("exports", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_identified_function(r: dict[str, Any]) -> s.IdentifiedFunction:
    """Build one :class:`IdentifiedFunction`: matched_name/library=BINARY; address/score safe."""
    return s.IdentifiedFunction(
        address=str(r["address"]),
        matched_name=_w(r["matched_name"], DataOrigin.BINARY),
        library=_w(r["library"], DataOrigin.BINARY),
        score=float(r["score"]),
    )


@_fail_closed
def _build_identified_functions(r: dict[str, Any]) -> s.IdentifyFunctionsOut:
    """Build :class:`IdentifyFunctionsOut` from a plain worker result (ADR-042).

    ``total`` is recomputed from the wrapped matches (== ``len(matches)``) so the contract holds
    regardless of any worker-reported count; ``truncated`` carries the worker's own clip flag (the
    adapter OR-s the caller's ``limit`` clip on top in :meth:`RpcGhidraAdapter.identify_functions`).
    """
    matches = [_build_identified_function(m) for m in r.get("matches", [])]
    return s.IdentifyFunctionsOut(
        matches=matches,
        total=len(matches),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_coverage(r: dict[str, Any]) -> s.CoverageOut:
    """Build :class:`CoverageOut`: pure ratios from worker byte counts (no binary-derived content).

    Computes ``undefined_bytes`` and the code/data ratios server-side (guarding divide-by-zero with
    a 0.0 ratio when the program has no addressable bytes). All fields are safe scalars.

    Args:
        r: The worker's plain ``coverage`` counts.

    Returns:
        The typed :class:`CoverageOut`.
    """
    total = int(r["total_bytes"])
    code = int(r["defined_code_bytes"])
    data = int(r["defined_data_bytes"])
    undefined = max(0, total - code - data)
    return s.CoverageOut(
        total_bytes=total,
        defined_code_bytes=code,
        defined_data_bytes=data,
        undefined_bytes=undefined,
        code_ratio=(code / total if total else 0.0),
        data_ratio=(data / total if total else 0.0),
        function_count=int(r["function_count"]),
    )


@_fail_closed
def _build_cyclomatic_complexity(r: dict[str, Any]) -> s.CyclomaticComplexity:
    """Build :class:`CyclomaticComplexity` from worker CFG counts: name=BINARY; complexity is pure.

    Computes the McCabe number in the pure core (``vivarium.core.metrics.cyclomatic_complexity``)
    from the worker-extracted block/edge counts; only the function ``name`` is binary-derived.

    Args:
        r: The worker's plain ``function_cfg`` counts.

    Returns:
        The typed :class:`CyclomaticComplexity`.
    """
    from vivarium.core.metrics import cyclomatic_complexity as _mccabe

    block_count = int(r["block_count"])
    edge_count = int(r["edge_count"])
    return s.CyclomaticComplexity(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        complexity=_mccabe(block_count, edge_count),
        block_count=block_count,
        edge_count=edge_count,
        incomplete=bool(r.get("incomplete", False)),
    )


# --- mutation (write) result builders (v1.1 — ADR-012; old_name is binary-derived → Untrusted) ---
@_fail_closed
def _build_rename_result(r: dict[str, Any]) -> s.RenameResult:
    """Build a ``RenameResult`` from the worker's plain dict (wraps the prior name Untrusted)."""
    return s.RenameResult(
        address=str(r["address"]),
        old_name=_w(r["old_name"], DataOrigin.BINARY),
        new_name=str(r["new_name"]),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_rename_symbol_result(r: dict[str, Any]) -> s.RenameSymbolResult:
    """Build a ``RenameSymbolResult`` (adds the closed-vocabulary symbol kind)."""
    return s.RenameSymbolResult(
        address=str(r["address"]),
        old_name=_w(r["old_name"], DataOrigin.BINARY),
        new_name=str(r["new_name"]),
        applied=bool(r["applied"]),
        kind=str(r["kind"]),
    )


@_fail_closed
def _build_set_comment_result(r: dict[str, Any]) -> s.SetCommentResult:
    """Build a ``SetCommentResult`` (no binary-derived field — all server/closed-vocabulary)."""
    return s.SetCommentResult(
        address=str(r["address"]),
        comment_type=str(r["comment_type"]),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_undo_out(sid: str, r: dict[str, Any]) -> s.SessionUndoOut:
    """Build a ``SessionUndoOut`` (session id is server-known/safe; ``undone`` from the worker)."""
    return s.SessionUndoOut(session_id=sid, undone=bool(r["undone"]))


@_fail_closed
def _build_structural_rename_result(r: dict[str, Any]) -> s.StructuralRenameResult:
    """Build a ``StructuralRenameResult`` (function + prior name → Untrusted; ADR-013)."""
    return s.StructuralRenameResult(
        address=str(r["address"]),
        function=_w(r["function"], DataOrigin.BINARY),
        old_name=_w(r["old_name"], DataOrigin.BINARY),
        new_name=str(r["new_name"]),
        applied=bool(r["applied"]),
    )


# --- structural type-aware (ADR-014 Phase B) — echoed signature/type fields are binary-derived ---
def _type_ref_params(ref: s.TypeRef) -> dict[str, Any]:
    """Serialize a :class:`TypeRef` into plain RPC params (no C string — ADR-014 §2).

    The worker resolves these fields against the program's ``DataTypeManager``; only one of
    ``base``/``named`` is set (model-validated), and the modifiers are bounded.

    Args:
        ref: The validated :class:`TypeRef` to serialize.

    Returns:
        A plain, JSON-serializable dict mirroring the ``TypeRef`` shape.
    """
    return {
        "base": ref.base,
        "named": ref.named,
        "pointer_levels": ref.pointer_levels,
        "array_len": ref.array_len,
    }


@_fail_closed
def _build_set_function_signature_result(r: dict[str, Any]) -> s.SetFunctionSignatureResult:
    """Build a ``SetFunctionSignatureResult`` (echoed signatures → Untrusted; ADR-014 §6).

    ``new_signature`` is untrusted because Ghidra RE-RENDERS our applied prototype (the worker is
    untrusted on the way out — ADR-005); ``address``/``applied`` are server/worker-controlled.
    """
    return s.SetFunctionSignatureResult(
        address=str(r["address"]),
        function=_w(r["function"], DataOrigin.BINARY),
        old_signature=_w(r["old_signature"], DataOrigin.BINARY),
        new_signature=_w(r["new_signature"], DataOrigin.BINARY),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_apply_data_type_result(r: dict[str, Any]) -> s.ApplyDataTypeResult:
    """Build an ``ApplyDataTypeResult`` (resolved type name → Untrusted; ADR-014 §6)."""
    return s.ApplyDataTypeResult(
        address=str(r["address"]),
        type_name=_w(r["type_name"], DataOrigin.BINARY),
        size=int(r["size"]),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_apply_type_archive_result(r: dict[str, Any]) -> s.ApplyTypeArchiveResult:
    """Build an ``ApplyTypeArchiveResult`` (ADR-051) — all fields SAFE scalars (no Untrusted)."""
    return s.ApplyTypeArchiveResult(
        archive=str(r["archive"]),
        functions_updated=int(r["functions_updated"]),
        applied=bool(r["applied"]),
    )


# --- composite-type creation (ADR-015 Phase C) — every result field is server/worker-controlled
# (the name is the one WE set + validated; size/field_count/applied are worker scalars), so NONE is
# Untrusted-wrapped (ADR-015 §7). A future field echoing Ghidra's rendered layout MUST be Untrusted.
def _field_spec_params(field: s.FieldSpec) -> dict[str, Any]:
    """Serialize a :class:`FieldSpec` into plain RPC params (no C string — ADR-015 §2).

    The worker resolves ``type`` against the program's ``DataTypeManager`` (NEVER parses it); the
    bounded ``name``/``offset`` are passed through as-is.

    Args:
        field: The validated :class:`FieldSpec` to serialize.

    Returns:
        A plain, JSON-serializable dict mirroring the ``FieldSpec`` shape (``type`` a TypeRef dict).
    """
    return {"name": field.name, "type": _type_ref_params(field.type), "offset": field.offset}


@_fail_closed
def _build_define_struct_result(r: dict[str, Any]) -> s.DefineStructResult:
    """Build a ``DefineStructResult`` — all fields server/worker-controlled, SAFE (ADR-015 §7)."""
    return s.DefineStructResult(
        name=str(r["name"]),
        kind=str(r["kind"]),
        size=int(r["size"]),
        field_count=int(r["field_count"]),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_define_union_result(r: dict[str, Any]) -> s.DefineUnionResult:
    """Build a ``DefineUnionResult`` — all fields server/worker-controlled, SAFE (ADR-015 §7)."""
    return s.DefineUnionResult(
        name=str(r["name"]),
        kind=str(r["kind"]),
        size=int(r["size"]),
        field_count=int(r["field_count"]),
        applied=bool(r["applied"]),
    )


def _build_delete_type_result(r: dict[str, Any]) -> s.DeleteTypeResult:
    """Build a ``DeleteTypeResult`` — all fields are server/worker scalars, SAFE (ADR-031)."""
    return s.DeleteTypeResult(
        name=str(r["name"]),
        deleted=bool(r["deleted"]),
        dependents_reverted=int(r["dependents_reverted"]),
    )


# --- multi-type composite batch (ADR-021) — like ADR-015, every result field is server/worker-
# controlled (the names are the ones WE set + validated; sizes/counts/applied are worker scalars),
# so NONE is Untrusted-wrapped. A future field echoing Ghidra's rendered layout MUST be Untrusted.
def _composite_spec_params(spec: s.CompositeSpec) -> dict[str, Any]:
    """Serialize a :class:`CompositeSpec` into plain RPC params (no C string — ADR-021/§2).

    The worker resolves each member ``type`` against the program's ``DataTypeManager`` / the
    pre-registered batch handles (NEVER parses it); the bounded ``kind``/``name``/``packed`` and
    each field's ``name``/``offset`` are passed through.

    Args:
        spec: The validated :class:`CompositeSpec` to serialize.

    Returns:
        A plain, JSON-serializable dict mirroring the entry (``fields[].type`` a TypeRef dict).
    """
    return {
        "kind": spec.kind,
        "name": spec.name,
        "fields": [_field_spec_params(f) for f in spec.fields],
        "packed": spec.packed,
    }


@_fail_closed
def _build_define_types_result(r: dict[str, Any]) -> s.DefineTypesResult:
    """Build a ``DefineTypesResult`` — all fields server/worker-controlled, SAFE (ADR-021)."""
    return s.DefineTypesResult(
        types=[
            s.DefinedType(
                name=str(t["name"]),
                kind=str(t["kind"]),
                size=int(t["size"]),
                field_count=int(t["field_count"]),
            )
            for t in r["types"]
        ],
        applied=bool(r["applied"]),
    )


# --- cross-session annotation persistence (ADR-018; export read-out) ---------------------------
# The worker returns a PLAIN document of USER_DEFINED annotations (entries are plain dicts). These
# builders turn it into the typed ``ExportedAnnotationDocument``, wrapping every binary-derived
# value (read-out names/comments/recovered signatures) as ``Untrusted`` (ADR-005). The TypeRef /
# FieldSpec structures are allow-listed structured references (base/named identifier + bounded
# modifiers) — safe scalars, round-tripped bare so the client can re-import. The server overlays
# the authoritative ``binary.sha256``; ``schema_version`` is the worker-reported document version.


def _exported_type_ref_from_plain(r: dict[str, Any]) -> s.ExportedTypeRef:
    """Build an :class:`ExportedTypeRef` from a plain worker dict — ``named`` wrapped (ADR-005).

    The ``named`` reference is a type name read out of the hostile program (binary-derived → an
    injection vector), so it is ``Untrusted``-wrapped at this chokepoint; ``base`` is closed-vocab
    and the modifiers are server-safe scalars (CWE-200 — no hostile name leaves bare).

    Args:
        r: ``{"base", "named", "pointer_levels", "array_len"}`` from the worker.

    Returns:
        The reconstructed :class:`ExportedTypeRef` (binary-derived ``named`` wrapped).
    """
    return s.ExportedTypeRef(
        base=r.get("base"),
        named=_w_opt(r.get("named"), DataOrigin.BINARY),
        pointer_levels=int(r.get("pointer_levels", 0)),
        array_len=r.get("array_len"),
    )


def _exported_field_spec_from_plain(r: dict[str, Any]) -> s.ExportedFieldSpec:
    """Build an :class:`ExportedFieldSpec` — member ``name`` Untrusted-wrapped (ADR-005)."""
    return s.ExportedFieldSpec(
        name=_w(r["name"], DataOrigin.BINARY),
        type=_exported_type_ref_from_plain(r["type"]),
        offset=r.get("offset"),
    )


# C901: flat field-by-field mapping of one untrusted export record into the typed entry (one over).
def _build_exported_entry(r: dict[str, Any]) -> s.ExportedEntry:  # noqa: C901
    """Build one exported annotation entry from a plain worker dict (binary strings → Untrusted).

    Dispatches on the worker-reported ``kind``; binary-derived read-out values (current names,
    comment text, selectors) are wrapped at the ADR-005 chokepoint, while structured references
    (``TypeRef``/``FieldSpec``) and addresses/closed-vocab fields stay bare/safe.

    Args:
        r: The plain entry dict from the worker.

    Returns:
        The typed exported entry (the union variant for ``kind``).

    Raises:
        KeyError/ValueError: On a malformed entry (the ``_fail_closed`` wrapper on the caller maps
            it to ``worker-unavailable``).
    """
    kind = str(r["kind"])
    if kind == "rename_function":
        return s.ExportedRenameFunctionEntry(
            kind="rename_function",
            function=str(r["function"]),
            new_name=_w(r["new_name"], DataOrigin.BINARY),
        )
    if kind == "rename_symbol":
        return s.ExportedRenameSymbolEntry(
            kind="rename_symbol",
            identifier=str(r["identifier"]),
            new_name=_w(r["new_name"], DataOrigin.BINARY),
        )
    if kind == "rename_local_variable":
        return s.ExportedRenameLocalVariableEntry(
            kind="rename_local_variable",
            function=str(r["function"]),
            variable=_w(r["variable"], DataOrigin.BINARY),
            new_name=_w(r["new_name"], DataOrigin.BINARY),
        )
    if kind == "rename_parameter":
        return s.ExportedRenameParameterEntry(
            kind="rename_parameter",
            function=str(r["function"]),
            parameter=_w(r["parameter"], DataOrigin.BINARY),
            new_name=_w(r["new_name"], DataOrigin.BINARY),
        )
    if kind == "set_comment":
        return s.ExportedSetCommentEntry(
            kind="set_comment",
            address=str(r["address"]),
            comment_type=str(r["comment_type"]),
            text=_w(r["text"], DataOrigin.BINARY),
        )
    if kind == "set_function_signature":
        return s.ExportedSetFunctionSignatureEntry(
            kind="set_function_signature",
            function=str(r["function"]),
            return_type=_exported_type_ref_from_plain(r["return_type"]),
            parameters=[
                s.ExportedParamSpec(
                    name=_w(p["name"], DataOrigin.BINARY),
                    type=_exported_type_ref_from_plain(p["type"]),
                )
                for p in r.get("parameters", [])
            ],
            calling_convention=r.get("calling_convention"),
        )
    if kind == "apply_data_type":
        return s.ExportedApplyDataTypeEntry(
            kind="apply_data_type",
            address=str(r["address"]),
            type=_exported_type_ref_from_plain(r["type"]),
            clear_existing=bool(r.get("clear_existing", False)),
        )
    if kind == "define_types":
        # ADR-032: the interdependent-composite round-trip batch. Each member's name + field names
        # are binary-derived (read out of the hostile program) → Untrusted-wrapped (ADR-005).
        return s.ExportedDefineTypesEntry(
            kind="define_types",
            types=[_exported_composite_spec_from_plain(t) for t in r["types"]],
        )
    if kind == "define_struct":
        return s.ExportedDefineStructEntry(
            kind="define_struct",
            name=_w(r["name"], DataOrigin.BINARY),
            fields=[_exported_field_spec_from_plain(f) for f in r["fields"]],
            packed=bool(r.get("packed", False)),
        )
    if kind == "define_union":
        return s.ExportedDefineUnionEntry(
            kind="define_union",
            name=_w(r["name"], DataOrigin.BINARY),
            fields=[_exported_field_spec_from_plain(f) for f in r["fields"]],
        )
    raise ValueError("unknown exported annotation entry kind")


def _exported_composite_spec_from_plain(t: dict[str, Any]) -> s.ExportedCompositeSpec:
    """Build an exported composite spec (one define_types batch member) — names Untrusted (ADR-032).

    Args:
        t: The plain ``{"kind", "name", "fields", "packed"?}`` composite dict from the worker.

    Returns:
        The typed :class:`ExportedCompositeSpec` (``name`` + each field name Untrusted-wrapped).
    """
    return s.ExportedCompositeSpec(
        kind=cast(Literal["struct", "union"], str(t["kind"])),
        name=_w(t["name"], DataOrigin.BINARY),
        fields=[_exported_field_spec_from_plain(f) for f in t["fields"]],
        packed=bool(t.get("packed", False)),
    )


def _export_annotations_params(targets: s.ExportTargets) -> dict[str, Any]:
    """Shape the change-log selection into the ``export_annotations`` RPC params (ADR-027 D4).

    Pure (no I/O, no JVM) so it is unit-testable hermetically (the worker ``_gh_*`` edge is not).
    Emits ONLY identity keys — comment ``(address, comment_type)`` pairs and composite names — never
    a binary-derived value (ADR-002/master §5). The shape matches the worker's expectation in
    ``rpc-protocol.md``:
    ``{"targets": {"comments": [{address, comment_type}], "composites": [name]}}``.

    Args:
        targets: The server-built export selection from the session change-log.

    Returns:
        The plain JSON-RPC params dict for the ``export_annotations`` method.
    """
    return {
        "targets": {
            "comments": [
                {"address": c.address, "comment_type": c.comment_type} for c in targets.comments
            ],
            "composites": list(targets.composites),
        }
    }


@_fail_closed
def _build_exported_annotation_document(r: dict[str, Any]) -> s.SessionExportAnnotationsOut:
    """Build the typed ``SessionExportAnnotationsOut`` from the plain worker export result.

    Wraps the advisory ``binary.name`` as ``Untrusted`` (binary-derived); the ``sha256`` is the
    server-relevant digest of input (safe). Each entry is built by :func:`_build_exported_entry`
    (binary-derived strings wrapped). A malformed result fails closed via the decorator.

    Args:
        r: ``{"schema_version", "binary": {"sha256", "name"?, "size"?}, "entries": [...]}``.

    Returns:
        The typed export result (untrusted-wrapped document).
    """
    binary = r["binary"]
    return s.SessionExportAnnotationsOut(
        document=s.ExportedAnnotationDocument(
            schema_version=int(r["schema_version"]),
            binary=s.ExportedBinaryRef(
                sha256=str(binary["sha256"]),
                name=_w_opt(binary.get("name"), DataOrigin.BINARY),
                size=binary.get("size"),
            ),
            entries=[_build_exported_entry(e) for e in r.get("entries", [])],
        )
    )
