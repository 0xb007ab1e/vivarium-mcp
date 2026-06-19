"""Critical-path unit tests for ``security.limits`` — pre-worker DoS bounds (WS4).

``resolve_limits`` and ``check_binary_size`` are 100%-critical-path controls (the first DoS line,
enforced on the server before any byte reaches Ghidra — PLAN §3 F7, TB3). These tests cover the
clamp logic (a caller may only make a limit STRICTER, never wider than the hard ceiling), boundary
values, and the integer/sign/type edge cases that a naive comparison would miss.

All inputs are synthetic; no I/O, deterministic, hermetic (master §4).
"""

from __future__ import annotations

import pytest

from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.security import limits as lim
from vivarium.security.limits import (
    DEFAULT_ANALYSIS_TIMEOUT_S,
    DEFAULT_MAX_BINARY_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_SESSIONS,
    DEFAULT_TOOL_TIMEOUT_S,
    DEFAULT_WORKER_CPUS,
    DEFAULT_WORKER_MEM_MIB,
    DEFAULT_WORKER_PIDS,
    DEFAULT_WORKER_TMPFS_PROJECT_MIB,
    DEFAULT_WORKER_TMPFS_SCRATCH_MIB,
    HARD_MAX_ANALYSIS_TIMEOUT_S,
    HARD_MAX_BINARY_BYTES,
    HARD_MAX_SESSIONS,
    HARD_MAX_WORKER_CPUS,
    HARD_MAX_WORKER_MEM_MIB,
    HARD_MAX_WORKER_PIDS,
    HARD_MAX_WORKER_TMPFS_PROJECT_MIB,
    HARD_MAX_WORKER_TMPFS_SCRATCH_MIB,
    Limits,
    WorkerResources,
    check_binary_size,
    plausible_max_bytes,
    resolve_limits,
    resolve_worker_resources,
)

pytestmark = pytest.mark.critical


# ----------------------------------------------------------------------------------------------
# Frozen constants (defense against accidental drift of the contract values)
# ----------------------------------------------------------------------------------------------
def test_frozen_default_and_hard_constants() -> None:
    """The default + hard-ceiling constants match the frozen WS0 contract."""
    assert DEFAULT_MAX_BINARY_BYTES == 128 * 1024 * 1024
    assert DEFAULT_ANALYSIS_TIMEOUT_S == 600
    assert DEFAULT_TOOL_TIMEOUT_S == 60
    assert DEFAULT_MAX_RESPONSE_BYTES == 4 * 1024 * 1024
    assert DEFAULT_MAX_SESSIONS == 4
    assert HARD_MAX_BINARY_BYTES == 1024 * 1024 * 1024
    assert HARD_MAX_ANALYSIS_TIMEOUT_S == 3600
    assert HARD_MAX_SESSIONS == 32


# ----------------------------------------------------------------------------------------------
# resolve_limits — defaults
# ----------------------------------------------------------------------------------------------
def test_resolve_none_returns_defaults() -> None:
    """No overrides → the safe built-in defaults."""
    resolved = resolve_limits(None)
    assert resolved == Limits()


def test_resolve_empty_dict_returns_defaults() -> None:
    """An empty override map is equivalent to no overrides."""
    assert resolve_limits({}) == Limits()


# ----------------------------------------------------------------------------------------------
# resolve_limits — clamping (the security-critical behavior)
# ----------------------------------------------------------------------------------------------
def test_stricter_override_is_honored() -> None:
    """A value below the ceiling is accepted verbatim (callers may tighten limits)."""
    resolved = resolve_limits({"max_sessions": 2, "max_binary_bytes": 1024})
    assert resolved.max_sessions == 2
    assert resolved.max_binary_bytes == 1024


@pytest.mark.parametrize(
    ("key", "ceiling"),
    [
        ("max_binary_bytes", HARD_MAX_BINARY_BYTES),
        ("analysis_timeout_s", HARD_MAX_ANALYSIS_TIMEOUT_S),
        ("tool_timeout_s", HARD_MAX_ANALYSIS_TIMEOUT_S),
        ("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES),
        ("max_sessions", HARD_MAX_SESSIONS),
        ("max_sessions_per_owner", HARD_MAX_SESSIONS),
    ],
)
def test_widening_override_is_clamped_to_ceiling(key: str, ceiling: int) -> None:
    """An attempt to widen any limit far past its ceiling is clamped DOWN — never honored."""
    resolved = resolve_limits({key: ceiling * 1000})
    assert getattr(resolved, key) == ceiling


@pytest.mark.parametrize(
    ("key", "ceiling"),
    [
        ("max_binary_bytes", HARD_MAX_BINARY_BYTES),
        ("analysis_timeout_s", HARD_MAX_ANALYSIS_TIMEOUT_S),
        ("max_sessions", HARD_MAX_SESSIONS),
        ("max_sessions_per_owner", HARD_MAX_SESSIONS),
    ],
)
def test_exact_ceiling_is_allowed(key: str, ceiling: int) -> None:
    """A value exactly at the ceiling is accepted (boundary)."""
    assert getattr(resolve_limits({key: ceiling}), key) == ceiling


def test_response_bytes_cannot_be_raised_above_default() -> None:
    """``max_response_bytes`` has no higher ceiling — it cannot be raised above its default."""
    resolved = resolve_limits({"max_response_bytes": DEFAULT_MAX_RESPONSE_BYTES * 10})
    assert resolved.max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES


def test_value_one_is_the_floor() -> None:
    """The minimum accepted positive value is 1 (boundary)."""
    assert resolve_limits({"max_sessions": 1}).max_sessions == 1


def test_max_sessions_per_owner_defaults_off_and_is_settable() -> None:
    """The per-owner cap is OFF by default (None) and accepts a positive override (ADR-017)."""
    assert resolve_limits().max_sessions_per_owner is None
    assert resolve_limits({"max_sessions_per_owner": 2}).max_sessions_per_owner == 2


# ----------------------------------------------------------------------------------------------
# resolve_limits — fail-closed rejection
# ----------------------------------------------------------------------------------------------
def test_unknown_key_rejected() -> None:
    """An unknown limit key fails closed (not silently ignored)."""
    with pytest.raises(GhidraMcpError) as ei:
        resolve_limits({"max_threads": 9})
    assert ei.value.envelope.type is ErrorType.VALIDATION
    assert ei.value.envelope.status == 400


@pytest.mark.parametrize("value", [0, -1, -1000])
def test_non_positive_value_rejected(value: int) -> None:
    """Zero/negative limits fail closed."""
    with pytest.raises(GhidraMcpError) as ei:
        resolve_limits({"max_sessions": value})
    assert ei.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.parametrize("value", [True, False, 1.5, "8", None])
def test_non_int_value_rejected(value: object) -> None:
    """Non-int values (incl. ``bool``, which is an ``int`` subclass) fail closed."""
    with pytest.raises(GhidraMcpError) as ei:
        resolve_limits({"max_sessions": value})  # type: ignore[dict-item]
    assert ei.value.envelope.type is ErrorType.VALIDATION


def test_error_detail_is_safe_and_names_only_the_key() -> None:
    """The validation detail is a safe summary — it never leaks internals."""
    with pytest.raises(GhidraMcpError) as ei:
        resolve_limits({"max_binary_bytes": 0})
    detail = ei.value.envelope.detail
    assert "max_binary_bytes" in detail
    assert "Traceback" not in detail
    assert "/" not in detail  # no paths


# ----------------------------------------------------------------------------------------------
# check_binary_size
# ----------------------------------------------------------------------------------------------
def test_size_under_cap_passes() -> None:
    """A size below the cap is accepted (does not raise)."""
    check_binary_size(1024, Limits())  # no exception == accepted


def test_size_zero_passes() -> None:
    """A zero-byte input is not a size violation (other validation handles emptiness)."""
    check_binary_size(0, Limits())  # no exception == accepted


def test_size_exactly_at_cap_passes() -> None:
    """A size exactly equal to the cap is accepted (boundary — ``>`` not ``>=``)."""
    check_binary_size(DEFAULT_MAX_BINARY_BYTES, Limits())  # no exception == accepted


def test_size_one_over_cap_rejected() -> None:
    """One byte over the cap is rejected with LIMIT_EXCEEDED before the worker (boundary)."""
    with pytest.raises(GhidraMcpError) as ei:
        check_binary_size(DEFAULT_MAX_BINARY_BYTES + 1, Limits())
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED
    assert ei.value.envelope.status == 413
    assert ei.value.envelope.retryable is False


def test_size_respects_custom_stricter_cap() -> None:
    """``check_binary_size`` enforces a tightened ``max_binary_bytes`` from resolved limits."""
    strict = resolve_limits({"max_binary_bytes": 100})
    check_binary_size(100, strict)  # at cap, ok
    with pytest.raises(GhidraMcpError) as ei:
        check_binary_size(101, strict)
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED


@pytest.mark.parametrize("bad", [-1, -1024, True, False, 3.0, "10", None])
def test_negative_or_non_int_size_fails_closed(bad: object) -> None:
    """A negative/non-int size fails closed as VALIDATION (guards a sign/overflow bug upstream)."""
    with pytest.raises(GhidraMcpError) as ei:
        check_binary_size(bad, Limits())  # type: ignore[arg-type]
    assert ei.value.envelope.type is ErrorType.VALIDATION


def test_oversize_detail_reports_cap_and_size_only() -> None:
    """The LIMIT_EXCEEDED detail reports the rejected size + cap and nothing sensitive."""
    with pytest.raises(GhidraMcpError) as ei:
        check_binary_size(DEFAULT_MAX_BINARY_BYTES + 1, Limits())
    detail = ei.value.envelope.detail
    assert str(DEFAULT_MAX_BINARY_BYTES) in detail
    assert "Traceback" not in detail
    assert "/" not in detail


def test_hard_ceilings_table_covers_all_limit_fields() -> None:
    """Every ``Limits`` field has an entry in the clamp table (no un-clamped surface)."""
    from dataclasses import fields

    assert {f.name for f in fields(Limits)} == set(lim._HARD_CEILINGS)


# ----------------------------------------------------------------------------------------------
# resolve_worker_resources — defaults (ADR-023 / F1)
# ----------------------------------------------------------------------------------------------
def test_worker_frozen_default_and_hard_constants() -> None:
    """The worker default + hard-ceiling constants match the ratified ADR-023 values."""
    assert DEFAULT_WORKER_MEM_MIB == 4096
    assert DEFAULT_WORKER_CPUS == 2
    assert DEFAULT_WORKER_PIDS == 512
    assert DEFAULT_WORKER_TMPFS_SCRATCH_MIB == 2048
    assert DEFAULT_WORKER_TMPFS_PROJECT_MIB == 4096
    assert HARD_MAX_WORKER_MEM_MIB == 32768
    assert HARD_MAX_WORKER_CPUS == 16
    assert HARD_MAX_WORKER_PIDS == 4096
    assert HARD_MAX_WORKER_TMPFS_SCRATCH_MIB == 16384
    assert HARD_MAX_WORKER_TMPFS_PROJECT_MIB == 32768


def test_resolve_worker_none_returns_defaults() -> None:
    """No overrides → the safe built-in worker defaults."""
    assert resolve_worker_resources(None) == WorkerResources()


def test_resolve_worker_empty_dict_returns_defaults() -> None:
    """An empty override map is equivalent to no worker overrides."""
    assert resolve_worker_resources({}) == WorkerResources()


# ----------------------------------------------------------------------------------------------
# resolve_worker_resources — clamping
# ----------------------------------------------------------------------------------------------
def test_worker_below_default_override_is_honored() -> None:
    """A value below the default is accepted verbatim (an operator may run a smaller worker)."""
    resolved = resolve_worker_resources({"mem_mib": 1024, "cpus": 1})
    assert resolved.mem_mib == 1024
    assert resolved.cpus == 1


def test_worker_above_default_below_ceiling_override_is_honored() -> None:
    """A value above the default but below the ceiling is accepted verbatim (tunable up)."""
    resolved = resolve_worker_resources({"mem_mib": 8192})
    assert resolved.mem_mib == 8192


@pytest.mark.parametrize(
    ("key", "ceiling"),
    [
        ("mem_mib", HARD_MAX_WORKER_MEM_MIB),
        ("cpus", HARD_MAX_WORKER_CPUS),
        ("pids", HARD_MAX_WORKER_PIDS),
        ("tmpfs_scratch_mib", HARD_MAX_WORKER_TMPFS_SCRATCH_MIB),
        ("tmpfs_project_mib", HARD_MAX_WORKER_TMPFS_PROJECT_MIB),
    ],
)
def test_worker_widening_override_is_clamped_to_ceiling(key: str, ceiling: int) -> None:
    """An attempt to widen a worker bound far past its ceiling is clamped DOWN (CWE-400)."""
    assert getattr(resolve_worker_resources({key: ceiling * 1000}), key) == ceiling


@pytest.mark.parametrize(
    ("key", "ceiling"),
    [
        ("mem_mib", HARD_MAX_WORKER_MEM_MIB),
        ("cpus", HARD_MAX_WORKER_CPUS),
        ("pids", HARD_MAX_WORKER_PIDS),
        ("tmpfs_scratch_mib", HARD_MAX_WORKER_TMPFS_SCRATCH_MIB),
        ("tmpfs_project_mib", HARD_MAX_WORKER_TMPFS_PROJECT_MIB),
    ],
)
def test_worker_exact_ceiling_is_allowed(key: str, ceiling: int) -> None:
    """A worker value exactly at the ceiling is accepted (boundary)."""
    assert getattr(resolve_worker_resources({key: ceiling}), key) == ceiling


def test_worker_value_one_is_the_floor() -> None:
    """The minimum accepted positive worker value is 1 (boundary)."""
    assert resolve_worker_resources({"pids": 1}).pids == 1


# ----------------------------------------------------------------------------------------------
# resolve_worker_resources — fail-closed rejection
# ----------------------------------------------------------------------------------------------
def test_worker_unknown_key_rejected() -> None:
    """An unknown worker-resource key fails closed (not silently ignored)."""
    with pytest.raises(GhidraMcpError) as ei:
        resolve_worker_resources({"gpus": 1})
    assert ei.value.envelope.type is ErrorType.VALIDATION
    assert ei.value.envelope.status == 400


@pytest.mark.parametrize("value", [0, -1, -4096])
def test_worker_non_positive_value_rejected(value: int) -> None:
    """Zero/negative worker bounds fail closed."""
    with pytest.raises(GhidraMcpError) as ei:
        resolve_worker_resources({"mem_mib": value})
    assert ei.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.parametrize("value", [True, False, 1.5, "4096", None])
def test_worker_non_int_value_rejected(value: object) -> None:
    """Non-int worker values (incl. ``bool``) fail closed."""
    with pytest.raises(GhidraMcpError) as ei:
        resolve_worker_resources({"mem_mib": value})  # type: ignore[dict-item]
    assert ei.value.envelope.type is ErrorType.VALIDATION


def test_worker_error_detail_is_safe_and_names_only_the_key() -> None:
    """The worker-resource validation detail is a safe summary — no internals/paths."""
    with pytest.raises(GhidraMcpError) as ei:
        resolve_worker_resources({"cpus": 0})
    detail = ei.value.envelope.detail
    assert "cpus" in detail
    assert "Traceback" not in detail
    assert "/" not in detail


def test_worker_hard_ceilings_table_covers_all_fields() -> None:
    """Every ``WorkerResources`` field has a worker-clamp-table entry (no un-clamped knob)."""
    from dataclasses import fields

    assert {f.name for f in fields(WorkerResources)} == set(lim._WORKER_HARD_CEILINGS)


# ----------------------------------------------------------------------------------------------
# plausible_max_bytes — warn-only pre-flight threshold (pure; 100%)
# ----------------------------------------------------------------------------------------------
def test_plausible_max_bytes_default_ratio() -> None:
    """Default ratio is 2x worker memory, in bytes."""
    assert plausible_max_bytes(4096) == 4096 * 1024 * 1024 * 2


def test_plausible_max_bytes_custom_ratio() -> None:
    """A custom ratio scales the threshold (fractional ratios truncate to int)."""
    assert plausible_max_bytes(1024, ratio=1.5) == int(1024 * 1024 * 1024 * 1.5)


def test_plausible_max_bytes_returns_int() -> None:
    """The threshold is always a plain int (a float ratio is truncated)."""
    result = plausible_max_bytes(100, ratio=2.5)
    assert isinstance(result, int)
    assert result == int(100 * 1024 * 1024 * 2.5)
