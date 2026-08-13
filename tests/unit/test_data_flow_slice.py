"""Unit tests for ADR-064 `data_flow_slice` — schema boundary + result builder.

The worker's HighFunction def-use walk is a `# pragma: no cover` JVM edge validated by the gated
integration test; these cover the server-side contract: input validation (direction enum, caps,
required fields) and the `_build_data_flow_slice` mapper (Untrusted wrapping + boundary nodes).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vivarium.core.envelope import Untrusted
from vivarium.ghidra.rpc_client import _build_data_flow_slice
from vivarium.tools import schemas as s

# --- schema boundary -----------------------------------------------------------------------------


def test_defaults_backward_bounded() -> None:
    """Absent direction/caps default to a bounded backward slice."""
    m = s.DataFlowSliceIn(session_id="sess", function="0x1000", seed="0x1010")
    assert m.direction == "backward"
    assert m.max_nodes == 256
    assert m.max_depth == 64


@pytest.mark.parametrize("direction", ["backward", "forward"])
def test_both_directions_accepted(direction: str) -> None:
    """Both slice directions validate."""
    m = s.DataFlowSliceIn(session_id="s", function="f", seed="0x1010", direction=direction)  # type: ignore[arg-type]
    assert m.direction == direction


def test_unknown_direction_rejected() -> None:
    """A direction outside the closed set fails closed."""
    with pytest.raises(ValidationError):
        s.DataFlowSliceIn(session_id="s", function="f", seed="0x1010", direction="sideways")  # type: ignore[arg-type]


def test_function_and_seed_required() -> None:
    """Both function and seed are required, non-empty."""
    with pytest.raises(ValidationError):
        s.DataFlowSliceIn(session_id="s", seed="0x1010")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        s.DataFlowSliceIn(session_id="s", function="f", seed="")


def test_caps_bounded() -> None:
    """max_nodes/max_depth are >= 1 and clamped by the schema ceiling."""
    with pytest.raises(ValidationError):
        s.DataFlowSliceIn(session_id="s", function="f", seed="0x1", max_nodes=0)
    with pytest.raises(ValidationError):
        s.DataFlowSliceIn(session_id="s", function="f", seed="0x1", max_depth=0)


# --- result builder (rpc_client) -----------------------------------------------------------------


def test_builder_wraps_ops_and_keeps_boundary() -> None:
    """`_build_data_flow_slice` wraps each rendered op untrusted and preserves boundary nodes."""
    out = _build_data_flow_slice(
        {
            "seed": "0x00401010",
            "direction": "backward",
            "nodes": [
                {
                    "address": "0x00401000",
                    "pcode_op": "(register, r0, 8) COPY (const, 0x8, 8)",
                    "role": "def",
                },
                {"address": None, "pcode_op": "param_1", "role": "boundary"},
            ],
            "truncated": True,
        }
    )
    assert out.seed == "0x00401010"
    assert out.direction == "backward"
    assert out.truncated is True
    assert len(out.nodes) == 2
    # def node: address is a safe scalar; the rendered op is Untrusted (decompiler-derived).
    assert out.nodes[0].address == "0x00401000"
    assert out.nodes[0].role == "def"
    assert isinstance(out.nodes[0].pcode_op, Untrusted)
    # boundary node: no address; the var name is still untrusted.
    assert out.nodes[1].address is None
    assert out.nodes[1].role == "boundary"
    assert isinstance(out.nodes[1].pcode_op, Untrusted)


def test_builder_tolerates_missing_pcode_op() -> None:
    """A boundary node with no name yields pcode_op=None (not a bare/empty Untrusted)."""
    out = _build_data_flow_slice(
        {
            "seed": "0x1",
            "direction": "forward",
            "nodes": [{"address": None, "pcode_op": None, "role": "boundary"}],
        }
    )
    assert out.nodes[0].pcode_op is None
    assert out.truncated is False
