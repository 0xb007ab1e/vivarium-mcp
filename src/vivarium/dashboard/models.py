"""View models for the read-only dashboard API (display-only MVP).

Deliberately small + JSON-serializable. The ONE load-bearing rule: any field carrying binary-derived
(attacker-controlled) content is a :class:`UiValue` with ``untrusted=True`` so the browser knows to
render it inert (ADR-005). Everything else is a server-computed scalar (safe): ids, states, counts,
percentages, ISO timestamps, closed-vocabulary labels.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class UiValue:
    """A string tagged for the browser as trusted-metadata vs UNTRUSTED binary-derived content.

    Mirrors the ADR-005 envelope at the UI boundary: ``untrusted=True`` MUST be rendered as inert
    text (``textContent``), never as HTML/markup. The dashboard NEVER emits a raw binary-derived
    string outside this wrapper.
    """

    value: str
    untrusted: bool = True

    def json(self) -> dict[str, Any]:
        """Serialize to ``{"value": str, "untrusted": bool}``."""
        return {"value": self.value, "untrusted": self.untrusted}


def tag(value: str) -> dict[str, Any]:
    """Serialize a binary-derived string as a tagged UNTRUSTED leaf for :attr:`SessionEvent.data`.

    Shorthand for ``UiValue(value, untrusted=True).json()`` — the ``{"value", "untrusted": true}``
    shape the browser renders inert. Use it for every attacker-controlled leaf placed in a panel
    payload (symbol names, strings, call-graph labels), never a bare string (ADR-005).
    """
    return UiValue(value, untrusted=True).json()


def sym_ref(address: str, name: str, **extra: Any) -> dict[str, Any]:
    """Build a cross-reference to a symbol: a SAFE ``id`` (address) + a tagged UNTRUSTED ``name``.

    The canonical shape for every navigable link in the RE browser — callers/callees, call-graph
    nodes, and the ``referenced_by`` back-references on strings/imports/exports. ``id`` is the
    server-computed address (safe, the navigation key); ``name`` is binary-derived (tagged inert).
    Extra safe scalars (e.g. ``at`` for a call-site address, ``kind`` for an xref category) may be
    attached via kwargs.
    """
    return {"id": address, "name": tag(name), **extra}


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """One analysis session's live status — all fields SAFE server scalars.

    Attributes:
        session_id: Opaque id — safe.
        state: Lifecycle state (closed vocabulary, e.g. ``open``/``analyzing``/``ready``) — safe.
        progress_percent: Analyze progress ``0..100`` or ``None`` (indeterminate/idle) — safe.
        phase: Analyze phase (``importing``/``analyzing``/``finalizing``) or ``None`` — safe.
        binary_sha256: Digest of the input (server-computed, not derived content) — safe.
        tool_count: Tool calls made in this session — safe.
        last_tool: Name of the most recent tool (closed catalog name) — safe.
        started_at: ISO-8601 UTC start — safe.
    """

    session_id: str
    state: str
    progress_percent: int | None
    phase: str | None
    binary_sha256: str | None
    tool_count: int
    last_tool: str | None
    started_at: str

    def json(self) -> dict[str, Any]:
        """Serialize to a plain dict (all safe scalars)."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SessionEvent:
    """One live event streamed over SSE for a session.

    ``kind`` is a closed vocabulary. For ``kind="output"``/``"verdict"`` the human-facing content is
    binary-derived and carried in ``content`` as an UNTRUSTED :class:`UiValue`;
    ``progress``/``tool`` events carry only safe scalars. The richer analysis panels
    (``metadata`` / ``imports`` / ``exports`` / ``strings`` / ``callgraph``) carry a structured
    ``data`` payload (see below).

    **``data`` tagging convention (ADR-005).** ``data`` is a plain, JSON-safe container of *safe*
    scalars (counts, hex addresses, closed-vocabulary labels). Any binary-derived (attacker-
    controlled) leaf inside it MUST be a tagged value — the serialized :class:`UiValue` shape
    ``{"value": str, "untrusted": true}`` — never a bare string. The browser renders every such
    tagged object inert (``textContent``) exactly like ``content``; safe scalars render as text.
    The producer (:mod:`vivarium.dashboard.state` helpers) is responsible for the tagging; the
    dashboard never emits a raw binary-derived string outside a tagged value.

    **``function`` kind (RE browser).** A per-function context artifact, keyed by a canonical safe
    ``id`` (address). It may arrive in parts — a stub (name + callers/callees) first, then a later
    event with the same ``id`` hydrates ``decompile`` / ``variables`` / ``xrefs``; the browser
    merges by ``id`` (progressive hydrate). Shape (untrusted leaves via :func:`tag`)::

        data = {
          "id": "00104c00",                       # address, SAFE navigation key
          "name": tag("main"),                    # UNTRUSTED
          "signature": tag("int main(int, char **)"),   # UNTRUSTED (optional)
          "decompile": tag("<C source>"),         # UNTRUSTED (optional, may hydrate later)
          "callers":  [ sym_ref(addr, name), ... ],     # who calls this
          "callees":  [ sym_ref(addr, name), ... ],     # what this calls
          "xrefs":    [ sym_ref(addr, label, kind="string"|"data"|"import", at=addr), ... ],
          "variables":[ {"name": tag(..), "type": tag(..), "kind": "param"|"local", "storage": s} ],
          "provenance": {"tool": "function_context", "address": "00104c00"}   # SAFE lineage
        }

    Strings / imports / exports items may carry ``id`` (address, safe) + ``referenced_by``
    (a list of :func:`sym_ref` to the functions that use them) so the browser can show back-refs
    and cross-navigate both directions.

    **``workflow`` kind (Runs).** A workflow-run status, keyed by a safe ``id``, streamed by the
    agent as it executes a prebuilt/custom workflow so the UI shows a step tracker. All safe
    (closed-vocabulary op names + states); no binary-derived leaves. Shape::

        data = {
          "id": "run-1", "name": "Triage",
          "state": "running"|"done"|"failed",
          "steps": [ {"op": "session_analyze", "label": "analyze",
                      "state": "pending"|"running"|"done"|"failed", "view": "overview"?} ]
        }

    Attributes:
        kind: ``progress`` | ``tool`` | ``output`` | ``verdict`` | ``metadata`` | ``imports`` |
            ``exports`` | ``strings`` | ``callgraph`` | ``function`` | ``workflow`` — safe.
        session_id: Owning session — safe.
        percent: For ``progress``: ``0..100`` or ``None`` — safe.
        phase: For ``progress``: phase label or ``None`` — safe.
        tool: For ``tool``: the tool name (closed catalog) — safe.
        label: A short safe label for the pane (e.g. ``"decompile FUN_00401000"``) — safe.
        content: For ``output``/``verdict``: the binary-derived text — UNTRUSTED.
        data: For the panel kinds: a structured payload whose untrusted leaves are tagged
            ``{"value", "untrusted"}`` values (see the convention above); ``None`` otherwise.
    """

    kind: str
    session_id: str
    percent: int | None = None
    phase: str | None = None
    tool: str | None = None
    label: str | None = None
    content: UiValue | None = None
    data: dict[str, Any] | None = None

    def json(self) -> dict[str, Any]:
        """Serialize to a plain dict; ``content`` becomes the tagged UiValue shape (or ``None``)."""
        return {
            "kind": self.kind,
            "session_id": self.session_id,
            "percent": self.percent,
            "phase": self.phase,
            "tool": self.tool,
            "label": self.label,
            "content": self.content.json() if self.content is not None else None,
            "data": self.data,
        }


@dataclass(frozen=True, slots=True)
class GateStatus:
    """One CI/build gate's status — all safe (closed labels)."""

    name: str
    status: str  # pass | fail | pending | skipped

    def json(self) -> dict[str, Any]:
        """Serialize."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BuildSnapshot:
    """The build/deliverable snapshot — what the agent shipped, for validation. All fields SAFE.

    Attributes:
        tool_count: Total Tier-1 tools in the catalog — safe.
        read_only_count: How many are read-only — safe.
        gates: CI gate statuses — safe.
        recent_prs: Recent PR titles/numbers (project's own text, not binary-derived) — safe.
        benchmark: Small summary of the validation benchmark (cases, accuracy) — safe scalars.
    """

    tool_count: int
    read_only_count: int
    gates: list[GateStatus] = field(default_factory=list)
    recent_prs: list[str] = field(default_factory=list)
    benchmark: dict[str, Any] = field(default_factory=dict)

    def json(self) -> dict[str, Any]:
        """Serialize (gates expanded)."""
        return {
            "tool_count": self.tool_count,
            "read_only_count": self.read_only_count,
            "gates": [g.json() for g in self.gates],
            "recent_prs": self.recent_prs,
            "benchmark": self.benchmark,
        }
