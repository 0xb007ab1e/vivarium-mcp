# ADR-012: Mutation (write) tools — first gated increment

- **Status:** Accepted — design + the locked-decision calls **ratified by the human 2026-06-12**:
  (1) **annotation-only** first set (§1: `rename_function`, `rename_symbol`, `set_comment`),
  (2) **session-scoped write-consent** gating (§3), (3) **session-scoped ephemeral / no persistence**
  (§4). **Implementation remains gated** — the PROPOSED contract additions (§5/§6) ratify into
  `docs/contracts/**` and the build lands via reviewed, gated PRs (no mutation code yet).
- **Date:** 2026-06-12
- **Deciders:** Human (ratified the §1/§3/§4 calls) + PM; recorded by Software Architect
- **Builds on / constrained by:** ADR-001 (out-of-process), ADR-002 (one worker/session, kill+wipe
  on evict), ADR-005 (untrusted-data envelope), ADR-006/011 (transport seam), the frozen contracts
  in `docs/contracts/**`, and threat-model **TB7** (`docs/security/threat-model.md` §10).
- **Supersedes the deferral in:** the tool catalog's "Deferred — Mutation tools (gated)" note
  (`docs/contracts/tool-catalog.md:117-120`) and PLAN §2 ("Still deferred: mutation tools (gated)").

## Context

v1 and the v1.1 increments (semantic-naming ADR-007, Tier-2 ADR-008, HTTP ADR-011) are **read-only
and output-only**: every tool extracts or derives facts and **never mutates the Ghidra program
database**. The threat-model addenda for both v1.1 increments record this explicitly — "tools are
read-only/output-only; no rename/retype/comment-write/`runScript` exists" (threat-model.md:218,
:258).

That read-only posture is the dominant reason the system's top residual risk — **indirect prompt
injection** (TB4) — is rated "limited blast radius": the threat model states the bound plainly:
"the tools are **read-only** (no destructive action exists to trigger)" (threat-model.md:107). The
model also flags the exact change this ADR proposes: "revisit when mutation tools (v1.1) are
considered (they raise LLM08 sharply)" (threat-model.md:154, :160).

The semantic-naming workflow (ADR-007) is the concrete driver. Today the **client LLM** infers a
good name for a function and its locals, drafts recompilable C, and… has nowhere to write it back:
the server can only *report* the current Ghidra name (`function_context` returns the current
`name`/`signature` as untrusted, `schemas.py:840-842`). A reverse engineer's loop — *rename the
function, name its parameters and locals, annotate with a comment, refine the type* — cannot be
persisted. Mutation tools close that loop.

Mutation is **new agency**. Per `std-owasp-llm` LLM08 (excessive agency) and
`workflow-gated-actions`, exposing a write surface to an LLM is a privilege escalation: a hostile
binary's decompiled output (which the client treats as untrusted, ADR-005) can now influence the
client into issuing *writes*. The write target is the per-session analysis state, not the host — so
this is **not** a host-compromise boundary (ADR-001 still holds; see below) — but it is a real new
trust boundary (**TB7**) over the integrity of the analysis the operator relies on, and it sharply
raises the value of an injection that reaches the client.

## Decision

### 1. Scope — minimal first write set (annotation-only); defer the structural writes

Ship a **minimal, annotation-oriented** initial write set. Every member renames or annotates an
*existing* object the read tools already resolve; **none** creates/destroys program structure,
defines types, or alters the disassembly/CFG. Recommended INITIAL set (3 tools):

| New tool | Mutates | Ghidra write API (worker-only) | Maps to read tool it mirrors |
|----------|---------|--------------------------------|------------------------------|
| `rename_function` | a function's name | `Function.setName(name, SourceType.USER_DEFINED)` | `get_function` / `decompile_function` |
| `rename_symbol` | a data/label/global symbol's name | `Symbol.setName(name, SourceType.USER_DEFINED)` | `get_symbol` / `list_symbols` |
| `set_comment` | one comment (EOL/PRE/POST/PLATE/REPEATABLE) at an address | `Listing.setComment(addr, CodeUnit.<KIND>_COMMENT, text)` | `get_comments` |

These three are the load-bearing 80% of the semantic-naming loop and are the **lowest-risk,
highest-confidence** writes: each is a single-object, single-API-call, transaction-wrappable change
with a trivial inverse (set the name/comment back), and each reuses an existing worker resolver
(`_resolve_function` `_jvm_bridge.py:1278`, `_gh_get_symbol` `_jvm_bridge.py:576`, the comment
reader `_gh_get_comments` `_jvm_bridge.py:660`).

**DEFER to a later, separately-designed gated increment (do NOT build now):**

- **`rename_local_variable` / `rename_parameter`** — renaming a decompiler local requires the
  `HighFunction`/`HighSymbol` path (`DecompInterface` → `decompileFunction` →
  `HighFunctionDBUtil.updateDBVariable`), which is stateful (re-decompile to get the high symbol),
  failure-prone, and Ghidra-version-sensitive. High value for naming, but materially more API
  surface and abuse surface than the annotation set. **Defer to the second mutation increment.**
- **`set_function_signature` / `set_prototype`** — applying a recovered signature
  (`ApplyFunctionSignatureCmd` / `Function.setSignature` / `Function.updateFunction`) re-flows
  parameters and storage; it is a *structural* change to the function model, not an annotation, and
  composes with type definition. **Defer.**
- **`define_data_type` / `create_struct` / `apply_data_type`** — mutating the `DataTypeManager`
  (define a struct/typedef, then apply it at an address) is the most invasive: it changes the
  program's type universe and re-renders dependent data/decompilation. **Defer to its own increment**
  (it carries the most parsing of attacker-influenced type strings — highest injection-into-API
  surface).
- **`runScript` / arbitrary script execution** — remains permanently out of scope (PLAN §2,
  tool-catalog.md:117). Mutation does **not** reopen it.

**Why minimal-first.** It is the smallest surface that delivers the naming-loop value; each tool is
trivially reversible (bounding the integrity-tampering blast radius — TB7-T); the abuse-test matrix
is small enough to be exhaustive in one increment (`topic-testing`); and it lets us validate the
*gating model* (the genuinely novel part — §3) on low-risk writes before extending to structural
ones. Adding each deferred tool later is a reviewed, gated catalog addition through the same seam
(ADR-006), exactly as ADR-007/008 added read tools — proportional, not big-bang
(`topic-migration` incremental posture).

### 2. Write trust boundary (TB7) — flow; ADR-001 unchanged

A mutation flows through the **identical** layered path as a read, with a write at the far end. The
server still **never loads the JVM or mutates a program** (ADR-001:18-20) — it validates, authorizes,
and bounds, then asks the worker to perform the write over the internal RPC. Only the worker's
JVM bridge calls a Ghidra write API, inside a transaction.

```
client (LLM)                          ── TB1/TB6 ──> server shell (NO JVM)
  rename_function{session_id, function, new_name}
                                                     1. pydantic *In schema (frozen, extra=forbid)
                                                     2. core.validation.validate_name(new_name)   ← NEW: write-target name validated as untrusted
                                                     3. sessions.authorize(session_id)  (BOLA chokepoint, manager.py:197)
                                                     4. [gate check — §3]
                                                     5. audit-log INTENT (tool, session, target addr, sizes — NO binary content)
  port.rename_function(sid, args) ──── TB2 (UDS) ──> worker RPC loop (sole client)
                                                     6. dispatch → backend.rename_function(params)
                                                     7. resolve target (existing _resolve_* helper)
                                                     8. txn = program.startTransaction("rename_function")  ← ADR-012 atomicity
                                                        try: func.setName(new_name, USER_DEFINED)
                                                        program.endTransaction(txn, commit=True)   on success
                                                        program.endTransaction(txn, commit=False)  on failure (fail closed — roll back)
                                                     9. return {address, old_name, new_name, applied:true}
       <── TB4 (untrusted result) ── server wraps any echoed binary-derived field (old_name) in Untrusted[...] (ADR-005)
                                                    10. audit-log OUTCOME (applied/denied, store still session-scoped)
```

Key invariants preserved:

- **ADR-001 holds:** the write executes only in the worker; the server orchestrates. The
  architecture-invariant CI test (ADR-001:24-26) is unchanged — no JVM import appears server-side.
- **TB2 unchanged in shape:** mutation adds **new RPC methods**, not a new channel. Same per-session
  UDS, same length-prefixed framing, same strict schema validation, same kill-on-timeout
  (rpc-protocol.md §6).
- **The worker is still untrusted on the way out (ADR-005/TB4):** a write tool that echoes the
  prior name (`old_name`) wraps it `Untrusted[...]`; the server-controlled `applied` boolean and the
  normalized `address` are bare. The worker cannot dictate session lifecycle (the manager overlays
  authoritative fields — registry.py:192-209) and a write result is just data.

### 3. Gating / approval model (LLM08) — session-scoped *write consent*, per-tool annotation

This is the genuinely new design decision. Mutation is exposed to an LLM, so per
`workflow-gated-actions` (§"Gated — require explicit … approval", and the LLM08 mapping) a write is
a candidate gated action. But `workflow-gated-actions` gates *host/prod/outward/irreversible*
actions; a rename inside a disposable, session-scoped, ephemeral worker store (ADR-002 — wiped on
evict) is **none of those** — it is reversible, local, non-prod, and confined. Treating every rename
as a per-call human gate would make the naming loop unusable (hundreds of renames per binary) and
push operators to disable the control. So we choose a **proportional** model:

**Recommended model — "write consent is opt-in per session; once granted, individual annotation
writes are autonomous; structural writes always gate":**

1. **Default-deny:** a session is **read-only by default**. A mutation tool called on a session
   without write consent fails closed with a `validation-error`-class envelope (`detail:
   "session is read-only; write consent not granted"`). The safe default is no agency (master §2;
   `workflow-gated-actions` default-deny).
2. **Explicit, auditable consent grant:** the operator opts a session into writes via a new
   server-side lifecycle tool **`session_enable_writes`** (mirrors `session_close`, server-side,
   no worker RPC). This is the **single gate** the operator clears — it is the human-in-the-loop
   approval, granted **once per session**, recorded in the session record and the audit log. It is
   **not** transferable across sessions and is **revocable** (`session_disable_writes`, or implicit
   on evict).
3. **Within a write-enabled session, the ANNOTATION set (§1's three tools) runs autonomously** —
   no per-call gate. Justification: each is reversible, session-scoped, and bounded; the consent
   grant *is* the approval for "this operator wants this session annotated by the agent." Every
   write is still **audit-logged** (intent + outcome) for repudiation defense (TB7-R).
4. **STRUCTURAL writes (the deferred set: locals, signatures, types) will require, in addition to
   session write-consent, a per-tool capability flag** set at consent time
   (`session_enable_writes{allow_structural: bool}`, default `false`) — so the riskier writes are a
   separate, explicit opt-in even within a write-enabled session. (Defined now so the consent shape
   is forward-compatible; the structural tools themselves are deferred.)
5. **Transport composition (ADR-011):** on the HTTP edge, write consent is **per authenticated
   principal + session** and the grant call is itself subject to the same authn/authZ + rate limits
   as any tool (it is in the catalog). On a **network bind**, `session_enable_writes` SHOULD be
   surfaced to the operator as a `workflow-gated-actions` gate at the orchestration layer (a network
   client enabling writes is materially higher-impact than a loopback one). v1.1-mutation remains
   **single-principal** — consent is held by the one operator (BOLA closed-by-construction per
   ADR-011 §6; a per-principal `owner` check lands with multi-principal, unchanged by this ADR).

This composes cleanly with `workflow-gated-actions` delegation: a delegated agent that wants to
enable writes **stops and returns a gate request** (it never self-grants); the human (or the scoped
`sdlc-gate-approver` policy, if and only if the run's autonomy policy lists session-write-enable as
reversible/non-prod/in-scope) clears it. The *individual* annotation writes after consent are the
autonomous, reversible, in-scope class.

> **Alternative gating models considered** (see §"Alternatives"): (A) per-call human gate on every
> write — rejected (unusable, drives control-disabling); (B) fully autonomous writes with only an
> audit trail — rejected (no human-in-the-loop for new agency; violates LLM08 least-agency and
> `workflow-gated-actions` for the *capability* grant); (C) the recommended hybrid — consent gates
> the *capability*, audit + reversibility bound the *exercises*, structural writes gate separately.

### 4. Atomicity + undo/rollback; persistence vs. ephemerality

**Atomicity — one Ghidra transaction per mutation (mandatory).** Each write tool wraps its single
Ghidra write in `program.startTransaction(<tool_name>)` / `program.endTransaction(txn_id, commit)`.
On the write API succeeding, the worker commits (`commit=True`); on **any** exception it ends the
transaction with `commit=False` (roll back) and returns a typed error — **fail closed** (master §2,
`topic-error-handling`). No mutation leaves the program partially applied. (The worker already
references this pattern for analysis — `_jvm_bridge.py:321` "inside a started transaction".) One tool
call == one transaction == one undoable unit; we do **not** batch multiple tools in one transaction
in this increment (keeps each call's atomicity and audit unit clean; batching is a later concern).

**Undo within a session.** Ghidra's transaction model gives per-program undo/redo. We expose a
minimal, optional **`session_undo`** server-side lifecycle tool (recommended, low cost) that asks the
worker to `program.undo()` the last committed transaction — giving the operator a one-step revert of
an agent mistake without re-importing. (If deemed scope creep, defer it — the annotation writes are
each individually reversible by issuing the inverse rename/comment, so `session_undo` is a
convenience, not a correctness requirement. **Recommend including it**: cheap, and a strong
mitigation for TB7-T/injection-induced bad writes.)

**Persistence — session-scoped only; mutations DO NOT survive eviction (recommended).** Per ADR-002,
each session owns one disposable worker and a per-session project store that is **killed and
verified-wiped on eviction** (TTL/idle/close/poison/shutdown — manager.py:261-359, ADR-002:18-21).
Mutations live in that ephemeral store. Therefore:

- **Mutations are durable only for the life of the session** (across tool calls, while the worker is
  alive — the program object persists in the worker, `_jvm_bridge.py:296-298`). They are **lost on
  eviction by design** — this is consistent with "no cross-binary worker reuse" and the
  confidentiality wipe (ADR-002).
- **No new persistent store is introduced in this increment.** Persisting annotations beyond a
  session (a saved-project / export-and-reimport path, or a Ghidra Server) is a **separate, deferred
  increment** with its own threat model — it reintroduces durable confidential state (a hostile
  binary's artifacts surviving on disk) that ADR-002's wipe deliberately eliminates, and an
  import-of-attacker-influenced-annotations boundary. **Out of scope here.**
- **Optional, explicitly-deferred export path (design hook only):** a future `session_export_annotations`
  could emit the applied renames/comments as a **structured, untrusted-wrapped, inert data document**
  (JSON of `{address, kind, old, new}`) the operator re-applies deliberately — never an executable
  Ghidra script (that would be a `runScript`-class hole). Noted so the schema leaves room; **not
  built now.**

> **Recommendation:** session-scoped only (no persistence) for the first increment. It keeps ADR-002's
> wipe invariant intact, adds no durable confidential state, and matches the "annotate during a triage
> session" use case. Cross-session persistence is a deliberate, separately-modeled future call.

### 5. RPC additions (PROPOSED — for PM ratification into `docs/contracts/rpc-protocol.md` §4)

Three **new worker-facing RPC methods**, added to the frozen allow-list
(`worker/dispatch.py:50` `RPC_METHODS` / rpc-protocol.md §4). Each mirrors the existing request/
response shape (params = tool schema minus `session_id`; worker returns plain values; the server
wraps any binary-derived field). The lifecycle tools (`session_enable_writes`,
`session_disable_writes`, `session_undo`) are **server-side**, **not** worker RPC methods (like
`session_create`/`close` today, rpc-protocol.md:78-79).

| New RPC method | params | result | errors (rpc-protocol.md §5 codes) |
|----------------|--------|--------|-----------------------------------|
| `rename_function` | `{function: str, new_name: str}` | `{address: str, old_name: str, new_name: str, applied: bool}` | `-32602 invalid-params` (bad name), `-32004 not-found` (function), `-32010 analysis-failed` (txn/setName failed → rolled back) |
| `rename_symbol` | `{identifier: str, new_name: str}` | `{address: str, old_name: str, new_name: str, kind: str, applied: bool}` | `-32602`, `-32004` (symbol), `-32010` (rolled back) |
| `set_comment` | `{address: str, comment_type: str, text: str \| null}` | `{address: str, comment_type: str, applied: bool}` (`text:null` clears the comment) | `-32602` (bad addr/type), `-32010` (rolled back) |

- The worker performs each inside a transaction (§4) and returns **plain** values; `old_name` is the
  pre-write Ghidra name (the server wraps it `Untrusted[...]`). No new error *codes* are needed —
  the existing slug→`ErrorType` map (rpc-protocol.md:89-95, errors.py:22-52) already covers
  validation/not-found/analysis-failed/internal; a rolled-back write maps to `analysis-failed`
  (Ghidra refused/failed the write — not a server bug — consistent with errors.py:48-49). **No new
  `ErrorType` member is required.**
- **Defer**red structural RPCs (`rename_local_variable`, `set_function_signature`, `define_data_type`,
  `apply_data_type`) are named here only as the forward shape; **not added to `RPC_METHODS` now.**

### 6. Tool-catalog additions (PROPOSED — for PM ratification into `docs/contracts/tool-catalog.md`
   + `src/ghidra_mcp/tools/schemas.py` + `registry.py` `TIER1_TOOL_NAMES`)

The catalog count moves from **35** read-only tools to **35 + 6 = 41** (3 worker write tools + 3
server-side write-lifecycle tools). Tests asserting the count (tool-catalog.md:9) update accordingly.
All write tools are **session-scoped** (`_SessionScopedIn`), `frozen`, `extra="forbid"` — mirroring
every existing tool (schemas.py:38-58).

**New pydantic schema sketches** (mirroring the read-tool style; bounds reuse the existing
`_MAX_NAME` = 1024 constant and `core.validation` semantic checks):

```python
# --- write target name: the new untrusted input that needs the strictest validation ---
# Reuse validate_name() AND add a write-specific allow-list (see §7): a symbol/function NAME the
# client supplies is attacker-INFLUENCED (the LLM may have been injection-steered) — bound length,
# reject control/separator chars (already in validate_name), and (NEW) restrict to an identifier
# charset so it cannot smuggle markup/path/zero-width payloads into the program DB.

class RenameFunctionIn(_SessionScopedIn):
    """Arguments for `rename_function` — set a function's name (write; gated by session consent)."""
    function: str = Field(min_length=1, max_length=_MAX_NAME)   # existing function (addr|name)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)   # validate_name + identifier allow-list

class RenameResult(_Out):
    """Result of a rename write."""
    address: str                 # server-normalized — safe
    old_name: Untrusted[str]     # the PRIOR Ghidra name — binary-derived → untrusted (ADR-005)
    new_name: str                # the server-validated name we set — SAFE (we validated it)
    applied: bool                # server/worker-controlled — safe

class RenameSymbolIn(_SessionScopedIn):
    """Arguments for `rename_symbol` — set a data/label/global symbol's name (write)."""
    identifier: str = Field(min_length=1, max_length=_MAX_NAME)  # existing symbol (addr|name)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)

class RenameSymbolResult(RenameResult):
    """Result of `rename_symbol` (adds the symbol kind)."""
    kind: str                    # FUNCTION/LABEL/… — closed-vocabulary, safe

class SetCommentIn(_SessionScopedIn):
    """Arguments for `set_comment` — set/clear one comment at an address (write)."""
    address: str = Field(min_length=1, max_length=_MAX_NAME)
    comment_type: Literal["EOL", "PRE", "POST", "PLATE", "REPEATABLE"]   # closed allow-list
    text: str | None = Field(default=None, max_length=_MAX_COMMENT)      # None clears; bounded length

class SetCommentResult(_Out):
    """Result of `set_comment`."""
    address: str
    comment_type: str
    applied: bool

# --- server-side write-lifecycle (no worker RPC), mirroring SessionCloseIn/Out ---
class SessionEnableWritesIn(_SessionScopedIn):
    """Grant this session WRITE CONSENT (the human-in-the-loop gate for mutation — LLM08)."""
    allow_structural: bool = Field(default=False)   # forward hook: gate the deferred structural set

class SessionWriteStateOut(_Out):
    """Reports a session's write-consent state."""
    session_id: str
    writes_enabled: bool
    allow_structural: bool

class SessionDisableWritesIn(_SessionScopedIn):
    """Revoke write consent for this session (return to read-only)."""

class SessionUndoIn(_SessionScopedIn):
    """Undo the last committed mutation transaction in this session (optional convenience)."""

class SessionUndoOut(_Out):
    """Result of session_undo."""
    session_id: str
    undone: bool          # whether a transaction was undone (false if nothing to undo)
```

**Bounds / allow-list / validation (per tool):**

- `new_name`: `validate_name()` (length ≤ 1024, no control/C1/separator chars — validation.py:145)
  **plus a NEW `validate_write_name()` allow-list** (§7) restricting to a conservative identifier
  charset (`[A-Za-z_][A-Za-z0-9_$.]*`-class) so an injection-steered client cannot write markup,
  zero-width, RTL, path, or whitespace-laden text *into the program DB* (a stored-injection / data
  poisoning vector that read-only tools never had — the name is now persisted and re-served).
- `address`: `parse_address()` (validation.py:96 — hex, ≤16 digits, 64-bit bound) and **confined to
  the memory map by the worker** before the write (same posture as `read_bytes`, registry.py:360-365).
- `comment_type`: a **`Literal` closed allow-list** (the 5 kinds the reader already enumerates,
  `_jvm_bridge.py:677-683`) — no free-form type.
- `text` (comment): bounded by a new `_MAX_COMMENT` (recommend ≤ 4096) and run through a new
  `validate_comment_text()` that strips/annotates control + bidi/zero-width chars (the comment is
  stored and re-served via `get_comments`, so it must be normalized **on the way in** too — this is
  the write-side mirror of the `core.envelope.wrap` normalization, ADR-005).
- Every write handler **authorizes the session AND checks write consent** before delegating
  (the new gate chokepoint, §3) — failing closed.

> `Untrusted[...]` marks a binary-derived field. Note the asymmetry vs. read tools: the **`new_name`
> we set is SAFE** (we validated it server-side), but the **`old_name` we echo back is untrusted**
> (it came from the binary). `applied`/`address`/`kind`/`comment_type` are server/closed-vocabulary
> — bare.

### 7. Validation & abuse

**Input validation (TB7 / TB1 — the write target is untrusted, attacker-INFLUENCED input):**

- The decompiled C and existing names the client reasons over are untrusted (ADR-005); an indirect
  prompt injection (TB4) can steer the client into proposing a malicious `new_name`/`text`. So the
  **write payload is validated as hostile input** at the boundary, allow-list only
  (`std-owasp-proactive` #5, CWE-20): identifier charset for names, bounded length, closed-vocabulary
  comment type, normalized comment text. **No value is ever interpolated into a Ghidra script** —
  there is no `runScript` (PLAN §2); the worker calls a typed Java setter with the validated value.
  This neutralizes "injection into Ghidra scripting" by construction (validation.py already documents
  the no-interpolation stance, validation.py:9-10).
- **Stored-injection / data-poisoning is the NEW class:** a name/comment written now is persisted in
  the program DB and **re-served by the read tools** (`list_symbols`, `get_comments`, …) wrapped
  `Untrusted[...]`. Two-sided defense: (a) validate+normalize on the **way in** (this ADR's new
  validators) so the stored value is conservative, and (b) the existing untrusted-envelope normalizes
  on the **way out** (ADR-005) — defense in depth; neither alone is the guarantee.
- **Path/overflow:** `address` reuses `parse_address` + worker map-confinement (CWE-22/190 already
  handled, validation.py:96-142, :181-220).

**Abuse tests to add** (extend `tests/security/test_abuse_cases.py` / threat-model §6; benign/
synthetic fixtures only, master §5; each must FAIL the attack i.e. the control holds, deterministic
+ hermetic):

1. **Write-without-consent** — a mutation tool on a session without `session_enable_writes` is
   **denied** (read-only default; fail closed). (TB7-E / gating)
2. **Injection-steered malicious name** — a `new_name` containing markup / `../path` / zero-width /
   RTL / control chars is **rejected by `validate_write_name`** (not written to the DB). (TB7-T/E,
   stored-injection)
3. **Comment stored-injection** — a `set_comment` `text` carrying a prompt-injection payload + bidi/
   zero-width is **normalized/annotated on write** and, when read back via `get_comments`, is
   returned `Untrusted`-wrapped + normalized — never bare instructions. (TB7-T / TB4 — extends
   abuse-case 5)
4. **Failed-write atomicity** — a worker write that raises mid-transaction **rolls back**
   (`commit=False`) and surfaces `analysis-failed`; the program is unchanged (no partial state).
   (TB7-T / atomicity)
5. **Cross-session write isolation** — write consent + a rename on session A does **not** enable
   writes on, or mutate, session B; B stays read-only and its store is independent. (TB7-T / store-I,
   extends abuse-case 8)
6. **Write-flood / consumption** — a burst of writes is bounded by the same per-tool timeout +
   concurrency cap + (HTTP) rate limit as reads; the worker is killed on a hung write; no unbounded
   growth (each write is one bounded transaction). (TB7-D / TB1-D)
7. **BOLA on the grant** — `session_enable_writes` against an unknown/foreign session id yields the
   same `session-invalid` envelope (no oracle); the grant cannot target another session. (TB7-E /
   BOLA)
8. **ADR-001 invariant** — the architecture-invariant test still passes: no JVM/PyGhidra import on
   any server-side module, including the new write handlers (write executes only in the worker).

**Mutation/contract testing:** the gate chokepoint (consent check) and `validate_write_name` are
**critical-path** (new agency / authZ) → **100% coverage + mutation testing** (master §4,
`topic-testing`). The worker `_gh_*` write helpers are coverage-omitted JVM edges exercised only by
the real-worker integration suite (same posture as every `_gh_*`, _jvm_bridge.py:243-246).

## Consequences

- **Positive:** closes the semantic-naming loop (rename + annotate persist within a session); the
  smallest possible write surface; ADR-001 containment unchanged (server never mutates); every write
  is atomic + reversible + audited; the gating model is validated on low-risk writes before
  structural ones; additive to the frozen contracts via the ADR-006 seam (no rewrite).
- **Negative / risk:** **LLM08 agency rises** — the system now *has* a destructive action an
  injection could trigger; mitigated by default-deny write consent (the human gate), allow-list write
  validation, per-write audit, transaction rollback, optional `session_undo`, and the unchanged
  ADR-002 ephemerality (worst case is a poisoned-but-disposable session, wiped on evict). The top
  residual (prompt injection, threat-model §5) must be re-rated for TB7 (done in the threat-model
  addendum); it is no longer "no destructive action exists."
- **Negative:** more schemas + a new consent state on the session record + new validators; clients
  must understand write-consent and the read-only default.
- **Open / deferred:** structural writes (locals/signatures/types) and cross-session persistence are
  deliberately deferred to their own gated increments; `runScript` stays out of scope permanently.

## Alternatives considered

- **No mutation (status quo):** keeps the strongest posture but leaves the naming loop unable to
  persist — the explicit driver. Rejected (the increment exists to enable writes).
- **Build the full write set at once** (functions + symbols + locals + signatures + types): higher
  value sooner but a large, hard-to-exhaustively-test abuse surface and the structural writes carry
  the most attacker-influenced-type-string parsing. Rejected for minimal-first (this ADR §1).
- **Gating model A — per-call human gate on every write:** maximal control, but unusable for a
  hundreds-of-renames loop and pushes operators to disable the control. Rejected.
- **Gating model B — fully autonomous writes, audit-only:** usable but provides no human-in-the-loop
  for the *new agency* itself (violates LLM08 least-agency + `workflow-gated-actions` for the
  capability grant). Rejected.
- **Gating model C (CHOSEN) — session-scoped write consent (one gate) + autonomous annotation writes
  + separate gate for structural writes + full audit + reversibility.** Proportional to the
  reversible/local/session-scoped nature of annotation writes while keeping a real human gate on the
  capability. Recommended.
- **Persist annotations across sessions (saved project / export-import / Ghidra Server):** higher
  utility (resume a triage) but reintroduces durable confidential state that ADR-002's verified-wipe
  deliberately removes, plus an import-of-attacker-influenced-annotations boundary. Rejected for this
  increment; deferred to its own threat-modeled increment.
- **Reuse a generic `set_property` tool instead of typed per-object write tools:** smaller catalog
  but a broad, free-form surface (which property? on what?) that is harder to validate and allow-list
  and edges toward script-like generality. Rejected — typed, narrow tools per `std-owasp-llm` LLM07
  (typed least-privilege tool params).
