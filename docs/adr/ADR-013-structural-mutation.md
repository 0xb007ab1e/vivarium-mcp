# ADR-013: Structural mutation (write) tools — second gated increment

- **Status:** Accepted — design + the locked-decision calls **ratified by the human 2026-06-12**:
  (a) **Phase A = name-only `rename_local_variable` + `rename_parameter`** (defer signatures +
  data-types to Phase B), (b) **structured/constrained signature+type input** (never free-form C),
  (c) signature + data-type define/apply **deferred to Phase B**. **Implementation remains gated** —
  PROPOSED contract additions ratify into `docs/contracts/**` and the build lands via reviewed,
  gated PRs (no mutation code yet).
- **Date:** 2026-06-12
- **Deciders:** Human (ratified the scope/input-model/phasing calls) + PM; recorded by Software Architect.
- **Builds on / constrained by:** ADR-001 (out-of-process — the server never loads the JVM or
  mutates), ADR-002 (one worker/session, kill+verified-wipe on evict), ADR-005 (untrusted-data
  envelope), ADR-011 (HTTP edge composition), the **just-merged ADR-012** annotation-mutation
  increment (`rename_function`/`rename_symbol`/`set_comment`, the `allow_structural` consent hook,
  one-transaction-per-write), the frozen contracts in `docs/contracts/**`, and threat-model **TB7**
  (`docs/security/threat-model.md` §10).
- **Extends:** ADR-012 §1 (the DEFERRED structural set it named:
  `rename_local_variable`/`rename_parameter`, `set_function_signature`/`set_prototype`,
  `define_data_type`/`apply_data_type` — `ADR-012-mutation-tools.md:65-80`).

## Context

ADR-012 shipped the **annotation-only** first write set and validated the genuinely novel part — the
**gating model** (`session_enable_writes` + per-session, default-deny write consent, ADR-012 §3) — on
the lowest-risk writes: each annotation write is a single-object, single-API-call,
transaction-wrappable change with a trivial inverse (`ADR-012-mutation-tools.md:58-63`). ADR-012
deliberately deferred the **structural** writes and, critically, **already built the forward hook**
for them: the consent grant carries an `allow_structural` flag (default `false`), the session record
tracks it, and `require_write_consent(structural=True)` enforces it.

The merged plumbing is already in place and **idle**, waiting for this increment to use it:

- **Session manager:** `enable_writes(session_id, allow_structural=...)`
  (`manager.py:249-277`), `_Session.allow_structural` (`manager.py:99-114`), and the structural
  chokepoint `require_write_consent(session_id, structural=True)` which raises `VALIDATION`
  "structural writes not permitted for this session" when `allow_structural` is false
  (`manager.py:301-331`). **No new gate mechanism is needed — only new handlers that pass
  `structural=True`.**
- **Schemas:** `SessionEnableWritesIn{allow_structural}` (`schemas.py:1298-1310`),
  `_MAX_NAME`/`_MAX_COMMENT` constants (`schemas.py:33-38`).
- **Worker transaction primitive:** `_in_transaction(tool_name, write)` (`_jvm_bridge.py:1425-1451`)
  — but see §4 for the reviewer's Low fix it still carries.

The driver is the same semantic-naming loop (ADR-007) that motivated ADR-012, but one level deeper.
After an LLM renames a function and its callees, the next reverse-engineering step is **naming the
function's parameters and locals, and recovering its signature/types** — exactly the structural
writes deferred in ADR-012. `function_context` already returns the current `signature` and decompiled
C as `Untrusted[...]` (`schemas.py:850-856`); the client can infer better names/types but has nowhere
to persist them. This increment closes that deeper loop.

**Structural writes are materially riskier than annotations** — three new risk classes (§2) that the
annotation set did not have. The dominant new one is that **type and signature strings are
attacker-influenced input parsed by Ghidra's C parser** (`DataTypeParser` / `CParser` /
`ApplyFunctionSignatureCmd`), which is a much larger injection-into-API surface than a typed Java
`setName` call. This ADR's central decision (§2(a), §"KEY DECISIONS") is **how to neutralize that**:
prefer a constrained/structured input over free-form C.

## Decision

### 1. Scope + phasing — land the HighFunction local/param renames now; defer signature & types

The structural set has three sub-families with sharply different risk. We **phase**, not big-bang
(`topic-migration` incremental posture; the same reasoning ADR-012 §1 used to ship annotations
first):

| Candidate | Sub-family | Ghidra write API (worker-only) | Recommendation |
|-----------|-----------|--------------------------------|----------------|
| `rename_local_variable` | local rename | `DecompInterface.decompileFunction` → `HighFunction` → `HighSymbol` → `HighFunctionDBUtil.updateDBVariable(highSym, newName, null, USER_DEFINED)` | **IN this increment** |
| `rename_parameter` | param rename | same HighFunction path (the high symbol is a parameter) | **IN this increment** |
| `set_function_signature` | signature | `ApplyFunctionSignatureCmd` / `Function.setSignature` / `Function.updateFunction` | **DEFER (separate increment)** |
| `define_data_type` / `apply_data_type` | data types | `DataTypeManager` + `CParser`/`DataTypeParser` | **DEFER (separate increment)** |

**Phase A (this ADR — `rename_local_variable`, `rename_parameter`):** these are the **structural
analogue of the annotation renames** — they set a *name* on an existing decompiler variable, reusing
the already-built `validate_write_name` identifier allow-list (`validation.py:303-337`). They are
"structural" only because the *mechanism* (the HighFunction re-decompile path, §2(b)) is stateful and
version-sensitive — **not** because they parse an attacker-supplied type string. **They carry the new
HighFunction-state risk but NOT the type-string-parsing risk** — making them the right next rung:
high naming value (locals/params dominate the readability of a decompiled function), reuses the
proven name validator, and lets us validate the HighFunction mechanism on a name-only write before we
add type-string parsing.

> A local/param rename *can* optionally carry a new data type (`updateDBVariable` accepts a
> `DataType` argument). **Phase A passes `null` for the data type** — name-only — precisely to keep
> the type-string-parsing surface out of this increment. Retyping a local is part of the deferred
> data-type phase.

**DEFER to Phase B (its own gated, separately-threat-modeled increment) — `set_function_signature`,
`define_data_type`, `apply_data_type`:** these are deferred **because** they parse
attacker-influenced type strings through Ghidra's C parser (the highest injection-into-API surface,
§2(a)) and re-flow parameters/storage + re-render dependent decompilation (the largest blast radius,
§2(c)). ADR-012 §1 already flagged data-type define/apply as "the most invasive… carries the most
parsing of attacker-influenced type strings — highest injection-into-API surface"
(`ADR-012-mutation-tools.md:77-80`). We do **not** want to introduce the HighFunction mechanism AND
the C-parser surface in the same increment — that is precisely the "large, hard-to-exhaustively-test
abuse surface" ADR-012 rejected (`ADR-012-mutation-tools.md:421-423`). Phase B's input model is the
security-critical call this ADR pre-decides in §2(a) / §"KEY DECISIONS" so the schema and validators
are designed before any C-parser code is written — but **no signature/type tool is added to the
catalog, `RPC_METHODS`, or the bridge in this increment.**

- **`runScript` / arbitrary script execution** — remains permanently out of scope (PLAN §2,
  `tool-catalog.md:142-145`). Structural mutation does **not** reopen it.

**Phasing rationale (the recommendation):** Phase A is the smallest structural surface that delivers
the deeper naming-loop value; it reuses the proven `validate_write_name` allow-list and the existing
`allow_structural` gate; its abuse-test matrix is small enough to be exhaustive in one increment
(`topic-testing`); and it validates the genuinely new **HighFunction re-decompile mechanism** on a
name-only write before Phase B layers attacker-influenced type-string parsing on top. This is the
exact proportional posture ADR-012 §1 used — minimal-first, additive through the ADR-006 seam.

### 2. The hard new risks (the crux — what makes structural ≠ annotation)

Three risk classes the annotation set (ADR-012) did **not** have. Phase A faces (b); Phase B faces all
three. We address (a) by **pre-deciding the Phase B input model** so the design is fixed before code;
(b) is the live Phase-A concern; (c) is bounded by ephemerality + audit + undo.

**(a) Type/signature strings are attacker-influenced input parsed by Ghidra's C parser
[Phase B — DEFERRED, but design-decided now].**
A recovered or LLM-proposed type/signature string (`struct foo { int *a; ... }`, `void f(int, char*)`)
would flow into `DataTypeParser` / `CParser` / `ApplyFunctionSignatureCmd`. Unlike a typed
`Function.setName(str, SourceType)` call (a leaf setter that cannot interpret its argument), a
**C-type parser is a small interpreter**: it tokenizes, resolves type references, and can recurse.
The decompiled C the client reasons over is untrusted and of hostile origin (ADR-005); an indirect
prompt injection (TB4) can steer the client into proposing a malicious type string. The threat is
**parser abuse**, not "RCE via parsing" (Ghidra's `CParser` is a data-type declaration parser, not a
preprocessor — it does **not** `#include`, expand macros, run pragmas, or execute code; that is
exactly why TB5's *compiler* sandbox exists separately, `threat-model.md:116-127`). The realistic
abuse is (i) a pathological/recursive declaration that exhausts CPU/memory in the worker
(consumption — CWE-400), (ii) a declaration that defines/overwrites unintended types as a side effect
(scope creep beyond the one target), and (iii) smuggling markup/zero-width/RTL **into type names**
that then re-serve through the read tools (stored injection — the same class as ADR-012 §7).

**Design decision for Phase B (pre-decided so the increment is bounded before it is built):
do NOT accept free-form C type strings. Accept a CONSTRAINED, STRUCTURED input.** Phase B's
`set_function_signature` takes a **structured signature model**, not a C string:

```text
SetFunctionSignatureIn{
  session_id, function,
  return_type:   TypeRef,            # NOT a C string — a structured reference
  parameters:    list[ParamSpec],    # bounded count (<= _MAX_PARAMS, recommend 64)
  calling_convention: str | None,    # closed allow-list of CC names
}
ParamSpec{ name: str (validate_write_name), type: TypeRef }
TypeRef = a reference to an EXISTING, RESOLVED data type by:
  - a base-type enum (void/int/uint/char/.../intN/floatN — a closed vocabulary), OR
  - the name of a type ALREADY PRESENT in the program's DataTypeManager (validated to exist,
    not parsed), with bounded pointer/array modifiers ({pointer_levels: int <= 8, array_len: int?}).
```

This **eliminates the C-parser surface for signatures entirely**: the worker assembles the
`FunctionDefinitionDataType` from already-resolved `DataType` handles (looked up in the
`DataTypeManager`, `_jvm_bridge.py:710`) — no string is parsed. The validation is allow-list
type-reference resolution (CWE-20), and `validate_write_name` (already built) guards every name. This
is the `std-owasp-llm` LLM07 posture (typed least-privilege tool params over a free-form surface) and
directly mirrors ADR-012's rejection of a generic `set_property` tool
(`ADR-012-mutation-tools.md:437-440`).

**If — and only if — a future increment must accept a free-form C type string** (e.g. to *define* a
brand-new struct that does not yet exist), it is gated by an even narrower opt-in and bounded by:
(i) a new `validate_type_decl()` that bounds total length (recommend ≤ 4096), nesting depth, and
declaration count, and rejects preprocessor/`#`/pragma tokens, comments, and any non-declaration
syntax (allow-list to a single type declaration); (ii) parsing under the worker's wall-clock + memory
caps that already **kill the worker on timeout** (so a parser bomb is contained — TB7-D/TB3-D); (iii)
the explicit contract that the parser **only declares a type — no scripting, no include, no execution
results** (`validation.py:9-10` already documents the no-interpolation stance); (iv) the resulting
type name re-validated with `validate_write_name`. **This path is NOT in this increment and NOT in
Phase B as recommended** — it is named only so the structured-first decision is on the record as the
deliberate alternative to it. **This is KEY DECISION (b).**

**(b) HighFunction re-decompile state [Phase A — the live concern].**
Renaming a local/parameter is **not** a leaf setter. It requires the decompiler's high-level view:
`DecompInterface().openProgram(program)` → `decompileFunction(func, timeout, monitor)` →
`results.getHighFunction()` → resolve the `HighSymbol` for the target local → and only then
`HighFunctionDBUtil.updateDBVariable(highSym, newName, dataType=null, SourceType.USER_DEFINED)`. This
is **stateful and failure-prone**: the decompile can fail or time out, the high symbol may not resolve
(the name the client gave may not match a high symbol — Ghidra's decompiler synthesizes local names),
and the API is Ghidra-version-sensitive (ADR-012 §1 flagged exactly this:
`ADR-012-mutation-tools.md:67-71`). Design controls:

- The decompile runs under a **bounded `DecompInterface` timeout** inside the worker (the same
  posture as the read decompile path, `_jvm_bridge.py:402-411`), and the whole RPC is under the
  per-call timeout that **kills the worker on expiry** (ADR-002, `rpc-protocol.md` §6). A decompile
  bomb cannot hang the server.
- The `updateDBVariable` write runs inside `_in_transaction` (§4) — but the **decompile that obtains
  the HighSymbol happens BEFORE `startTransaction`** (resolution is read-only); only the DB update is
  transacted. This keeps the transaction tight (one undoable unit) and means a *resolution* failure
  surfaces as `not-found` (no transaction opened), while a *write* failure rolls back.
- A target local/param that does not resolve to a `HighSymbol` is a clean `not-found` (`-32004`), not
  a partial write — fail closed.
- The `HighSymbol` resolution must be by a **stable identifier** the read side already exposes
  (recommend: the local's storage/representative address or the decompiler-assigned symbol name from
  `function_context`), not a fragile free-form match — see KEY DECISION (a) for the exact identifier
  contract.

**(c) Larger tampering blast radius — re-flow + re-render [Phase A partial, Phase B full].**
A structural write re-flows more than its target. Renaming a local re-renders that function's
decompilation (the new name appears everywhere the variable is used) — bounded to **one function**.
A *signature* change (Phase B) re-flows parameters/storage and changes every **caller's** decompiled
view (the call site now shows the new prototype); a *type* change (Phase B) re-renders every data
item and function that references the type. This is a genuinely larger integrity-tampering surface
than an annotation (which touched exactly one name/comment). Controls — **the same defense-in-depth as
ADR-012 §4, which is why the increment stays small**: each write is **one Ghidra transaction →
rollback on failure** (§4); **`session_undo`** (already built, `registry.py:577-585`) reverts the last
committed transaction in one step (the strongest mitigation for an injection-induced bad structural
write); and **ADR-002 session ephemerality** means the worst case is a mis-restructured **disposable**
session, wiped on evict — never host or durable-data compromise. The blast radius is *integrity of
the analysis*, not the host (ADR-001 unchanged — §3).

### 3. Write trust boundary (TB7) — flow unchanged in shape; ADR-001 holds

A structural mutation flows through the **identical** layered path ADR-012 §2 defined, with a High
Function-based write at the far end. The server still **never loads the JVM or mutates a program**
(ADR-001) — it validates, authorizes (BOLA chokepoint), requires structural write consent, then asks
the worker to perform the write over the internal RPC. Only the worker's JVM bridge runs the decompile
(to obtain the HighSymbol) and the `updateDBVariable` write, inside one transaction.

```
client (LLM)                          -- TB1/TB6 --> server shell (NO JVM)
  rename_local_variable{session_id, function, variable, new_name}
                                                     1. pydantic *In schema (frozen, extra=forbid)
                                                     2. validate_name(function) + validate_target_ref(variable)
                                                        + validate_write_name(new_name)   <- attacker-influenced
                                                     3. sessions.require_write_consent(sid, structural=True)
                                                        (authorize BOLA + allow_structural gate — manager.py:301)
                                                     4. audit-log INTENT (tool, session, sizes — NO content)
  port.rename_local_variable(sid, args) - TB2 (UDS) -> worker RPC loop (sole client)
                                                     5. dispatch -> backend.rename_local_variable(params)
                                                     6. resolve function (_resolve_function); DECOMPILE
                                                        (bounded) -> HighFunction -> resolve HighSymbol
                                                        [read-only, BEFORE startTransaction]
                                                     7. _in_transaction("rename_local_variable", _write)
                                                        _write: HighFunctionDBUtil.updateDBVariable(
                                                                  highSym, new_name, null, USER_DEFINED)
                                                        commit on success / endTransaction(commit=False)
                                                        on ANY exception incl. commit-time (§4 fix)
                                                     8. return {address, function, old_name, new_name, applied}
       <- TB4 (untrusted) -- server wraps echoed binary-derived fields (function, old_name) Untrusted[...]
                                                     9. audit-log OUTCOME (applied/denied)
```

Invariants preserved (ADR-012 §2): **ADR-001 holds** (the write — and the decompile — execute only in
the worker; the architecture-invariant CI test covers the new structural handlers); **TB2 unchanged in
shape** (two new RPC methods, not a new channel; same per-session UDS, framing, schema validation,
kill-on-timeout); **the worker is still untrusted on the way out (ADR-005/TB4)** — the echoed
`function`/`old_name` are `Untrusted[...]`, while server-controlled `applied`/`address` are bare.

### 4. Atomicity + the reviewer's Low fix to `_in_transaction` (CWE-460)

**Reuse one-transaction-per-write + rollback (ADR-012 §4).** Each Phase-A write wraps its single DB
update in `_in_transaction(tool_name, write)` — one tool call == one transaction == one undoable unit
(`_jvm_bridge.py:1425-1451`).

**Fix the `_in_transaction` flaw flagged in the ADR-012 review (CWE-460 — clean-up after exception
done wrong).** The current control flow commits **outside** the try/except:

```python
# CURRENT (_jvm_bridge.py:1445-1451) — BUG: commit is outside try/except
txn = program.startTransaction(tool_name)
try:
    write()
except Exception as exc:
    program.endTransaction(txn, False)                    # roll back on write failure
    raise WorkerError(CODE_ANALYSIS_FAILED, "write failed and was rolled back") from exc
program.endTransaction(txn, True)                          # <-- commit OUTSIDE try: if THIS raises,
                                                           #     the txn is left dangling, the program
                                                           #     is in an indeterminate state, and a
                                                           #     raw exception escapes (not typed)
```

`program.endTransaction(txn, True)` (the commit) can itself fail — Ghidra may run end-of-transaction
fixups (the decompiler/analysis manager re-flows dependent state, *especially* for a structural write
that changes a signature/type). If that commit raises, the current code: (1) does **not** roll back,
(2) leaves the transaction unterminated, and (3) lets a raw, untyped exception cross the worker
boundary instead of a safe `analysis-failed`. That is the CWE-460 defect. **Corrected control flow —
move the commit inside, with rollback on commit failure (fail closed, master §2,
`topic-error-handling`):**

```python
# CORRECTED — commit is INSIDE the try; a commit-time failure also rolls back + raises typed error
txn = program.startTransaction(tool_name)
committed = False
try:
    write()
    program.endTransaction(txn, True)                      # commit INSIDE try
    committed = True
except Exception as exc:
    if not committed:
        # The write OR the commit failed; end the (still-open) transaction WITHOUT committing.
        with contextlib.suppress(Exception):               # best-effort rollback; never mask the
            program.endTransaction(txn, False)             # original cause (topic-resource-management)
        raise WorkerError(CODE_ANALYSIS_FAILED, "write failed and was rolled back") from exc
    raise                                                   # unreachable in practice; explicit
```

Notes on the corrected flow: the `committed` flag distinguishes "commit succeeded" from "commit
raised" so we never double-end the transaction; the rollback `endTransaction(txn, False)` is itself
wrapped `suppress(Exception)` so a secondary failure in the rollback cannot mask the original
`analysis-failed` cause (topic-resource-management — clean-up on every path, never throw from the
clean-up); and **any** failure — in `write()` or in the commit — surfaces as the same safe
`analysis-failed` slug (`worker/dispatch.py:45`) with the program left rolled back. This fix is
**in-scope for this increment** (it lands with the structural tools that most exercise commit-time
re-flow) and applies to the existing annotation writes too (defense in depth — they share the
primitive). No new `ErrorType` member is needed.

> **Atomicity unchanged otherwise:** still one transaction per call, no batching of multiple tools in
> one transaction (ADR-012 §4); `session_undo` (`registry.py:577-585`) reverts the last committed
> transaction.

### 5. PROPOSED RPC additions (for PM ratification into `docs/contracts/rpc-protocol.md` §4)

Two **new worker-facing RPC methods** added to the frozen allow-list (`RPC_METHODS`,
`worker/dispatch.py:50-89` / `rpc-protocol.md` §4), mirroring the ADR-012 write methods (params = tool
schema minus `session_id`; worker returns plain values; the server wraps any binary-derived field).
**No new server-side lifecycle tool** — the structural gate reuses the existing `session_enable_writes`
(§3).

| New RPC method | params | result | errors (`rpc-protocol.md` §5 codes) |
|----------------|--------|--------|-------------------------------------|
| `rename_local_variable` | `{function: str, variable: str, new_name: str}` | `{address: str, function: str, old_name: str, new_name: str, applied: bool}` | `-32602 invalid-params` (bad name), `-32004 not-found` (function or high symbol), `-32010 analysis-failed` (decompile/txn failed → rolled back) |
| `rename_parameter` | `{function: str, parameter: str, new_name: str}` | `{address: str, function: str, old_name: str, new_name: str, applied: bool}` | `-32602`, `-32004` (function or parameter), `-32010` (rolled back) |

- `variable`/`parameter` is the **stable identifier** of the target local/param (see KEY DECISION
  (a)): recommend the decompiler-assigned symbol name as surfaced by `function_context`, with the
  storage/representative address as the canonical fallback. The worker resolves it to a `HighSymbol`;
  no match → `not-found`.
- The worker performs each via the HighFunction path (§2(b)) inside `_in_transaction` (the corrected
  §4 flow) and returns **plain** values; `old_name` is the pre-write decompiler name → the server
  wraps it `Untrusted[...]`.
- **No new error *codes*** — the existing slug→`ErrorType` map (`worker/dispatch.py:40-47`,
  `rpc-protocol.md` §5) covers `invalid-params`/`not-found`/`analysis-failed`. A rolled-back or
  failed-decompile write maps to `analysis-failed` (consistent with ADR-012 §5,
  `ADR-012-mutation-tools.md:240-246`). **No new `ErrorType` member required.**
- **Deferred Phase B RPCs** (`set_function_signature`, `define_data_type`, `apply_data_type`) are named
  here only as the forward shape; **not added to `RPC_METHODS` now.**

### 6. PROPOSED tool-catalog + schema additions (for PM ratification)

The catalog count moves from **41** (`tool-catalog.md:9`) to **41 + 2 = 43** (two worker write tools;
no new lifecycle tool — the structural gate reuses `session_enable_writes`). Tests asserting the count
(`tool-catalog.md:9`, the `TIER1_TOOL_NAMES` length test) update accordingly. Both tools are
session-scoped (`_SessionScopedIn`), `frozen`, `extra="forbid"` (mirroring every existing tool,
`schemas.py:41-58`).

**New pydantic schema sketches** (mirroring the ADR-012 write-tool style; bounds reuse `_MAX_NAME`):

```python
# --- Phase A structural writes: rename a decompiler local / parameter (HighFunction path) ---
class RenameLocalVariableIn(_SessionScopedIn):
    """Arguments for `rename_local_variable` — set a function-local variable's name (structural).

    Gated by `session_enable_writes{allow_structural: true}` + require_write_consent(structural=True).
    Name-only: no data-type change in this increment (the worker passes a null DataType — §1).
    """
    function: str = Field(min_length=1, max_length=_MAX_NAME)   # existing function (addr|name)
    variable: str = Field(min_length=1, max_length=_MAX_NAME)   # the target local (stable id — §a)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)   # validate_write_name (existing)

class RenameParameterIn(_SessionScopedIn):
    """Arguments for `rename_parameter` — set a function parameter's name (structural)."""
    function: str = Field(min_length=1, max_length=_MAX_NAME)
    parameter: str = Field(min_length=1, max_length=_MAX_NAME)  # the target param (name or index — §a)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)

class StructuralRenameResult(_Out):
    """Result of a structural local/parameter rename (ADR-013 §6)."""
    address: str                 # the function's entry address — server-normalized, safe
    function: Untrusted[str]     # the function's current name — binary-derived → untrusted (ADR-005)
    old_name: Untrusted[str]     # the PRIOR decompiler name — binary-derived → untrusted (ADR-005)
    new_name: str                # the server-validated name we set — SAFE (we validated it)
    applied: bool                # server/worker-controlled — safe

# --- Phase B (DEFERRED — NOT added to the catalog now; shape recorded so §2(a)/KEY DECISION (b)
#     is on the record). Structured signature input — NO free-form C string parsed (§2a). ---
# class SetFunctionSignatureIn(_SessionScopedIn):
#     function: str
#     return_type: TypeRef             # structured ref to an EXISTING/base type — not a C string
#     parameters: list[ParamSpec] = Field(max_length=_MAX_PARAMS)   # recommend 64
#     calling_convention: str | None   # closed allow-list
```

**Bounds / allow-list / validation (per Phase-A tool):**

- `new_name`: **reuse the existing `validate_write_name()`** (`validation.py:303-337`) — the
  conservative identifier allow-list (`[A-Za-z_][A-Za-z0-9_$.]*`) that rejects markup, path
  separators, whitespace, zero-width/RTL/control characters. **No new name validator needed** — a
  local/param name has the identical stored-injection / data-poisoning profile as a function/symbol
  name (it is persisted and re-served by `decompile_function`/`function_context`).
- `function`: `validate_name()` (existing read-path validator, `validation.py:160`), resolved by the
  worker's `_resolve_function` (`_jvm_bridge.py:1508`).
- `variable` / `parameter`: a **new `validate_target_ref()`** (below) — the target identifier is *not*
  a name we write (so `validate_write_name`'s charset is wrong) but it IS attacker-influenceable and
  used to select a HighSymbol; validate it as bounded, control-char-free input (reuse the
  `validate_name` baseline) and let the worker fail closed (`not-found`) if it does not resolve.

**New validator (proposed for `core.validation`):**

- `validate_target_ref(value: str) -> str` — validates a structural-write **target reference** (the
  `variable`/`parameter` identifier). Bounded length (`MAX_NAME_LEN`), rejects control/separator chars
  (reuse the `validate_name` baseline, `validation.py:160-193`). It is **not** restricted to the write
  identifier charset (the decompiler may have assigned names like `local_28`, `param_1`, or storage
  references the client echoes back) — it is a *selector*, not a persisted value, so the worker's
  `not-found` is the authoritative confinement. (For Phase B, `validate_type_decl` /
  `validate_calling_convention` are named in §2(a) but **not** added in this increment.)

> `Untrusted[...]` marks a binary-derived field. The asymmetry from ADR-012 §6 holds: the `new_name`
> we set is **SAFE** (server-validated), but the echoed `function` and `old_name` are **untrusted**
> (binary-derived). `address`/`applied` are server/worker-controlled — bare.

### 7. Validation & abuse

**Input validation (TB7 / TB1 — the write target and name are attacker-INFLUENCED input):**

- The decompiled C and local names the client reasons over are untrusted (ADR-005); an indirect prompt
  injection (TB4) can steer the client into proposing a malicious `new_name`. The write payload is
  validated as hostile input at the boundary, allow-list only (`std-owasp-proactive` #5, CWE-20):
  **`validate_write_name` for the name** (reused, `validation.py:303-337`), `validate_target_ref` for
  the selector, `validate_name` for the function. **No value is interpolated into a Ghidra script** —
  there is no `runScript` (PLAN §2); the worker calls a typed `HighFunctionDBUtil.updateDBVariable`
  with the validated name and a **`null` data type** (§1) — so **no type string is parsed in this
  increment** (the §2(a) C-parser surface is entirely absent from Phase A by construction).
- **Stored-injection / data-poisoning** is the same class ADR-012 §7 addressed: a name written now is
  persisted and re-served by `decompile_function`/`function_context` wrapped `Untrusted[...]`.
  Two-sided defense unchanged: validate+normalize on the way **in** (`validate_write_name`) and the
  untrusted-envelope normalizes on the way **out** (ADR-005).

**Abuse tests to add** (extend `tests/security/test_abuse_cases.py` / threat-model §6 / §10; benign/
synthetic fixtures only, master §5; each must FAIL the attack — the control holds — deterministic +
hermetic):

1. **Structural-without-`allow_structural`** — `rename_local_variable`/`rename_parameter` on a session
   enabled with `allow_structural=false` is **denied** with `VALIDATION` "structural writes not
   permitted" (the existing `require_write_consent(structural=True)` chokepoint, `manager.py:326-330`).
   (TB7-E / gating) — **the new high-value test for this increment.**
2. **Structural-without-any-consent** — the same tools on a read-only session (no
   `session_enable_writes` at all) are denied "session is read-only" (default-deny, `manager.py:321`).
   (TB7-E)
3. **Injection-steered malicious local/param name** — a `new_name` with markup / `../path` /
   zero-width / RTL / control chars is **rejected by `validate_write_name`** (never written). (TB7-T /
   stored-injection — extends ADR-012 abuse-case 15)
4. **HighFunction resolution failure → no partial write** — a `variable`/`parameter` that does not
   resolve to a HighSymbol (or a function whose decompile fails/times out) surfaces `not-found` /
   `analysis-failed` with the program **unchanged** (resolution is before `startTransaction`; a write
   failure rolls back). (TB7-T / atomicity)
5. **Failed-write / commit-time atomicity (the §4 fix)** — a write that raises in `write()` **or in
   the commit** (`endTransaction(txn, True)`) **rolls back** and surfaces `analysis-failed`; the
   program is unchanged. This test specifically exercises the corrected `_in_transaction` flow — a
   commit-time exception must NOT leave a dangling transaction or escape untyped (CWE-460). (TB7-T)
6. **Cross-session structural isolation** — `allow_structural` + a local rename on session A does
   **not** enable or mutate session B; B stays read-only and its store is independent. (TB7-T /
   store-I — extends ADR-012 abuse-case 18)
7. **Structural-write-flood / consumption** — a burst of structural writes (each triggering a
   decompile) is bounded by the per-tool timeout (kills the worker on a hung decompile) + concurrency
   cap + (HTTP) rate limit; no unbounded growth. (TB7-D — extends ADR-012 abuse-case 19)
8. **BOLA on structural grant** — `session_enable_writes{allow_structural: true}` against an
   unknown/foreign session id yields the same `session-invalid` envelope (no oracle); the grant
   cannot target another session. (TB7-E / BOLA — same chokepoint as ADR-012 abuse-case 20)
9. **ADR-001 invariant under structural writes** — the architecture-invariant test still passes: no
   JVM/PyGhidra import on any server-side module, including the new structural write handlers (the
   write — and the decompile to obtain the HighSymbol — execute only in the worker). (TB7-E)

**Mutation/contract testing:** the structural gate path
(`require_write_consent(structural=True)`) and `validate_target_ref` are **critical-path** (new
agency / authZ) → **100% coverage + mutation testing** (master §4, `topic-testing`). The corrected
`_in_transaction` commit/rollback flow is critical-path atomicity → its branch coverage (write
failure, commit failure, success) is asserted at the unit level with a fake program (the real
`_gh_*`/HighFunction edges remain coverage-omitted JVM edges exercised only by the real-worker
integration suite, same posture as every `_gh_*`, `_jvm_bridge.py:1287`).

## Consequences

- **Positive:** closes the deeper semantic-naming loop (locals/params persist within a session) on
  the **smallest** structural surface; reuses the proven `validate_write_name` allow-list and the
  already-built `allow_structural` gate (no new gate mechanism); **fixes the CWE-460 `_in_transaction`
  defect** (benefiting the annotation writes too); ADR-001 containment unchanged (server never
  mutates, decompile-for-HighSymbol runs in the worker); each write is atomic + reversible
  (`session_undo`) + audited; pre-decides the security-critical Phase B input model (structured, not
  free-form C) so the riskiest surface is designed before it is built; additive through the ADR-006
  seam (no contract rewrite).
- **Negative / risk:** the HighFunction re-decompile path is stateful, failure-prone, and
  Ghidra-version-sensitive (§2(b)) — mitigated by bounded decompile timeout, resolution-before-txn,
  clean `not-found` on no-match, and worker-kill on a hung decompile. LLM08 agency rises again (a
  structural write has a larger re-render blast radius than an annotation, §2(c)) — bounded by the
  two-level opt-in, transaction rollback, `session_undo`, per-write audit, and ADR-002 ephemerality
  (a poisoned structural session is disposable and wiped on evict).
- **Negative:** two more schemas + one new selector validator + two RPC methods + the HighFunction
  bridge edge; clients must understand the `allow_structural` two-level opt-in and the stable target
  identifier.
- **Open / deferred:** **Phase B** (`set_function_signature`, `define_data_type`, `apply_data_type` —
  the type-string-parsing surface) is deferred to its own gated, separately-threat-modeled increment
  with the **structured-input** model pre-decided here (§2(a)); cross-session persistence stays
  deferred (ADR-012 §4); `runScript` stays permanently out of scope.

## Alternatives considered

- **Build the full structural set at once** (locals + params + signatures + types): higher value
  sooner but introduces the HighFunction mechanism AND the attacker-influenced C-parser surface in one
  increment — a large, hard-to-exhaustively-test abuse surface (the exact thing ADR-012 §1 rejected,
  `ADR-012-mutation-tools.md:421-423`). Rejected for phasing.
- **Free-form C type strings for signatures/types** (accept `void f(int, char*)` / `struct {...}` and
  parse via `DataTypeParser`/`CParser`): maximally expressive and matches how a human uses Ghidra, but
  it is the **largest injection-into-API surface** (§2(a)) — a small interpreter fed
  attacker-influenced input, with parser-bomb consumption and unintended-type-definition side effects.
  Rejected in favor of the **structured/constrained input** (§2(a), KEY DECISION (b)) — typed
  least-privilege params (`std-owasp-llm` LLM07), the same reasoning that rejected ADR-012's generic
  `set_property`.
- **A new gate mechanism for structural writes** (e.g. per-structural-call human approval, or a
  separate `session_enable_structural` lifecycle tool): rejected — ADR-012 §3 already built the
  forward-compatible `allow_structural` flag on the single consent gate precisely so structural writes
  need **no** new mechanism; adding one would duplicate the chokepoint and break the clean two-level
  opt-in.
- **Leave `_in_transaction` commit outside the try/except** (status quo): rejected — a commit-time
  re-flow failure (more likely for structural writes) leaves a dangling transaction and escapes
  untyped (CWE-460). The §4 fix is mandatory for this increment.
- **A local-rename that also retypes the variable in Phase A** (pass a non-null DataType to
  `updateDBVariable`): rejected for this increment — it would drag the type-string/type-resolution
  surface into Phase A, defeating the point of phasing. Name-only first.

---

## Design summary

This increment (ADR-013, **Phase A**) extends ADR-012's annotation writes with the **two
lowest-risk structural writes** — `rename_local_variable` and `rename_parameter` — via Ghidra's
HighFunction path, gated by the **already-built** `allow_structural` consent flag (no new gate), and
**fixes the CWE-460 `_in_transaction` commit-outside-try defect** the ADR-012 review flagged. It
**defers** signature and data-type writes (Phase B) — the surface that parses attacker-influenced C
type strings — to a separate increment, and **pre-decides** that Phase B will accept a
**structured/constrained** signature input (resolved type references + bounded params), **not**
free-form C, eliminating the C-parser injection surface by construction. Catalog: **41 → 43** (two
worker write tools, no new lifecycle tool). Threat-model TB7 (§10) is extended with a structural-write
subsection (this PR).

**Files in this design PR:** `docs/adr/ADR-013-structural-mutation.md` (this file);
`docs/security/threat-model.md` §10 (structural-write subsection appended). **Proposed for PM
ratification into the frozen contracts** (not edited here): `docs/contracts/tool-catalog.md`
(count 41→43, two rows + deferred Phase B note), `docs/contracts/rpc-protocol.md` §4 (two RPC
methods), `src/ghidra_mcp/tools/schemas.py` (the new models), `src/ghidra_mcp/core/validation.py`
(`validate_target_ref`; reuse `validate_write_name`), `worker/dispatch.py` (`RPC_METHODS` += 2), and
the `_in_transaction` fix in `src/ghidra_mcp/ghidra/_jvm_bridge.py`.

## KEY DECISIONS FOR HUMAN RATIFICATION

**(a) Structural scope / phasing — RECOMMEND: ship `rename_local_variable` + `rename_parameter` now
(Phase A); defer `set_function_signature`, `define_data_type`, `apply_data_type` (Phase B).**
Rationale: locals/params are the structural *analogue* of the annotation renames (a name on an
existing object), reuse the proven `validate_write_name` allow-list, and carry the new HighFunction
mechanism risk but **not** the type-string-parsing risk — letting us validate the HighFunction path on
a name-only write before Phase B adds C-type parsing. Sub-decision to confirm: **the stable target
identifier** for `variable`/`parameter` — recommend the decompiler-assigned symbol name surfaced by
`function_context`, with the local's storage/representative address as the canonical fallback (so the
client references something the read side already exposes, not a fragile free-form guess).

**(b) The type/signature INPUT MODEL — RECOMMEND: structured / constrained, NOT free-form C
(the security-critical call).** When Phase B lands, `set_function_signature` should take a **structured
signature** (resolved `TypeRef`s + bounded `ParamSpec` list + closed-vocabulary calling convention),
assembled in the worker from already-resolved `DataType` handles — **no C string is parsed**, so the
`DataTypeParser`/`CParser` injection-into-API surface (§2(a)) is eliminated by construction
(`std-owasp-llm` LLM07; mirrors the rejection of ADR-012's generic `set_property`). Accepting a
free-form C type string is the explicit, **not-recommended** alternative; if a future increment must
define brand-new types from a string, it requires a dedicated `validate_type_decl` (bounded length /
depth / declaration count, no preprocessor/pragma/`#`/comments), parsing under the worker's
kill-on-timeout caps, and the contract that the parser only *declares* a type (no scripting/include/
execution) — a separate, even narrower opt-in. **Decide the structured-vs-free-form direction now** so
Phase B's schema and validators are designed before any C-parser code exists.

**(c) Is data-type define/apply IN this increment or deferred again — RECOMMEND: deferred again
(Phase B), and signature too.** Data-type define/apply is the most invasive write (largest re-render
blast radius, §2(c)) and the heaviest type-string parser (§2(a)); ADR-012 §1 already named it the
highest injection surface. Keeping it (and signatures) in Phase B keeps this increment's abuse matrix
small enough to be exhaustive and avoids introducing the HighFunction mechanism and the C-parser
surface together. Confirm: Phase A is **name-only** (the `updateDBVariable` data-type argument is
`null`), so even *retyping* a local is part of the deferred Phase B.
