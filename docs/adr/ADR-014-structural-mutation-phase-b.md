# ADR-014: Structural mutation (write) tools — Phase B (signature + data-type apply)

- **Status:** Accepted — design + the locked-decision calls **ratified by the human 2026-06-12**:
  (a) **`set_function_signature` + `apply_data_type` now; defer new-composite `define_data_type`/
  `create_struct` to Phase C**, (b) **TypeRef = existing/base types only + bounded pointer/array
  modifiers** (resolved, never parsed; `named` ref strict-validated), (c) **calling-convention
  allow-list = program-derived (`getCompilerSpec().getCallingConventions()`) + static fallback**.
  **Implementation remains gated** — the PROPOSED contract additions ratify into `docs/contracts/**`
  and the build lands via reviewed, gated PRs (no mutation code yet).
- **Date:** 2026-06-12
- **Deciders:** Human (ratified the scope / TypeRef-model / calling-convention calls) + PM; recorded
  by Software Architect.
- **Builds on / constrained by:** ADR-001 (out-of-process — the server never loads the JVM or
  mutates), ADR-002 (one worker/session, kill + verified-wipe on evict), ADR-005 (untrusted-data
  envelope), ADR-011 (HTTP edge composition), **ADR-012** (annotation mutation — the gate /
  one-transaction / audit model), and the **merged ADR-013 Phase A** (`rename_local_variable` /
  `rename_parameter`; the `allow_structural` consent hook; the corrected `_in_transaction`). Frozen
  contracts in `docs/contracts/**`; threat-model **TB7 (structural)** (`docs/security/threat-model.md`
  §10).
- **Extends:** ADR-013 §1 (the deferred Phase-B set it named — `set_function_signature`,
  `define_data_type`/`create_struct`, `apply_data_type`, `ADR-013-structural-mutation.md:70-71`) and
  ADR-013 §2(a) + its KEY DECISION (b), **ratified by the human**, which pre-decided the Phase-B input
  model: **structured/constrained, NOT free-form C** (`ADR-013-structural-mutation.md:133-169`,
  `:554-565`).

## The pre-decided constraint (NOT relitigated here)

ADR-013 §2(a) and its KEY DECISION (b) — ratified by the human — locked the Phase-B input model: it
accepts a **structured / constrained** signature + type input (resolved `TypeRef`s + bounded
`ParamSpec` + closed-vocabulary calling convention, assembled from **already-resolved `DataType`
handles**) and **never** a free-form C string parsed by Ghidra's `CParser` / `DataTypeParser`
(`ADR-013-structural-mutation.md:135-157`). This ADR's entire design is built around eliminating that
C-parser injection surface **by construction**: no client-supplied string ever reaches a Ghidra type
parser. The free-form-C alternative is recorded in §"Alternatives" only as the explicitly-rejected
option (per ADR-013 §2a's "named only so the structured-first decision is on the record").

## Context

ADR-012 shipped annotation writes and validated the gating model. ADR-013 **Phase A** shipped the
first structural writes — `rename_local_variable` / `rename_parameter` (decompiler HighFunction path,
**name-only**) — and is **merged**: the gate (`require_write_consent(structural=True)`,
`manager.py:301-331`), the structural handlers (`registry.py:661-710`), the corrected one-transaction
`_in_transaction` (the CWE-460 fix, `_jvm_bridge.py:1533-1569`), the structural schemas
(`schemas.py:1349-1398`), the validators (`validate_target_ref`, `validate_write_name`,
`validation.py:303-360`), and the RPC methods (`rpc-protocol.md:80-83`) are all in place. The catalog
is at **43** tools (`tool-catalog.md:9`).

Phase A deliberately left the **deepest** rung of the semantic-naming loop (ADR-007) unbuilt:
recovering a function's **signature** (return type + parameter types/names + calling convention) and
defining/**applying** the **data types** the decompilation references. `function_context` already
returns the current `signature` and decompiled C as `Untrusted[...]` (`schemas.py:818+`,
`_gh_get_function` `_jvm_bridge.py:551`) — the client can infer a better prototype and types but has
**nowhere to persist them**. This increment closes that loop while honoring ADR-013's pre-decision.

ADR-013 §1 flagged this set as carrying **all three** structural risk classes (§2 there): (a) the
type-string C-parser surface, (b) the HighFunction re-decompile state (Phase A already faces this),
and (c) the **largest** re-flow/re-render blast radius (a signature change re-renders every
**caller**; a type change re-renders every data item and function referencing it). Phase A faced (b);
Phase B faces (a) — **neutralized by the structured input** — and (c).

## Decision

### 1. Scope + sub-phasing — land `set_function_signature` + `apply_data_type` now; defer composite-type *creation* to Phase C

The Phase-B candidate set (ADR-013 §1) has three sub-families of sharply different surface. We
**sub-phase again** — the same proportional, minimal-first posture ADR-012 §1 and ADR-013 §1 used
(`topic-migration` incremental):

| Candidate | Sub-family | Ghidra write API (worker-only) | Recommendation |
|-----------|-----------|--------------------------------|----------------|
| `set_function_signature` | signature (over **resolvable** types) | build `FunctionDefinitionDataType` from resolved `DataType` handles + `ParameterDefinitionImpl`/`ParameterImpl`; apply via `Function.updateFunction(name, returnType, params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED)` (or `ApplyFunctionSignatureCmd` over the assembled definition) | **IN this increment (Phase B)** |
| `apply_data_type` | apply an **existing/resolvable** type at an address | resolve `TypeRef` → `DataType`; `DataUtilities.createData(program, addr, dt, length, clearMode)` / `Listing.createData(addr, dt)` | **IN this increment (Phase B)** |
| `define_data_type` / `create_struct` | **create a NEW composite** (struct/union with field specs) | `StructureDataType`/`UnionDataType` built field-by-field from `FieldSpec[]`, then `DataTypeManager.addDataType(dt, conflictHandler)` | **DEFER to Phase C** |

**Phase B (this ADR — `set_function_signature`, `apply_data_type`):** both operate over types that
**already exist or are base/derived from a closed vocabulary** — they *consume* `TypeRef`s, they do
not *create* a type universe. `set_function_signature` assembles a `FunctionDefinitionDataType` from
already-resolved return/parameter `DataType` handles; `apply_data_type` resolves one `TypeRef` and
lays it down at a validated address. Neither parses a C string (§2). Both reuse the proven
`validate_write_name` (parameter names) and the existing `allow_structural` gate. This is the
**structural analogue** of what Phase A did for names, now for *types the program already knows*.

**DEFER to Phase C (`define_data_type` / `create_struct`):** *creating* a new composite type is the
**largest** new surface — it is unbounded field specs (each a `name` + `TypeRef` + optional offset),
nested composites, alignment/packing choices, and a permanent mutation of the program's **type
universe** that re-renders *every* dependent data item and decompiled function (ADR-013 §2c, the
widest blast radius). It also reintroduces the recursive/self-referential definition risk (a struct
referencing itself or a cycle of structs — a structured-input analogue of the parser-bomb consumption
ADR-013 §2a worried about, now in *our* assembly code rather than Ghidra's parser). Keeping it in
Phase C keeps **this** increment's abuse matrix small enough to be exhaustive (`topic-testing`) and
lets us validate the `TypeRef` resolution model and the signature re-flow mechanism on
**already-resolvable** types before adding composite **construction**. This is **KEY DECISION (a)**.

> **`apply_data_type` over a Phase-B `TypeRef` can still reference an existing struct** (resolved by
> name from the program's `DataTypeManager`) — it just cannot *define* one. So a client that wants to
> apply a struct the binary already has (Ghidra recovered it) is served in Phase B; *creating* a
> brand-new struct waits for Phase C.

- **`runScript` / arbitrary script execution** — remains permanently out of scope (PLAN §2,
  `tool-catalog.md:153`). Structural Phase B does **not** reopen it.

### 2. The structured input model (the core — eliminates the C-parser surface by construction)

No client-supplied string ever reaches `CParser` / `DataTypeParser` / `ApplyFunctionSignatureCmd`'s
string overload. The worker assembles every Ghidra type object from **already-resolved `DataType`
handles** looked up in the program's `DataTypeManager` (the read path already does this lookup —
`_gh_get_data_type` `_jvm_bridge.py:739-748`). Validation is allow-list type-*reference* resolution
(CWE-20), not parsing.

#### 2.1 `TypeRef` — a structured reference to a type, never a C declaration

A `TypeRef` names a base type and bounded modifiers; the worker resolves it to a concrete `DataType`.
It admits **no free text** beyond a single bounded type-name token that is *looked up* (not parsed):

```text
TypeRef {
  # exactly ONE of `base` or `named` identifies the underlying type:
  base:  Literal[BASE_TYPE_VOCAB] | None     # closed enum: void/bool/char/uchar/
                                             #   int8/uint8/int16/uint16/int32/uint32/int64/uint64/
                                             #   int/uint/long/ulong/float/double/wchar_t/...
  named: str | None                          # name of a type ALREADY PRESENT in the program's
                                             #   DataTypeManager — validated to EXIST (looked up by
                                             #   name + optional category path), NEVER parsed
  pointer_levels: int = 0                    # 0..=_MAX_POINTER_DEPTH (recommend 8) — `*` count
  array_len:      int | None = None          # None = not an array; else 1..=_MAX_ARRAY_LEN
                                             #   (recommend 65536) — fixed-length array
}
```

Resolution (worker, read-only, **before** any transaction):

1. Resolve the **leaf** type: if `base` is set, map the closed enum to the program's built-in
   `DataType` (e.g. `IntegerDataType`, `CharDataType`, `VoidDataType`, or sized
   `AbstractIntegerDataType` from the `DataTypeManager`'s built-in category). If `named` is set, look
   it up via the `DataTypeManager` (`getDataType(CategoryPath, name)` / iterate `getAllDataTypes`,
   the same lookup `_gh_get_data_type` uses) — **must already exist**; no match → `not-found`.
2. Apply `pointer_levels` by wrapping in `PointerDataType` that many times (bounded ≤ `_MAX_POINTER_DEPTH`).
3. Apply `array_len` by wrapping in `ArrayDataType(elem, array_len, elem.getLength())` (bounded).
4. Exactly one of `base`/`named` MUST be set (validator-enforced); both/neither → `VALIDATION`.

An **unresolvable** `TypeRef` (unknown `named`, out-of-vocab `base`, out-of-bounds modifier) **fails
closed** (`VALIDATION` at the boundary for shape/vocab/bounds; `not-found` at the worker for an
unknown `named` that passed shape validation) — **never** falls back to parsing. This is the
`std-owasp-llm` LLM07 typed-least-privilege posture and mirrors ADR-012's rejection of the generic
`set_property` tool.

#### 2.2 `ParamSpec` — a bounded parameter

```text
ParamSpec {
  name: str   # validate_write_name (the EXISTING identifier allow-list — validation.py:303-337)
  type: TypeRef
}
```

#### 2.3 The signature input

```text
SetFunctionSignatureIn(_SessionScopedIn) {
  function:           str                       # existing function (addr|name); validate_name
  return_type:        TypeRef
  parameters:         list[ParamSpec]           # bounded: max_length=_MAX_PARAMS (recommend 64)
  calling_convention: str | None = None         # closed allow-list (see §2.5); None = leave unchanged
}
```

#### 2.4 The apply-type input

```text
ApplyDataTypeIn(_SessionScopedIn) {
  address:   str                                # hex; parse_address + worker map-confinement
  type:      TypeRef                            # resolved (existing/base/derived) — never parsed
  clear_existing: bool = False                  # whether to clear conflicting defined data first
}
```

#### 2.5 Bounded counts + closed vocabularies (the construction-time DoS guard)

- `_MAX_PARAMS` ≈ **64** (a function with >64 params is pathological; bounds construction cost and
  the re-flow surface — CWE-400).
- `_MAX_POINTER_DEPTH` ≈ **8** (a sane `****…` cap).
- `_MAX_ARRAY_LEN` ≈ **65536** (bounds array element-count; an array `DataType` is cheap but its
  application footprint is `elem_size * len` bytes — must be confined to the memory map by the worker
  before `apply_data_type`, same posture as `read_bytes`).
- `BASE_TYPE_VOCAB` — a fixed `Literal` enum of base type names mapped to built-in `DataType`s; not
  client-extensible.
- `calling_convention` — a **closed allow-list** (§"KEY DECISION (c)"): recommend deriving it at
  startup from the program's `getCompilerSpec().getCallingConventions()` (the conventions Ghidra
  actually knows for *this* program), with a conservative static fallback set
  (`{default, __cdecl, __stdcall, __fastcall, __thiscall, __vectorcall}`). The client-supplied name is
  membership-checked against that set; a non-member → `VALIDATION`; `None` leaves the convention
  unchanged. **Never** a free-form convention string.

**Why this admits no C string into Ghidra's parser:** every field is either a closed enum
(`base`, `calling_convention`, the `Literal`s), a bounded integer (`pointer_levels`, `array_len`,
`_MAX_PARAMS`), or a single bounded *identifier* token (`named`, `ParamSpec.name`) that is **looked
up** (`named`) or **validated against the identifier allow-list** (`name`). The worker constructs
`FunctionDefinitionDataType` / `PointerDataType` / `ArrayDataType` / the resolved leaf entirely from
typed Java objects. `DataTypeParser` and `CParser` are **never instantiated** on a client value.

### 3. New validators (PROPOSED for `core.validation`)

Pure, I/O-free, allow-list, fail-closed — the established `validation.py` posture (`validation.py:8-14`).

- `validate_type_ref(ref) -> None` — validates a `TypeRef`'s **shape and bounds** (the pure part;
  the *existence* of a `named` type is a worker concern → `not-found`): exactly one of `base`/`named`
  set; `base` ∈ `BASE_TYPE_VOCAB`; `named` passes the baseline `validate_name` charset (bounded,
  control/separator-free — `validation.py:160`) **and** the write-name identifier allow-list
  (`validate_write_name`, `validation.py:303`) *iff* we treat a `named` reference as untrusted-influenced
  (recommend yes — it is attacker-influenceable and used as a DB lookup key, though it is a *selector*
  not a *persisted* value; the conservative choice is the stricter allow-list, which a legitimate
  recovered type name satisfies); `0 ≤ pointer_levels ≤ _MAX_POINTER_DEPTH`;
  `array_len is None or 1 ≤ array_len ≤ _MAX_ARRAY_LEN`.
- `validate_signature(sig) -> None` — validates a `SetFunctionSignatureIn` payload: `function` via
  `validate_name`; `len(parameters) ≤ _MAX_PARAMS`; each `ParamSpec.name` via `validate_write_name`
  (persisted into the program DB → strict allow-list, same as a local/param rename); each
  `ParamSpec.type` and `return_type` via `validate_type_ref`; `calling_convention` via
  `validate_calling_convention`. Parameter names need not be unique server-side (Ghidra disambiguates),
  but an empty/duplicate-heavy list is bounded by `_MAX_PARAMS`.
- `validate_calling_convention(name | None) -> None` — `None` is allowed (leave unchanged); otherwise
  membership in the closed allow-list (§2.5). Control-free, bounded length, no free-form.

These are **critical-path** (new agency surface; the structured-input gate that *replaces* a parser)
→ **100% coverage + mutation testing** (master §4, `topic-testing`). They contain **no** type-string
parsing — `validate_type_decl` (the free-form-C bounder ADR-013 §2a named) is **NOT** added (the
structured model makes it unnecessary; it stays a named, rejected alternative).

### 4. Gating / atomicity — reuse Phase A wholesale (CONFIRM: no new mechanism)

**Gate.** `set_function_signature` and `apply_data_type` are structural → each handler calls the
**existing** `ctx.sessions.require_write_consent(args.session_id, structural=True)`
(`manager.py:301-331`) before validating inputs and delegating — exactly the Phase-A handler shape
(`registry.py:665`, `:695`). **No new consent flag, no new lifecycle tool.** A session must have
`session_enable_writes{allow_structural: true}` (`manager.py:249-277`); otherwise the call fails
closed (`VALIDATION` "structural writes not permitted" / "session is read-only"). The two-level
default-deny opt-in (writes off → annotations → structural) is unchanged.

**Atomicity.** Each write wraps its single mutation in the **corrected one-transaction**
`_in_transaction(tool_name, write)` (`_jvm_bridge.py:1533-1569`) — one tool call == one transaction ==
one undoable unit, commit **inside** the try, best-effort suppressed rollback on any failure
(including the commit-time re-flow that a signature/type change makes *more* likely to raise — the
exact CWE-460 case the fix targets). `session_undo` (`registry.py:580`) reverts the last committed
transaction in one step. **CONFIRMED: the Phase-A primitives cover Phase B unchanged** — Phase B adds
no new gate or transaction mechanism, only new handlers + RPC methods + worker bridge edges.

**Resolution-before-transaction (extends ADR-013 §2b).** `TypeRef` resolution and `_resolve_function`
are **read-only** and happen **before** `startTransaction` — an unresolvable type or unknown function
surfaces `not-found` with **no transaction opened** (fail closed, no partial write). Only the
`updateFunction` / `createData` write is transacted; a *write/commit* failure rolls back.

### 5. PROPOSED RPC additions (for PM ratification into `rpc-protocol.md` §4)

Two **new worker-facing RPC methods** added to the frozen allow-list (`RPC_METHODS`,
`worker/dispatch.py` / `rpc-protocol.md:70-83`), mirroring the ADR-012/013 write methods (params = tool
schema minus `session_id`; worker returns plain values; the server wraps binary-derived fields). **No
new server-side lifecycle tool** — the gate reuses `session_enable_writes` (§4).

| New RPC method | params | result | errors (`rpc-protocol.md` §5) |
|----------------|--------|--------|-------------------------------|
| `set_function_signature` | `{function: str, return_type: TypeRef, parameters: [ParamSpec], calling_convention: str\|null}` | `{address: str, function: str, old_signature: str, new_signature: str, applied: bool}` | `-32602 invalid-params` (bad name/cc/shape), `-32004 not-found` (function or an unresolvable `TypeRef`), `-32010 analysis-failed` (updateFunction/txn/commit failed → rolled back) |
| `apply_data_type` | `{address: str, type: TypeRef, clear_existing: bool}` | `{address: str, type_name: str, size: int, applied: bool}` | `-32602` (bad addr/shape), `-32004` (unresolvable `TypeRef`), `-32010` (rolled back; incl. address-not-in-map / conflict-without-clear) |

- An **unresolvable `TypeRef`** (unknown `named`) is `not-found` (the type does not exist in this
  program — same slug as a missing function); a malformed `TypeRef` (bad vocab/bounds) is caught at
  the server boundary as `invalid-params` before the RPC. A write/commit failure is `analysis-failed`
  (rolled back), consistent with ADR-012 §5 / ADR-013 §5.
- `old_signature` is the pre-write prototype string (`getPrototypeString`, `_jvm_bridge.py:551`) →
  binary-derived → the server wraps it `Untrusted[...]`. `new_signature` is **also** binary-derived on
  the way back (Ghidra re-renders the applied prototype, which can normalize/expand our input) → wrap
  it `Untrusted[...]` too. `type_name` (apply) is the resolved type's name → binary-derived →
  `Untrusted[...]`. `address`/`size`/`applied` are server/worker-controlled scalars → bare.
- **No new error *codes*** — the existing slug→`ErrorType` map (`rpc-protocol.md:96-102`) covers
  `invalid-params`/`not-found`/`analysis-failed`. **No new `ErrorType` member.**
- **Phase C RPCs** (`define_data_type`/`create_struct`) named only as forward shape; **not added now.**

### 6. PROPOSED tool-catalog + schema additions (for PM ratification)

The catalog count moves from **43** (`tool-catalog.md:9`) to **43 + 2 = 45** (two worker write tools;
no new lifecycle tool). The count tests update (`test_tools_registry.py:341`,
`test_tool_schemas.py:80`, `tool-catalog.md:9`). Both tools are session-scoped (`_SessionScopedIn`),
`frozen`, `extra="forbid"` (every existing tool — `schemas.py:41-58`).

**New pydantic schema sketches** (mirroring the ADR-013 structural style; bounds via new
`_MAX_PARAMS`/`_MAX_POINTER_DEPTH`/`_MAX_ARRAY_LEN`):

```python
# --- shared structured type model (NO free-form C — ADR-013 §2a / ADR-014 §2) ---
_MAX_PARAMS = 64
_MAX_POINTER_DEPTH = 8
_MAX_ARRAY_LEN = 65_536

# closed base-type vocabulary mapped to Ghidra built-ins in the worker (not client-extensible)
BaseType = Literal[
    "void", "bool", "char", "uchar", "wchar_t",
    "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64",
    "int", "uint", "long", "ulong", "float", "double",
]

class TypeRef(_In):
    """A structured reference to a data type — resolved against the program's DataTypeManager.

    Exactly one of `base`/`named` identifies the leaf type; modifiers are bounded. NO C string is
    parsed — the worker assembles a DataType from already-resolved handles (ADR-014 §2.1).
    """
    base:  BaseType | None = None
    named: str | None = Field(default=None, min_length=1, max_length=_MAX_NAME)  # must already exist
    pointer_levels: int = Field(default=0, ge=0, le=_MAX_POINTER_DEPTH)
    array_len: int | None = Field(default=None, ge=1, le=_MAX_ARRAY_LEN)
    # model_validator: exactly one of base/named set (boundary VALIDATION otherwise)

class ParamSpec(_In):
    """One parameter of a structured signature (ADR-014 §2.2)."""
    name: str = Field(min_length=1, max_length=_MAX_NAME)   # validate_write_name (persisted)
    type: TypeRef

class SetFunctionSignatureIn(_SessionScopedIn):
    """Arguments for `set_function_signature` — structured signature (NO C string — ADR-014 §2).

    Gated by session_enable_writes{allow_structural: true} + require_write_consent(structural=True).
    """
    function: str = Field(min_length=1, max_length=_MAX_NAME)
    return_type: TypeRef
    parameters: list[ParamSpec] = Field(default_factory=list, max_length=_MAX_PARAMS)
    calling_convention: str | None = Field(default=None, max_length=_MAX_NAME)  # closed allow-list

class SetFunctionSignatureResult(_Out):
    """Result of `set_function_signature` (ADR-014 §5)."""
    address: str                       # function entry — server-normalized, safe
    function: Untrusted[str]           # current name — binary-derived → untrusted (ADR-005)
    old_signature: Untrusted[str]      # PRIOR prototype — binary-derived → untrusted
    new_signature: Untrusted[str]      # re-rendered applied prototype — binary-derived → untrusted
    applied: bool                      # server/worker-controlled — safe

class ApplyDataTypeIn(_SessionScopedIn):
    """Arguments for `apply_data_type` — lay a RESOLVABLE type at an address (ADR-014 §2.4)."""
    address: str = Field(min_length=1, max_length=_MAX_NAME)
    type: TypeRef
    clear_existing: bool = Field(default=False)

class ApplyDataTypeResult(_Out):
    """Result of `apply_data_type` (ADR-014 §5)."""
    address: str                       # server-normalized — safe
    type_name: Untrusted[str]          # resolved type's name — binary-derived → untrusted
    size: int                          # applied size in bytes — worker-computed scalar, safe
    applied: bool                      # safe

# --- Phase C (DEFERRED — NOT added now; shape recorded for KEY DECISION (a)):
# class FieldSpec(_In): name: str; type: TypeRef; offset: int | None
# class DefineDataTypeIn(_SessionScopedIn):
#     name: str; kind: Literal["struct","union"]; fields: list[FieldSpec] (bounded); packed: bool
```

**Bounds / allow-list / validation (per tool):**

- `function`: `validate_name` (read-path baseline, `validation.py:160`), resolved by `_resolve_function`.
- `address` (apply): `parse_address` (`validation.py:111`) + **worker map-confinement before write**
  (same posture as `read_bytes`/`set_comment`, `registry.py`/`_jvm_bridge.py`) — an address outside
  the memory map fails closed (`analysis-failed`/`not-found`), no write.
- `return_type` / `ParamSpec.type` / apply `type`: `validate_type_ref` (§3) at the boundary; the
  worker resolves against the `DataTypeManager` and `not-found`s an unknown `named`.
- `ParamSpec.name`: **reuse `validate_write_name`** (`validation.py:303`) — a parameter name is
  persisted and re-served by `function_context`/`decompile_function`, identical stored-injection
  profile as a Phase-A local/param name.
- `calling_convention`: `validate_calling_convention` (§3) — closed allow-list / `None`.
- Every handler **authorizes + requires structural write consent** (`require_write_consent(
  structural=True)`) before delegating — fail closed.

> `Untrusted[...]` asymmetry (ADR-012/013 §6): the names/closed-vocab values **we set** are SAFE
> (server-validated); the echoed `function`/`old_signature`/`new_signature`/`type_name` are
> **binary-derived → untrusted** (note `new_signature` is untrusted because Ghidra **re-renders** our
> applied prototype — the worker is untrusted on the way out, ADR-005). `address`/`size`/`applied` are
> server/worker-controlled — bare.

### 7. Validation & abuse

**Input validation (TB7 / TB1 — the signature/type input is attacker-INFLUENCED):** the decompiled C
the client reasons over is hostile (ADR-005); an indirect prompt injection (TB4) can steer the client
into a malicious signature/type payload. The whole payload is validated at the boundary, allow-list
only (`std-owasp-proactive` #5, CWE-20): `validate_signature` / `validate_type_ref` /
`validate_calling_convention` (§3) + `validate_write_name` for parameter names + `parse_address` +
worker map-confinement. **No value is parsed by a C-type parser** — the §2 structured model assembles
typed Java objects; `CParser`/`DataTypeParser` are never instantiated on a client value
(`validation.py:9-10` no-interpolation stance holds, now extended to no-parsing).

**Stored-injection / data-poisoning** is the same class as ADR-012 §7 / ADR-013 §7: a parameter name
written now is persisted and re-served by `function_context`/`decompile_function` wrapped
`Untrusted[...]`. Two-sided defense unchanged: `validate_write_name` in, untrusted-envelope out.

**Abuse tests to add** (extend `tests/security/test_abuse_cases.py` / threat-model §6 / §10;
benign/synthetic fixtures only, master §5; each must FAIL the attack — deterministic + hermetic):

31. **Type-ref injection attempt rejected** — a `TypeRef.named` carrying C-declaration syntax / markup
    / `*`-laden text / a struct body (`"struct{int x;}"`, `"int*"`, `"a;b"`) is **rejected by
    `validate_type_ref`** (it is not a valid identifier and is never parsed) → `VALIDATION`; no type
    is defined or applied. (TB7-T — the design-eliminated C-parser surface, proven absent.)
32. **Unresolvable-type fail-closed** — a `set_function_signature`/`apply_data_type` with a
    well-formed but **unknown** `named` `TypeRef` surfaces `not-found` with the program **unchanged**
    (resolution is before `startTransaction`); no partial write. (TB7-T / atomicity)
33. **Signature re-flow corruption / commit-time atomicity** — a signature change whose
    `updateFunction` **or its commit-time re-flow** (re-rendering callers) raises **rolls back** and
    surfaces `analysis-failed`; no dangling transaction, no untyped escape (exercises the §4 corrected
    `_in_transaction` — CWE-460). The program is unchanged. (TB7-T — extends case 26)
34. **Oversized-params / construction DoS** — `parameters` longer than `_MAX_PARAMS`, `pointer_levels`
    > `_MAX_POINTER_DEPTH`, or `array_len` > `_MAX_ARRAY_LEN` is **rejected at the boundary**
    (`VALIDATION`/`LIMIT_EXCEEDED`) before any worker call; a hung re-flow is bounded by the per-tool
    timeout that **kills the worker** (consumption — CWE-400). (TB7-D — extends case 28)
35. **Injection-steered malicious parameter name** — a `ParamSpec.name` with markup/`../path`/
    zero-width/RTL/control chars is **rejected by `validate_write_name`** (never written). (TB7-T —
    extends case 24)
36. **Cross-session structural isolation** — `allow_structural` + a signature/type apply on session A
    does **not** enable or mutate session B; B stays read-only, store independent. (TB7-T / store-I —
    extends case 27)
37. **Structural-consent-required** — `set_function_signature`/`apply_data_type` on a session with
    `allow_structural=false` is denied "structural writes not permitted"; on a read-only session,
    "session is read-only" (the `require_write_consent(structural=True)` chokepoint,
    `manager.py:326-330`). (TB7-E / gating — extends cases 22/23)
38. **BOLA on the structural grant** — unchanged: a grant against an unknown/foreign session id yields
    the same `session-invalid` envelope (no oracle). (TB7-E / BOLA — same chokepoint as case 29)
39. **ADR-001 invariant under Phase-B writes** — the architecture-invariant test still passes: no
    JVM/PyGhidra import on any server-side module, including the new `set_function_signature` /
    `apply_data_type` handlers (the write **and** the type resolution execute only in the worker).
    (TB7-E — extends case 30)
40. **Address-not-in-map / out-of-bounds apply** — `apply_data_type` at an address outside the program
    memory map (or where the type's footprint would overrun a region) fails closed
    (`analysis-failed`/`not-found`) with no write — worker map-confinement before the transaction.
    (TB7-T)

**Mutation/contract testing:** `validate_type_ref`, `validate_signature`, `validate_calling_convention`,
and the structural-consent path are **critical-path** (the typed barrier that *replaces* the C parser
+ new agency/authZ) → **100% coverage + mutation testing** (master §4, `topic-testing`). The corrected
`_in_transaction` branches (write-failure / commit-failure / success) stay asserted at the unit level
with a fake program; the real `_gh_set_function_signature` / `_gh_apply_data_type` JVM edges (the
`DataTypeManager` lookup, `FunctionDefinitionDataType` assembly, `updateFunction`, `createData`) are
coverage-omitted JVM edges exercised only by the real-worker integration suite — the same posture as
every `_gh_*` (`_jvm_bridge.py:724`, ADR-013 §7).

## Consequences

- **Positive:** closes the **deepest** semantic-naming rung (signatures + applying recovered types
  persist within a session) on the smallest surface that delivers it; **eliminates the C-parser
  injection surface by construction** (ADR-013 §2a honored — no client string reaches
  `CParser`/`DataTypeParser`); reuses the proven `validate_write_name`, the existing `allow_structural`
  gate, and the corrected `_in_transaction` (no new gate/transaction mechanism); ADR-001 containment
  unchanged (server never mutates; type resolution and write run only in the worker); each write is
  atomic + reversible (`session_undo`) + audited; additive through the ADR-006 seam (no contract
  rewrite); keeps composite-type *creation* (the widest surface) for Phase C so this increment's abuse
  matrix is exhaustive.
- **Negative / risk:** the signature re-flow blast radius is **larger than a rename** — it re-renders
  every **caller**'s decompiled view (ADR-013 §2c) — bounded by one-transaction rollback (incl. the
  §4 commit-time fix), `session_undo`, per-write audit, and ADR-002 ephemerality (a mis-restructured
  session is disposable, wiped on evict — never host/durable compromise). LLM08 agency rises again (a
  signature/type change is higher-impact than a name). The `updateFunction`/`createData` JVM edges and
  the `DataTypeManager` resolution are Ghidra-version-sensitive (mitigated by the integration suite +
  bounded timeouts + fail-closed `not-found`).
- **Negative:** four new schemas (`TypeRef`, `ParamSpec`, two `*In` + two results) + three new
  validators + two RPC methods + two worker bridge edges; clients must learn the structured `TypeRef`
  model (vs. the C string they may expect) and that only **resolvable** types are accepted in Phase B.
- **Open / deferred:** **Phase C** (`define_data_type`/`create_struct` — *creating* composite types,
  with `FieldSpec[]` and the recursive-definition guard) is deferred to its own gated,
  separately-threat-modeled increment; cross-session persistence stays deferred (ADR-012 §4);
  `runScript` stays permanently out of scope (PLAN §2).

## Alternatives considered

- **Free-form C type/signature strings** (accept `void f(int, char*)` / `struct {...}` and parse via
  `DataTypeParser`/`CParser`/`ApplyFunctionSignatureCmd`): maximally expressive and matches how a human
  uses Ghidra, but it is the **largest injection-into-API surface** (ADR-013 §2a) — a small
  interpreter fed attacker-influenced input, with parser-bomb consumption and unintended-type-definition
  side effects. **Rejected** — pre-decided against by ADR-013 §2a / KEY DECISION (b), ratified by the
  human (`ADR-013-structural-mutation.md:554-565`). The structured model (§2) is the chosen
  typed-least-privilege posture (`std-owasp-llm` LLM07; the same reasoning that rejected ADR-012's
  generic `set_property`). The `validate_type_decl` bounder ADR-013 §2a named for a hypothetical
  free-form path is **not** added — the structured model makes it unnecessary.
- **Ship composite-type *creation* (`define_data_type`) in Phase B too:** higher value sooner but
  introduces the widest re-render blast radius AND the recursive/self-referential definition surface in
  the same increment as the signature re-flow — a large, hard-to-exhaustively-test abuse surface (the
  posture ADR-012 §1 / ADR-013 §1 rejected). **Rejected** — deferred to Phase C (KEY DECISION (a)).
- **A new gate mechanism for Phase-B writes** (a separate `session_enable_signatures` flag or per-call
  human gate): **rejected** — ADR-012 §3 / ADR-013 built the `allow_structural` flag on the single
  consent gate precisely so the whole structural set needs **no** new mechanism; adding one duplicates
  the chokepoint and breaks the clean two-level opt-in.
- **`TypeRef` over existing types only (no `base` vocabulary):** simpler, but a client could not give a
  function an `int` return without the program already having a named `int` type — too restrictive.
  **Rejected** in favor of the closed `base` vocabulary mapped to built-ins (§2.5), which adds no
  parsing surface.
- **Resolve `named` types lazily inside the transaction:** simpler control flow but a resolution
  failure would then occur *mid-transaction* (partial-write risk). **Rejected** — resolution is
  read-only and happens **before** `startTransaction` (§4), so an unresolvable type is a clean
  `not-found` with no transaction opened (ADR-013 §2b posture).

---

## Design summary

ADR-014 (structural mutation **Phase B**) extends ADR-013 Phase A's name-only structural writes with
the two **type-aware** structural writes — `set_function_signature` (a structured signature over
resolvable types) and `apply_data_type` (lay a resolvable type at an address). It honors the
**human-ratified** ADR-013 §2(a) pre-decision: the input is a **structured/constrained `TypeRef` +
bounded `ParamSpec` + closed-vocabulary calling-convention** model assembled in the worker from
**already-resolved `DataType` handles** — **no client string ever reaches Ghidra's `CParser` /
`DataTypeParser`**, eliminating the C-parser injection surface **by construction**. It **reuses Phase
A wholesale** — the `allow_structural` gate (`require_write_consent(structural=True)`,
`manager.py:301-331`), the corrected one-transaction `_in_transaction` (`_jvm_bridge.py:1533-1569`),
`validate_write_name`, and the audit/`session_undo` machinery — adding **no** new gate or transaction
mechanism. It **defers composite-type *creation*** (`define_data_type`/`create_struct`) to **Phase C**
(the widest re-render surface + recursive-definition risk), keeping this increment's abuse matrix
exhaustive. Catalog: **43 → 45** (two worker write tools, no new lifecycle tool). ADR-001 holds (the
server never mutates; type resolution and the write run only in the worker). Threat-model TB7
(structural) is extended with the Phase-B specifics.

**Files in this design PR:** `docs/adr/ADR-014-structural-mutation-phase-b.md` (this file);
`docs/security/threat-model.md` §10 TB7 (structural) extended with a Phase-B subsection (this PR).
**Proposed for PM ratification into the frozen contracts** (NOT edited here):
`docs/contracts/tool-catalog.md` (count 43→45, two rows + Phase-C deferral note),
`docs/contracts/rpc-protocol.md` §4 (two RPC methods + `TypeRef`/`ParamSpec` param shape),
`src/ghidra_mcp/tools/schemas.py` (`TypeRef`, `ParamSpec`, `SetFunctionSignatureIn`/`Result`,
`ApplyDataTypeIn`/`Result`, the `_MAX_PARAMS`/`_MAX_POINTER_DEPTH`/`_MAX_ARRAY_LEN`/`BaseType`
constants), `src/ghidra_mcp/core/validation.py` (`validate_type_ref`, `validate_signature`,
`validate_calling_convention`), `worker/dispatch.py` (`RPC_METHODS` += 2), and the worker bridge edges
(`_gh_set_function_signature`, `_gh_apply_data_type`) in `src/ghidra_mcp/ghidra/_jvm_bridge.py`. No
`_in_transaction` change is needed (the ADR-013 §4 fix already covers commit-time re-flow).

## KEY DECISIONS FOR HUMAN RATIFICATION

**(a) Phase-B scope — RECOMMEND: ship `set_function_signature` + `apply_data_type` now; DEFER
`define_data_type`/`create_struct` (new composite-type creation) to Phase C.** Rationale: signatures
and applying a type *consume* `TypeRef`s over types that already exist or derive from a closed base
vocabulary — they reuse `validate_write_name` and the existing gate and do not mutate the program's
type universe. *Creating* a new composite is the largest surface (unbounded field specs, nesting,
permanent type-universe mutation re-rendering every dependent item, and a recursive/self-referential
definition risk) — keeping it in Phase C keeps this increment's abuse matrix exhaustive and validates
the `TypeRef` resolution + signature re-flow mechanism on already-resolvable types first. (Note:
`apply_data_type` can still reference an existing struct Ghidra recovered — only *defining* a new one
waits.)

**(b) The exact `TypeRef` resolution model — RECOMMEND: existing-types-only + a closed base-type
vocabulary, with bounded pointer/array modifiers; NO ability to build new composites in Phase B.** A
`TypeRef` resolves to a leaf via either a closed `BaseType` enum (mapped to Ghidra built-ins) or a
`named` type **looked up and required to already exist** in the program's `DataTypeManager` (validated,
never parsed), then wrapped in bounded `PointerDataType`/`ArrayDataType` modifiers
(`pointer_levels ≤ 8`, `array_len ≤ 65536`). This admits no C string into any Ghidra parser. The
alternative — letting `TypeRef` *build* new composites inline — is Phase C (see (a)); the alternative
of free-form C is the explicitly rejected option (§"Alternatives", per ADR-013 §2a). **Sub-decision:**
should a `named` reference be held to the strict `validate_write_name` identifier allow-list (recommend
**yes** — conservative; a legitimate recovered type name satisfies it) or only the looser baseline
`validate_name` (a `named` is a selector, not a persisted value)?

**(c) The calling-convention allow-list source — RECOMMEND: derive the allow-list at startup from the
program's `getCompilerSpec().getCallingConventions()` (the conventions Ghidra knows for *this*
program), with a conservative static fallback set (`{default, __cdecl, __stdcall, __fastcall,
__thiscall, __vectorcall}`); membership-check the client value against it; `None` leaves the convention
unchanged.** This keeps the vocabulary closed and *correct for the program's architecture* (an x86
program and an ARM program legitimately differ) rather than a hardcoded global list, while never
accepting a free-form convention string. Confirm whether the program-derived set or a fixed static set
is preferred (the program-derived set is more precise but adds a worker round-trip / a cached lookup at
session import).
