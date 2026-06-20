# Blind analysis example: a stripped SQLite binary

This document is a worked example of using Vivarium to analyze a program with no
prior knowledge of what it is, and then checking the conclusions against the real
source code. It is meant to show two things:

1. What you actually feed into the tools and what they hand back.
2. How close a careful, evidence-based reading of a stripped binary gets to the
   ground truth.

The exercise was run as a genuine blind test. The source code was downloaded and
set aside in a separate folder that was not opened until every conclusion below
had already been written down. The comparison section was filled in last.

If you are new to reverse engineering: a "stripped" binary is one with all of its
human-readable names removed. There are no function names, no variable names, and
no debug information. The analyst sees numbered placeholders like `FUN_0043e140`
and has to work out what each piece of code does from its behavior alone.

---

## 1. The subject

A single command-line program was chosen because its source is openly available,
so the answers can be checked afterward.

| Property | Value |
| --- | --- |
| File name (as imported) | `sqlite3.blind` |
| Size | 2.6 MiB (2,727,048 bytes) |
| SHA-256 | `d45e31f35493db2a23e895bb4fdc04f26eeaa49f2ad9b603e48ca45ba88a49ac` |
| Format | ELF 64-bit, x86-64, statically linked |
| Symbols | Stripped (no names, no debug info) |
| Build | Compiled at `-O2` (normal release optimization) |

The build was deliberately set up to look like something you would find in the
wild: release optimization on, all names stripped out, and statically linked so
the standard C library is baked into the same file. No debugging aids were left
in. (Section 8 explains why that detail matters.)

At the time of analysis the analyst knew only the file on disk. The name
`sqlite3.blind` was assigned by the person preparing the test and was treated as
meaningless; nothing in the workflow relied on it.

---

## 2. What gets ingested

Working with Vivarium follows a fixed, read-only sequence. Each step is a single
tool call. Nothing about the binary is executed at any point. Ghidra runs inside
an isolated, locked-down worker container, and the server process never loads the
binary itself.

1. `session_create` opens a fresh, isolated analysis session.
2. `session_import` loads the file into that session.
3. `session_analyze` runs Ghidra's auto-analysis (disassembly, function
   discovery, cross-references, decompilation groundwork).

From that point on, every other tool just reads results out of the analyzed
program. When finished, `session_close` tears the worker down and wipes its
project store, so no binary-derived data lingers.

Everything the tools return about the binary is wrapped in an "untrusted data"
envelope. The rule is simple: bytes that came out of a hostile binary are treated
as inert data, never as instructions. They are never executed, never rendered as
markup, and any URLs or file paths found inside them are never followed.

---

## 3. What the tools returned (program level)

These are the program-wide facts gathered before looking at any individual
function. Together they form a first impression: how big is this thing, how is it
shaped, and does anything jump out as dangerous.

### Program summary (`program_summary`)

| Measure | Value | Plain meaning |
| --- | --- | --- |
| Functions | 4,197 | A large program, not a small utility. |
| Imports | 0 | Nothing is loaded from outside. Confirms it is statically linked. |
| Exports | 1 | One entry point. This is an application, not a shared library. |
| Strings | 4,127 | A lot of embedded text to mine for clues. |
| Entry point | `0x4048a0` | Where execution begins. |

### Coverage (`coverage`)

| Measure | Value | Plain meaning |
| --- | --- | --- |
| Code ratio | 0.721 | About 72 percent of the analyzed space is recognized code. |
| Data ratio | 0.150 | About 15 percent is data. |
| Undefined bytes | 354,149 | Leftover regions the analysis did not classify, normal for a big static binary. |

### Call graph shape (`call_graph_metrics`)

| Measure | Value | Plain meaning |
| --- | --- | --- |
| Edges | 14,121 | Total "function A calls function B" relationships. |
| Leaf functions | 997 | Functions that call nothing else (low-level helpers). |
| Root functions | 1,545 | Functions nothing else calls (entry-like or setup code). |
| Recursive components | 102 | Groups of functions that call each other in cycles. |

The two most useful rankings from the call graph were:

- **Most called (highest fan-in):** `FUN_0043e140` (called from 414 places),
  `FUN_005a9380` (308), `thunk_FUN_00581680` (260), `FUN_00440860` (252).
  A function called from hundreds of places is almost always a core utility,
  something like memory management, string handling, or error reporting.

- **Calls the most others (highest fan-out):** `FUN_004f26d0` (calls 138
  others), `FUN_0042d7a0` (132), `FUN_005103f0` (112). A function that calls a
  very large number of others is usually a central dispatcher or an interpreter
  loop.

### Security scans

- `ioc_scan` (indicators of compromise): nothing alarming. The "domains" and
  "email" patterns it surfaced trace back to ordinary C-library locale data, not
  to any network behavior. A SHA-256-looking string turned out to be a build
  identifier embedded in the program, not a marker of anything malicious.
- `crypto_constant_scan`: reported the presence of **MD5** based on a block of
  well-known constant values at address `0x630530`. Hold onto this result; section
  6 shows what the source revealed it to actually be.

At this stage, with no source consulted, the working theory was: a large,
self-contained command-line application built around an interpreter or virtual
machine, with at least one hashing routine compiled in, and no signs of malicious
intent.

---

## 4. Semantic analysis of individual functions

Two functions were singled out for deeper reading, one from each end of the call
graph: the most-called helper and the biggest dispatcher. The goal was to name
what each one does using only its decompiled logic and the text it references.

### FUN_0043e140, the most-called function

The decompiled logic was short and very specific:

- It first checks whether its pointer argument is null and returns immediately if
  so.
- Otherwise it decrements two separate global counters. One of the decrements
  uses a function pointer that measures the size of the block being passed in.
- It then makes a tail call to another function, reached through a function
  pointer, that does the real work.

Read in plain terms: this is a wrapper around freeing memory. It updates two
running totals (how many bytes are in use and how many allocations are
outstanding), then hands off to whatever the configured "real free" routine is.
The use of a function pointer for the actual free is a strong signal that the
program lets you swap in a custom memory allocator.

**Blind conclusion:** a public memory-free function with built-in allocation
accounting, delegating to a pluggable underlying allocator.

### FUN_004f26d0, the largest dispatcher

This function calls 138 others and references a distinctive set of text strings,
including:

- "abort due to ROLLBACK"
- "another row available"
- "no more rows available"
- "%s constraint failed"
- "cannot store %s value in %s column %s.%s"
- "sqlite_master"
- "database disk image is malformed"

The vocabulary here is unmistakable: rows, columns, constraints, rollback, a
master table, and a corrupted disk image. This is the engine of a database. A
function that calls well over a hundred helpers and speaks in this vocabulary is
the part that walks through a compiled query program one operation at a time.

**Blind conclusion:** the central execution engine of a database, the loop that
runs a prepared statement step by step. The references to a "master" table and to
on-disk corruption confirmed the program is a self-contained SQL database engine.

### Hashing routine

The crypto scan's hit at `0x630530` pointed at a block of constants used to seed
a hash. On its own, before the source check, the safe statement was: "a standard
hash function is compiled in, flagged by its initialization constants." The exact
family was left as a question to confirm in section 6, because several common hash
algorithms share these particular starting values.

---

## 5. Putting the picture together

From the blind pass alone, with no source read, the program was described as:

> A large, statically linked, command-line SQL database engine. It contains its
> own memory allocator layer with usage accounting, a virtual machine that
> executes prepared statements, and a bundled cryptographic hash routine. It
> shows no indicators of malicious behavior.

That description was written down and frozen before the source folder was opened.

---

## 6. Side by side with the source

Only after the conclusions above were locked did the comparison begin. The subject
turned out to be the SQLite command-line shell, version 3.53.2, built from the
public amalgamation source. Here is how each blind conclusion held up.

### Memory-free wrapper

**Blind conclusion:** null-check, decrement two counters (one via a size-measuring
function pointer), then delegate the real free through a function pointer.

**Source (`sqlite3_free`, the public free routine):**

```c
SQLITE_API void sqlite3_free(void *p){
  if( p==0 ) return;
  ...
  if( sqlite3GlobalConfig.bMemstat ){
    sqlite3_mutex_enter(mem0.mutex);
    sqlite3StatusDown(SQLITE_STATUS_MEMORY_USED, sqlite3MallocSize(p));
    sqlite3StatusDown(SQLITE_STATUS_MALLOC_COUNT, 1);
    sqlite3GlobalConfig.m.xFree(p);
    sqlite3_mutex_leave(mem0.mutex);
  }else{
    sqlite3GlobalConfig.m.xFree(p);
  }
}
```

This is an exact behavioral match. The null-check is the first line. The two
counters are `SQLITE_STATUS_MEMORY_USED` (decremented by the measured size, which
is the "size-measuring function pointer" seen in the decompilation) and
`SQLITE_STATUS_MALLOC_COUNT`. The real free is `sqlite3GlobalConfig.m.xFree`, a
function pointer, which is exactly why the program supports a custom allocator.
The mutex calls do not appear in the binary because this build was compiled
single-threaded, so the compiler removed them, leaving precisely the shape the
blind read described.

### Database execution engine

**Blind conclusion:** the central step-by-step execution loop of a database,
identified by its constraint, rollback, column, and corruption messages.

**Source:** the function is `sqlite3VdbeExec`, declared as
`int sqlite3VdbeExec(Vdbe*)`. In SQLite this is the bytecode interpreter that
runs a prepared statement one instruction at a time. The matched strings line up
directly:

- "cannot store %s value in %s column %s.%s" is produced inside the interpreter
  when a value fails a column type check.
- "abort due to ROLLBACK" and "another row available" are status messages tied to
  statement execution.

The identification was correct, including the role (a per-instruction
interpreter) and the reason it had the highest fan-out in the whole program.

### Hash routine, and a useful correction

**Blind conclusion:** a standard hash is present, flagged by its initialization
constants. The automated scanner labeled it **MD5**.

**Source:** the constants at the flagged location belong to **SHA-1**, not MD5:

```c
static void hash_init(SHA1Context *p){
  p->state[0] = 0x67452301;
  p->state[1] = 0xEFCDAB89;
  p->state[2] = 0x98BADCFE;
  p->state[3] = 0x10325476;
  p->state[4] = 0xC3D2E1F0;
  ...
}
```

A check of the source confirmed there is no MD5 in this program at all; the
bundled hashes are SHA-1 and SHA-3. The scanner's "MD5" label is a family-level
match rather than an exact one: MD5 and SHA-1 share the same first four magic
starting values (`0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`). SHA-1
adds a fifth (`0xC3D2E1F0`) that MD5 does not have. A scanner keyed on the first
four words will call the block "MD5"; the surrounding code and that fifth constant
identify it as SHA-1.

This is exactly the kind of nuance a side-by-side comparison exists to surface. The
scanner was right that a well-known hash with those constants is present, and right
to flag it, but the precise name needed the extra evidence. The honest reading is:
"a hash from the MD5 and SHA-1 family is present here," refined by inspection to
SHA-1.

---

## 7. Scorecard

| Blind conclusion | Verdict against source |
| --- | --- |
| Large, statically linked command-line program | Correct |
| Self-contained SQL database engine | Correct |
| Most-called function is a memory-free wrapper with accounting | Correct, it is `sqlite3_free` |
| Memory layer supports a pluggable allocator | Correct, via the `xFree` function pointer |
| Largest dispatcher is the statement execution engine | Correct, it is `sqlite3VdbeExec` |
| A standard hash is compiled in | Correct |
| That hash is MD5 (automated label) | Partially correct, actually SHA-1; same constant family |
| No indicators of malicious behavior | Correct |

Every structural and behavioral conclusion held up. The single correction was
refining an automated hash label from MD5 to SHA-1, and even that was a
near-miss caused by two algorithms sharing constants, not a wrong call about
whether crypto was present.

---

## 8. Fifteen functions mapped to their source

The two functions in section 4 were the deep dives. To show the method holds at
scale, this section takes the fifteen highest-signal functions from the call graph
(the most-called helpers and the largest dispatchers, plus the bundled hash from
the crypto scan), identifies each one blind, and then lines it up against the
source signature confirmed afterward.

Each function was presented by Vivarium only as a numbered placeholder, for example
`FUN_0043e140`. The "blind identification" column is what was concluded from the
decompiled logic and the referenced-string fingerprint alone. The "source
signature" column is the match found later in the SQLite 3.53.2 amalgamation
(file `sqlite3.c`) and the shell driver (`shell.c`).

| # | Decompiled (address) | How it surfaced | Blind identification | Source signature | Location |
| --- | --- | --- | --- | --- | --- |
| 1 | `FUN_0043e140` | fan-in 414 | free wrapper with allocation accounting, delegates through a function pointer | `void sqlite3_free(void *p)` | sqlite3.c:31858 |
| 2 | `FUN_00440860` | fan-in 252 | bounded malloc with soft-heap alarm and statistics | `static void mallocWithAlarm(int n, void **pp)` | sqlite3.c:31713 |
| 3 | `FUN_00447630` | fan-in 215 | connection free returning memory to lookaside free-lists | `void sqlite3DbFreeNN(sqlite3 *db, void *p)` | sqlite3.c:31886 |
| 4 | `FUN_00457cb0` | fan-in 189 | idempotent library init (mutex, page cache, hash tables) | `int sqlite3_initialize(void)` | sqlite3.c (decl 2010) |
| 5 | `FUN_00464af0` | fan-in 148 | connection alloc popping the lookaside free-lists | `void *sqlite3DbMallocRawNN(sqlite3 *db, u64 n)` | sqlite3.c:32110 |
| 6 | `FUN_004fc400` | fan-in 92 | statement stepper wrapping the interpreter, returns ROW or DONE | `int sqlite3_step(sqlite3_stmt*)` over `static int sqlite3Step(Vdbe *p)` | sqlite3.c:94328 |
| 7 | `FUN_004714c0` | fan-in 91 | bytecode emitter writing 24-byte op records (opcode, p1, p2, p3) | `int sqlite3VdbeAddOp3(Vdbe *p, int op, int p1, int p2, int p3)` | sqlite3.c:88021 |
| 8 | `FUN_004f26d0` | fan-out 138 | per-instruction bytecode interpreter | `int sqlite3VdbeExec(Vdbe *p)` | sqlite3.c:97321 |
| 9 | `FUN_0042d7a0` | fan-out 132 | shell dot-command dispatcher | `static int do_meta_command(const char *zLine, ShellState *p)` | shell.c:32473 |
| 10 | `FUN_005103f0` | fan-out 112 | parser grammar-rule actions (generated reduce engine) | `static YYACTIONTYPE yy_reduce(...)` | sqlite3.c:183456 |
| 11 | `FUN_005189b0` | fan-out 94 | PRAGMA handler (pragma names, foreign-key actions, integrity check) | `void sqlite3Pragma(Parse*, Token*, Token*, Token*, int)` | sqlite3.c:145083 |
| 12 | `FUN_004d59c0` | fan-out 73 | WHERE-clause planner and code generation | `WhereInfo *sqlite3WhereBegin(Parse*, SrcList*, Expr*, ExprList*, ...)` | sqlite3.c:175509 |
| 13 | `FUN_004dbe80` | fan-out 70 | recursive SELECT code generation (SCAN, MATERIALIZE, CO-ROUTINE) | `int sqlite3Select(Parse*, Select*, SelectDest*)` | sqlite3.c:156443 |
| 14 | `FUN_00402600` | fan-out 66, no callers | shell entry point and command-line flag parsing | `int main(int argc, char **argv)` | shell.c:36436 |
| 15 | hash routine at `0x630530` | crypto-constant scan | a bundled hash (the scanner labeled it MD5) | `static void hash_init(SHA1Context *p)` (SHA-1) | shell.c:~5360 |

How to read this result:

- Rows 1 through 14 were named purely from decompiled logic and string
  fingerprints, with no source open, and every one matched. The identification
  also explained why each function ranked where it did. For example,
  `sqlite3_initialize` (row 4) is called at the top of nearly every public API as a
  one-time setup guard, which is exactly why it has 189 callers.
- Row 6 is a public wrapper (`sqlite3_step`) over a static inner stepper
  (`sqlite3Step`). The decompiled body is the inner one, and it calls row 8
  (`sqlite3VdbeExec`) directly, which is how the stepper-to-interpreter
  relationship was confirmed from the binary alone.
- Rows 1, 3, 5 and 7 form a recognizable memory and code-generation core: a public
  free, a connection-aware free and its matching allocator (both keyed on the same
  lookaside free-list offsets seen in the decompilation), and the single bytecode
  emitter that the rest of code generation funnels through.
- Row 15 is the one refinement, the same MD5-to-SHA-1 correction described in
  section 6, included here so the table reflects every finding.
- Not every heavily-used function belongs to this program. Two other very
  high fan-in functions were identified as statically linked C library code
  (the system `free`, recognized by its `free(): invalid pointer` message, and a
  glibc assertion handler). They are left out of this table, which is scoped to the
  program's own source.

---

## 9. Honest notes and caveats

**Size.** The request was for a binary in the 5 to 10 MB range. A stripped, static
SQLite shell settles at about 2.6 to 3.0 MiB regardless of optimization level, and
there was no honest way to inflate it into that range without changing the build in
ways that defeat the test (see the next note). The trade made here was to keep the
test genuinely blind and the comparison clean rather than hit the size target. If a
larger subject matters more than the source comparison, a static build of OpenSSL
lands naturally in the 5 to 8 MB range and would be a good follow-up.

**Why no debug build.** An earlier attempt compiled SQLite with debugging
assertions turned on to get closer to the size target. That build was discarded
because its assertion messages embedded real function names, file names, and
internal field names directly into the binary as text. That would have leaked the
answers and made the "blind" test meaningless. The build used here has all of that
removed, which is why the analyst had to work purely from logic and from generic
error strings that exist in any release build.

**What stripping does and does not hide.** Even fully stripped, this program gave
itself away through the text it must contain to function: SQL error messages,
status strings, and the fixed constants of a standard hash. Names can be removed,
but a program's behavior and the messages it shows its users cannot. That is the
core lesson of the exercise.

**Tool labels are leads, not verdicts.** The crypto scanner's MD5 result is a good
example of using an automated finding as a starting point and confirming the
specifics by reading the code. The scan correctly drew attention to real
cryptographic constants; the exact algorithm name needed one more step.

---

## 10. Reproducing this

The subject was built from the public SQLite amalgamation with a normal release
configuration and then stripped:

```
gcc -O2 -static -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION \
    -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_RTREE -DSQLITE_ENABLE_GEOPOLY \
    -DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_DBSTAT_VTAB -DSQLITE_ENABLE_STAT4 \
    -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK \
    shell.c sqlite3.c -o sqlite3.blind -lm
strip --strip-all sqlite3.blind
```

The analysis itself used only the read-only Vivarium tools, in this order:
`session_create`, `session_import`, `session_analyze`, then `program_summary`,
`coverage`, `call_graph_metrics`, `ioc_scan`, `crypto_constant_scan`,
`decompile_function` on the two target functions, and finally `session_close`.

The source comparison was performed against the matching SQLite source, opened
only after the analysis was complete.
