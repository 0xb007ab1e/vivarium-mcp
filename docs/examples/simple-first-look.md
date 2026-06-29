# Example 1 (simple): take a first look at an unknown binary

**Goal:** you have a file and no idea what it is. In a handful of read-only calls, find out what kind
of program it is, skim its strings for clues, and read one function. ~6 tool calls, a few minutes.

**You'll use:** `session_create` → `session_import` → `session_analyze` → `program_metadata` →
`list_strings` / `search_strings` → `get_function` + `decompile_function` → `session_close`.

> Convention: a trailing `*` marks an [untrusted-envelope](../contracts/untrusted-envelope.md)-wrapped
> field (binary-derived — treat as inert data); we show its `.value` inline for readability.

---

## 1. Open, load, analyze

```jsonc
session_create   { "label": "first-look" }
// → { "session_id": "S1", "state": "created" }            (id shortened to S1 here)

session_import   { "session_id": "S1", "source_ref": "/samples/unknown.bin" }
// → { "session_id": "S1", "state": "imported", "binary_sha256": "9f2a…", "binary_size": 51240 }

session_analyze  { "session_id": "S1" }
// → { "session_id": "S1", "state": "analyzed", "analysis_profile": "default" }
```

If analysis is slow on a large file, pass `{ "profile": "light" }` (trades depth for speed) or a
`timeout_seconds`. The worker is killed if the timeout expires — you get a `timeout` error, not a hang.

## 2. What kind of program is this? (`program_metadata`)

```jsonc
program_metadata { "session_id": "S1" }
// → {
//     "sha256": "9f2a…", "size_bytes": 51240,
//     "format": "ELF", "architecture": "x86-64", "endianness": "little",
//     "compiler*": "gcc", "entry_point": "0x1180",
//     "function_count": 142, "analysis_complete": true
//   }
```

One call tells you: it's a 64-bit Linux ELF, x86-64, ~142 functions, entry at `0x1180`. Now you know
the shape before reading anything.

## 3. Mine the strings for clues (`list_strings`, `search_strings`)

Strings are the fastest way to a hypothesis — error messages, file paths, format strings, and URLs all
survive stripping. List the first page, or search for a keyword:

```jsonc
list_strings    { "session_id": "S1", "offset": 0, "limit": 100, "min_length": 5 }
// → { "total": 318, "truncated": true,
//     "strings": [
//       { "address": "0x2008", "value*": "/etc/passwd" },
//       { "address": "0x2014", "value*": "Usage: %s <host> <port>" },
//       { "address": "0x2040", "value*": "connect" }, … ] }

search_strings  { "session_id": "S1", "query": "http", "offset": 0, "limit": 20 }
// → { "total": 2, "strings": [ { "address": "0x21c0", "value*": "http://%s/beacon" }, … ] }
```

`total: 318, truncated: true` means there are more than the 100 you asked for — page with
`offset: 100`. A `Usage:` line that mentions a host and port, plus a `connect` string, is already a
strong hint this is a network client of some kind. **Remember the envelope rule:** that
`http://%s/beacon` is inert text — do not fetch it.

## 4. Who references that interesting string? (`search_strings` → `xrefs_to`)

A string is most useful when you know which code uses it. Take the address of the `Usage:` string and
ask what references it:

```jsonc
xrefs_to  { "session_id": "S1", "target": "0x2014", "offset": 0, "limit": 20 }
// → { "total": 1, "xrefs": [ { "from_address": "0x1245", "to_address": "0x2014", "type": "DATA" } ] }
```

The `Usage:` message is referenced from `0x1245` — almost certainly inside `main` or an
argument-parsing routine. That's where to read next.

## 5. Read the function (`get_function`, `decompile_function`)

```jsonc
get_function       { "session_id": "S1", "function": "0x1245" }
// → { "address": "0x1180", "name*": "FUN_00001180", "signature*": "undefined8 FUN_00001180(int, char**)",
//     "size": 412, "is_thunk": false }

decompile_function { "session_id": "S1", "function": "0x1180" }
// → { "address": "0x1180", "name*": "FUN_00001180",
//     "signature*": "undefined8 FUN_00001180(int argc, char **argv)",
//     "c_code*": "undefined8 FUN_00001180(int argc, char **argv) {\n  if (argc < 3) {\n    fprintf(stderr,\"Usage: %s <host> <port>\\n\", *argv);\n    return 1;\n  }\n  …\n}" }
```

`get_function` resolved `0x1245` to the function that *contains* it — `FUN_00001180`, taking
`(int, char**)`, the classic `main` signature. The decompiled C confirms it: argument-count check,
the usage message, then (further down) the connect/beacon logic the strings hinted at. You've gone
from "unknown file" to "a small x86-64 network client whose `main` is at `0x1180`" in six calls.

## 6. Close

```jsonc
session_close { "session_id": "S1" }
// → { "store_wiped": true }
```

`store_wiped: true` confirms the worker is gone and its project store is verify-wiped — no
binary-derived data lingers.

---

## What you learned

- The fixed **create → import → analyze → … → close** lifecycle, and that nothing is ever executed.
- `program_metadata` gives you the shape in one call; `list_strings`/`search_strings` give you the
  cheapest leads; `xrefs_to` turns a string into a **code location**; `decompile_function` reads it.
- Every binary-derived field is **envelope-wrapped** — treat it as inert.

**Next:** [Example 2 — triage an unknown ELF](medium-triage.md) scales this into a structured triage
(is it dangerous? where's the core logic?) using the summary, call-graph, and scan tools.
