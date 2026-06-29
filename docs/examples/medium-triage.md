# Example 2 (medium): triage an unknown ELF

**Goal:** you've been handed an unfamiliar binary and need to answer, with evidence, three questions:
**what is it, is it dangerous, and where is the interesting code?** This is the workflow you'd run on
a sample before deciding whether it deserves a deep dive. ~10–12 read-only calls.

**You'll use:** `program_summary` (the one-call overview) → `coverage` → `call_graph_metrics` →
`identify_functions` (library-function ID) → `ioc_scan` + `crypto_constant_scan` → `list_imports` →
`function_context` on the hot functions → `xrefs_to` to follow a lead.

> All read-only — nothing about the program changes. `*` = [untrusted-envelope](../contracts/untrusted-envelope.md)-wrapped.
> Assume `session_create` / `session_import` / `session_analyze` already ran (Example 1) and the
> session id is `S2`.

---

## 1. One call for the whole picture (`program_summary`)

`program_summary` rolls metadata + counts + coverage + call-graph metrics + the triage scans into a
single response — start here, then drill in:

```jsonc
program_summary { "session_id": "S2", "max_complex_functions": 5, "max_iocs": 10, "include_call_graph": true }
// → {
//     "metadata": { "format": "ELF", "architecture": "x86-64", "compiler*": "gcc", "entry_point": "0x4048a0" },
//     "function_count": 1240, "import_count": 38, "export_count": 1, "string_count": 902,
//     "coverage": { "code_ratio": 0.68, "data_ratio": 0.14, "undefined_bytes": 81120 },
//     "call_graph_metrics": { "edge_count": 4310, "leaf_count": 402, "root_count": 511,
//                             "recursive_component_count": 7,
//                             "top_fan_in": [ { "address": "0x402a10", "name*": "FUN_00402a10", "count": 196 }, … ],
//                             "top_fan_out": [ { "address": "0x4051c0", "name*": "FUN_004051c0", "count": 88 }, … ] },
//     "top_complex_functions": [ { "address": "0x4051c0", "name*": "FUN_004051c0", "complexity": 142 }, … ],
//     "ioc_counts": [ { "category": "ipv4", "count": 3 }, { "category": "url", "count": 1 } ],
//     "crypto_algorithms": [ "AES", "base64" ]
//   }
```

Read this top-down:
- **38 imports, 1 export** → a dynamically-linked *application* (not a library). The import list will
  name the OS facilities it uses.
- **`code_ratio` 0.68** → most of the analyzed space is recognized code; analysis is healthy.
- **`top_fan_in`** (most-*called*) → core utilities (memory, string, error helpers). **`top_fan_out`**
  (calls-the-most) → dispatchers / main loops. These two lists are your "read these first" shortlist.
- **`ioc_counts`** flags 3 IPv4 + 1 URL, **`crypto_algorithms`** flags AES + base64 → worth a closer
  look, but these are **heuristic leads, not verdicts** (see step 4).

## 2. Identify the library code so you can ignore it (`identify_functions`)

Most functions in a typical binary are *library* code (libc, crypto, compression). Vivarium runs
Ghidra's FunctionID service to label them, so you can focus on the program's *own* logic:

```jsonc
identify_functions { "session_id": "S2", "limit": 200, "min_score": 12 }
// → { "total": 71, "truncated": false,
//     "matches": [
//       { "address": "0x44e120", "matched_name*": "deflate", "library*": "zlib 1.3.1 x86-64", "score": 38 },
//       { "address": "0x44a300", "matched_name*": "EVP_DecryptUpdate", "library*": "openssl 3.x x86-64", "score": 31 },
//       { "address": "0x402a10", "matched_name*": "malloc", "library*": "musl 1.2.5 x86-64", "score": 27 }, … ] }
```

71 functions are now identified as zlib / OpenSSL / musl libc. Two payoffs: (1) the high-fan-in
`0x402a10` from step 1 is just `malloc` — not interesting; cross it off. (2) the presence of **OpenSSL
`EVP_DecryptUpdate`** corroborates the `crypto_algorithms: ["AES"]` lead with a *named* function. A FID
match is a **best-effort hint** (a function can match several candidates) — `matched_name`/`library`
are envelope-wrapped — but it dramatically narrows the field.

## 3. What OS facilities does it use? (`list_imports`)

```jsonc
list_imports { "session_id": "S2", "offset": 0, "limit": 100 }
// → { "total": 38, "imports": [
//      { "name*": "socket",  "library*": "libc.so.6" }, { "name*": "connect", "library*": "libc.so.6" },
//      { "name*": "fork",    "library*": "libc.so.6" }, { "name*": "execve",  "library*": "libc.so.6" },
//      { "name*": "open",    "library*": "libc.so.6" }, { "name*": "inet_pton", … }, … ] }
```

`socket`/`connect`/`inet_pton` → it talks to the network. `fork`/`execve` → it spawns processes. With
the AES/base64 crypto and the 3 IPv4 + 1 URL IOCs, a hypothesis is forming: **a networked program that
encrypts traffic and can run commands.** That profile warrants care — keep triaging.

## 4. Treat the scans as leads, then confirm (`ioc_scan`, `crypto_constant_scan`, `xrefs_to`)

The scans point; *you* confirm by reading code. Pull the actual IOC values and the crypto findings:

```jsonc
ioc_scan { "session_id": "S2", "offset": 0, "limit": 10, "categories": ["ipv4","url"] }
// → { "total": 4, "matches": [
//      { "category": "url",  "value*": "http://203.0.113.10/x", "source_address": "0x49a0c8" },
//      { "category": "ipv4", "value*": "203.0.113.10", "source_address": "0x49a0d0" }, … ] }

crypto_constant_scan { "session_id": "S2", "offset": 0, "limit": 10 }
// → { "total": 1, "findings": [ { "algorithm": "AES", "kind": "sbox", "address": "0x498200" } ] }
```

Now turn a lead into a code location — who *uses* that URL?

```jsonc
xrefs_to { "session_id": "S2", "target": "0x49a0c8", "offset": 0, "limit": 20 }
// → { "total": 1, "xrefs": [ { "from_address": "0x405310", "to_address": "0x49a0c8", "type": "DATA" } ] }
```

The hardcoded URL is referenced from `0x405310`. Read that function next (step 5). **Caveat the IOCs
honestly:** `ioc_scan`/`crypto_constant_scan` are heuristic — an "IP" might be version data, an AES
s-box might be a lookup table that merely *looks* like one. The blind-SQLite example shows a real case
where the crypto scanner said "MD5" but the constants were actually SHA-1. Confirm by reading.

## 5. Read the hot functions with full context (`function_context`)

Rather than `decompile_function` in isolation, `function_context` bundles the decompilation **plus**
its callees, callers, and the strings it references — everything you need to name it in one call:

```jsonc
function_context { "session_id": "S2", "function": "0x405310", "include_decompilation": true,
                   "max_callees": 20, "max_callers": 10, "max_strings": 20 }
// → {
//     "address": "0x405310", "name*": "FUN_00405310",
//     "signature*": "void FUN_00405310(void)",
//     "callees": [ { "address": "0x44e120", "name*": "deflate" }, { "address": "0x405880", "name*": "FUN_00405880" }, … ],
//     "callers": [ { "address": "0x4061f0", "name*": "FUN_004061f0" } ],
//     "referenced_strings*": [ "http://203.0.113.10/x", "POST %s HTTP/1.1", "User-Agent: %s" ],
//     "decompilation*": "void FUN_00405310(void) { … snprintf(buf,…,\"POST %s HTTP/1.1\",…); …connect(…); …EVP_EncryptUpdate(…); … }"
//   }
```

The evidence converges: this function builds an HTTP `POST`, opens a socket, and runs the payload
through OpenSSL encryption — a **beaconing / C2 client**. You reached that with no execution, from
strings + imports + FID + one contextual decompile.

## 6. Optional: rank what to read next (`call_graph_metrics` / `analysis_order`)

To plan a deeper pass, `call_graph_metrics`'s `top_fan_in`/`top_fan_out` (step 1) is the quick ranking;
for a *cluster* you intend to fully reverse, `analysis_order` returns functions in **leaf-first**
order (helpers before the code that calls them) — that's the entry point to Example 3.

---

## What you learned

- **`program_summary` first** — one call frames the whole binary; everything else drills into it.
- **`identify_functions` (FID)** separates library noise from the program's own code — the single
  biggest time-saver on a real binary.
- The **scans are leads, not verdicts** — `ioc_scan`/`crypto_constant_scan` point; `xrefs_to` +
  `function_context` let you *confirm* by reading. Triage is evidence, not the tool's say-so.
- You profiled a likely C2 client — type, capabilities, and the exact beacon function — entirely
  read-only.

**Next:** [Example 3 — recover & document a cluster](large-annotate-and-recover.md) turns this
understanding into durable, shareable annotations using the gated write path.
