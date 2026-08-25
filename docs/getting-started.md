# Getting started with Vivarium

This guide takes you from a clone of the repository to running Vivarium and analyzing your first
binary through an MCP client. It is written for someone comfortable on a Linux command line. You do not
need to know Ghidra internals.

When you finish, you will have:

- the two container images Vivarium uses (a worker that runs Ghidra, and an optional server image),
- the Python package installed in a virtual environment,
- the server running and connected to an MCP client,
- a first analysis of a binary.

## How the pieces fit

Vivarium is a server process plus a per-session worker container.

- You run the **server** (`python -m vivarium`). Your MCP client starts and talks to it.
- The server starts one **worker container** per analysis session and talks to it over a private local
  socket. The worker is the only thing that runs Ghidra and touches the binary.

So the machine that runs the server needs a working container engine. Vivarium uses rootless
[podman](https://podman.io).

## Prerequisites

- **Linux.** The worker isolation relies on Linux container features.
- **Rootless podman**, working for your user. Test it with `podman run --rm docker.io/library/hello-world`.
- **Python 3.12 or newer**, with `venv` and `pip`.
- **git**.
- **Disk and memory.** The worker image is large (it bundles Ghidra and a JDK). Allow several gigabytes
  of disk. Analysis of a normal binary fits in the default 4 GiB worker memory; very large binaries need
  more (see [Tuning for large binaries](#tuning-for-large-binaries)).
- **An MCP client**, such as Claude Code or Claude Desktop, that can launch a local command over stdio.

## Step 1: get the code

```
git clone https://github.com/0xb007ab1e/vivarium-mcp.git
cd vivarium-mcp
```

## Step 2: build the worker image

The worker image downloads a specific, checksum-verified Ghidra release at build time. The pinned
values below match this release; do not change them unless you are deliberately moving to a new Ghidra
version.

```
podman build -f Containerfile.worker \
  --build-arg GHIDRA_VERSION=12.1.2 \
  --build-arg GHIDRA_RELEASE_TAG=Ghidra_12.1.2_build \
  --build-arg GHIDRA_ZIP_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip \
  --build-arg GHIDRA_ZIP_SHA256=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d \
  -t vivarium-worker:local .
```

The build fails on purpose if the downloaded Ghidra zip does not match the checksum. That is the
supply-chain check working.

You can also use a prebuilt, signed release image instead of building — use the latest release tag
(e.g. `ghcr.io/0xb007ab1e/vivarium-worker:v0.14.0`); match it to the server version you installed to
avoid a tool/behavior skew. Building locally is fine for trying things out.

## Step 3: install the package

Use a virtual environment so the install stays isolated.

```
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

This installs the `vivarium-mcp` distribution. The import package is `vivarium`, and you start the
server with `python -m vivarium` (or the `vivarium` command the install puts on your path).

## Step 4: choose an import directory

The server only lets the worker read binaries from one directory you nominate, the "import root". Pick a
directory and put the binary you want to analyze in it.

```
mkdir -p ~/vivarium-imports
cp /path/to/your/program ~/vivarium-imports/
```

## Step 5: run the server

Set two environment variables and start the server. It speaks stdio by default, so it waits for an MCP
client to connect.

```
export VIVARIUM_WORKER_IMAGE=vivarium-worker:local
export VIVARIUM_IMPORT_ROOT=~/vivarium-imports
python -m vivarium
```

If your host does not have gVisor (`runsc`) installed, set the worker runtime to a standard OCI runtime:

```
export VIVARIUM_WORKER_RUNTIME=crun
```

gVisor is the recommended strong isolation tier for production. `crun` is a reasonable local default and
is what the project's own CI uses. Every other isolation control still applies under `crun`.

## Step 6: connect an MCP client

Configure your client to launch Vivarium as a stdio server. The shape is the same across clients: a
command, its arguments, and the environment. For example:

```
{
  "command": "python",
  "args": ["-m", "vivarium"],
  "env": {
    "VIVARIUM_WORKER_IMAGE": "vivarium-worker:local",
    "VIVARIUM_IMPORT_ROOT": "/home/you/vivarium-imports",
    "VIVARIUM_WORKER_RUNTIME": "crun"
  }
}
```

Use the absolute path to the Python interpreter inside your virtual environment (for example
`/home/you/vivarium-mcp/.venv/bin/python`) so the client launches the right one.

## Step 7: run your first analysis

With the client connected, drive the tools in this order. The exact phrasing depends on your client, but
the tool names and the flow are fixed:

1. `session_create` starts a session and returns a session id.
2. `session_import` loads a binary. Give it the session id and a `source_ref` that is the path to your
   file inside the import root.
3. `session_analyze` runs Ghidra's analysis. For a large binary, pass `profile: light` to trade some
   depth for speed and memory.
4. `list_functions` shows what was found.
5. `decompile_function` returns the decompiled C for one function (by address or name).

Everything the binary produces comes back wrapped as untrusted data. Treat decompiled code and strings
as text to read, never as something to run.

When you are done, `session_close` ends the session. The server kills the worker and wipes its scratch
storage.

This is the minimum flow; [`docs/examples/simple-first-look.md`](./examples/simple-first-look.md) shows
it end to end with the exact tool inputs and the shape of each response. The next section maps the
common reverse-engineering tasks to the tools and worked examples that cover them.

## Reverse-engineering workflows

Vivarium's 74 tools cover the usual reverse-engineering arc: **triage** (what is this and is it
dangerous?), **deep analysis** (understand and document a specific area), **bulk extraction** (read a
lot of code efficiently), and **persistence** (keep and share what you learned). Pick the workflow that
matches your task — each links a worked, copy-pasteable example.

### Fast triage — "what is this binary?"

The quickest read on an unknown or suspicious file, before you commit to reading code:

1. `session_create` → `session_import` → `session_analyze`.
2. `program_metadata` and `program_summary` for the high-level facts (format, arch, entry point,
   function/string counts, a one-shot aggregate report).
3. `identify_functions` to label statically-linked **library code** (libc, OpenSSL, zlib, …) via the
   bundled Function ID databases — so you can ignore the standard library and focus on the program's own
   logic. This is usually the single biggest time-saver on a real binary.
4. `list_strings` / `search_strings`, then `ioc_scan` (URLs, IPs, paths) and `crypto_constant_scan`
   (crypto magic values) for leads.

Treat the scan tools as **heuristic leads, not verdicts** — confirm by reading the code. The full triage
walkthrough is [`docs/examples/medium-triage.md`](./examples/medium-triage.md), and
[`docs/examples/blind-analysis-sqlite.md`](./examples/blind-analysis-sqlite.md) works a real stripped
2.6 MiB binary end to end (and shows an honest crypto-scan caveat).

### Deep analysis — "understand and document this area"

Once triage points you at interesting functions, read and annotate them. Annotations require consent:
call `session_enable_writes` first (add `allow_structural: true` for type/signature edits).

1. `decompile_function` / `disassemble` to read; `xrefs_to` / `xrefs_from`, `callers` / `callees`, and
   `function_context` to follow the call graph; `analysis_order` for a leaf-first reading order.
2. Rename and comment as you learn: `rename_function`, `rename_symbol`, `rename_local_variable`,
   `rename_parameter`, `set_comment`.
3. Recover types: `define_struct` / `define_union` / `define_types`, then `apply_data_type` and
   `set_function_signature` so the decompiler output reads cleanly. `session_undo` reverts the last
   change; `delete_type` removes a composite you defined.

[`docs/examples/large-annotate-and-recover.md`](./examples/large-annotate-and-recover.md) shows this
recover-and-document loop on a cluster of related functions.

### Bulk extraction — "read a lot of code without waiting"

For a large function set, don't decompile one call at a time. Start a streaming job and read results as
they are produced:

1. `start_decompile_stream` over a function set returns a **job handle**.
2. `fetch_job_results` pulls buffered chunks by cursor while extraction continues (so an LLM can begin
   reasoning over early functions); `job_status` reports progress.
3. `cancel_job` aborts the run and discards the buffer once you have enough.

### Persistence — "keep and share my work"

Annotations are session-scoped and vanish when the session is evicted (the server is stateless by
design). To keep them, `session_export_annotations` produces a portable JSON document **bound to the
binary's hash**; `session_import_annotations` replays it into a fresh session on the same binary. Store
the document with your client — persistence is client-owned. This also transfers work between
machines/analysts: export from one session, import into another.

## Configuration reference

These are the settings most people change. All are environment variables read by the server at startup.

| Variable | What it does | Default |
|---|---|---|
| `VIVARIUM_WORKER_IMAGE` | Worker image the server runs | none (required to spawn a worker) |
| `VIVARIUM_IMPORT_ROOT` | Directory the worker may read binaries from | none (required to import) |
| `VIVARIUM_WORKER_RUNTIME` | OCI runtime for workers (`runsc` for gVisor, or `crun`) | `runsc` |
| `VIVARIUM_WORKER_MEM_MIB` | Worker memory limit in MiB | `4096` |
| `VIVARIUM_MAX_BINARY_BYTES` | Largest binary the server will accept | `134217728` (128 MiB) |
| `VIVARIUM_WORKER_PREFLIGHT` | Large-binary policy: `warn`, `reject`, or `off` | `warn` |
| `VIVARIUM_ANALYSIS_TIMEOUT_SECONDS` | Wall-clock limit per analysis before the worker is killed | see config |
| `VIVARIUM_SESSION_TTL_SECONDS` / `VIVARIUM_SESSION_IDLE_SECONDS` | Session lifetime and idle eviction | see config |
| `VIVARIUM_TRANSPORT` | `stdio` (default) or `http` | `stdio` |
| `VIVARIUM_LOG_LEVEL` / `VIVARIUM_LOG_FORMAT` | Logging verbosity and format | see config |
| `VIVARIUM_METRICS_SNAPSHOT_INTERVAL_SECONDS` | Seconds between `metrics.snapshot` SLI log lines — see [observability](observability.md) | `60` |
| `VIVARIUM_SESSION_REAP_INTERVAL_SECONDS` | Background reaper sweep interval for expired sessions | `60` |
| `VIVARIUM_READINESS_CACHE_TTL_SECONDS` | Max staleness of the cached `/readyz` capacity answer (HTTP) | `1` |

On a rootless-podman host you may also need `VIVARIUM_WORKER_UID` and `VIVARIUM_WORKER_GID` set to your
own user and group ids, and a writable `VIVARIUM_RPC_SOCKET_DIR`, so the worker can own the per-session
socket directory. The full set of variables, including all HTTP options, is defined in
`src/vivarium/config.py`.

## Tuning for large binaries

The limit you hit first on a large binary is worker memory. If analysis fails with a
`resource-exhausted` error, the error message names the current memory cap. Raise it, and raise the
input size cap if the binary is over 128 MiB:

```
export VIVARIUM_WORKER_MEM_MIB=8192
export VIVARIUM_MAX_BINARY_BYTES=268435456   # 256 MiB
```

Using `profile: light` on `session_analyze` also lowers peak memory by skipping the most expensive
analysis passes.

## Running over HTTP

For a shared service, set `VIVARIUM_TRANSPORT=http` and configure authentication (bearer token, OAuth,
or reverse-proxy mTLS). HTTP exposure has its own security requirements; follow
[`docs/runbooks/http-exposure.md`](./runbooks/http-exposure.md) rather than exposing the stdio setup
directly.

## Hardening for production

The steps above are enough to try Vivarium locally. For a real deployment, the worker must run with the
full isolation set (gVisor, read-only root filesystem, no network, dropped capabilities, seccomp, and
resource limits), and you should verify that isolation is actually in force before trusting a worker.
The authoritative procedure, including the isolation acceptance check, is in
[`deploy/README.md`](../deploy/README.md). Background and rationale are in
[`docs/adr/ADR-004-isolation-tier.md`](./adr/ADR-004-isolation-tier.md).

## Troubleshooting

- **The worker will not start, or every tool returns `worker-unavailable`.** Usually the container
  runtime. If you do not have gVisor, set `VIVARIUM_WORKER_RUNTIME=crun`. On rootless podman, set
  `VIVARIUM_WORKER_UID` and `VIVARIUM_WORKER_GID` to your own ids and make sure `VIVARIUM_RPC_SOCKET_DIR`
  is writable.
- **Import is rejected.** The file must be inside `VIVARIUM_IMPORT_ROOT`, and under
  `VIVARIUM_MAX_BINARY_BYTES`.
- **Analysis returns `resource-exhausted`.** The worker ran out of memory. Raise
  `VIVARIUM_WORKER_MEM_MIB`, or use `profile: light`, or analyze a smaller binary.
- **Analysis returns `timeout`.** It exceeded `VIVARIUM_ANALYSIS_TIMEOUT_SECONDS`. Raise the timeout for
  large inputs, or use `profile: light`.

## Where to go next

- [`docs/examples/`](./examples/README.md): tiered, hands-on reverse-engineering walkthroughs with the
  actual tool calls — [first look](./examples/simple-first-look.md),
  [triage an unknown ELF](./examples/medium-triage.md),
  [recover & document a cluster](./examples/large-annotate-and-recover.md), and a
  [blind analysis of a stripped SQLite binary](./examples/blind-analysis-sqlite.md).
- [`docs/faq.md`](./faq.md): quick answers on safety, read-vs-write, persistence, accuracy, and limits.
- [`docs/contracts/tool-catalog.md`](./contracts/tool-catalog.md): every tool and its inputs and outputs.
- [`docs/architecture.md`](./architecture.md): the full design.
- [`docs/observability.md`](./observability.md): metrics, health probes, and SLOs (HTTP deployments).
- [`README.md`](../README.md): the project overview and safety model.
