# Seccomp profiles — Ghidra worker isolation (ADR-004)

ADR-004 mandates **seccomp `RuntimeDefault`** for the worker, **verified to load** (not assumed).
This directory documents how that is satisfied and provides an optional stricter profile.

## Default (mandatory) — `RuntimeDefault`

`deploy/` applies the container runtime's built-in default seccomp profile, which blocks the
~44 dangerous syscalls (e.g. `mount`, `ptrace`, `reboot`, `kexec_load`, `bpf`, `clock_settime`,
`unshare` of dangerous namespaces) while allowing the broad set a normal JVM workload needs.

- **podman:** the default profile applies automatically unless overridden. It is sourced from
  `/usr/share/containers/seccomp.json`. We pass it explicitly so the control is **visible and
  auditable** (`--security-opt seccomp=RuntimeDefault` in `deploy/worker-run.sh`).
- **Verification (ADR-004 acceptance criterion):** `deploy/verify-isolation.sh` asserts seccomp is
  active inside the worker by reading `/proc/1/status` → `Seccomp:` field MUST be `2` (filter mode).
  A value of `0` (disabled) FAILS the check. This proves the profile actually loaded.

## Stronger (optional) — `worker-seccomp.json`

`worker-seccomp.json` is a tighter, **default-deny (`SCMP_ACT_ERRNO`)** allow-list scoped to what a
headless Ghidra JVM doing offline analysis actually needs. It explicitly denies networking syscalls
beyond `socket(AF_UNIX)` (the worker's only legitimate socket use is its UDS) as defense-in-depth
on top of `--network=none`.

> **Tuning caveat (ADR-004):** the JVM + gVisor combination touches a wide syscall surface; a custom
> profile can break the JVM in subtle ways. The custom profile is **opt-in** and must be validated
> with `deploy/verify-isolation.sh` + a full import→analyze→decompile smoke test against a synthetic
> binary BEFORE it replaces `RuntimeDefault`. Until validated, `RuntimeDefault` is the baseline.

Apply the stronger profile only after validation:

```
--security-opt seccomp=infra/seccomp/worker-seccomp.json
```

## With gVisor (`runsc`)

gVisor itself intercepts and re-implements syscalls in user space, providing a second, independent
syscall boundary. seccomp + gVisor are complementary (defense in depth): seccomp filters what
reaches the gVisor sentry; gVisor isolates what the sentry forwards to the host kernel.
