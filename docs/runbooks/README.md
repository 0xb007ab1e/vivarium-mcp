# Runbooks — `ghidra-mcp`

Operational procedures, adapted to this service (`workflow-runbooks`). Runbooks are part of "done"
for a deployable service; they are validated in a drill before being relied on.

> **WS0 status:** these are **scaffolds** with the service-specific decision points filled in and
> `<...>` placeholders for commands that depend on WS2/WS3 (worker runtime, deploy). WS3 + the
> release workstream complete the commands and run the first drill.

| Runbook | When |
|---------|------|
| [`deploy.md`](deploy.md) | promote a gate-passing, digest-pinned build |
| [`rollback.md`](rollback.md) | revert a bad release |
| [`incident-response.md`](incident-response.md) | suspected worker escape / breach / outage |
| [`backup-restore.md`](backup-restore.md) | (limited) restore of config/state; sessions are ephemeral |
| [`on-call.md`](on-call.md) | alert response + escalation |
| [`scaling.md`](scaling.md) | tune the worker concurrency cap / resource limits |
| [`secret-rotation.md`](secret-rotation.md) | rotate any future credential (none in v1) |
| [`evict-poisoned-worker.md`](evict-poisoned-worker.md) | **service-specific:** evict/rotate a poisoned/hung worker |
| [`dependency-patch.md`](dependency-patch.md) | **service-specific:** patch a Ghidra/JDK/dep CVE via a digest bump |
| [`supply-chain-pinning.md`](supply-chain-pinning.md) | **service-specific (GATED):** pin base images/Ghidra/CI-actions by digest + generate the hash-pinned lockfile |
| [`http-exposure.md`](http-exposure.md) | **service-specific (v1.1):** expose the server over HTTP (loopback / UDS / network+TLS+bearer); reverse-proxy; token/TLS secret handling |

Standard structure (`_TEMPLATE`): When to use · Severity · Prerequisites/access · Steps (commands +
expected output) · Verification · Rollback/abort · Escalation · Related.
