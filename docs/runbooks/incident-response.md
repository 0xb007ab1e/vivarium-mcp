# Runbook: Incident Response

> Rules: `@rules/workflow-incident-response.md`. SCAFFOLD — contacts/commands finalized in WS3.

## When to use
- Suspected **worker sandbox escape / compromise**, evidence of exploitation, data exposure, or a
  major outage. When in doubt, declare.

## Severity / impact
- Suspected escape/compromise or artifact exposure → **SEV1**. Contained single-worker poisoning
  with no escape → SEV2/3 (often just `evict-poisoned-worker.md`).

## Prerequisites & access
- Incident channel: GitHub (issues / Security Advisory); paging; access to server + worker logs and the container runtime;
  break-glass location. Anyone may declare.

## Steps
1. **Declare** + open the channel; assign Incident Commander + scribe; start a timeline.
2. **Assess** scope from telemetry (`topic-logging-observability`); map to threat-model TBs and
   ATT&CK techniques where useful; set severity.
3. **Preserve evidence FIRST** on a suspected escape: capture worker logs + a container snapshot (`podman inspect <worker-cid>` + `podman diff <worker-cid>`, or the configured engine)
   before killing (the worker is otherwise wiped on evict).
4. **Contain:** evict the affected session(s) (kill worker + verified-wipe — `evict-poisoned-worker.md`);
   if systemic, stop accepting new sessions / take the server offline; isolate the host if escape is
   confirmed. v1 has no secrets to rotate (note any future creds).
5. **Eradicate:** if the vector is a Ghidra/JDK/dep CVE → `dependency-patch.md` (digest bump);
   if a code/validation bug → patch + regression test.
6. **Recover:** redeploy known-good (`rollback.md`/`deploy.md`), verify, monitor for recurrence.
7. Honor any breach-notification duties + timelines (`std-privacy` if personal data ever involved —
   not expected in v1).

## Verification
- Attacker access revoked; affected sessions gone + stores wiped; systems healthy; monitoring shows
  no recurrence.

## Post-incident
- Blameless post-mortem within a few days: timeline, root cause, tracked action items. Feed gaps
  back into the threat model + abuse tests (WS4). Update this runbook.

## Related
- `evict-poisoned-worker.md`, `dependency-patch.md`, `rollback.md`; threat model.

---
_Status: scaffold (pre-1.0) — deploy/promote commands pending WS3 tooling; not yet drill-validated. Owner: repo maintainer (solo — no formal on-call rotation pre-1.0)._
