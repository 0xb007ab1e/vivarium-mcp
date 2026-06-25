# Runbook: Secret Rotation

> Rules: `@rules/workflow-secrets.md`. SCAFFOLD.

## When to use
- Rotating a credential on schedule, suspected exposure, or personnel change.

## Scope note (this service)
- **v1 has NO runtime secrets** (single stdio process, no network, no auth boundary, no outbound
  credentials). There is nothing to rotate in v1.
- This runbook is a placeholder for **v1.1+**, when the HTTP transport (ADR-006) or any outbound
  integration introduces a credential. At that point credentials come from the secret manager at
  runtime (never committed), and rotation follows the standard add-new-before-revoke-old flow.

## Steps (v1.1+, when a secret exists)
1. Generate the new credential in the secret manager: `<cmd>`.
2. Provision it alongside the old (dual-valid window): `<cmd>`.
3. Roll out to consumers (deploy/hot-reload): `<cmd>`; verify adoption in logs.
4. Revoke the old credential: `<cmd>` (for a confirmed compromise, revoke FIRST).

## Verification
- Consumers authenticate with the new secret; the old is rejected; no auth-error spike.

## Escalation
- Confirmed exposure → run under `incident-response.md`; page security.

## Related
- `incident-response.md`; `@rules/workflow-secrets.md`; ADR-006 (HTTP v1.1).

---
_Status: scaffold (pre-1.0) — deploy/promote commands pending WS3 tooling; not yet drill-validated. Owner: repo maintainer (solo — no formal on-call rotation pre-1.0)._
