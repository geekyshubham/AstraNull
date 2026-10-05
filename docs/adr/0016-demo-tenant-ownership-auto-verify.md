# ADR-0016: Demo Tenant Ownership Auto-Verify

## Status

Accepted. Requested by the product owner for the demo account (`admin@demo.astranull.local`, tenant `ten_demo`), explicitly including production deployments.

## Context

Live probes only reach a target after the customer proves control of it (DNS TXT, provider account, or confirmed attestation). Demos need to show detection on domains the demo tenant cannot prove ownership of.

## Decision

Tenants listed in `ASTRANULL_DEMO_AUTO_VERIFY_TENANTS` (comma separated) have every new target recorded as verified at creation:

| Field | Value |
|---|---|
| `state` | `user_confirmed` |
| `source_kind` | `manual_override` |
| `source_ref` | `{ "method": "demo_auto_verify", "demo": true }` |
| Audit action | `target.ownership_demo_auto_verified` |

The row is written in the same transaction as the target, on every creation path (direct, group add, CSV import, bulk import) in both the dev store and Postgres. The portal labels it **Verified (demo)**. Existing targets are covered with:

```bash
ASTRANULL_DEMO_AUTO_VERIFY_TENANTS=ten_demo node scripts/demo-auto-verify-backfill.mjs --tenant-id ten_demo
```

The variable is unset by default. It is scoped per tenant, not per user, because ownership is tenant-scoped.

## Consequences

| Positive | Negative |
|---|---|
| Demos can run detection on any domain. | The demo tenant can send live safe probes to domains nobody proved control of, including in production. |
| Every shortcut row is audited and labeled, so it is never mistaken for real proof. | Anyone with demo tenant credentials inherits this power. Rotate demo credentials and keep the tenant allowlist to demo tenants only. |
| No schema change: uses existing `user_confirmed` / `manual_override` values. | Removing a tenant from the variable does not revoke rows already written; remove them or re-verify. |

SOC gating for high-scale tests (ADR-0003) is unchanged.
