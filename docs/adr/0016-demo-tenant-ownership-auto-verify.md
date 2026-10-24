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

SOC gating for high-scale tests (ADR-0003) is no longer enforced for any tenant; see the amendment below.

## Amendment (2026-10-24): No Execution Gates, For Any Tenant

The earlier demo-only ungating is now the global behaviour. Every check in the catalog is runnable by every tenant, and the admission gates that used to deny a start are advisory only. Nothing is restricted to the demo account any more; the demo account simply keeps its ownership auto-verify shortcut.

### Removed gates (all tenants)
1. **Input Requirements**: `port`, `port_or_declared_tcp_deny`, `port_or_declared_udp_deny`, every `declared_*` requirement, `origin_binding`, and `two_perspectives` no longer block admission. Every check reports `requires_additional_input: false` and is selectable, plannable, and scannable. When the input is genuinely absent the run is still created and finalized as `inconclusive` / `required_input_missing` (see below) instead of erroring.
2. **Hourly Safe-Run Cap**: `max_runs_per_hour` no longer denies a start. The observed count is audited as `hourly_cap` when it is exceeded.
3. **Safe Test Windows**: Safe test window closures (`safe_window_closed`, `policy_safe_window_closed`, and scan dispatch denials) no longer block execution for any tenant, not only demo. A run outside the window is audited as `safe_window`.
4. **Minimum Interval**: `min_seconds_between_runs` no longer blocks. A run inside the normal interval is audited as `min_interval`.
5. **SOC Gating**: `risk_class: 'soc_gated'` is descriptive only. High-scale and SOC-gated checks are runnable, selectable, plannable, and startable without a SOC gate block, and high-scale / offensive workflows no longer require multi-party SOC approval to execute. Bypassed SOC gating is audited as `'soc_gated'`.
6. **Feature-Flag Routes**: Route-level feature gates and service-level adapters for WAF posture, connectors, and external discovery evaluate unified per-tenant feature access helpers (`wafPostureEnabledFor`, `connectorsEnabledFor`, `externalDiscoveryEnabledFor`, `protectionValidationEnabledFor` in `src/lib/tenantFeatureAccess.mjs`). Explicit demo tenants access all route families without 404 `*_feature_disabled`.
7. **Deployment Features Alignment**: `GET /v1/tenant/deployment-features` (`getTenantDeploymentFeatures`) aligns directly to these per-tenant helpers so portal affordances match route authorization; `demo_tenant` reflects the explicit check (`isExplicitDemoTenant`).
8. **Destination Binding**: `bindProbeProfileDestinationsToTarget` no longer rewrites or refuses caller-supplied probe destinations; the profile is honoured as supplied. Only target metadata that does not match the target host is still stripped.

Every bypass that changes an outcome is audited with action `test_run.demo_gates_bypassed` and `metadata.bypassed: [...]` listing the bypassed gates (`input_requirement:<code>`, `hourly_cap`, `safe_window`, `min_interval`, `soc_gated`). The action name is retained for compatibility even though it now applies to every tenant.

### Explicit Tenant Scoping vs Wildcards
Wildcards (`*` or `all` in `ASTRANULL_DEMO_AUTO_VERIFY_TENANTS`) only apply to ownership, subscription, and auto-verify bypasses. Route-backed feature flags still require explicit tenant IDs via `isExplicitDemoTenant(tenantId, env)` or matching the demo account (`admin@demo.astranull.local`, `Astra-D1TrtI4HMTSrwKRW-9`), and never return true for a wildcard. If a wildcard is configured, a startup warning is logged.

### Gates Kept (Safety, Not Admission)
- **Kill Switch**: Active kill switch halts all execution (`kill_switch_active`).
- **Per-Check Safety Caps**: `max_events`, `max_requests`, and per-kind bounds are still enforced during a run.
- **Concurrent Run Blocker**: `concurrent_run_blocked` still prevents overlapping runs on the same target.
- **Tenant Suspension**: `tenant_suspended` lifecycle state halts execution.
- **State Sanity**: `target_group_not_found`, `target_not_found`, `unknown_check`, `missing_target_id`, and `target_kind_not_supported` still return their 4xx responses.

### Missing Input Handling (`required_input_missing`)
When a check lacks genuine required input (e.g. no declared deny rules or no service port), the run is created and immediately finalized cleanly as:
- `status: 'verdicted'`
- `verdict: 'inconclusive'`
- `explanation_reason: 'required_input_missing'`
- `explanation`: Plain message naming the missing requirement (e.g. "No denied port is declared, so there was nothing to probe.")
- `requests_sent: 0` (zero probe traffic sent; never errors).



## Production login identity correction (2026-10-19)

The public password login resolves to the authenticated stored pair `tenantId: ten_demo`, `userId: usr_admin`. Demo execution recognition now accepts that exact pair, including the snake-case session form, rather than requiring an email-shaped user ID or a legacy synthetic tenant ID. Neither `ten_demo` alone nor `usr_admin` in another tenant grants the account exception. The existing explicit tenant allowlist continues to apply independently.

Deployment-feature projection and both dev-store/PostgreSQL run admission pass the authenticated context through demo recognition and policy normalization. The bypass audit remains attached to request-marker runs. The kill switch, suspension, concurrent-run guard and per-check traffic ceilings remain enforced. High-scale catalog entries still use request markers; no traffic generator or governed adapter bypass is introduced.

The browser regression uses the actual production tenant/user pair and submits exactly the 6 exploit, 7 delivery-pattern and 5 high-scale definitions. Separate regressions check other users/tenants, all 18 individual starts, audit records and the production PostgreSQL admission path. No schema migration or API shape changes are required.
