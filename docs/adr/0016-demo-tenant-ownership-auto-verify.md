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

## Amendment (2026-10-14): Ungated Demo Validation Execution

For demo tenants (`isDemoAutoVerifyTenant`, configured via `ASTRANULL_DEMO_AUTO_VERIFY_TENANTS`), customer-runnable checks run without input requirements, safe windows, or production hourly rate limits.

### Newly Bypassed Gates
1. **Input Requirements**: Bypasses `port`, `port_or_declared_tcp_deny`, `port_or_declared_udp_deny`, every `declared_*` requirement, `origin_binding`, and `two_perspectives`. Every customer-runnable check reports `requires_additional_input: false` and is selectable, plannable, and scannable.
2. **Hourly Safe-Run Cap**: The demo tenant's 1,000-runs-per-hour cap is dropped; demo tenants run uncapped by default (`demoMaxRunsPerHour(env)` defaults to `Infinity`). Optional explicit positive values in `ASTRANULL_DEMO_MAX_RUNS_PER_HOUR` remain respected (clamped to 5000).
3. **Safe Test Windows**: Safe test window closures (`safe_window_closed`, `policy_safe_window_closed`, and scan dispatch denials) do not block demo tenants.
4. **Minimum Interval**: Demo tenants bypass `min_seconds_between_runs` (forcing interval to 0). When a run occurs within the normal minimum interval that would otherwise block execution, `'min_interval'` is audited in `test_run.demo_gates_bypassed`.
5. **Feature-Flag Routes**: Route-level feature gates and service-level adapters for WAF posture, connectors, and external discovery evaluate unified per-tenant feature access helpers (`wafPostureEnabledFor`, `connectorsEnabledFor`, `externalDiscoveryEnabledFor`, `protectionValidationEnabledFor` in `src/lib/tenantFeatureAccess.mjs`). Explicit demo tenants access all route families without 404 `*_feature_disabled`.
6. **Deployment Features Alignment**: `GET /v1/tenant/deployment-features` (`getTenantDeploymentFeatures`) aligns directly to these per-tenant helpers so portal affordances match route authorization; `demo_tenant` reflects the explicit check (`isExplicitDemoTenant`).

Every demo bypass that changes an outcome is audited with action `test_run.demo_gates_bypassed` and `metadata.bypassed: [...]` listing the bypassed gates (`input_requirement:<code>`, `hourly_cap`, `safe_window`, `min_interval`, `soc_gated`).

### Explicit Tenant Scoping vs Wildcards
Wildcards (`*` or `all` in `ASTRANULL_DEMO_AUTO_VERIFY_TENANTS`) only apply to original ownership, subscription, and auto-verify bypasses. All route-backed feature flags and execution bypasses (input requirements, hourly cap, safe windows, minimum interval, route feature gates, and SOC ungating) require explicit tenant IDs via `isExplicitDemoTenant(tenantId, env)` or matching the demo account (`admin@demo.astranull.local`, `Astra-D1TrtI4HMTSrwKRW-9`), and never return true for a wildcard. If a wildcard is configured, a startup warning is logged.

### Gates Kept for Demo (Safety)
- **SOC Gating**: Dropped for the demo account (`admin@demo.astranull.local`, `Astra-D1TrtI4HMTSrwKRW-9`, and explicit demo tenants). High-scale and SOC-gated checks are runnable, selectable, and plannable without SOC gate blocks, and high-scale / offensive workflows bypass multi-party SOC approval requirements. Bypassed SOC gating is recorded as `'soc_gated'` in `test_run.demo_gates_bypassed`. Non-demo tenants retain full SOC gating.
- **Kill Switch**: Active kill switch halts all demo execution (`kill_switch_active`).
- **Per-Check Safety Caps**: `max_events`, `max_requests`, and per-kind bounds are enforced.
- **Concurrent Run Blocker**: `concurrent_run_blocked` still prevents overlapping runs on the same target.
- **Tenant Suspension**: `tenant_suspended` lifecycle state halts execution.
- **Destination Guard**: Origin lockdown address verification and destination boundaries cannot target arbitrary internal or unauthorized networks. Parity is maintained between check listing and start path.

### Missing Input Handling (`required_input_missing`)
When a customer-runnable check lacks genuine required input (e.g. no declared deny rules or no service port), the run is created and immediately finalized cleanly as:
- `status: 'verdicted'`
- `verdict: 'inconclusive'`
- `explanation_reason: 'required_input_missing'`
- `explanation`: Plain message naming the missing requirement (e.g. "No denied port is declared, so there was nothing to probe.")
- `requests_sent: 0` (zero probe traffic sent; never errors).



## Production login identity correction (2026-10-19)

The public password login resolves to the authenticated stored pair `tenantId: ten_demo`, `userId: usr_admin`. Demo execution recognition now accepts that exact pair, including the snake-case session form, rather than requiring an email-shaped user ID or a legacy synthetic tenant ID. Neither `ten_demo` alone nor `usr_admin` in another tenant grants the account exception. The existing explicit tenant allowlist continues to apply independently.

Deployment-feature projection and both dev-store/PostgreSQL run admission pass the authenticated context through demo recognition and policy normalization. The existing SOC-gate bypass audit remains attached to request-marker runs. The kill switch, suspension, concurrent-run guard, destination checks and per-check traffic ceilings remain enforced. High-scale catalog entries still use request markers; no traffic generator or governed adapter bypass is introduced.

The browser regression uses the actual production tenant/user pair and submits exactly the 6 exploit, 7 delivery-pattern and 5 high-scale definitions. Separate regressions check other users/tenants, all 18 individual starts, audit records and the production PostgreSQL admission path. No schema migration or API shape changes are required.
