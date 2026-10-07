# Provider-neutral protection validation: rollout notes

Status: local engineering verification only. Staging and live acceptance are outstanding (see "Open release gates"). Deployment is a separate, explicit release action. Nothing in this document is a production-completion claim.

Related: [plan](../implementation/provider-neutral-protection-validation-plan.md), [detection/23](../detection/23-application-entry-path-validation.md), [ADR-0017](../adr/0017-application-entry-path-validation.md), [API](../api.md#application-entry-paths-and-firewall-change-acceptance), [origin execution rules](current-release-origin-execution.md), [ADR-0014](../adr/0014-inconclusive-readiness-coverage.md).

## What ships in two parts

| Part | Gate | Why |
|---|---|---|
| PV-01 evidence correction (scanner, `host_sni_bypass` executor, correlation, projections, portal labels) | **Not gated.** It ships as a correctness fix. | Timeouts, refusals, TLS errors and generic error pages must stop producing protection claims for every tenant, whether or not the new workflow is enabled. |
| PV-02 to PV-08 workflow (entry paths, comparisons, firewall acceptance, matrix, report, findings, retests, configuration explanations, portal sections) | Tenant gate `protection_validation`, **off by default**. | Additive feature; enabled per tenant after staging evidence. |

## Tenant feature gate

Resolved by `isProtectionValidationEnabled` in `src/services/tenantDeploymentFeatures.mjs`, in this order:

1. `ASTRANULL_PROTECTION_VALIDATION_ENABLED=0` turns the workflow off for **every** tenant, including demo tenants (ADR-0016). This is the rollback switch.
2. `ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS` (JSON object, `tenant_id` to `true`/`false` or `1`/`0`) overrides the default per tenant.
3. Otherwise `ASTRANULL_PROTECTION_VALIDATION_ENABLED` (unset means off). Demo tenants are on unless step 1 or an explicit false tenant override applies.

Demo detection (`isDemoAutoVerifyTenant`, committed before this change set) treats every tenant id starting with `Astra-` as a demo tenant, plus the ids in `ASTRANULL_DEMO_AUTO_VERIFY_TENANTS`. Confirm no customer tenant id matches that prefix before deploying, or those tenants get the workflow without an explicit enable. An explicit false override can disable one demo tenant.

`GET /v1/tenant/deployment-features` reports `protection_validation`. With the gate off, every protection-validation route and `GET /v1/reports/protection-validation` return `404 protection_validation_disabled`, and the portal shows a "not enabled" notice and calls no protection-validation route.

Related settings:

| Setting | Effect |
|---|---|
| `ASTRANULL_APPROVED_PROBE_SOURCES` | JSON object of source perspective to signed worker ids. Set it before relying on firewall comparisons across more than one worker pool. Without it, every signed worker is the shared pool `astranull-signed-public-worker`; with it, unregistered workers have no source and cannot satisfy a comparison. Invalid or explicitly empty configured registries admit no workers. |
| `ASTRANULL_WAF_POSTURE_ENABLED`, tenant connectors, `waf:connector_read` | Required for configuration explanations (PV-08). Without them configuration is `disabled` or `redacted`; behavior results are unaffected. |

## Migration order

Apply with the normal `npm run migrate:postgres` flow **before** deploying the application build. All four are additive and leave existing rows untouched.

| Order | Migration | Contents | Operational note |
|---|---|---|---|
| 1 | `0068_protection_validation.sql` | Entry-path relations, versioned expectations, immutable comparison baselines and evaluations, with same-tenant foreign keys, RLS, uniqueness and audit-friendly digests. | New tables only. |
| 2 | `0069_protection_findings.sql` | Nullable `findings` columns (`source`, `dedupe_key`, `finding_class`, `priority`, `protection_validation_json`), a CHECK constraint, a partial unique dedupe index, and retest comparison context. | `ADD CONSTRAINT` validates and `CREATE UNIQUE INDEX` builds over the existing `findings` table under a write-blocking lock. Run in a low-traffic window and watch lock wait time on large tenants. |
| 3 | `0070_protection_baseline_capture_indexes.sql` | Capture-id and capture-head indexes on `protection_comparison_baselines`. | The table is new, so the build is cheap. |
| 4 | `0071_entry_path_comparison_lifecycle.sql` | `entry_path_comparisons` and `entry_path_comparison_items` with same-tenant foreign keys, forced RLS, a per-tenant idempotency key, one running comparison per reviewed plan digest, and triggers that keep the approved scope immutable, finished rows final and history undeletable. | New tables only. `make validate-db-schema` now checks both tables, their RLS policies, the `entry_path_comparisons_tenant_id_id_key` constraint and the seven `fk_entry_path_comparison*` foreign keys. |

`npm run validate-db-schema` (or `make validate-db-schema`) checks that `db/schema.sql` matches the migrations. Run `npm run postgres:tenant-query:audit` after any further repository change.

Rollback is at the application level: turn the gate off. Do **not** drop the tables or columns, because retained declarations, baselines, evaluations and findings are immutable history. An older build ignores the new tables and the nullable finding columns.

## Enable sequence

1. Apply migrations 0068 to 0071, then deploy the build. The PV-01 correction and the 2026-10-06 status-code semantics are active immediately.
1. Make sure the Postgres background tick runs for the tenants you enable: `npm run validation-scan:runner -- --tenant-id <id>` (or the `test-policy-runner` service, which runs it on every tick) now also advances entry-path comparisons. Give the runner the same `ASTRANULL_PROTECTION_VALIDATION_ENABLED*` values as the control plane. If the runner reads the gate as off it pauses comparisons instead of cancelling them, so a missing flag only delays work.
2. Configure `ASTRANULL_APPROVED_PROBE_SOURCES` if more than one signed worker pool exists.
3. Enable named staging tenants with `ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS`. Record staging evidence (see "Open release gates").
4. Enable named customer tenants. Only then consider the global default.

## Flag disablement and queued-work cancellation

Set `ASTRANULL_PROTECTION_VALIDATION_ENABLED=0` (all tenants) or `false` for a tenant in `ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS`, then restart or redeploy so the runtime config reloads.

| Work | Behavior after disablement |
|---|---|
| New declarations, plans, starts, baselines, comparisons, reports, retests | Refused with `404 protection_validation_disabled`. |
| Running entry-path comparisons | The next advance in the API process (dev-json 30-second tick, a run-terminal hook, or a start replay) skips every `pending` or `deferred` path with `skip_reason: "protection_validation_disabled"`, starts nothing, and finishes the comparison as `cancelled` once no path is outstanding. Audited as `entry_path_comparison.item_skipped` and `entry_path_comparison.cancelled`. The Postgres runner tick only pauses on the gate (it never cancels), so an API-side event or the cancel route settles a disabled comparison. |
| Runs a comparison already started | Ordinary bounded signed runs. They finish under their own deadlines and budgets. To stop them immediately use `POST /v1/test-runs/:id/cancel` or the tenant kill switch; both remain available while the gate is off. The comparison cancel route is gated, so it is not available after disablement. |
| Protection-finding retests already created | Ordinary test runs; cancel the same way. New retests are refused. |
| Firewall comparisons | Synchronous and passive; nothing is queued. |
| Postgres entry-path comparisons | Wired. Started paths are ordinary signed runs; cancel them with the comparison cancel route (while the gate is on), `POST /v1/test-runs/:id/cancel`, or the kill switch. The kill switch cancels every outstanding path on the next advance. |

To stop running comparisons **while keeping the gate on**, use `POST /v1/entry-path-comparisons/:id/cancel` (skips outstanding paths and cancels started runs through the existing run cancel path) or the tenant kill switch.

Disablement never deletes declarations, baselines, evaluations or findings. Existing protection findings stay in the ordinary findings list with their recorded lifecycle.

## Retest requirements

- 2026-10-06 status-code round: the 41 `waf.evasion_*.safe` checks move to `1.1.0` (signature-based grading, permitted baseline always sent, a transport error is never `external_allowed`); `l3.firewall_exposure_scan.safe` moves to `1.1.0` (5-second job split across ports); the host/SNI checks and `waf.fingerprint.safe` are `1.2.0`; WAF enforcement, inspection-limit and class-marker checks are `1.1.0`. Older results stay as recorded and are not compared with new ones (`check_version_mismatch`). Firewall baselines captured with `firewall-acceptance-v1` or `firewall-acceptance-v2` need a fresh capture for v3.
- PV-01 bumps `waf.fingerprint.safe`, `waf.origin_bypass.safe`, `origin.host_sni_bypass.safe`, `origin.direct_reachability.safe` and `origin.direct_bypass.safe` to `1.1.0`. Historical verdicts are not rewritten. Coverage treats older versions as needing an explicit new governed run (ADR-0014); customers must retest to obtain current conclusions.
- A standalone `host_sni_bypass` denial earns readiness credit only when origin lockdown is confirmed over a healthy permitted-path baseline. The executor records no baseline today, so these denials now correlate to `inconclusive`. Expect a visible drop in conclusive origin results after deploy; this is intended.
- Protection-finding retests (`retest_of_finding_id`) recheck the active relation or expectation, active same-tenant targets, an intact declaration digest and current ownership before creating a run. Failure is `409 retest_not_authorized`. Re-enabling the gate never replays a stale scope.
- A changed declaration or expectation does not reinterpret older baselines. Capture a new baseline after any declaration change.

## Monitoring

| Signal | Meaning | Action |
|---|---|---|
| `protection_validation_findings_failed` | Findings could not be derived from a newly recorded evaluation. | Investigate; the evaluation itself is stored. |
| `entry_path_comparison_record_failed` | A finished comparison's evaluation was not recorded. | Investigate before trusting the comparison view. |
| `entry_path_comparison_finalized_hook_failed` | The finalization hook threw. | Investigate with the record-failed counter. |
| `entry_path_comparison_tick_failed` | The 30-second dev-json advance tick threw. | Deferred paths will not resume until fixed. |
| `entry_path_comparison_advance_failed` | One comparison threw during a tick or start replay. The tick records it and moves on to the next due comparison. | Inspect that comparison; others keep advancing. |
| `entry_path_comparison_conflict` | A save lost a compare-and-set race (`lock_version`). | Expected under concurrency; investigate only if it climbs steadily. |
| `entry_path_comparison_lock_unavailable` | No comparison-lock connection within 2 seconds (Postgres). The run-finished hook falls back to a reconcile request that the next runner tick settles. | Check `lockPoolMax` (4) and runner cadence. |
| `entry_path_comparison_run_hook_failed` | The Postgres run-finished hook threw. | The next runner tick settles finished runs through `listDue`. |
| Runner summary `tenants[].comparisons` | Per-tenant `due_count` and `advanced[]` (`comparison_id`, `status`, `reason`). A tenant-level `error` makes the runner exit non-zero. | Alert on repeated `paused` or `advance_failed`. |
| `target_configuration_context_failed` | Configuration explanation could not be attached to target detail. | Explanation-only; behavior results unaffected. |
| Audit actions `entry_path.*`, `firewall_expectation.*`, `firewall_baseline.captured`, `firewall_comparison.evaluated`, `entry_path_comparison.*` | Mutation and execution trail. | Review for unexpected starts or `scope_rejected`. |
| Existing run metrics, kill-switch state, probe-activity telemetry | Comparisons use ordinary signed runs. | Unchanged dashboards apply. |
| Post-deploy shift in origin verdicts toward `inconclusive` | Expected from PV-01. | Compare with the pre-deploy count; do not treat it as an outage. |

## Staging evidence (2026-10-06)

A bounded live run against `aistripped.com` (the user-designated test target, about 40 requests through the signed safe-check path, dev-json persistence, demo ownership proof under ADR-0016) is recorded in [protection-validation-staging-evidence-2026-10-06.md](protection-validation-staging-evidence-2026-10-06.md). It confirmed the CDN-edge guard, signature-only marker grading, idempotent comparison starts and the missing-evidence rule. It also found defects D1 to D11. This round fixed them in code with fixture-only regression tests (`tests/unit/staging-defect-regressions.test.mjs`, `tests/unit/probe-worker.test.mjs`, `tests/unit/entry-path-comparison-signed-scope.test.mjs`, `tests/unit/entry-path-comparison.test.mjs`, `tests/unit/protection-validation-report.test.mjs`); no live traffic was sent to verify the fixes:

| Defect | Fix |
|---|---|
| D1 IPv6 literal crashes the worker | IPv6 literals are bracketed in probe URLs; an unexpected probe exception becomes an `error` result (`probe_execution_failed`) with the counted attempts instead of exiting the worker. |
| D2 IPv6 split into host and port | One shared endpoint parser: `[v6]:port` is split, a bare IPv6 literal never is. |
| D3 port lists dropped by the worker | The worker keeps `open_ports`, `filtered_ports`, `closed_ports`, `marker_results`, `variant_results`, `variants` and `phases`. |
| D4 all-filtered scan rejected, worker exits | The scheduler tolerance now also applies to `blocked`; a 4xx result rejection (other than 401/403/408/429) is final for that job only. |
| D5 forbidden-port checks never send | `l3.forbidden_tcp_port.safe`, `l3.forbidden_udp_port.safe` and `l3.ipv6_reachability.safe` accept `tcp` (`host:port`) targets. |
| D6 one filtered port ends the scan | Per-port connect time is the remaining job time divided by ports left; catalog job ceiling is 5 s (`1.1.0`). |
| D7 TLS 1.3 handshake shown as edge block | `tls_audit` correlates to a TLS-profile result. |
| D8 inconclusive rows void definitive WAF rows | Inconclusive marker rows are ignored (G4). |
| D9 open 443 raises a finding | Only 80/443 open is `allowed_as_expected`, no finding. |
| D10 dev-json comparisons stall on `collecting` runs | The dev ticker finalizes expired collecting runs of running comparisons, which fires their hooks. |
| D11 | (a) gap outcomes such as `not_applicable` are kept in `attempts[]`; (b) unsampled firewall items carry `post_change_not_sampled`; (c) reports use the newest firewall evaluation that sampled each expectation. (d) Not a defect: a null binding port/path means the scheme default (443, `/`). |

## Open release gates

These remain open, so every PV row in `PROGRESS.md` stays `[~]`:

- Owned staging endpoints for cloud-edge, appliance/reverse-proxy and unknown/custom responses, and approved external source locations (plan open question 1). Fixture and mock tests show code behavior, not provider certification. The `aistripped.com` run covered only a Cloudflare-fronted site with no reachable origin.
- A live re-run of the D1 to D11 fixes (IPv6 targets, port scans, forbidden-port checks, TLS profile) through the signed worker.
- Scenarios the staging run could not cover: explicit deny, application identity (needs a nonce-bound canary, plan open question 2), pre/post regression on a real change, and declared login/API paths (no login/API URL was linked from the test site).
- Postgres comparison lifecycle under live signed workers (local Postgres integration only), and hosted deployment verification of the runner and PV flag env. The Compose file now forwards the same PV flags and approved source registry to the control plane and test-policy runner; no deployment was performed during review.
- A producer for declared signatures: nothing yet fills the signed `declared_origin_lockdown` or `declared_block_signature` profile fields from a customer declaration, so origin lockdown is never confirmed and only vendor signatures count as blocks. Host/SNI and scanner origin legs send HEAD, so a body-hash declaration can only match on GET legs.
- Product decisions: whether the "status code is never evidence on its own" rule also applies to `probeBotChallenge`, `probeRateLimitSequence` and the HTTP method-policy status list; outbox delivery for high/critical protection findings in Postgres.
- A `host_sni_bypass` permitted-path baseline (budget and design change) so direct-origin denials can confirm lockdown.
- Human sign-off on the rendered protection-validation pages. An automated review at 375/768/1024/1440 px in both themes, keyboard-only and with reduced motion was done on 2026-10-06 (11 defects fixed, spec checks added); a person has not yet reviewed it.

## Local review, 2026-10-07

See [review and verification record](../implementation/provider-neutral-protection-validation-review.md). This review corrects source-registry fallback, policy-order persistence, weak origin identity, generic authorization-error grading, skipped-path evaluation recording, host counting, expectation pinning, capped-source disclosure, mapped firewall finding targets, origin retest binding, concurrent finding creation, UI pagination races, and firewall refusal semantics. Production/live evidence gates above remain open.
