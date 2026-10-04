# ADR-0011: Current-release target declarations and protection profile

## Status

Accepted (2026-10-04). Typed declarations are authorized for this slice. Analytics, history, lineage, origin-binding tables, and a new verdict engine are later slices.

## Context

Targets and target groups had tags and free-form metadata, but no typed customer declaration. Target detail copied a WAF vendor into the CDN provider when CDN status was `detected`, defaulted an absent origin bypass to `not_exposed`, defaulted absent marker rules to `0`, and labeled every finding owner `edge-sre`. Coverage math was easy to mix with marker effectiveness and with checks that were never applicable.

## Decision

1. **Declaration is a typed object, stored as `declaration_json`.** Migration `0063_target_declarations.sql` adds the column to `targets` and `target_groups` (`JSONB NOT NULL DEFAULT '{}'` plus an object check). Existing tenant RLS covers the column. Metadata keys `declaration` and `declaration_json` are reserved and cannot set it. Tags stay tags. Endpoint kind and value stay immutable.
2. **Fields are purpose (max 200), service_roles (`website`, `api`, `login`, `dns`, `network`, canonical order), owner label (max 80), and criticality (`critical`, `high`, `medium`, `low`).** An omitted field may inherit from the target group. An explicit null or empty list is unassigned and does not inherit. Source is `target`, `target_group`, or null. Nothing infers an assignee, vendor, or business context.
3. **The stored object and the presented object are different.** Writes merge a partial patch into `declaration_json`. Reads return `declaration` with status and source. Inventory and detail use that same presented shape. A declaration change is audited as `target.declaration_updated` or `target_group.declaration_updated` in the same transaction as the row write, alongside the existing update audit.
4. **Protection profile is a pure read of recorded rows.** `deriveProtectionProfile` emits `protection_profile` (`protection-profile.v1`) and sibling `coverage`. The five families are waf, cdn, cloud, dns, and origin_hosting. CDN never falls back to the WAF vendor. DNS and origin hosting stay unknown without an explicit recorded source. Cloud is an observed edge or cloud layer, not origin. Missing confidence stays null. A recorded `0` stays `0`.
5. **Legacy defaults change only when the value was absent.** Origin bypass defaults to `not_tested`. Marker rules default to null. A recorded `not_exposed` or a recorded `0` still surfaces. Finding `owner_group` comes from a same-tenant `finding_remediations` row when one exists, otherwise `unassigned`. A remediation row with a missing or different `tenant_id` is ignored. Dev-json detail collection reads (findings, counts, verifications, posture snapshots, connectors, validation runs, fingerprints) require `tenant_id` equal to the caller. Postgres detail queries keep their existing `tenant_id` predicates.
6. **Coverage counts compatible customer-runnable pairs.** Kind mismatches are outside the plan. Setup-required checks (`checkRequiresAdditionalInput`) are `excluded`. SOC-gated checks are omitted. `evaluated`, `conclusive`, `inconclusive`, `not_run`, `stale`, `unknown`, `partial`, and `excluded` stay separate. Percentage is null when the applicable denominator is 0 and is 0 when nothing conclusive was measured. Unknown and partial pairs stay in that denominator and never increment `conclusive_count`. Stale keeps `prior_state`. Marker effectiveness stays on unit `definitive_marker` and is not copied from coverage. Runtime launch gates stay `not_evaluated`; this slice does not call the test-run start path.
7. **A current conclusive pair is a finalized external observation.** The run status must be `completed` or `verdicted`, `completed_at` must parse, the verdict must be evidence-backed, `check_version` must equal the catalog `version`, and a check that defines `probe_profile.scenario` or `scenario_family` must record `scenario_version`. Canceled, unfinalized, evidence-less, and time-unknown rows are `unknown`. A version gap is `partial`. `producer_kind: internal_simulation`, `simulation: SAFE_PROBE_SIMULATION`, `probe_simulation_evidence`, or a manual/customer declaration is retained on `retained` and is not `live_external`. This derivation does not start a probe and does not add a browser engine.
8. **Origin lockdown is a binding, not a reachability row.** `origin.status` is `not_tested` when no direct-origin observation is recorded and `unknown` when one is recorded but `binding_id` is null. `assurance` stays `none`. The recorded status, tested target, and scenario stay on `origin.reachability` with explicit limitations. No binding table or executor is added here.
9. **Optional WAF connector configuration is permission- and feature-scoped.** Core fingerprint, marker rules, origin-bypass state, and `edge_detection` stay on target detail for roles that can read the target, including viewer. `connector` and `raw_context_yaml` are returned only when `wafPostureEnabled` and the tenant connector feature are both on and the role has `waf:connector_read` (and `ctx.scopes`, when present, includes that permission). Otherwise those fields are null, `configuration_access` is `redacted`, and `configuration_disabled_reason` is `feature_disabled` or `permission_denied`. Stored YAML is read at request time; secret-like lines and token strings are redacted. A missing fingerprint score is null / `not_recorded`. A recorded 0 stays 0. No YAML is synthesized.
10. **Freshness is versioned.** Family observations use `protection-profile.observation.v1` (7 days, unit `family_observation`). Coverage uses `protection-profile.coverage.v1` (7 days, unit `target_check_pair`). A stale fact keeps its provider and prior state. One family's timestamp is not reused for another family.

## Consequences

Dev-json and Postgres target reads both return `declaration`. Target detail in both stores adds `protection_profile` and `coverage`. Postgres latest-run lookup for that derivation includes every check run for the target, not only policy-bound checks.

`src/server.mjs` already passes the PATCH body through and returns the detail payload, so this slice does not edit it. `patchTargetById` is what forwards `declaration`. `db/schema.sql` now has the same `declaration_json` columns and object checks as migration 0063. `TARGET_DETAIL_SHAPE` includes `declaration`, `protection_profile`, and `coverage`. Finding owner expectations in the detail parity tests are `unassigned` when no same-tenant remediation row exists. A later history/binding worker wires an authorized origin binding. This slice does not.

## Methods the next server owner can call

| Method | Body or result |
|---|---|
| `patchTarget`, `patchTargetById` | `{ tags?, expected_behavior?, metadata?, declaration? }`. Kind and value changes return 409 `target_identity_immutable`. |
| `patchTargetGroup`, `createTargetGroup` | Existing group fields plus optional `declaration`. |
| `addTarget`, `createTargetDirect` | Existing target fields plus optional `declaration`. |
| `listTargets`, `getTargetDetail` | Each target includes `declaration`. Detail also includes `protection_profile` and `coverage`. |

`declaration` input: `{ purpose?, service_roles?, owner?: string \| null \| { label }, criticality? }`. Unknown keys return 400 `invalid_declaration`.
