# Current-release target profile

Typed declarations and a recorded-evidence protection profile for one target. This slice does not start probes, score readiness, or build analytics, history, or lineage.

## Declaration

Stored on `targets.declaration_json` and `target_groups.declaration_json` (migration `0063_target_declarations.sql` and the same columns in `db/schema.sql`, default `{}`, object check).

| Input | Rules |
|---|---|
| `purpose` | String or null. Max 200. |
| `service_roles` | Subset of `website`, `api`, `login`, `dns`, `network`. Stored in that order. `[]` means unclassified. |
| `owner` | String, null, or `{ label }`. Max 80. Status and source are rejected. |
| `criticality` | `critical`, `high`, `medium`, `low`, or null. |

Presented shape, on every inventory item and detail target:

```json
{
  "purpose": "login portal",
  "purpose_status": "declared",
  "purpose_source": "target",
  "service_roles": ["api", "login"],
  "service_roles_status": "declared",
  "service_roles_source": "target",
  "owner": { "status": "declared", "label": "App team", "source": "target" },
  "criticality": { "status": "inherited", "value": "high", "source": "target_group" }
}
```

Status is `declared`, `inherited`, or `unassigned`. Source is `target`, `target_group`, or null. A target field that was never stored inherits a non-empty group value and is marked `inherited` / `target_group`. An explicit null or empty list stays on the target: status `unassigned`, source `target` (or `target_group` when the group itself cleared the field). The raw `declaration_json` object is not the presented object and is not returned as `declaration`. Tags are not part of this object. Metadata cannot set it (`declaration` and `declaration_json` are reserved metadata keys). No assignee, vendor, or business-context field is added.

UI: purpose is at most 200 characters and the owner label is at most 80. Send `owner` as a string, null, or `{ label }` only. Render `purpose_status`, `service_roles_status`, `owner.status`, and `criticality.status` from the response. Do not infer a source the payload did not return.

## Writes

Dev-json and Postgres:

| Method | Notes |
|---|---|
| `patchTarget(ctx, groupId, targetId, body)` | Persists `body.declaration` when present. |
| `patchTargetById(ctx, targetId, body)` | Forwards `declaration`, tags, expected behavior, and metadata. Kind or value changes return 409. |
| `patchTargetGroup(ctx, id, body)` | Same declaration object on the group. |
| `addTarget(ctx, groupId, body)` | Optional declaration on create. |
| `createTargetDirect(ctx, body)` | Optional declaration on create. |
| `createTargetGroup(ctx, body)` | Optional declaration on create. |
| `listTargets(ctx)` | Each item includes `declaration`. |
| `getTargetDetail(ctx, targetId, query)` | `target.declaration`, `protection_profile`, `coverage`. |

Invalid input returns `{ error: "invalid_declaration", status: 400, field, message }` and does not write. Changing kind or value returns 409 `target_identity_immutable` and does not write the declaration. A declaration change also appends `target.declaration_updated` or `target_group.declaration_updated` in the same Postgres transaction as `target.updated` / `target_group.updated`.

`src/server.mjs` already gives those PATCH handlers the JSON body and returns the detail service payload. No server edit is required unless a later allowlist drops `declaration`. The Postgres service pass-through calls the repository methods above.

## Protection profile

`deriveProtectionProfile({ now, target, edgeRow, policies, observations, catalog })` returns `{ protection_profile, coverage }`. It reads rows only.

`protection_profile` (`protection-profile.v1`) has `families.waf`, `families.cdn`, `families.cloud`, `families.dns`, and `families.origin_hosting`. Each family has status, reason, provider, confidence, observed time, evidence refs, sources, and freshness. CDN does not fall back to the WAF vendor. DNS is not inferred from CNAME or addresses. Origin hosting stays `unknown` / `no_origin_hosting_observation` without an explicit record. Cloud is an observed edge or cloud layer. Aggregate row confidence is not copied onto a family. Missing confidence is null.

`origin.binding_id` stays null in this slice. `origin.status` is `not_tested` when no direct-origin observation is recorded and `unknown` when a `network_firewall.direct_origin_reachability` status is recorded. `origin.assurance` is `none`. `origin.reachability` keeps that recorded status, source `edge_detection.network_firewall`, tested target, scenario, and limitations. It is not a host-origin lockdown. `effectiveness` uses unit `definitive_marker` and its own percentage. Coverage uses unit `target_check_pair`.

Coverage counts customer-runnable, kind-compatible checks. Setup-required checks are `excluded`. Kind mismatches and SOC-gated checks are outside the plan. Counts `evaluated`, `conclusive`, `inconclusive`, `not_run`, `stale`, `unknown`, `partial`, and `excluded` are separate. Percentage is null at a zero denominator and 0 when the measured conclusive count is 0. Unknown and partial pairs remain in the denominator. Each pair has `launchable: null` and `launch_block_reason: "not_evaluated"`. `coverage.runtime_launch_gates` is `not_evaluated`.

A pair is `conclusive` and `live_external: true` only when the run is `completed` or `verdicted`, `completed_at` is present, the verdict cites evidence, `check_version` matches the catalog check `version`, a scenario on the check has a recorded `scenario_version`, and the row is not simulation or a manual declaration. Missing `completed_at` is `unknown` / `observation_time_unknown` even if `started_at` exists. Canceled and unfinalized runs are `unknown`. No evidence is `unknown`. A missing or mismatched check or scenario version is `partial`. `internal_simulation`, `SAFE_PROBE_SIMULATION`, `probe_simulation_evidence`, and `manual_declaration` / `customer_declaration` stay on `retained` with `live_external: false`. UI must not show those retained facts as current live external coverage.

Freshness policies: `protection-profile.observation.v1` (7 days, `family_observation`) and `protection-profile.coverage.v1` (7 days, `target_check_pair`).

Absent WAF marker rules are null. A recorded 0 stays 0. Absent origin bypass is `not_tested`. A recorded `not_exposed` stays. Finding owner is the same-tenant remediation `owner_group` when that row exists, otherwise `unassigned`. Dev-json findings, verifications, posture snapshots, connectors, validation runs, and fingerprints with a missing or different `tenant_id` do not change counts or sources.

`waf_posture.fingerprint` is independent of connector access. A missing score is null and `score_status` is `not_recorded`. `waf_posture.connector` and `raw_context_yaml` are null unless the WAF posture flag and the tenant connector feature are on and the caller has `waf:connector_read`. The payload then sets `configuration_access` to `allowed` or `redacted` and `configuration_disabled_reason` to null, `feature_disabled`, or `permission_denied`. `profiles.edge` and `profiles.core_fingerprint` stay `independent`. Stored YAML is redacted for secret-like keys and token strings. The detail payload does not invent YAML.

## Follow-ups outside this slice

- Analytics, history, lineage, and an authorized origin binding (`binding_id`) are separate slices. This slice does not add that executor.
- A run with no recorded `check_version` is `partial` (`missing_check_version`). A run with no recorded producer is `provenance: unspecified` and is not relabeled as simulation. Coverage does not reclassify those rows by starting a probe.
