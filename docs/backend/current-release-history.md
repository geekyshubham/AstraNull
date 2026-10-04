# Current-release history foundation

Retained target observations, declared origin bindings, and explicit retest lineage. Writers now stamp runs from the catalog and append signed-result history on the real producer paths. **Version note (2026-10-04):** the HTTP owner has since landed the observation and origin-binding routes on `server.mjs` (dev targetHistory injection and Postgres runtime injection, fail-closed with `503 postgres_route_not_wired`, missing/foreign target `404 unknown_target`), and `db/schema.sql` now carries the additive sync of migration `0064`. The "HTTP handoff" table below reflects the state at the time this slice was written; landed status is noted inline.

Dev JSON and Postgres share the same prepare, compare, project, and plan functions. Postgres pointer updates use `astranull_observation_order_before`, the SQL twin of `compareObservationOrder`.

## Exported methods

`src/lib/checkDefinitionVersion.mjs`

- `canonicalDefinitionDigest(definition)`, `deriveCheckDefinitionVersion(definition, body)`
- `approvedScenarioVersion(check, opsScenario)`, `deriveRunEvidenceStamp(check, body, runtime)`

`src/services/targetHistory.mjs`

- `OBSERVATION_FAMILIES`, `SUCCESSFUL_OUTCOMES`, `TRANSPORT_FAILURE_OUTCOMES`, `RETAINED_OUTCOMES`, `CLOCK_SKEW_MS`
- `normalizeObservationTimestamp`, `compareObservationOrder`, `classifyAttempt`, `observationTimeError`
- `redactProvenance`, `observationDigest`, `encodeObservationCursor`, `decodeObservationCursor`
- `assessComparability`, `projectObservation`, `prepareObservation`
- `transportOutcomeFromProbe`, `originOutcomeFromProbe`
- `acceptTargetObservation(ctx, input, options)` — internal append. No RBAC. `options.internal === true` keeps a server-derived `check_version` and `producer_kind`.
- `appendTargetObservation(ctx, input, options)` — public append. Requires `evidence:write` or `test_run:start`. Always stores with `internal: false`, so a request body cannot set the version or producer.
- `listTargetObservations(ctx, query)` — `evidence:read` or `target_group:read`
- `getCurrentFamilyState(ctx, query)` — same read gate
- `listObservationsForTests(tenantId)`

`src/services/originBindings.mjs`

- `currentOriginProof`, `bindingRecordsFromStore`, `deriveBindingScope`, `planOriginBinding`, `presentOriginBinding`
- `validateOriginBindingForRun` — run-start guard; both proofs current; approved origin check only
- `createOriginBinding`, `archiveOriginBinding` — `target_group:write`, audited. Create still requires origin proof only.
- `getOriginBinding`, `listOriginBindings` — `target_group:read`, current proof rechecked, no audit write
- `assessOriginReachability(binding, observations, proof)`

`src/services/retestLineage.mjs`

- `planRetestRegistration`, `labelRunRelation`, `presentFindingLineage`
- `registerRetestLineage` — `finding:write`
- `listFindingLineage` — `finding:read`

`src/persistence/postgres/targetHistoryRepository.mjs`

- `createTargetHistoryRepository(pool)`

`src/persistence/postgres/targetHistoryServiceAdapters.mjs`

- `createPostgresTargetHistoryServices({ repository, audit })`
- methods: `appendTargetObservation`, `listTargetObservations`, `getCurrentFamilyState`, `createOriginBinding`, `archiveOriginBinding`, `getOriginBinding`, `listOriginBindings`, `assessOriginReachability`, `registerRetestLineage`, `listFindingLineage`, `assessComparability`
- The adapter's `appendTargetObservation` honors `options.internal`. HTTP must not copy that flag from the request. The edge hook calls `acceptTargetObservation` directly.

`src/services/targetEdgeDetectionStore.mjs`

- `recordTargetEdgeDetectionFromEvent` still keeps one current edge row. When the declared target row exists, it also appends one observation per WAF and CDN family, and Cloud only when `edge_signature.cloud_hosted` is a boolean. A missing target skips history. An older or equal `(observed_at, source_completed_at, test_run_id)` does not replace the current edge row. A timestamp before declaration or in the future does not move it.

Validation scan reads accept `advance: false` or `advance: 'false'` in both stores. `getValidationScan`, `getValidationScanActivity`, `advanceScan`, and `dispatchDueValidationScans` then skip dispatch and advance. Omitting the flag keeps the previous active behavior.

## Ordering and retention

Current pointers sort by `(observed_at, source_completed_at, id)`.

- Timestamps are UTC with six fractional digits (`YYYY-MM-DDTHH:mm:ss.SSSSSSZ`).
- A null `source_completed_at` is older than any real completion at the same `observed_at`.
- Ids compare as raw bytes (`COLLATE "C"` in Postgres).
- A pointer moves only when the candidate is strictly newer. Ties stay.
- `successful` outcomes: `detected`, `not_detected`, `pass`, `fail`, `reachable`, `unreachable`.
- `failed_attempt`: `timeout`, `tls_failure`, `dns_failure`, `transport_failure`, `source_disconnected`. These do not replace the last successful family row. `fresh_negative` is true only when that successful outcome is `not_detected`. `provider_loss` is always false in this slice.
- `retained_noncurrent`: `inconclusive`, `canceled`, `cancelled`, `stale`, `error`, `pending`. These are kept and do not move either pointer.
- History is append-only. The current row is not projected backwards.
- Idempotency needs a nonce or an event id. The same digest is the same observation. A different nonce, event id, or a second matching row is `409 idempotency_conflict`. Replay does not insert again and does not move the pointer.
- `observed_at` must be at or after `target.created_at` and at most 120 seconds ahead of the supplied clock. Missing declaration time is `409 declaration_time_unknown`. A deleted or archived target is `404 unknown_target`.

## Comparison

`assessComparability(previous, next)` is comparable only when both rows are successful and share target, check, corpus version, scenario version, check version, family, origin binding, and producer. Otherwise `comparable` is false, `direction` is null, and `reason` is one of:

`missing_observation`, `transport_failure`, `not_successful`, `target_mismatch`, `check_mismatch`, `missing_version`, `corpus_changed`, `scenario_changed`, `check_version_changed`, `context_mismatch`.

When comparable, `change` is `unchanged` or `changed`. Direction is `appeared`, `disappeared`, `improvement`, `regression`, `unclassified`, or `provider_changed`. Pass/fail is the only improvement or regression pair. Transport failure and a missing or changed version are never an improvement or a regression.

Provider identity is the recorded safe provider string only. A recorded provider change with the same versions, target, check, family, and context is an explicit `changed` / `provider_changed` entry carrying `details.before_provider` and `details.after_provider` — an attribution change, never an improvement or a loss. A missing provider is a comparison gap only where the provider identity is the substance of the outcome: two same `detected` results whose vendor was not recorded are `provider_not_recorded`. The same generic outcome (`pass`/`fail`), the same bound `reachable`/`unreachable` origin result, and the same `not_detected` absence stay behavior comparable without a provider, because no vendor is implied by them. `comparison_gaps` (including these) are serialized onto both the protection profile and coverage objects, next to `comparable_changes`.

## Safe reads

`listTargetObservations` accepts `target_id`, `family`, `from`, `to`, `cursor`, and `limit` (clamp 1–100, default 50). The cursor is a base64url JSON tuple `{ observed_at, source_completed_at, id }`. Pages are newest first. An invalid cursor is `400 invalid_cursor`. Reads do not persist.

Provenance keeps short strings, finite numbers, and booleans. Keys matching header, cookie, authorization, password, secret, token, credential, body, or raw are dropped, as are long strings and values that look like a cookie or a bearer token. Redaction runs before insert and again on project.

List payload:

```json
{
  "items": [],
  "count": 0,
  "next_cursor": null,
  "filters": { "target_id": null, "family": null, "from": null, "to": null }
}
```

Current payload:

```json
{
  "target_id": "tgt_app",
  "items": [{
    "family": "waf",
    "last_successful": {},
    "latest_failed_attempt": null,
    "fresh_negative": false,
    "provider_loss": false
  }]
}
```

An observation item carries `id`, `tenant_id`, `target_id`, `target_group_id`, `family`, `check_id`, `test_run_id`, `source_kind`, `source_id`, `corpus_version`, `scenario_version`, `check_version`, `observed_at`, `source_completed_at`, `outcome`, `attempt_class`, `producer_kind`, `origin_binding_id`, `provenance`, and `created_at`. Append also returns `replayed`.

Families: `waf`, `cdn`, `cloud`, `dns`, `origin_hosting`, `maintenance`. Source kinds: `edge_detection`, `validation_run`, `explicit_record`. Producer kinds, server-derived only: `signed_probe`, `live_external`, `internal_simulation`, `customer_declaration`, `manual`. `signed_probe` is authenticated signed-worker egress. An inline ops check is `customer_declaration` on the run and `internal_simulation` on its event. A dispatch mode of `signed-worker` does not mark that ops check live.

## Check definition version

`deriveCheckDefinitionVersion` reads the catalog definition, not the request body. A real `definition.version` wins (`derivation: "explicit"`). `live`, `latest`, `current`, `producer`, `live_external`, and `user` fall through to `derivation: "canonical_digest"` and `check_version: "sha256:<digest>"`. The digest is sorted-key JSON SHA-256. `producer_kind` and `live` are removed. Request and body patterns stay in the hash. Credential key values and bearer, cookie, and authorization strings become `[redacted]` inside the hashed material and are not returned. Body fields `version`, `check_version`, `scenario_version`, `producer_kind`, `live`, and `expected_behavior` are ignored and listed. The helper does not import the check catalog.

`deriveRunEvidenceStamp` is what run creation stores. `check_version` is that derivation. `scenario_version` is `probe_profile.scenario`, else `probe_profile.scenario_family`, else the approved ops scenario passed by the caller, else null. `expected_behavior` is `check.default_expected_behavior` only, copied onto `expected_behavior_json` and described in `provenance_json`. A missing catalog default stays null. The stored run value is the snapshot from start. `target.expected_behavior` remains the target declaration and is not rewritten. Old rows with a null `check_version` stay partial.

## Origin bindings

A binding joins two targets that already exist in the same tenant: a protected hostname or non-IP URL, and an origin that is an `ip` target or a URL whose host is an IP literal. Host and SNI come from the protected declaration. Port and path come from the URL, `target.port`, a single allowed scope value, or one caller choice that is inside that scope. Several allowed ports or paths with no choice is `port_unspecified` or `path_unspecified`. `direct_ip`, `discovered_endpoint`, `discovered_endpoints`, `endpoint`, and `destination` are rejected.

Origin proof uses `effectiveTargetVerifications` and `ownershipProofFromStates` on that origin target. `dns_verified` and `user_confirmed` pass. `agent_verified` does not. `provider_verified` on an IP is not current provider DNS proof and is treated as pending. A target group's `ownership_status` does not authorize the binding. A foreign target id is `404 unknown_target` and the response does not include the other tenant's hostname.

The stored row is a declared relation. Presented fields stay `assurance: "none"`, `lockdown: "not_tested"`, `relation: "declared_binding"`, `capacity_assurance: false`. `currently_authorized` is recomputed from the current proof and an active status, and covers the origin proof only; it never implies protected-side proof or a runnable run (job start still requires both proofs). Create and archive are audited in the same transaction as the row. Reads are not.

Replaying an active pair replays only the identical stored scope. Creating the same active protected/origin pair whose derived host, SNI, port, or path differs from the stored choice is `409 scope_conflict` (with `existing_id`) in both stores — never a silent replay of another port or path. An exact identical scope replays without a mutation or traffic. A scope outside the current declaration is still `400 scope_mismatch`.

Reachability is a pure read. Only a later (`observed_at` at or after the binding's `created_at`) successful finalized observation that names that `origin_binding_id`, targets the origin, has `source_completed_at`, and has outcome `reachable`, `unreachable`, `pass`, or `fail` counts. The result still says `lockdown: "not_established"` and is not a capacity assurance. Older unbound observations stay unbound. Creating a binding does not rewrite them. An observation that names a binding must target that origin and must not predate the binding.

## Retest lineage

`registerRetestLineage` records intent exactly `"retest"` for one finding and one run in the same tenant, with the same `target_id` and `check_id`. Anything else is `404` or `409 pair_mismatch`. The same pair without a lineage row is `later_same_pair` with reason `no_explicit_retest_intent`. The finding's own run is `originating`. A different pair is `not_comparable`. `can_advance_remediation` is false. `sibling_closure` is false.

`startTestRun` is the writer. `retest_of_finding_id` requires `finding:write` and the same tenant, target, and check. The role check uses `roleHasPermission` before `requirePermission`, so an allowed role does not record a false `rbac.denied`. Postgres inserts the lineage row in the same transaction as the run, before dispatch. The dev store registers lineage after the run row is pushed and before dispatch, and removes both if registration or dispatch fails. The column `test_runs.retest_of_finding_id` is set only by that path. `listFindingLineage` and `registerRetestLineage` alone do not set it and do not close findings.

`planFindingPatch` accepts `open`, `in_progress`, `accepted_risk`, `resolved`, `closed`, `false_positive`, and `accepted`. Closure statuses set `closed_at` to the request time. A later closure keeps the existing timestamp. `open` and `in_progress` clear it. Any other status is `400 invalid_lifecycle` and is not written. The audit action stays `finding.updated`. The payload does not include `fix_proved`. `getFinding` adds `closed_at`, `lineage`, `retests`, `originating`, and `latest` from `readFindingLineage` when that method exists. Customer scrub still removes agent wording from notes. Siblings are not closed.

## Read-only scans

`advance: false` and `advance: "false"` return before lease, lock, dispatch, or `startTestRun`. `advanceScan(ctx, id, { advance: false })` returns `{ scan_id, acquired: false, reason: "advance_disabled", dispatched: false }`. `dispatchDueValidationScans(ctx, { advance: false })` returns `[]`. `getValidationScan(ctx, id, { advance: false })` and `getValidationScanActivity(ctx, id, { advance: false })` still load the scan and do not start checks. `listValidationScans` has no advance path. **Landed:** the HTTP controller now always passes `advance: false` for the scan GET and activity GET, so reads are passive on both stores regardless of role or query parameters; the create-pending path still runs one initial advance through the explicit start, and the runner drives everything else.

## Migration

`db/migrations/0064_target_observations_origins_lineage.sql` adds `target_observations`, `target_observation_current`, `origin_bindings`, and `finding_retest_lineage`, plus RLS. It adds nullable `test_runs.check_version`, `scenario_version`, `producer_kind`, `origin_binding_id`, `retest_of_finding_id`, `expected_behavior_json`, and `provenance_json`, and `findings.closed_at`. Producer checks include `signed_probe`. A `BEFORE UPDATE` trigger on `target_edge_detections` keeps a stamped current row from moving backward. Ordering is `observed_at`, then `test_run_id`, because that table has no `source_completed_at`. A null `observed_at` on the existing row still accepts the update, so an unstamped upsert keeps its previous behavior. It does not rewrite `0063` and does not backfill or close findings. Grants stay with the harness, which grants the app role after migrations.

## Writers

`startTestRun` in the dev store and the Postgres adapter calls `deriveRunEvidenceStamp` and copies the stamp onto the run. Body version, producer, live, and expected-behavior flags are not stored. `origin_binding_id` is checked with `validateOriginBindingForRun` before insert. A revoked or disabled connector makes a `provider_verified` row pending, so that proof does not authorize the run. `direct_ip` and the other undeclared destination keys are rejected.

`recordProbeResultEdgeDetection` appends history on the ingest client, then upserts only a persistable edge detection whose history was accepted. Transport and other non-persistable results append `failed_attempt` and return without upsert. Idempotency conflict aborts the probe mutation with 409. Origin history uses `require_binding`. The dev probe coordinator calls `recordSignedProbeHistory` for the same split. A public `appendTargetObservation` forces `internal: false`. The Postgres history adapter honors `options.internal` only when the server caller sets it.

`historyReadModel` adds `retained_family_states`, `comparable_changes`, `comparison_gaps`, and `origin_bindings` after `deriveProtectionProfile`. A confirmed change is the two newest successful observations of one family when `assessComparability` says `changed`; every non-comparable pair is a `comparison_gaps` entry with its reason (including `check_version_changed`). Both `comparable_changes` and `comparison_gaps` serialize onto the protection profile and coverage objects. The portal detail read adds two sequential queries for the newest 100 observations and active bindings, and a third proof query only when a binding row exists. No binding leaves `origin.binding_id` null and `origin.reason` at `no_origin_binding_recorded`.

## HTTP handoff

`server.mjs` is not edited here.

| Call | Current HTTP | Landed status / controller note |
|---|---|---|
| `POST /v1/test-runs` | Forwards the body and maps `result.error` to its status. `retest_of_finding_id` and `origin_binding_id` already reach the service. Body version and producer flags are ignored. | Nothing for stamps. Do not trust body `producer_kind`, `check_version`, `live`, or `expected_behavior`. |
| `GET /v1/findings/:id` | Returns the service object, including `closed_at`, `lineage`, `retests`, `originating`, and `latest`. | Landed and contract-pinned: `latest` carries `status`/`finalized`/`completed_at` (`FT-SHAPE-02b`); an unfinalized attempt stays `pending` and never claims a later passing result. |
| `PATCH /v1/findings/:id` | Returns 200 with the service value unless it is null. | **Landed:** the controller returns `result.status` on `result.error` before the 200; invalid lifecycle is `400 invalid_lifecycle` and nothing is stored. |
| Scan GET, activity GET | **Landed:** the controller always passes `advance: false` on both reads — no HTTP GET advances or dispatches, and an `advance=true` query parameter is not forwarded. | Advancement runs only through the explicit runner path. |
| Due dispatch and manual advance | Explicit dispatch/advance run through the `validation-scan-runner` path (`dispatchDueValidationScans`/`advanceScan` with a runner context). | HTTP GETs never dispatch. |
| Observation append | No route. | Do not add one that copies `internal`, `producer_kind`, or `check_version` from the body. Server writers call `appendTargetObservation` or `appendAcceptedEdgeHistory` with server-derived fields. |

## Limits

- There is no origin executor. A binding is not a destination and not a lockdown test. Assurance stays `none`.
- Dev history is skipped when the target row is absent. The edge persistence case with no target still updates one current edge row.
- Binding inspection reads are authorized and do not write audit.
- Origin reachability and the portal profile read the newest 100 observations.
- The edge current row has no `source_completed_at`. The monotonic trigger uses `observed_at` and `test_run_id`.
- At the time of this slice `db/schema.sql` and `PROGRESS.md` were outside it. Landed since: `db/schema.sql` carries the additive sync of migration `0064`, and `PROGRESS.md`/the acceptance matrix are maintained by the documentation owner.

### Concurrent retries

Observation insertion uses `ON CONFLICT DO NOTHING` and re-reads all rows matching the nonce, event id, or digest in the same tenant transaction. An identical winner is a replay; ambiguous or incompatible identities return `409 idempotency_conflict`. This avoids attempting a query after a unique violation has aborted the ingest transaction. Only a newly inserted observation updates the current pointer.

Active origin-binding creation uses the unique tenant/protected-target/origin-target pair and re-checks the full stored Host/SNI/port/path before replaying. A different scope returns `409 scope_conflict`; a replay preserves the exact creation timestamp and does not append another audit event. Retest-lineage insertion similarly replays the unique finding/run intent only when its target and check match. Concurrent retries do not update the immutable lineage or close findings.


### Customer finding fields and chronology

Customer finding patches forward only the documented lifecycle, assignment, and notes fields. `closed_at` is derived by the lifecycle planner; evidence and verdict references remain server-owned. A note edit cannot erase a recorded closure or rewrite its proof. Declaration and origin-binding time guards compare normalized six-digit UTC timestamps, preserving the same microsecond chronology as retained observations and Postgres reads.
