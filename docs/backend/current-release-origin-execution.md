# Current-release origin execution (bound signed jobs)

How a bound Host/SNI origin run is started, serialized, recovered, and finalized so the signed probe job carries ONLY the server-validated approved scope. Dev JSON and Postgres runtimes share the same pure helpers (`src/lib/probeJobs.mjs`, `src/lib/capabilityProbes.mjs`, `src/lib/checkDefinitionVersion.mjs`); the Postgres adapter (`src/persistence/postgres/validationServiceAdapters.mjs`) wires them over real repositories.

## Origin associations and paired identity extension (2026-10-16)

See [ADR-0032](../adr/0032-origin-associations-and-paired-identity.md) and the [research/evidence contract](../detection/24-origin-exposure.md). Optional persisted origin associations are a separate append-only source store, not execution authority. Their GET/import/collection routes cannot create targets, proofs, bindings or runs. Tenant opt-in is disabled by default; migration `0083_origin_clues.sql` adds the tenant-scoped tables and forced RLS. Unknown timestamps, incomplete sources and unavailable DNS questions remain explicit.

The target **Overview** now presents source review → separate declaration/ownership/binding → reviewed bounded check. Import/collection require confirmation. Existing Origin relations show exact finalized binding/run/check evidence on either target, with current authority separate from historical validity. Archived relations retain inspectable evidence but cannot authorize new work. The Inspector remains the source of actual identity/baseline metadata; missing historical fields are not inferred.

### Durable execution grant

Both memory and PostgreSQL use `validateOriginBindingForExecution` immediately before reserving traffic. A signed scope is not perpetual authority: the active binding, both current undeleted/unarchived targets, both ownership states and exact target descriptors/Host/SNI/port/path must match. PostgreSQL locks the authoritative rows within its transaction. Origin-target jobs and protected-host `nfw.origin_lockdown.safe` jobs follow the same contract. New signed jobs carry immutable `origin_authority`; legacy jobs without the required authority fail closed rather than acquiring a new authorization snapshot during recovery.

Finalized historical observations use the recorded binding/scope/authority, not the binding's current status. Historical evidence surviving revocation does not authorize execution. The exact current-state check also applies to paired identity jobs and both reviewed ownership proof references.

Archive cancels queued/leased exact-bound work through existing cancellation machinery. All effective proof expiry/revocation/demotion denies later durable grants, including when the counterpart changed after signing or lease. A proactive queued-work sweep for every implicit proof invalidation is not implemented; no single positive ownership-transition hook covers that set. Local grant tests do not establish interruption of traffic already admitted before revocation.

### Separately reviewed paired identity

The existing entry-path comparison planner accepts `origin.identity_pair.head.v1` / `origin-identity-head-v1`, and the analogous GET IDs. Select **exactly one active origin entry path**, anchored on the protected target. The baseline is inside that same job; do not include an additional primary-route job. The UI provides explicit HEAD/GET modes and displays both targets, proof references, exact request scope and limits in the Start confirmation.

The immutable `paired_plan` is included in the existing reviewed plan digest. Only the comparison service's server-internal reviewed context can authorize its start; ordinary direct run starts cannot fabricate it. Signed `constraints.origin_identity_pair` includes both destinations/proofs, binding, method/scenario, Host/SNI/port/path, comparison scope digest and aggregate limits. Worker preflight vets both destinations before either request and preserves public-IP pinning, cancellation, operation accounting and kill switches.

Bounds: two HTTP requests, at most two DNS questions, no redirects/retries/assets, 5,000 ms total; GET reads at most 8,192 body bytes per leg / 16,384 total. HEAD remains bodyless. Both legs share the same job nonce, worker and exact scope. The existing fresh-comparable nonce predicate (at most 60 seconds) is unchanged. Content/certificate/title similarity alone supports only an association; generic/challenge/error/truncated or unhealthy responses cannot become nonce-confirmed application proof. TLS certificate trust/name evidence is recorded independently, not implied by successful transport.

These checks remain E2 observation-only, with no positive readiness/lockdown assurance. A confirmed direct application path is not proof of bypassing a particular WAF rule or DDoS capacity. The ordinary `host_sni_bypass` profiles still send at most one HEAD. `nfw.origin_lockdown.safe` remains violation-only. Typed positive `declared_origin_lockdown` acceptance is not closed by this work.

The remainder below describes the established one-HEAD path; paired jobs add the separately reviewed contract above rather than expanding that path silently.

## Run start — origin scope gate

`startTestRun` (dev in `src/services/testRuns.mjs`, Postgres in `src/persistence/postgres/validationServiceAdapters.mjs`):

1. `validateHostSniTargetBinding(check, target)` — signed-worker Host/SNI checks require the run target itself to be an IP literal or an IP-literal URL. `probe_profile.direct_ip` and target metadata `direct_origin_ip` cannot select another destination.
2. When `origin_binding_id` is present, `validateOriginBindingForRun` (in `src/services/originBindings.mjs`) enforces:
   - the binding is `active` and belongs to the same tenant,
   - the run target is exactly the binding's origin target (an IP literal),
   - the check's probe profile is `host_sni_bypass`,
   - the scope is re-derived from the protected target's current declaration and matches the stored binding exactly (`scope_mismatch` otherwise),
   - BOTH proofs (origin and protected) are current (`dns_verified` or stronger). Body keys `direct_ip`, `discovered_endpoint(s)`, `endpoint`, `destination` are banned outright.
3. Only the validated `{host, sni, port, path}` leaves that gate. It is captured into the run's provenance stamp:

```json
provenance_json: { ...derivation_stamp, origin_scope: { host, sni, port, path } }
```

A request body or target metadata can never supply `origin_scope`; only the server-side gate writes it. No binding → no snapshot → legacy unbound behavior.

## Signed job serialization

`buildSignedProbeJobRecord` (`src/lib/probeJobs.mjs`):

- Fails closed FIRST: a bound run — non-empty `origin_binding_id` — without a shape-valid approved scope snapshot in its provenance stamp throws `BoundRunScopeMissingError` (`code: 'bound_run_missing_approved_origin_scope'`) before any signing, job record, or dispatch. Target metadata (e.g. `protected_host`) or a caller probe profile can never stand in for a missing stored scope, and no dangerously "unbound" job is emitted from a bound legacy/recovery record. Genuinely unbound jobs (`origin_binding_id` absent) keep legacy behavior unchanged.
- Merges catalog profile + request override + target metadata, then `bindProbeProfileDestinationsToTarget` pins socket destinations to the verified target.
- `runBoundOriginScope(run, check)` reads ONLY `run.provenance_json.origin_scope` and only for a run carrying `origin_binding_id`. The snapshot is shape-validated (self-consistent host/sni, bounded port, safe path); a malformed bound snapshot fails closed at signed-job construction, never legacy unbound execution.
- For a bound run the merged `protected_host` label is replaced with the approved scope host, and `constraints.origin_scope` carries the exact approved Host/SNI/port/path.
- The signing payload covers `check_id, constraints (incl. origin_scope), id, nonce_hash, probe_profile, target, tenant_id, test_run_id` — so any tamper with the scope carrier, the profile label, or the target descriptor breaks `verifyProbeJobSignature`.
- `target.value` remains the independently verified origin IP literal (the socket destination); the Host/SNI/port/path are application-layer labels only.

## Worker execution

`approvedSignedOriginScope` (`src/lib/capabilityProbes.mjs`) consumes `constraints.origin_scope` after the same shape validation. `resolveHostSniTargets` then resolves:

- `hostname`/`hostHeader` = approved scope host (SNI equals host by derivation),
- `requestPort`/`requestPath` = approved scope port/path (URL targets are rebuilt onto the approved port/path, never their own),
- `directIp` = the target-bound literal (never `probe_profile.direct_ip` or metadata `direct_origin_ip`).

`probeHostSniBypass` vets and pins the direct destination, then issues one bounded HEAD with the protected Host header and TLS SNI. Budgets, deadlines, and destination pinning are unchanged for unbound jobs.

## Dispatch recovery

`repairSignedDispatch` (Postgres adapter) re-dispatches a durable policy/scan occurrence whose run row committed:

- rebuilds a missing probe job via `buildSignedProbeJobRecord` using the run re-read from storage — the persisted `provenance_json.origin_scope` round-trips through `mapTestRunRow`, so the rebuilt signature covers the exact approved scope, not caller input;
- refuses a binding conflict instead of silently re-signing when the persisted run nonce no longer matches a live job (`probe_dispatch_binding_conflict`);
- repairs the run correlation (`probe_job.dispatch_recovered` audit, `probe_job_recreated` flag) when the run was committed before its correlation landed;
- fails closed when the run is bound and its stored approved scope is missing or invalid: the unsafe rebuild is dropped, `probe_job.dispatch_recovery_blocked` is audited with `reason: 'bound_run_missing_approved_origin_scope'`, and the replay returns `probe_dispatch_recovery_scope_blocked` (503, `retryable: false`). The runtime request body can never repair a missing stored scope. Through the scan-recovery contract the bound run is then marked truthfully terminal (`cancelled`, `summary.dispatch_failed`) instead of ever dispatching a wrong-scope job.

On a new run's dispatch path a missing-scope build failure surfaces as `probe_job_dispatch_failed` (503) with the typed `reason` audited; the dev runtime drops the started run intent, and the Postgres runtime cancels the committed row — no orphaned run, no job.

## Finalization semantics

`verdictExpectedBehaviorForRun` (`src/lib/checkDefinitionVersion.mjs`):

- A stamped run (`producer_kind` set) finalizes ONLY against the immutable `expected_behavior_json` snapshot captured at start — a catalog change while the run collects cannot change outcome semantics.
- A stamped run with no recorded snapshot reports `null` truthfully → verdict `inconclusive`, never a phantom PASS.
- Only legacy unstamped runs keep the historical today-catalog fallback (`resolveExpectedBehaviorForCheck`).

`deriveRunEvidenceStamp` derives `check_version` (explicit catalog version else canonical digest), `scenario_version` (catalog/approved runtime only), and `producer_kind` (server-derived; request bodies can never supply any of these — `version`, `producer_kind`, `check_version`, `expected_behavior` in a body are ignored and recorded in `ignored_body_fields`).

## Verdict authority on reads

Run list and detail resolve the nested verdict from the published verdict store only, scoped to the same tenant and run (`listVerdictsForRuns` in Postgres, the `verdicts` store in dev JSON). A raw `run.verdict` string or the run status never invents a verdict: an unbacked run projects `verdict: null`. Nested verdict shapes keep their semantic fields; customer projections are scrubbed via `scrubRunForCustomer`.

## Catalog safety guard (unchanged)

`GET /v1/checks` (global catalog) intentionally excludes checks where `checkRequiresAdditionalInput` is true, including the four `host_sni_bypass` definitions; they remain resolvable through `GET /v1/checks/:id` and scoped catalog reads. Do not weaken that guard.

## Tests

- `tests/unit/current-release-origin-job-binding.test.mjs` — dev start/job/signature/TLS-starter scope matching, provenance-only scope derivation, snapshot finalization (drift, legacy fallback, null snapshot), and fail-closed negatives: bound legacy/recovery record with missing/invalid scope (including the metadata `protected_host` fallback repro) throws `BoundRunScopeMissingError` and never builds or signs a job; genuine unbound jobs stay supported. Zero DNS, zero sockets: resolvers throw if contacted and the TLS starter is a local capturing stub.
- `tests/integration/postgres-current-release-origin-job-binding.test.mjs` — real ephemeral Postgres: bound signed-worker start, recovery rebuild of a lost dispatch from the persisted snapshot, snapshot finalization under catalog drift, legacy fallback, null-snapshot inconclusive, list verdict authority (no invented verdict from `completed` status), and the fail-closed repair negative: a bound recovery run without its stored approved scope is reported blocked (503, `retryable: false`, audited `probe_job.dispatch_recovery_blocked`), no job is created, no duplicate run intent is committed, and the bound run is truthfully marked `dispatch_failed` instead of re-signed.
- `tests/unit/current-release-backend-history.test.mjs` — version/producer stamp derivation and body-field immunity.
