# Test Orchestration Engine

## Purpose

The Test Orchestration Engine turns a target group and selected checks into an executable, safe, evidence-backed test run.

## Inputs

| Input | Source |
|---|---|
| Tenant/user permissions | Auth/RBAC. |
| Target group | Target service. |
| Targets and expected behavior | Target group config. |
| Bound agents | Agent service. |
| Enabled checks | Check catalog. |
| Risk class | Check catalog. |
| Test window | Target group settings. |
| Safety caps | Check catalog and tenant settings. |

## Planner output

| Output | Description |
|---|---|
| Test run | Parent execution record. |
| Probe jobs | External probe tasks with target, nonce, timing, caps. |
| Agent jobs | Observation prep tasks sent over outbound channel. |
| Correlation rules | Expected event pairs and time windows. |
| Timeout rules | When to mark no observation/inconclusive. |
| Evidence manifest | What evidence must be stored. |

## Execution lifecycle

```text
Created
  -> Validating
  -> Waiting for Agent Ack
  -> Running Probes
  -> Waiting for Observations
  -> Correlating
  -> Verdict Emitted
  -> Findings Updated
  -> Completed
```

Failure states:

- cancelled,
- timed out,
- agent unavailable,
- unsafe window,
- permission denied,
- high-scale approval required,
- probe worker failed,
- correlation failed.

## Safety checks before execution

| Check | Required |
|---|---|
| User has permission | Yes |
| Target is declared | Yes |
| Agent is bound or check can run externally only | Yes |
| Check risk class is allowed | Yes |
| Current time is allowed window | When `safe_test_windows` configured on target group |
| Tenant `max_runs_per_hour` not exceeded | Yes (default 60 customer-runnable runs/hour) |
| Target group `min_seconds_between_runs` satisfied | When configured |
| Per-run `max_events` not exceeded | Yes on probe ingest, agent observations, no-observation marker |
| Rate/concurrency caps exist | Yes |
| High-scale approval not required for safe run | Yes |
| Duplicate overlapping run blocked | Yes |

Each started run stores merged `safety_constraints` (check caps plus target group `safety_policy`).

## Cancel semantics

`POST /v1/test-runs/:id/cancel` succeeds only for `planned`, `running`, or `collecting` runs. Terminal runs (`verdicted`, `cancelled`, etc.) return HTTP `409` with `{ error: "not_cancellable" }`. The optional body `{ reason }` is recorded on the run as `summary.cancellation` and in the `test_run.cancelled` audit entry together with `cancelled_by`, `cancelled_by_role`, `source`, and the revoked `cancelled_probe_job_ids` and `cancelled_agent_job_ids`. Pending or leased probe jobs and pending or acked agent jobs for the run are flipped to `cancelled`, so workers and agents never lease them afterwards.

## Validation scans (multi-check orchestration)

A validation scan is the customer-facing on-demand run. It is a parent record over ordinary test runs, not a new execution path (see [ADR-0006](../adr/0006-validation-scans-as-sequential-test-run-batches.md)).

| Concept | Behaviour |
|---|---|
| Plan | `check_ids` (1 to 500 customer-runnable safe checks, at most 500 planned steps — enough for one "run all checks" scan over the full catalog for one target) times either one exact `target_id` or every active target in the group. Pairs whose `supported_targets` exclude the target kind are recorded in `excluded` and never run. Selecting a SOC-gated, monitor-only, or unknown check fails the whole request (`403 soc_gated_check`, `400 unknown_check`). |
| Execution | Steps run one at a time because only one run may be active per target group. Each step calls `startTestRun` with a server-side `scanDispatch` context (scan id, step id, lease token). Child runs carry `scan_id` and `scan_step_id`. |
| Denial handling | `safe_min_interval_active` and the rolling hourly caps (`safe_rate_cap_exceeded`, `entitlement_limit_exceeded`) defer the step until the cooldown or hour window clears, so a long scan paces itself instead of failing. `safe_window_closed`, `kill_switch_active`, `tenant_suspended`, and a foreign `concurrent_run_blocked` deny the remaining steps and finish the scan. Per-step errors such as `prerequisites_not_met` or `ownership_not_verified` deny only that step. |
| Statuses | Scan: `scheduled`, `pending`, `running`, `completed`, `denied`, `cancelled`. Step: `pending`, `deferred`, `starting`, `running`, `collecting`, `verdicted`, `denied`, `skipped`, `cancelled`. |
| Progress | `GET /v1/validation-scans/:id` projects each step with the bounded request (`kind`, `method`, `path`, `protocol`, `max_requests`, `timeout_ms` from the probe profile and signed job constraints), the response (`external_result`, `status_code`), `requests_sent` from the worker safety attestation (`0` with `requests_simulated: true` in simulation mode), and the verdict record. |
| Activity | `GET /v1/validation-scans/:id/activity` merges `validation_scan.*` audit rows, child run audit rows, and child run events into one chronological metadata-only feed with allowlisted metadata keys. |
| Stop | `POST /v1/validation-scans/:id/cancel` marks the scan cancelled first, cancels the active child run through `cancelTestRun`, skips pending and deferred steps, and audits `validation_scan.cancelled`. A racing executor start is refused by `scan_dispatch_invalid`. |
| Scheduling | `scheduled_for` (at least one minute ahead) with optional `recurrence` (`daily`, `weekly`, `monthly` plus IANA timezone). Due scans are dispatched after re-checking kill switch, tenant suspension, group state, safe test window, and group concurrency; a denial sets status `denied`, audits `validation_scan.schedule_denied`, and never force-runs. Recurring scans create the next occurrence idempotently (`occurrence_key`). Only `scheduled` scans can be edited. |
| Advancement | No daemon in the API process. Run-terminal hooks (`src/services/runTerminalHooks.mjs`) advance the parent when a child verdicts or cancels; the read path advances active scans and dispatches due scans in dev-json mode; Postgres deployments run `npm run validation-scan:runner -- --tenant-id <tenant>` from a CronJob. |
| Audit | `validation_scan.created`, `scheduled`, `updated`, `dispatched`, `schedule_denied`, `step_started`, `step_deferred`, `step_denied`, `step_skipped`, `step_completed`, `cancelled`, `series_stopped`, `completed`, `advance_failed`, `create_denied`, `cancel_denied`. |

## Probe execution modes

| Mode | Config | Behavior |
|---|---|---|
| `simulation` | Default when `NODE_ENV` is not `production` (`ASTRANULL_PROBE_MODE` unset); **refused** if set explicitly when `NODE_ENV=production` | Metadata-only `SAFE_PROBE_SIMULATION` via in-process stub; immediate `probe_result` event for developer validation and CI only. |
| `signed-worker` | Default when `NODE_ENV=production`; requires `ASTRANULL_PROBE_WORKER_SECRET` (at least 32 decoded high-entropy bytes; e.g. `openssl rand -hex 32`) | Planner creates a signed `probeJobs` record with `max_probe_requests`, destination-resolver floor/cap, `max_total_operations` (also exposed as compatibility `max_requests`), and `timeout_ms` derived from `max_duration_seconds` and capped at `5000` unless lower. AstraNull-owned workers run `node workers/probe-worker.mjs` (env: `ASTRANULL_API_URL`, `ASTRANULL_PROBE_WORKER_ID`, `ASTRANULL_PROBE_WORKER_SECRET`, optional `ASTRANULL_PROBE_ONCE`, `ASTRANULL_PROBE_POLL_INTERVAL_MS` bounded 1s–60s; in Postgres mode also `ASTRANULL_PROBE_TENANT_ID` or `--tenant-id`). Workers HMAC-authenticate poll/result requests, bind tenant identity into `x-probe-tenant-id` when configured, verify each `job_signature`, reserve every logical probe and destination-vetting resolver attempt before I/O, execute only the allowlisted bounded profile, and post metadata-only results with exact split `safety_attestation`; the control plane rejects incomplete, incoherent, over-cap, or over-time results. Postgres mode wires the full safe validation loop through `runtime.services.testRuns` and `runtime.services.probeJobs`: safe-run start/cancel, signed job creation, worker lease/result ingestion, agent observation ingestion with exact-once job transition, probe/agent correlation, automatic verdict publication when both sides correlate, forced no-observation finalization after the observation window, and finding upsert from verdicts (with audit logging and metadata-only raw-field rejection). Run stays `running` until a compliant probe result is ingested, then `collecting` for agent correlation. **Release blockers** remain live/staging Postgres acceptance, tenant concurrency hardening, and production probe-worker fleet evidence — not loop wiring. Fleet deployment and multi-region ops remain outside this CLI. |

### Signed-job destination binding

For normal test jobs, every profile- or target-metadata-selected socket destination is bound to the exact verified target host after all catalog, body, and metadata merges. Alternate `direct_ip`, `resolver_host`, `secondary_nameservers`, `direct_origin_ip`, `alert_webhook_url`, and `webhook_url` values are removed (same-target values may remain). Host/SNI `protected_host` and bounded paths/query names remain non-destination metadata. Host/SNI signed-worker runs require the target itself to be an IP or an IP-literal URL and fail before persistence with `missing_target_bound_direct_address` otherwise; the same shared builder applies to Postgres recovery jobs.

## Job model

### Probe job

```json
{
  "job_id": "probe_job_123",
  "test_run_id": "run_123",
  "check_id": "origin_bypass_v1",
  "target": "203.0.113.10:443",
  "protocol": "HTTPS",
  "nonce": "generated-per-probe",
  "constraints": {
    "max_probe_requests": 1,
    "min_destination_resolver_attempts": 0,
    "max_destination_resolver_attempts": 0,
    "max_total_operations": 1,
    "max_requests": 1,
    "timeout_ms": 5000,
    "source_regions": ["us-east"]
  }
}
```

### Agent job

```json
{
  "job_id": "agent_job_123",
  "test_run_id": "run_123",
  "agent_id": "agent_123",
  "observe_for_nonce_hash": "hash",
  "observe_window_ms": 15000,
  "modes": ["packet_metadata", "canary_listener", "log_tail"]
}
```

## Signed probe fleet matrix evidence

Multi-region signed probe worker staging is tracked separately from in-process simulation and single-worker developer validation. Operators capture **metadata-only** fleet matrix evidence (regions, redacted worker IDs, control pass/fail, bounded probe profile kinds exercised) and validate it with:

```bash
node scripts/probe-fleet-matrix-evidence.mjs \
  --input path/to/probe-fleet-matrix-input.json \
  --out output/probe-fleet-matrix-evidence.json
```

`--validate-only` checks the input contract without writing output. Unit tests: `tests/unit/probe-fleet-matrix-evidence.test.mjs`.

The validator enforces:

| Dimension | Evidence shape |
|---|---|
| Regions | Required `us-east`, `eu-west`, `ap-southeast` rows with `worker_id_redacted`. |
| Signed job route | Poll `/internal/probe/jobs` and a result path under `/internal/probe/jobs/:id/result`. |
| Signature coverage | Per region: `job_signature_verified`, `tenant_header_signing`, `worker_hmac_auth` passed. |
| Health / governance | `health_status`, `rate_budget`, `egress_controls`, `abuse_monitoring` control rows. |
| Bounded profiles | Fleet must record exercise of each allowed safe profile kind (`http_head`, `tcp_connect`, `dns_resolve`, `metadata_marker`). |

Rejected inputs include raw requests/responses, packet captures, target IP inventories, secrets, worker HMAC secrets, and customer payloads. The output manifest lists `coverage_gaps` (`missing_regions`, `missing_probe_profiles`, `missing_signature_coverage`, `failed_controls`) without probe traffic or response bodies.

**Production note:** A passing manifest closes the **evidence shape** for probe fleet productionization only. Staging must still execute the live signed-worker fleet (lease, bounded probe, result ingest, tenant-scoped HMAC headers), attach operator evidence, and complete release signoff before production promotion.

## Completion criteria

Orchestration is complete when test runs are deterministic, bounded, auditable, retryable, and produce enough evidence for the correlation engine.
