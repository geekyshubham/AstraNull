# ADR-0006: Validation Scans as Sequential Test-Run Batches

## Status

Accepted.

## Context

A test run in AstraNull is exactly one check against one exact target, and the control plane allows only one active run per target group (`uniq_active_test_run`). Every safety gate lives inside `startTestRun`: SOC-gated refusal, tenant kill switch, declared target and ownership proof, safe test windows, hourly rate cap, cooldown, concurrency, prerequisites, and audit. Test policies schedule a single check on a cadence but cannot express "run these N checks now and show me progress".

Customers need an on-demand validation run with explicit check selection, live per-check progress, a metadata-only activity log, a Stop control, and scheduled scans that reuse the identical path. Changing `test_runs` to hold several checks would have touched verdict uniqueness, correlation, probe-job signing, and the vector-library truth model.

## Decision

Introduce a parent **validation scan** record that orchestrates existing test runs.

- A scan holds an ordered plan of steps, one per compatible check and target pair. Scope is either one exact target or every active, compatible target in the group. Incompatible pairs are recorded as excluded at plan time, never run.
- Steps execute **sequentially**. The executor starts the next step by calling the unchanged `startTestRun` with a server-side `scanDispatch` option carrying the scan id, step id, and a short-lived lease token. HTTP callers cannot supply this option; a forged or stale context is refused with `scan_dispatch_invalid`. Child runs record `scan_id` and `scan_step_id`.
- No gate is bypassed or duplicated. Denials from `startTestRun` are classified: cooldown defers the step until the group's minimum interval elapses; the hourly safe-run cap (`safe_rate_cap_exceeded`) and the subscription limit (`entitlement_limit_exceeded`) defer the step until the oldest run in the rolling hour ages out; window, kill switch, suspension, and foreign concurrency deny the remaining steps and finish the scan with partial results; per-step problems deny only that step. Every transition is audited under `validation_scan.*`.
- Scheduled and recurring scans start their steps under the `validation-scan-scheduler` system identity (with `on_behalf_of` the creator), matching test-policy dispatch, so a later role change of the creator does not alter or block governed execution. Run-now scans keep the creator's identity. Scan-driven starts in Postgres also refuse suspended tenants.
- Every scan write is guarded. Executor writes require the scan to still be `pending` or `running`; dispatch writes require `scheduled` plus the dispatcher's lease token; PATCH requires `scheduled` with no live lease; step links require the step to still be `starting`. A guard miss stops the writer instead of overwriting a concurrent Stop, edit, or dispatch. Dispatch activation and PATCH replace steps in the same transaction as the scan row, and one failing scan no longer aborts the tenant's dispatch tick (`validation_scan.dispatch_failed`).
- Probe signing fails closed. Any process that can advance a scan (API, `validation-scan-runner`, `collection-window-sweeper` through run-terminal hooks) resolves probe mode and secret with the same validated, trimmed loader as the API. Without valid signing material the next step is not started and `validation_scan.advance_blocked` is audited; a correctly configured runner resumes it. A signed-worker run is never left `running` without its probe job: missing material is refused before the run is written, a probe-job creation failure cancels the run (`summary.dispatch_failed`, step `probe_dispatch_failed`), and a scan step that replays onto a committed run recreates a missing probe job exactly like test-policy recovery.
- Scheduled scans are the same record in `scheduled` state with `scheduled_for` and optional daily, weekly, or monthly recurrence. Dispatch re-checks kill switch, suspension, group state, safe window, and concurrency; a scan that lands outside a window is denied and audited, never forced. Recurring scans create the next occurrence idempotently by occurrence key.
- Stop marks the scan cancelled first, cancels every active child bound to the scan through the existing cancel path, and skips pending steps. After each start the executor re-checks the scan; a child that committed after Stop is cancelled and audited. `cancel_series` cancels every scheduled occurrence in the series, and a dispatcher that created the next occurrence concurrently cancels it when it finds the series stopped. Run cancellation also revokes pending agent jobs and records actor and reason.
- No daemon runs inside the API process. Progress advances through run-terminal hooks, the read path for callers holding `test_run:start` (read-only roles never trigger dispatch or starts), and a tenant-scoped operator runner for Postgres deployments.
- The activity cursor follows ingestion order (audit sequence and `events.ingested_at`, migration 0055) rather than event time, so late agent observations are never skipped. Migration 0055 also indexes audit `metadata_json->>'scan_id'` and `->>'test_run_id'` for the activity query.
- Progress and activity are projections of existing data: probe profile and probe job constraints for the request, probe result metadata and safety attestation for the response and request counts, the verdict record for the outcome, and audit rows plus run events for the log. Only allowlisted metadata keys are exposed.

## Consequences

| Positive | Negative |
|---|---|
| Verdict, correlation, probe signing, and safety gates are unchanged and remain single-sourced in `startTestRun`. | Scan wall-clock time is the sum of its child runs; a cooldown defers the whole scan. |
| Metadata-only progress and log reuse existing records with no new transport. | Group-level denials abort the remainder of a scan with partial results. |
| Scheduled and on-demand scans share one executor, so safety behaviour cannot drift. | Postgres progress between runner ticks depends on hooks and the read path. |
| Stop is reliable mid-run: pending steps never start and revoked jobs are never leased. | Two new tenant-isolated tables and a run-level column pair must be migrated and validated. |
