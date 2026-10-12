import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { buildSignedProbeJobRecord, probeAuthority, signProbeJob, verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import { executionReservation, probeExecutionReceipt } from '../../src/lib/probeExecution.mjs';
import { projectRunActivity, probeActivityEvent } from '../../src/lib/probeActivity.mjs';
import { authenticateProbeWorker, probeWorkerAuthHeaders } from '../../src/services/probeCoordinator.mjs';
import { createProbeActivityReporter } from '../../workers/probe-activity-reporter.mjs';
import { processJob } from '../../workers/probe-worker.mjs';

const secret = 'verified-authority-secret-32-characters!!';
function fixture(now = new Date()) {
  const check = getCheckById('waf.fingerprint.safe');
  const run = { id: 'run_authority', tenant_id: 'ten_authority', target_id: 'target_authority', check_id: check.check_id,
    created_at: now.toISOString(), status: 'running', collection_deadline_at: new Date(now.getTime() + 120_000).toISOString() };
  const target = { id: run.target_id, kind: 'url', value: 'https://fixture.test/declared' };
  const job = buildSignedProbeJobRecord({ run, target, check, probeWorkerSecret: secret, now, newId: () => 'pjob_authority' });
  Object.assign(job, { status: 'leased', leased_at: now.toISOString(), leased_by: 'worker_authority' });
  return { run, job, target, check };
}

test('absolute authority is signed, bounded, and not renewed by recovery', () => {
  const now = new Date();
  const { run, job, target, check } = fixture(now);
  assert.equal(probeAuthority(job, now).ok, true);
  const recovered = buildSignedProbeJobRecord({ run, target, check, probeWorkerSecret: secret,
    now: new Date(now.getTime() + 60_000), newId: () => 'pjob_recovery' });
  assert.equal(recovered.constraints.not_after, job.constraints.not_after);
  assert.equal(probeAuthority(recovered, new Date(now.getTime() + 120_000)).reason, 'probe_authority_expired');
  job.constraints.not_after = new Date(now.getTime() + 180_000).toISOString();
  assert.equal(verifyProbeJobSignature(job, secret), false);
  job.job_signature = signProbeJob(job, secret);
  assert.equal(probeAuthority(job, now).reason, 'probe_authority_invalid');
});

test('expired and legacy signed jobs cannot execute any destination I/O', async () => {
  for (const legacy of [false, true]) {
    const { job } = fixture(new Date(Date.now() - 180_000));
    if (legacy) delete job.constraints.authority_version;
    job.job_signature = signProbeJob(job, secret);
    let io = 0;
    const result = await processJob({ secret }, job, { fetchFn: () => { io += 1; }, resolve4Fn: () => { io += 1; } });
    assert.equal(io, 0);
    assert.equal(result.safety_attestation.requests_sent, 0);
    assert.equal(result.metadata.error_class, legacy ? 'probe_authority_invalid' : 'probe_authority_expired');
  }
});

test('worker identity tampering invalidates pw2 authentication', () => {
  const config = { probeMode: 'signed-worker', probeWorkerSecret: secret };
  const headers = probeWorkerAuthHeaders('worker_authority', { method: 'GET', path: '/internal/probe/jobs', tenantId: 'ten_authority' }, secret);
  assert.equal(authenticateProbeWorker(headers, 'GET', '/internal/probe/jobs', '', config).ok, true);
  headers['x-probe-worker-id'] = 'worker_other';
  assert.equal(authenticateProbeWorker(headers, 'GET', '/internal/probe/jobs', '', config).status, 401);
});

test('whole operation budget is one-shot and a reclaimed unknown budget is never refunded', () => {
  const { job } = fixture();
  const first = executionReservation(job, job.leased_by, job.leased_at, 'reservation_1');
  assert.ok(first.reservation);
  assert.equal(first.reservation.max_total_operations, job.constraints.max_total_operations);
  job.worker_metadata.execution_reservation = first.reservation;
  assert.equal(executionReservation(job, job.leased_by, job.leased_at, 'reservation_2').error, 'probe_budget_already_reserved');
  Object.assign(job, { leased_at: new Date().toISOString(), leased_by: 'worker_reclaimed' });
  assert.equal(executionReservation(job, job.leased_by, job.leased_at, 'reservation_3').error, 'probe_budget_already_reserved');
});

test('positive result evidence requires the exact durable reservation and lease lineage', () => {
  const { job } = fixture();
  const attestation = { requests_sent: 1 };
  assert.equal(probeExecutionReceipt(job, job.leased_by, attestation, 'connected').error, 'probe_execution_not_reserved');
  job.worker_metadata.execution_reservation = executionReservation(job, job.leased_by, job.leased_at, 'reservation_receipt').reservation;
  assert.equal(probeExecutionReceipt(job, job.leased_by, attestation, 'connected').ok, true);
  assert.equal(probeExecutionReceipt(job, 'worker_other', attestation, 'connected').status, 409);
  job.leased_at = new Date(Date.now() + 1).toISOString();
  assert.equal(probeExecutionReceipt(job, job.leased_by, attestation, 'connected').status, 409);
  assert.equal(probeExecutionReceipt(job, job.leased_by, { requests_sent: 0 }, 'not_run').ok, true);
});

test('persistent reporting failures stop work and retain loss statistics', async () => {
  let stopped;
  const reporter = createProbeActivityReporter(fixture().job, async () => ({ status: 503 }), {
    heartbeatMs: 5, partitionGraceMs: 40, onStop: (value) => { stopped = value.reason; },
  });
  reporter.record({ stage: 'request_started', method: 'GET', url: 'https://fixture.test/declared' });
  await reporter.close();
  assert.equal(stopped, 'control_plane_unavailable');
  assert.ok(reporter.snapshot().delivery_failures > 0);
  assert.ok(reporter.snapshot().dropped_count > 0);
});

test('a hung reporter fails closed without waiting for its unresponsive transport', async () => {
  let stopped = false;
  const reporter = createProbeActivityReporter(fixture().job, () => new Promise(() => {}), {
    heartbeatMs: 5, partitionGraceMs: 30, onStop: () => { stopped = true; },
  });
  reporter.record({ stage: 'job_started' });
  await reporter.close();
  assert.equal(stopped, true);
});

test('capture overflow is explicit and paging preserves every available immutable event', async () => {
  const { run, job } = fixture();
  const sent = [];
  const reporter = createProbeActivityReporter(job, async (batch) => { sent.push(batch); return { status: 201 }; });
  for (let i = 0; i < 300; i += 1) reporter.record({ stage: 'attempt_started', operation: 'http' });
  await reporter.close();
  assert.equal(reporter.snapshot().recorded_count, 256);
  assert.equal(reporter.snapshot().dropped_count, 44);
  job.worker_metadata.capture = reporter.snapshot();
  const events = sent.flatMap((batch) => batch.items.map((item) => ({ ...probeActivityEvent(job, item, job.leased_by), ingested_at: item.at })));
  const ids = [];
  let cursor = null;
  let page;
  do {
    page = projectRunActivity(run, events, { job, limit: 7, cursor });
    assert.equal(page.capture.status, 'incomplete');
    ids.push(...page.items.map((item) => item.id));
    cursor = page.pagination.next_cursor;
  } while (page.pagination.has_more);
  assert.equal(ids.length, 257);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(projectRunActivity(run, events, { cursor: 'foreign-event' }).status, 400);
});

test('out-of-order observed times do not hide events received after an incremental cursor', () => {
  const { run, job } = fixture();
  const first = { ...probeActivityEvent(job, { sequence: 1, at: run.created_at, stage: 'job_started' }, job.leased_by), ingested_at: run.created_at };
  const initial = projectRunActivity(run, [first], { limit: 256, job });
  const late = { ...probeActivityEvent(job, { sequence: 2, at: new Date(Date.now() - 1000).toISOString(), stage: 'attempt_started' }, job.leased_by), ingested_at: new Date(Date.now() + 1).toISOString() };
  const update = projectRunActivity(run, [first, late], { cursor: initial.pagination.next_cursor, job });
  assert.equal(update.items.length, 1);
  assert.equal(update.items[0].id, late.id);
});

test('database cancellation remains Stop requested until an authenticated worker acknowledgment', () => {
  const { run, job } = fixture();
  run.status = 'cancelled'; run.completed_at = new Date().toISOString();
  const pending = projectRunActivity(run, [], { job });
  assert.equal(pending.stop.state, 'requested');
  assert.equal(pending.items.at(-1).stage, 'stop_requested');
  job.worker_metadata.stop_acknowledgment = { acknowledged_at: new Date().toISOString(), reason: 'job_revoked' };
  assert.equal(projectRunActivity(run, [], { job }).stop.state, 'acknowledged');
});
