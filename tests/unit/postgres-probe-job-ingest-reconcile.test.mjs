import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { probeJobLeaseTtlSeconds } from '../../src/persistence/postgres/probeJobRepository.mjs';

const TENANT = 'ten_demo';
const WORKER = 'pw_worker_1';
const OTHER_WORKER = 'pw_worker_2';
const WORKER_CTX = { tenantId: TENANT, workerId: WORKER, role: 'probe_worker' };
const OTHER_WORKER_CTX = { tenantId: TENANT, workerId: OTHER_WORKER, role: 'probe_worker' };
const NOW = '2026-06-01T12:00:00.000Z';
const CONSTRAINTS = { max_requests: 1, timeout_ms: 5000, max_duration_seconds: 120 };

const VALID_BODY = Object.freeze({
  external_result: 'connected',
  safety_attestation: { requests_sent: 1, duration_ms: 10 },
});

/**
 * In-memory stand-in for the probe-job + validation-evidence repositories.
 *
 * `appendProbeResultEventIdempotent` mirrors the real ON CONFLICT upsert keyed by
 * (tenant, run, signal_type, nonce_hash) so replays collapse onto one row, which is what makes
 * the reconciliation path meaningful rather than a fiction of the fake.
 */
function createHarness(options = {}) {
  const state = {
    runs: new Map(),
    jobs: new Map(),
    events: [],
    evidence: [],
    audit: [],
    completedCalls: [],
    updateCalls: [],
  };
  let failUpdateTestRunOnce = false;

  const probeJobs = {
    async leasePendingJobsForWorker() {
      return [];
    },
    async getJobById(ctx, id) {
      const job = state.jobs.get(id);
      return job && job.tenant_id === ctx.tenantId ? { ...job } : null;
    },
    async claimPendingJobForWorker(ctx, id, workerId, leasedAt) {
      const job = state.jobs.get(id);
      if (!job || job.status !== 'pending') return null;
      job.status = 'leased';
      job.leased_by = workerId;
      job.leased_at = leasedAt;
      return { ...job };
    },
    async markJobCompleted(ctx, id, completedAt) {
      const job = state.jobs.get(id);
      if (!job) return null;
      state.completedCalls.push({ id, completedAt });
      job.status = 'completed';
      job.completed_at = completedAt;
      return { ...job };
    },
    async createProbeJob(ctx, record) {
      state.jobs.set(record.id, { ...record, tenant_id: ctx.tenantId });
      return { ...record };
    },
    async cancelOpenProbeJobsForTestRuns() {
      return [];
    },
  };

  const validationEvidence = {
    async getTestRun(ctx, id) {
      const run = state.runs.get(id);
      return run ? { ...run } : null;
    },
    async listRunEvents(ctx, runId, opts = {}) {
      return state.events
        .filter((e) => e.test_run_id === runId)
        .filter((e) => (opts.signalType ? e.signal_type === opts.signalType : true))
        .map((e) => ({ ...e }));
    },
    async appendProbeResultEventIdempotent(ctx, record) {
      const existing = state.events.find(
        (e) =>
          e.test_run_id === record.test_run_id &&
          e.signal_type === 'probe_result' &&
          e.nonce_hash === record.nonce_hash,
      );
      if (existing) {
        Object.assign(existing, { ...record, id: existing.id, signal_type: 'probe_result' });
        return { ...existing };
      }
      const row = { ...record, signal_type: 'probe_result' };
      state.events.push(row);
      return { ...row };
    },
    async appendEvidence(ctx, record) {
      state.evidence.push({ ...record });
      return { ...record };
    },
    async updateTestRun(ctx, id, patch) {
      if (failUpdateTestRunOnce) {
        failUpdateTestRunOnce = false;
        throw new Error('simulated crash after event write');
      }
      state.updateCalls.push({ id, patch: { ...patch } });
      const run = state.runs.get(id);
      Object.assign(run, patch);
      return { ...run };
    },
  };

  const audit = {
    async appendAuditEvent(entry) {
      state.audit.push(entry);
      return entry;
    },
  };

  const repositories = { probeJobs, validationEvidence, audit };
  if (options.killSwitchActive !== undefined) {
    repositories.killSwitch = {
      async isKillSwitchActiveForTenant() {
        return options.killSwitchActive;
      },
    };
  }

  const svc = createPostgresProbeJobServices(repositories, {
    now: () => new Date(options.now ?? NOW),
    newId: (prefix) => `${prefix}_${state.events.length + state.evidence.length + 1}`,
  });

  return {
    state,
    svc,
    crashNextRunPatch() {
      failUpdateTestRunOnce = true;
    },
    seedRun(id, overrides = {}) {
      state.runs.set(id, {
        id,
        tenant_id: TENANT,
        status: 'running',
        correlation: { seeded: true },
        awaiting_external_probe: true,
        ...overrides,
      });
    },
    seedJob(id, overrides = {}) {
      state.jobs.set(id, {
        id,
        tenant_id: TENANT,
        test_run_id: 'run_1',
        target_id: 'tgt_1',
        check_id: 'origin.direct_bypass.safe',
        vector_family: 'origin',
        status: 'leased',
        leased_by: WORKER,
        leased_at: NOW,
        nonce_hash: 'nh_abc',
        probe_profile: { kind: 'metadata_marker' },
        constraints: CONSTRAINTS,
        completed_at: null,
        ...overrides,
      });
    },
    run() {
      return state.runs.get('run_1');
    },
    job(id = 'pjob_1') {
      return state.jobs.get(id);
    },
    probeEvents() {
      return state.events.filter((e) => e.signal_type === 'probe_result');
    },
  };
}

describe('postgres probe result ingest — crash reconciliation', () => {
  it('reconciles the run and completes the job when a retry follows a crash after the event write', async () => {
    const h = createHarness();
    h.seedRun('run_1');
      h.seedJob('pjob_1');

    // First attempt: event (and evidence) become durable, then the process dies before the
    // run patch lands. This is the state the old 409 made permanently unrepairable.
    h.crashNextRunPatch();
    await assert.rejects(() => h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY));

    assert.equal(h.probeEvents().length, 1, 'evidence is durable after the crash');
    assert.equal(h.run().awaiting_external_probe, true, 'run is left inconsistent');
    assert.equal(h.run().status, 'running');
    assert.notEqual(h.job().status, 'completed');

    // The worker's natural retry must repair, not 409.
    const retry = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(retry.error, undefined, 'retry must not be an error');
    assert.equal(retry.reconciled, true);
    assert.equal(retry.run_id, 'run_1');
    assert.equal(retry.probe_event.id, h.probeEvents()[0].id);

    assert.equal(h.run().status, 'collecting', 'run reconciled to collecting');
    assert.equal(h.run().awaiting_external_probe, false);
    assert.equal(h.run().probe_external_result, 'connected');
    assert.equal(h.run().correlation.nonce_hash, 'nh_abc');
    assert.equal(h.job().status, 'completed', 'job completed idempotently');
    assert.equal(h.probeEvents().length, 1, 'no duplicate probe event');
  });

  it('is a no-op on a second identical retry', async () => {
    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1');

    h.crashNextRunPatch();
    await assert.rejects(() => h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY));
    await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    const evidenceAfterFirstRetry = h.state.evidence.length;
    const completedAt = h.job().completed_at;
    const runAfterFirstRetry = { ...h.run() };

    const second = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(second.error, undefined);
    assert.equal(second.reconciled, true);

    assert.equal(h.probeEvents().length, 1, 'still exactly one probe event');
    assert.equal(h.state.evidence.length, evidenceAfterFirstRetry, 'no duplicate evidence row');
    assert.deepEqual({ ...h.run() }, runAfterFirstRetry, 'run state unchanged');
    assert.equal(h.job().completed_at, completedAt, 'completion timestamp not rewritten');
  });

  it('bounds reconciliation to idempotent fields — a mutated replay cannot re-drive run state', async () => {
    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1');

    h.crashNextRunPatch();
    await assert.rejects(() => h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY));
    await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(h.run().probe_external_result, 'connected');

    // A buggy or malicious worker replays with a flipped verdict. The durable event is the
    // source of truth, so the recorded result must not move.
    const tampered = { ...VALID_BODY, external_result: 'blocked' };
    await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', tampered);
    assert.equal(
      h.run().probe_external_result,
      'connected',
      'replay must not overwrite the durable verdict',
    );

    // Reconciliation never writes fields outside the fixed idempotent set.
    for (const call of h.state.updateCalls) {
      assert.deepEqual(
        Object.keys(call.patch).sort(),
        ['awaiting_external_probe', 'correlation', 'probe_external_result', 'status'].filter((k) =>
          Object.keys(call.patch).includes(k),
        ),
      );
    }
  });

  it('never resurrects a terminal run', async () => {
    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1');

    h.crashNextRunPatch();
    await assert.rejects(() => h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY));

    // Operator cancelled the run in the meantime.
    h.run().status = 'cancelled';
    await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(h.run().status, 'cancelled', 'status only moves running -> collecting');
  });
});

describe('postgres probe result ingest — reclaimed leases', () => {
  it('accepts a result from the new holder after the lease expired', async () => {
    const ttlMs = probeJobLeaseTtlSeconds(CONSTRAINTS) * 1000;
    const past = new Date(Date.parse(NOW) - ttlMs - 60_000).toISOString();

    const h = createHarness();
    h.seedRun('run_1');
    // Row still names the lost worker; the lease is long expired.
    h.seedJob('pjob_1', { status: 'leased', leased_by: WORKER, leased_at: past });

    const out = await h.svc.ingestProbeResult(OTHER_WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(out.error, undefined, 'reclaimed job must accept the new holder result');
    assert.equal(out.run_id, 'run_1');
    assert.equal(h.job().status, 'completed');
    assert.equal(h.run().status, 'collecting');
  });

  it('does not let another worker steal a job whose lease is still live', async () => {
    const ttlMs = probeJobLeaseTtlSeconds(CONSTRAINTS) * 1000;
    const recent = new Date(Date.parse(NOW) - ttlMs + 60_000).toISOString();

    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1', { status: 'leased', leased_by: WORKER, leased_at: recent });

    const out = await h.svc.ingestProbeResult(OTHER_WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(out.error, 'job_leased_to_another_worker');
    assert.equal(out.status, 403);
    assert.equal(h.probeEvents().length, 0, 'no evidence recorded for a rejected steal');
    assert.notEqual(h.job().status, 'completed');
  });

  it('fails closed when a leased job has no lease timestamp', async () => {
    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1', { status: 'leased', leased_by: WORKER, leased_at: null });

    const out = await h.svc.ingestProbeResult(OTHER_WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(out.error, 'job_leased_to_another_worker');
    assert.equal(out.status, 403);
  });

  it('still accepts the original holder within TTL', async () => {
    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1');
    const out = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(out.error, undefined);
    assert.equal(h.run().status, 'collecting');
  });
});

describe('postgres probe result ingest — kill-switch guards still hold', () => {
  it('refuses ingest for a kill-switched tenant before any read or write', async () => {
    const h = createHarness({ killSwitchActive: true });
    h.seedRun('run_1');
    h.seedJob('pjob_1');

    const out = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(out.error, 'kill_switch_active');
    assert.equal(out.status, 423);
    assert.equal(h.probeEvents().length, 0);
    assert.notEqual(h.job().status, 'completed');
    assert.ok(h.state.audit.some((e) => e.action === 'probe_job.kill_switch_denied'));
  });

  it('refuses reconciliation of an already-durable result while the switch is active', async () => {
    // The reconciliation path must not become a way around the emergency stop.
    const live = createHarness();
    live.seedRun('run_1');
    live.seedJob('pjob_1');
    live.crashNextRunPatch();
    await assert.rejects(() => live.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY));

    const stopped = createHarness({ killSwitchActive: true });
    stopped.seedRun('run_1');
    stopped.seedJob('pjob_1');
    stopped.state.events.push(...live.state.events);

    const out = await stopped.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(out.error, 'kill_switch_active');
    assert.equal(out.status, 423);
    assert.equal(stopped.run().status, 'running', 'no derived state written after the stop');
    assert.equal(stopped.run().awaiting_external_probe, true);
  });

  it('hands out no leases for a kill-switched tenant', async () => {
    const h = createHarness({ killSwitchActive: true });
    assert.deepEqual(await h.svc.listPendingProbeJobsForWorker(WORKER_CTX), []);
  });
});
