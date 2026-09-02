import '../helpers/dev-data-dir.mjs';

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
    writeClients: [],
    lockOrder: [],
    killSwitchClients: [],
  };
  const transactionClient = { id: 'probe-result-transaction-client' };
  let failUpdateTestRunOnce = false;
  let auditTransactionActive = false;
  let killSwitchReadIndex = 0;

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
    async claimJobForResult(ctx, id, workerId, leasedAt, expected = {}, callOptions = {}) {
      state.writeClients.push({ operation: 'claim', client: callOptions.client });
      if (options.rejectResultClaim === true) return null;
      const job = state.jobs.get(id);
      if (!job
        || job.status !== expected.status
        || (job.leased_by ?? null) !== (expected.leased_by ?? null)
        || (job.leased_at ?? null) !== (expected.leased_at ?? null)) return null;
      job.status = 'leased';
      job.leased_by = workerId;
      job.leased_at = leasedAt;
      return { ...job };
    },
    async markJobCompleted(ctx, id, completedAt, lease = {}, callOptions = {}) {
      state.writeClients.push({ operation: 'complete', client: callOptions.client });
      const job = state.jobs.get(id);
      if (!job
        || job.status !== 'leased'
        || job.leased_by !== lease.workerId
        || job.leased_at !== lease.leasedAt) return null;
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
    async appendProbeResultEventIdempotent(ctx, record, callOptions = {}) {
      state.writeClients.push({ operation: 'event', client: callOptions.client });
      if (options.rejectEventUpsertConflict === true) return null;
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
    async appendEvidence(ctx, record, callOptions = {}) {
      state.writeClients.push({ operation: 'evidence', client: callOptions.client });
      if (callOptions.idempotentByRelatedEvent === true) {
        const existing = state.evidence.find(
          (item) => item.test_run_id === record.test_run_id
            && item.label === record.label
            && item.related_event_id === record.related_event_id,
        );
        if (existing) return { ...existing };
      }
      state.evidence.push({ ...record });
      return { ...record };
    },
    async updateTestRun(ctx, id, patch, callOptions = {}) {
      state.writeClients.push({ operation: 'run', client: callOptions.client });
      if (failUpdateTestRunOnce) {
        failUpdateTestRunOnce = false;
        throw new Error('simulated crash after event write');
      }
      state.updateCalls.push({ id, patch: { ...patch } });
      const run = state.runs.get(id);
      if (
        Array.isArray(patch.expected_statuses)
        && !patch.expected_statuses.includes(run.status)
      ) {
        return null;
      }
      const { expected_statuses: _expectedStatuses, ...persistedPatch } = patch;
      Object.assign(run, persistedPatch);
      return { ...run };
    },
    async withRunMutationLock(ctx, runId, callback, callOptions = {}) {
      assert.equal(
        callOptions.client,
        transactionClient,
        'run lock must reuse the tenant audit transaction client',
      );
      state.lockOrder.push('run_lock');
      return { acquired: true, result: await callback(callOptions.client) };
    },
  };

  const audit = {
    async appendAuditEvent(entry, callOptions = {}) {
      state.writeClients.push({ operation: 'audit', client: callOptions.client });
      if (options.failKillSwitchAudit === true && entry.action === 'probe_job.kill_switch_denied') {
        throw new Error('injected kill-switch denial audit failure');
      }
      if (callOptions.idempotency) {
        const actions = callOptions.idempotency.actions ?? [entry.action];
        const existing = state.audit.find(
          (item) => actions.includes(item.action)
            && item.resource_type === callOptions.idempotency.resourceType
            && item.resource_id === callOptions.idempotency.resourceId,
        );
        if (existing) return existing;
      }
      state.audit.push(entry);
      return entry;
    },
    async withTenantAuditLock(_tenantId, callback) {
      state.lockOrder.push('audit_lock');
      const snapshot = structuredClone({
        runs: [...state.runs.entries()],
        jobs: [...state.jobs.entries()],
        events: state.events,
        evidence: state.evidence,
        audit: state.audit,
      });
      auditTransactionActive = true;
      try {
        return await callback({ client: transactionClient, prior: null });
      } catch (error) {
        state.runs = new Map(snapshot.runs);
        state.jobs = new Map(snapshot.jobs);
        state.events = snapshot.events;
        state.evidence = snapshot.evidence;
        state.audit = snapshot.audit;
        throw error;
      } finally {
        auditTransactionActive = false;
      }
    },
  };

  const repositories = { probeJobs, validationEvidence, audit };
  if (options.killSwitchActive !== undefined || options.killSwitchSequence !== undefined) {
    repositories.killSwitch = {
      async isKillSwitchActiveForTenant(_ctx, callOptions = {}) {
        state.killSwitchClients.push(callOptions.client);
        if (auditTransactionActive) {
          assert.equal(
            callOptions.client,
            transactionClient,
            'audit-first kill-switch read must reuse its transaction client',
          );
        }
        const sequence = options.killSwitchSequence;
        if (sequence) {
          const result = sequence[Math.min(killSwitchReadIndex, sequence.length - 1)];
          killSwitchReadIndex += 1;
          return result;
        }
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
    transactionClient,
    crashNextRunPatch() {
      failUpdateTestRunOnce = true;
    },
    seedRun(id, overrides = {}) {
      state.runs.set(id, {
        id,
        tenant_id: TENANT,
        target_id: 'tgt_1',
        check_id: 'origin.direct_bypass.safe',
        status: 'running',
        correlation: { nonce_hash: 'nh_abc', seeded: true },
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
    seedDurableProbeEvent(overrides = {}) {
      const event = {
        id: 'event_durable',
        tenant_id: TENANT,
        test_run_id: 'run_1',
        target_id: 'tgt_1',
        check_id: 'origin.direct_bypass.safe',
        source: 'probe_worker',
        signal_type: 'probe_result',
        producer_kind: 'signed_probe',
        nonce_hash: 'nh_abc',
        timestamp: '2026-05-31T23:58:59.000Z',
        metadata: {
          probe_job_id: 'pjob_1',
          external_result: 'connected',
          safety_attestation: { requests_sent: 1, duration_ms: 10 },
        },
        ...overrides,
      };
      state.events.push(event);
      return event;
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
  for (const producerKind of ['internal_simulation', 'public_api', 'legacy_untrusted']) {
    it(`does not reconcile a completed signed job from ${producerKind} evidence`, async () => {
      const h = createHarness();
      h.seedRun('run_1');
      h.seedJob('pjob_1', { status: 'completed', completed_at: NOW });
      h.state.events.push({
        id: `event_${producerKind}`,
        tenant_id: TENANT,
        test_run_id: 'run_1',
        target_id: 'tgt_1',
        check_id: 'origin.direct_bypass.safe',
        source: producerKind === 'internal_simulation' ? 'probe_stub' : 'public_api',
        signal_type: 'probe_result',
        producer_kind: producerKind,
        nonce_hash: 'nh_abc',
        metadata: {
          external_result: 'blocked',
          ...(producerKind === 'internal_simulation' ? {} : { probe_job_id: 'pjob_1' }),
        },
      });

      const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

      assert.ok(
        ['job_not_open', 'probe_event_binding_conflict'].includes(result.error),
        JSON.stringify(result),
      );
      assert.equal(result.reconciled, undefined);
      assert.equal(h.run().status, 'running');
      assert.equal(h.run().awaiting_external_probe, true);
      assert.equal(h.state.evidence.length, 0);
      assert.equal(h.state.audit.length, 0);
      assert.equal(h.state.completedCalls.length, 0);
    });
  }

  it('reconciles a historical durable event, stale run, and open job', async () => {
    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1');
    const durable = h.seedDurableProbeEvent();

    const retry = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(retry.error, undefined, 'retry must not be an error');
    assert.equal(retry.reconciled, true);
    assert.equal(retry.run_id, 'run_1');
    assert.equal(retry.probe_event.id, durable.id);

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
    h.seedDurableProbeEvent();

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
    h.seedDurableProbeEvent();

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
        ['awaiting_external_probe', 'correlation', 'expected_statuses', 'probe_external_result', 'status'].filter((k) =>
          Object.keys(call.patch).includes(k),
        ),
      );
    }
  });

  it('has no evidence, run, or completion side effects when result-lease claim loses', async () => {
    const h = createHarness({ rejectResultClaim: true });
    h.seedRun('run_1');
    h.seedJob('pjob_1');
    const beforeRun = { ...h.run(), correlation: { ...h.run().correlation } };

    const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.equal(result.error, 'job_not_open');
    assert.deepEqual(h.run(), beforeRun);
    assert.equal(h.state.events.length, 0);
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.updateCalls.length, 0);
    assert.equal(h.state.completedCalls.length, 0);
    assert.equal(h.job().status, 'leased');
  });

  it('reconciles a completed result after run finalization without resurrecting the run', async () => {
    const h = createHarness();
    h.seedRun('run_1', {
      status: 'verdicted',
      completed_at: '2026-06-01T12:01:00.000Z',
      correlation: { nonce_hash: 'nh_abc' },
      awaiting_external_probe: false,
      probe_external_result: 'connected',
    });
    h.seedJob('pjob_1', {
      status: 'completed',
      completed_at: '2026-06-01T12:00:30.000Z',
    });
    h.seedDurableProbeEvent();

    const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.equal(result.reconciled, true);
    assert.equal(h.run().status, 'verdicted');
    assert.equal(h.run().completed_at, '2026-06-01T12:01:00.000Z');
    assert.equal(h.state.evidence.length, 1);
    assert.equal(h.state.audit.length, 1);
    assert.equal(h.state.completedCalls.length, 0);
  });
  for (const status of ['pending', 'leased']) {
    it(`reconciles a durable result for a ${status} job after run finalization`, async () => {
      const h = createHarness();
      h.seedRun('run_1', {
        status: 'verdicted',
        completed_at: '2026-06-01T12:01:00.000Z',
        awaiting_external_probe: true,
        probe_external_result: null,
      });
      h.seedJob('pjob_1', {
        status,
        leased_by: status === 'leased' ? WORKER : null,
        leased_at: status === 'leased' ? NOW : null,
      });
      h.seedDurableProbeEvent();

      const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

      assert.equal(result.reconciled, true);
      assert.equal(h.run().status, 'verdicted', 'terminal run must not be resurrected');
      assert.equal(h.run().completed_at, '2026-06-01T12:01:00.000Z');
      assert.equal(h.job().status, 'completed');
      assert.equal(h.state.evidence.length, 1);
      assert.equal(h.state.audit.length, 1);
      assert.equal(h.state.completedCalls.length, 1);
    });
  }

  it('enforces the live lease holder while reconciling a terminal run', async () => {
    const h = createHarness();
    h.seedRun('run_1', { status: 'verdicted' });
    h.seedJob('pjob_1', { status: 'leased', leased_by: OTHER_WORKER, leased_at: NOW });
    h.seedDurableProbeEvent();

    const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.equal(result.error, 'job_leased_to_another_worker');
    assert.equal(result.status, 403);
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.audit.length, 0);
    assert.equal(h.state.completedCalls.length, 0);
    assert.equal(h.run().status, 'verdicted');
  });

  it('does not reconcile a durable event explicitly bound to another probe job', async () => {
    const h = createHarness();
    h.seedRun('run_1', { status: 'verdicted' });
    h.seedJob('pjob_1', { status: 'completed', completed_at: NOW });
    h.seedDurableProbeEvent({
      metadata: {
        probe_job_id: 'pjob_other',
        external_result: 'connected',
      },
    });

    const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.deepEqual(result, { error: 'probe_event_binding_conflict', status: 409 });
    assert.equal(
      h.state.writeClients.filter(({ operation }) => operation === 'event').length,
      0,
      'a conflicting durable binding must never reach the event upsert',
    );
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.audit.length, 0);
  });

  it('fails closed on a trusted duplicate with a conflicting target/check tuple', async () => {
    const h = createHarness();
    h.seedRun('run_1', { status: 'verdicted' });
    h.seedJob('pjob_1', { status: 'completed', completed_at: NOW });
    h.seedDurableProbeEvent({ target_id: 'tgt_other' });

    const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.deepEqual(result, { error: 'probe_event_binding_conflict', status: 409 });
    assert.equal(h.state.writeClients.length, 0);
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.audit.length, 0);
  });

  it('fails closed when exact and legacy trusted duplicate rows are ambiguous', async () => {
    const h = createHarness();
    h.seedRun('run_1', { status: 'verdicted' });
    h.seedJob('pjob_1', { status: 'completed', completed_at: NOW });
    h.seedDurableProbeEvent();
    h.seedDurableProbeEvent({ id: 'event_legacy', metadata: { external_result: 'connected' } });

    const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.deepEqual(result, { error: 'probe_event_binding_conflict', status: 409 });
    assert.equal(h.state.writeClients.length, 0);
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.audit.length, 0);
  });
});

describe('postgres probe result ingest — fresh job/run binding validation', () => {
  const mismatches = [
    ['target', { target_id: 'tgt_other' }],
    ['check', { check_id: 'dns.authoritative_availability.safe' }],
    ['nonce/correlation', { correlation: { nonce_hash: 'nh_other' } }],
  ];

  for (const [name, runOverrides] of mismatches) {
    it(`rejects a fresh ${name} mismatch before any write`, async () => {
      const h = createHarness();
      h.seedRun('run_1', runOverrides);
      h.seedJob('pjob_1');
      const beforeRun = structuredClone(h.run());
      const beforeJob = structuredClone(h.job());

      const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

      assert.deepEqual(result, { error: 'probe_job_binding_mismatch', status: 409 });
      assert.deepEqual(h.run(), beforeRun);
      assert.deepEqual(h.job(), beforeJob);
      assert.equal(h.state.writeClients.length, 0);
      assert.equal(h.state.events.length, 0);
      assert.equal(h.state.evidence.length, 0);
      assert.equal(h.state.audit.length, 0);
    });
  }
});

describe('postgres probe result ingest — transaction and historical repair', () => {
  it('fails closed when a concurrent conflicting event makes the atomic upsert return no row', async () => {
    const h = createHarness({ rejectEventUpsertConflict: true });
    h.seedRun('run_1');
    h.seedJob('pjob_1');
    const beforeRun = structuredClone(h.run());
    const beforeJob = structuredClone(h.job());

    const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.deepEqual(result, { error: 'probe_event_binding_conflict', status: 409 });
    assert.deepEqual(h.run(), beforeRun);
    assert.deepEqual(h.job(), beforeJob);
    assert.equal(h.state.events.length, 0);
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.audit.length, 0);
    assert.equal(h.state.completedCalls.length, 0);
  });

  it('rolls back every current-transaction mutation when a later write fails', async () => {
    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1');
    const beforeRun = structuredClone(h.run());
    const beforeJob = structuredClone(h.job());
    h.crashNextRunPatch();

    await assert.rejects(
      () => h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY),
      /simulated crash after event write/,
    );

    assert.deepEqual(h.run(), beforeRun);
    assert.deepEqual(h.job(), beforeJob);
    assert.equal(h.state.events.length, 0);
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.audit.length, 0);
  });

  it('uses the run-lock transaction client for every ingest mutation and audit', async () => {
    const h = createHarness({ killSwitchActive: false });
    h.seedRun('run_1');
    h.seedJob('pjob_1');

    const result = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.equal(result.error, undefined);
    assert.deepEqual(h.state.lockOrder, ['audit_lock', 'run_lock']);
    assert.deepEqual(h.state.killSwitchClients, [undefined, h.transactionClient]);
    assert.deepEqual(
      h.state.writeClients.map(({ operation }) => operation),
      ['claim', 'event', 'evidence', 'run', 'complete', 'audit'],
    );
    assert.ok(
      h.state.writeClients.every(({ client }) => client === h.transactionClient),
      'every mutation and the audit must receive the exact client supplied by the run lock',
    );
  });

  it('restores missing evidence and audit for a historically completed job exactly once', async () => {
    const h = createHarness();
    h.seedRun('run_1');
    h.seedJob('pjob_1', {
      status: 'completed',
      completed_at: '2026-05-31T23:59:00.000Z',
    });
    h.state.events.push({
      id: 'event_durable',
      tenant_id: TENANT,
      test_run_id: 'run_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      source: 'probe_worker',
      signal_type: 'probe_result',
      producer_kind: 'signed_probe',
      nonce_hash: 'nh_abc',
      timestamp: '2026-05-31T23:58:59.000Z',
      metadata: {
        external_result: 'blocked',
        safety_attestation: { requests_sent: 1, duration_ms: 10 },
      },
    });

    const first = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', {
      ...VALID_BODY,
      external_result: 'connected',
    });
    assert.equal(first.reconciled, true);
    assert.equal(h.state.evidence.length, 1);
    assert.equal(h.state.evidence[0].related_event_id, 'event_durable');
    assert.equal(h.state.evidence[0].metadata.external_result, 'blocked');
    assert.equal(h.state.evidence[0].created_at, '2026-05-31T23:58:59.000Z');
    assert.equal(h.state.audit.length, 1);
    assert.equal(h.state.audit[0].action, 'probe_job.result_reconciled');
    assert.equal(h.run().probe_external_result, 'blocked');
    assert.equal(h.job().completed_at, '2026-05-31T23:59:00.000Z');
    assert.equal(h.state.completedCalls.length, 0);

    const second = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(second.reconciled, true);
    assert.equal(h.state.evidence.length, 1, 'replay must not duplicate repaired evidence');
    assert.equal(h.state.audit.length, 1, 'replay must not duplicate repaired audit');
    assert.equal(h.job().completed_at, '2026-05-31T23:59:00.000Z');
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

  it('refuses reconciliation of an explicitly seeded durable result while the switch is active', async () => {
    // Model the pre-existing committed row directly: a failed transaction would have rolled it back.
    const stopped = createHarness({ killSwitchActive: true });
    stopped.seedRun('run_1');
    stopped.seedJob('pjob_1');
    stopped.seedDurableProbeEvent();

    const out = await stopped.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);
    assert.equal(out.error, 'kill_switch_active');
    assert.equal(out.status, 423);
    assert.equal(stopped.run().status, 'running', 'no derived state written after the stop');
    assert.equal(stopped.run().awaiting_external_probe, true);
  });

  it('audits activation between precheck and locked reread on the exact transaction client before mutation', async () => {
    const h = createHarness({ killSwitchSequence: [false, true] });
    h.seedRun('run_1');
    h.seedJob('pjob_1');

    const out = await h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY);

    assert.equal(out.error, 'kill_switch_active');
    assert.equal(out.status, 423);
    assert.deepEqual(h.state.killSwitchClients, [undefined, h.transactionClient]);
    assert.deepEqual(h.state.lockOrder, ['audit_lock', 'run_lock']);
    assert.deepEqual(
      h.state.writeClients.map(({ operation, client }) => [operation, client]),
      [['audit', h.transactionClient]],
    );
    assert.equal(h.state.audit.length, 1);
    assert.equal(h.state.audit[0].action, 'probe_job.kill_switch_denied');
    assert.equal(h.job().status, 'leased');
    assert.equal(h.state.events.length, 0);
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.updateCalls.length, 0);
  });

  it('rolls back and rejects when the locked activation denial audit cannot be persisted', async () => {
    const h = createHarness({
      killSwitchSequence: [false, true],
      failKillSwitchAudit: true,
    });
    h.seedRun('run_1');
    h.seedJob('pjob_1');

    await assert.rejects(
      () => h.svc.ingestProbeResult(WORKER_CTX, 'pjob_1', VALID_BODY),
      /injected kill-switch denial audit failure/,
    );

    assert.deepEqual(h.state.killSwitchClients, [undefined, h.transactionClient]);
    assert.equal(h.state.audit.length, 0);
    assert.equal(h.job().status, 'leased');
    assert.equal(h.state.events.length, 0);
    assert.equal(h.state.evidence.length, 0);
    assert.equal(h.state.updateCalls.length, 0);
  });

  it('hands out no leases for a kill-switched tenant', async () => {
    const h = createHarness({ killSwitchActive: true });
    assert.deepEqual(await h.svc.listPendingProbeJobsForWorker(WORKER_CTX), []);
  });
});
