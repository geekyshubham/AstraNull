import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';

const TENANT_ID = 'ten_demo';
const RUN_ID = 'run_1';
const JOB_ID = 'pjob_1';
const WORKER_ID = 'worker_1';
const NOW = '2026-06-01T12:00:00.000Z';
const CTX = { tenantId: TENANT_ID, workerId: WORKER_ID, role: 'probe_worker' };

function probeJobRow(status = 'leased') {
  return {
    id: JOB_ID,
    tenant_id: TENANT_ID,
    test_run_id: RUN_ID,
    target_id: 'target_1',
    check_id: 'origin.direct_bypass.safe',
    vector_family: 'origin',
    status,
    nonce_hash: 'nonce_hash_1',
    nonce_for_worker: 'nonce_1',
    probe_profile: { kind: 'http_head' },
    constraints_json: { max_requests: 1, timeout_ms: 5000 },
    target_descriptor_json: {},
    worker_metadata_json: {},
    job_signature: 'signature',
    leased_at: NOW,
    leased_by: WORKER_ID,
    completed_at: status === 'completed' ? NOW : null,
    ownership_verification_id: null,
    created_at: NOW,
  };
}

function runRow(status = 'running') {
  return {
    id: RUN_ID,
    tenant_id: TENANT_ID,
    target_group_id: 'group_1',
    target_id: 'target_1',
    check_id: 'origin.direct_bypass.safe',
    status,
    probe_external_result: status === 'collecting' ? 'connected' : null,
    awaiting_external_probe: status === 'running',
    safety_constraints: {},
    correlation_json: { nonce_hash: 'nonce_hash_1' },
    summary_json: {},
    created_at: NOW,
  };
}

function createAtomicityPool() {
  const clients = [];
  let activeClient = null;
  return {
    clients,
    async connect() {
      if (activeClient) {
        throw new Error('pool-size-1 second client requested');
      }
      const client = {
        id: `client_${clients.length + 1}`,
        queries: [],
        released: false,
        async query(text, params) {
          this.queries.push({ text, params });
          const sql = text.trim();
          if (sql.includes('pg_try_advisory_xact_lock')) {
            return { rows: [{ acquired: true }] };
          }
          if (sql.startsWith('SELECT') && sql.includes('FROM soc_kill_switch')) {
            return { rows: [{ active: false }] };
          }
          if (sql.startsWith('SELECT') && sql.includes('FROM probe_jobs')) {
            return { rows: [probeJobRow()] };
          }
          if (sql.startsWith('SELECT') && sql.includes('FROM test_runs')) {
            return { rows: [runRow()] };
          }
          if (sql.startsWith('SELECT') && sql.includes('FROM events')) {
            return { rows: [] };
          }
          if (sql.startsWith('UPDATE probe_jobs') && sql.includes("SET status = 'leased'")) {
            return { rows: [probeJobRow('leased')] };
          }
          if (sql.startsWith('INSERT INTO events')) {
            return {
              rows: [{
                id: 'event_1',
                tenant_id: TENANT_ID,
                event_id: null,
                test_run_id: RUN_ID,
                target_id: 'target_1',
                check_id: 'origin.direct_bypass.safe',
                agent_id: null,
                source: 'probe_worker',
                signal_type: 'probe_result',
                producer_kind: 'signed_probe',
                nonce_hash: 'nonce_hash_1',
                timestamp: NOW,
                metadata_json: {
                  external_result: 'connected',
                  safety_attestation: { requests_sent: 1, duration_ms: 10 },
                },
              }],
            };
          }
          if (sql.startsWith('SELECT') && sql.includes('FROM evidence_vault')) {
            return { rows: [] };
          }
          if (sql.startsWith('INSERT INTO evidence_vault')) {
            return {
              rows: [{
                id: 'evidence_1',
                tenant_id: TENANT_ID,
                test_run_id: RUN_ID,
                label: 'probe_worker_evidence',
                metadata_json: {},
                related_event_id: 'event_1',
                created_at: NOW,
              }],
            };
          }
          if (sql.startsWith('UPDATE test_runs')) {
            return { rows: [runRow('collecting')] };
          }
          if (sql.startsWith('UPDATE probe_jobs') && sql.includes("SET status = 'completed'")) {
            return { rows: [probeJobRow('completed')] };
          }
          if (sql.startsWith('SELECT') && sql.includes('FROM audit_logs')) {
            return { rows: [] };
          }
          if (sql.startsWith('INSERT INTO audit_logs')) {
            throw new Error('injected audit insert failure');
          }
          return { rows: [] };
        },
        release() {
          this.released = true;
          activeClient = null;
        },
      };
      clients.push(client);
      activeClient = client;
      return client;
    },
  };
}

function countStatement(client, statement) {
  return client.queries.filter(({ text }) => text.trim() === statement).length;
}

describe('postgres probe-result transaction atomicity', () => {
  it('uses one pool-size-1 audit/run client in lock order and rolls every write back on audit failure', async () => {
    const pool = createAtomicityPool();
    const repositories = {
      probeJobs: createProbeJobRepository(pool),
      validationEvidence: createValidationEvidenceRepository(pool),
      audit: createAuditRepository(pool),
      killSwitch: createKillSwitchRepository(pool),
    };
    const service = createPostgresProbeJobServices(repositories, {
      now: () => new Date(NOW),
      newId: (prefix) => (prefix === 'event' ? 'event_1' : 'evidence_1'),
    });

    await assert.rejects(
      () => service.ingestProbeResult(CTX, JOB_ID, {
        external_result: 'connected',
        safety_attestation: { requests_sent: 1, duration_ms: 10 },
      }),
      /injected audit insert failure/,
    );

    assert.equal(
      pool.clients.length,
      3,
      'kill-switch precheck, job pre-read, and one audit/run mutation checkout',
    );
    const [killSwitchReadClient, initialReadClient, mutationClient] = pool.clients;
    assert.equal(countStatement(killSwitchReadClient, 'COMMIT'), 1);
    assert.equal(countStatement(initialReadClient, 'COMMIT'), 1);
    assert.equal(countStatement(initialReadClient, 'ROLLBACK'), 0);

    assert.equal(countStatement(mutationClient, 'BEGIN'), 1);
    assert.equal(countStatement(mutationClient, 'COMMIT'), 0);
    assert.equal(countStatement(mutationClient, 'ROLLBACK'), 1);
    assert.equal(mutationClient.released, true);

    const statements = mutationClient.queries.map(({ text }) => text.trim());
    const tenantAuditLockIndex = mutationClient.queries.findIndex(
      ({ text, params }) => text.includes('pg_advisory_xact_lock(hashtext($1))')
        && params?.[0] === TENANT_ID,
    );
    const runLockIndex = mutationClient.queries.findIndex(
      ({ text }) => text.includes('pg_try_advisory_xact_lock'),
    );
    const killSwitchReadIndex = mutationClient.queries.findIndex(
      ({ text }) => text.includes('FROM soc_kill_switch'),
    );
    assert.ok(
      tenantAuditLockIndex >= 0
        && tenantAuditLockIndex < runLockIndex
        && runLockIndex < killSwitchReadIndex,
      'tenant audit lock must precede run locks and the shared-client kill-switch read',
    );
    const requiredWrites = [
      (sql) => sql.startsWith('UPDATE probe_jobs') && sql.includes("SET status = 'leased'"),
      (sql) => sql.startsWith('INSERT INTO events'),
      (sql) => sql.startsWith('INSERT INTO evidence_vault'),
      (sql) => sql.startsWith('UPDATE test_runs'),
      (sql) => sql.startsWith('UPDATE probe_jobs') && sql.includes("SET status = 'completed'"),
      (sql) => sql.startsWith('INSERT INTO audit_logs'),
    ];
    for (const matches of requiredWrites) {
      assert.ok(statements.some(matches), 'expected every ingest write on the mutation client');
    }
    assert.ok(statements.indexOf('ROLLBACK') > statements.findIndex((sql) => sql.startsWith('INSERT INTO audit_logs')));
  });
});

function createOwnershipResultHarness({
  completed = false,
  failAudit = false,
  verificationClosed = completed,
  verificationBindingMismatch = false,
  killSwitchSequence = [false],
} = {}) {
  const transactionClient = { kind: 'ownership-result-transaction-client' };
  let killSwitchReadIndex = 0;
  const state = {
    status: completed ? 'completed' : 'leased',
    audit: [],
    calls: [],
    ownershipSignals: 0,
    ownershipObserved: verificationClosed,
  };
  const job = () => ({
    id: 'pjob_ownership',
    tenant_id: TENANT_ID,
    test_run_id: 'ownership_1',
    target_id: 'agent_1',
    check_id: 'ownership.challenge',
    status: state.status,
    leased_by: WORKER_ID,
    leased_at: NOW,
    nonce_hash: 'ownership_nonce_hash',
    ownership_verification_id: 'ownership_1',
    probe_profile: { kind: 'ownership_challenge' },
    constraints: { max_requests: 1, timeout_ms: 5000 },
  });
  const probeJobs = {
    leasePendingJobsForWorker: async () => [],
    getJobById: async (_ctx, _id, options = {}) => {
      state.calls.push({ operation: 'get_job', client: options.client });
      return job();
    },
    claimPendingJobForWorker: async () => null,
    claimJobForResult: async (_ctx, _id, _worker, _now, _expected, options = {}) => {
      state.calls.push({ operation: 'claim', client: options.client });
      state.status = 'leased';
      return job();
    },
    markJobCompleted: async (_ctx, _id, _now, _lease, options = {}) => {
      state.calls.push({ operation: 'complete', client: options.client });
      state.status = 'completed';
      return job();
    },
    createProbeJob: async () => null,
    cancelOpenProbeJobsForTestRuns: async () => [],
  };
  const validationEvidence = {
    getTestRun: async () => null,
    listRunEvents: async () => [],
    appendProbeResultEventIdempotent: async () => null,
    appendEvidence: async () => null,
    updateTestRun: async () => null,
    async withRunMutationLock(_ctx, _runId, callback, options = {}) {
      state.calls.push({ operation: 'run_lock', client: options.client });
      assert.equal(options.client, transactionClient);
      return { acquired: true, result: await callback(options.client) };
    },
  };
  const audit = {
    async withTenantAuditLock(tenantId, callback) {
      assert.equal(tenantId, TENANT_ID);
      state.calls.push({ operation: 'audit_lock', client: transactionClient });
      const snapshot = {
        status: state.status,
        audit: [...state.audit],
        ownershipObserved: state.ownershipObserved,
      };
      try {
        return await callback({ client: transactionClient, prior: null });
      } catch (error) {
        state.status = snapshot.status;
        state.audit = snapshot.audit;
        state.ownershipObserved = snapshot.ownershipObserved;
        throw error;
      }
    },
    async appendAuditEvent(entry, options = {}) {
      state.calls.push({ operation: 'audit', client: options.client });
      if (failAudit) throw new Error('injected ownership audit failure');
      const actions = options.idempotency?.actions ?? [entry.action];
      const existing = state.audit.find((item) =>
        actions.includes(item.action)
          && item.resource_type === options.idempotency?.resourceType
          && item.resource_id === options.idempotency?.resourceId);
      if (existing) return existing;
      state.audit.push(entry);
      return entry;
    },
  };
  const ownershipVerification = {
    async recordOwnershipSignal(_ctx, verificationId, payload, options = {}) {
      state.calls.push({
        operation: 'ownership_signal',
        client: options.client,
        verificationId,
        nonceHash: payload.nonce_hash,
        probeJobId: payload.probe_job_id,
      });
      state.ownershipSignals += 1;
      if (verificationBindingMismatch) {
        return { error: 'ownership_probe_job_binding_mismatch', status: 409 };
      }
      if (verificationClosed) return { error: 'ownership_verification_not_open', status: 409 };
      state.ownershipObserved = true;
      return { verification: { id: verificationId, probe_observed: true } };
    },
  };
  return {
    state,
    transactionClient,
    service: createPostgresProbeJobServices(
      {
        probeJobs,
        validationEvidence,
        audit,
        killSwitch: {
          async isKillSwitchActiveForTenant(_ctx, options = {}) {
            state.calls.push({ operation: 'kill_switch_read', client: options.client });
            const active = killSwitchSequence[
              Math.min(killSwitchReadIndex, killSwitchSequence.length - 1)
            ];
            killSwitchReadIndex += 1;
            return active;
          },
        },
      },
      { ownershipVerification, now: () => new Date(NOW) },
    ),
  };
}

describe('postgres ownership probe-result transaction atomicity', () => {
  const body = {
    external_result: 'connected',
    safety_attestation: { requests_sent: 1, duration_ms: 10 },
  };

  it('takes the audit lock first and uses its exact client for claim, signal, completion, and audit', async () => {
    const harness = createOwnershipResultHarness();
    const result = await harness.service.ingestProbeResult(CTX, 'pjob_ownership', body);

    assert.equal(result.ownership_verification_id, 'ownership_1');
    assert.equal(harness.state.status, 'completed');
    const ordered = harness.state.calls.map((call) => call.operation);
    const auditLockIndex = ordered.indexOf('audit_lock');
    const runLockIndex = ordered.indexOf('run_lock');
    const killSwitchReadIndex = ordered.lastIndexOf('kill_switch_read');
    const claimIndex = ordered.indexOf('claim');
    assert.ok(
      auditLockIndex >= 0
        && auditLockIndex < runLockIndex
        && runLockIndex < killSwitchReadIndex
        && killSwitchReadIndex < claimIndex,
      'ownership mutation must hold audit → run/kill-switch gates before writes',
    );
    const mutationCalls = harness.state.calls.filter((call) =>
      call.client === harness.transactionClient
        && ['run_lock', 'kill_switch_read', 'claim', 'ownership_signal', 'complete', 'audit'].includes(call.operation));
    assert.deepEqual(
      mutationCalls.map((call) => call.operation),
      ['run_lock', 'kill_switch_read', 'claim', 'ownership_signal', 'complete', 'audit'],
    );
    assert.ok(mutationCalls.every((call) => call.client === harness.transactionClient));
    const signal = mutationCalls.find((call) => call.operation === 'ownership_signal');
    assert.equal(signal.verificationId, 'ownership_1');
    assert.equal(signal.nonceHash, 'ownership_nonce_hash');
    assert.equal(signal.probeJobId, 'pjob_ownership');
    assert.equal(harness.state.audit.length, 1);
  });

  it('rolls claim, ownership signal, and completion back when the final audit fails', async () => {
    const harness = createOwnershipResultHarness({ failAudit: true });
    await assert.rejects(
      () => harness.service.ingestProbeResult(CTX, 'pjob_ownership', body),
      /injected ownership audit failure/,
    );
    assert.equal(harness.state.status, 'leased');
    assert.equal(harness.state.ownershipObserved, false);
    assert.equal(harness.state.audit.length, 0);
    const mutationCalls = harness.state.calls.filter((call) =>
      ['claim', 'ownership_signal', 'complete', 'audit'].includes(call.operation));
    assert.ok(mutationCalls.every((call) => call.client === harness.transactionClient));
  });

  it('rejects an open job bound to an already-closed exact ownership verification', async () => {
    const harness = createOwnershipResultHarness({ verificationClosed: true });

    const result = await harness.service.ingestProbeResult(
      CTX,
      'pjob_ownership',
      body,
    );

    assert.deepEqual(result, { error: 'ownership_verification_not_open', status: 409 });
    assert.equal(harness.state.status, 'leased', 'result claim is rolled back');
    assert.equal(harness.state.audit.length, 0);
    assert.equal(harness.state.calls.some((call) => call.operation === 'complete'), false);
  });

  it('audits ownership-path activation between precheck and locked reread on the exact client', async () => {
    const harness = createOwnershipResultHarness({ killSwitchSequence: [false, true] });

    const result = await harness.service.ingestProbeResult(
      CTX,
      'pjob_ownership',
      body,
    );

    assert.equal(result.error, 'kill_switch_active');
    assert.equal(result.status, 423);
    const lockedReads = harness.state.calls.filter((call) =>
      ['run_lock', 'kill_switch_read', 'audit'].includes(call.operation));
    assert.deepEqual(
      lockedReads.map((call) => call.operation),
      ['kill_switch_read', 'run_lock', 'kill_switch_read', 'audit'],
    );
    assert.equal(lockedReads[0].client, undefined, 'the first read is only the non-authoritative precheck');
    assert.ok(lockedReads.slice(1).every((call) => call.client === harness.transactionClient));
    assert.equal(harness.state.audit.length, 1);
    assert.equal(harness.state.audit[0].action, 'probe_job.kill_switch_denied');
    assert.equal(harness.state.status, 'leased');
    assert.equal(harness.state.calls.some((call) => call.operation === 'claim'), false);
    assert.equal(harness.state.calls.some((call) => call.operation === 'ownership_signal'), false);
  });

  it('rolls back ownership-path denial and rejects when its locked audit fails', async () => {
    const harness = createOwnershipResultHarness({
      killSwitchSequence: [false, true],
      failAudit: true,
    });

    await assert.rejects(
      () => harness.service.ingestProbeResult(CTX, 'pjob_ownership', body),
      /injected ownership audit failure/,
    );

    assert.equal(harness.state.status, 'leased');
    assert.equal(harness.state.audit.length, 0);
    assert.equal(harness.state.calls.some((call) => call.operation === 'claim'), false);
    assert.equal(harness.state.calls.some((call) => call.operation === 'ownership_signal'), false);
  });

  it('never reconciles a completed ownership job with malformed reciprocal binding', async () => {
    const harness = createOwnershipResultHarness({
      completed: true,
      verificationBindingMismatch: true,
    });

    const result = await harness.service.ingestProbeResult(
      CTX,
      'pjob_ownership',
      body,
    );

    assert.deepEqual(result, {
      error: 'ownership_probe_job_binding_mismatch',
      status: 409,
    });
    assert.equal(result.reconciled, undefined);
    assert.equal(harness.state.audit.length, 0);
    assert.equal(harness.state.calls.some((call) => call.operation === 'claim'), false);
    assert.equal(harness.state.calls.some((call) => call.operation === 'complete'), false);
  });

  it('reconciles completed-job retries idempotently without reclaiming or recompleting', async () => {
    const harness = createOwnershipResultHarness({ completed: true });
    const first = await harness.service.ingestProbeResult(CTX, 'pjob_ownership', body);
    const second = await harness.service.ingestProbeResult(CTX, 'pjob_ownership', body);

    assert.equal(first.reconciled, true);
    assert.equal(second.reconciled, true);
    assert.equal(harness.state.calls.some((call) => call.operation === 'claim'), false);
    assert.equal(harness.state.calls.some((call) => call.operation === 'complete'), false);
    assert.equal(harness.state.ownershipSignals, 2);
    assert.equal(harness.state.audit.length, 1);
    assert.equal(harness.state.audit[0].action, 'probe_job.result_reconciled');
  });
});
