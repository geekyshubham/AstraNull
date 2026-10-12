import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { createServer } from 'node:http';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { createPostgresValidationServices, VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  VALIDATION_AUDIT_REPOSITORY_METHODS } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { executeProbeForJob, processJob, pollAndProcessOnce, parseWorkerConfig } from '../../workers/probe-worker.mjs';
import { signProbeJob, buildSignedProbeJobRecord } from '../../src/lib/probeJobs.mjs';
import { reserveProbeExecution, ingestProbeResult } from '../../src/services/probeCoordinator.mjs';
import { createPostgresProbeJobServices, PROBE_JOB_REPOSITORY_METHODS } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_owner', role: 'owner' };
const secret = 'review-runtime-denial-test-secret-32-bytes';
beforeEach(() => freshStore());
const repository = (methods) => Object.fromEntries(methods.map((name) => [name, () => {
  throw new Error(`unexpected repository call: ${name}`);
}]));

for (const body of [{ reviewed_operation_id: 'rop_selected' }, { reviewed_operation_id: null },
  { reviewed_operation_binding: { approved: true } }]) {
  const error = body.reviewed_operation_id === 'rop_selected' ? 'reviewed_operation_execution_unavailable'
    : Object.hasOwn(body, 'reviewed_operation_id') ? 'invalid_reviewed_operation_selection' : 'reviewed_operation_authority_not_allowed';
  test(`dev start cannot silently discard selected review authority: ${error}`, () => {
    const before = structuredClone(getStore());
    const result = startTestRun(ctx, body, { probeMode: 'simulation' });
    assert.equal(result.error, error);
    assert.deepEqual(getStore(), before);
  });
  test(`PostgreSQL start denies selected review before repository access: ${error}`, async () => {
    const services = createPostgresValidationServices({
      validationEvidence: repository(VALIDATION_EVIDENCE_REPOSITORY_METHODS),
      audit: repository(VALIDATION_AUDIT_REPOSITORY_METHODS), coreCatalog: repository(['getTargetGroup']),
      probeJobs: repository(['createProbeJob']), killSwitch: repository(['isKillSwitchActiveForTenant']),
    }, { reviewedSafeExecution: { available: true, ...repository(['withAdmission']) } });
    assert.equal((await services.testRuns.startTestRun(ctx, body, { probeMode: 'signed-worker' })).error, error);
  });
}

test('worker configuration rejects the interrupted lifecycle flag', () => {
  assert.throws(() => parseWorkerConfig([], {
    ASTRANULL_PROBE_WORKER_SECRET: secret,
    ASTRANULL_PROBE_TENANT_ID: ctx.tenantId,
    ASTRANULL_REVIEWED_SAFE_EXECUTION_ENABLED: '1',
  }), /Reviewed operation execution remains unavailable/);
});

for (const binding of [null, {}, { version: 'reviewed-operation-binding.v1' }]) {
  test('job creation rejects retained reviewed authority before profile access, ID allocation or signing', () => {
    let calls = 0;
    const forbidden = () => { calls++; throw new Error('unexpected job construction'); };
    assert.throws(() => buildSignedProbeJobRecord({
      run: { safety_constraints: { reviewed_operation_binding: binding } },
      check: Object.defineProperty({}, 'probe_profile', { get: forbidden }),
      target: {}, newId: forbidden, now: new Date(), probeWorkerSecret: secret,
    }), /reviewed_operation_execution_unavailable/);
    assert.equal(calls, 0);
  });
  for (const operation of ['ingestProbeActivity', 'consumeReviewedExecution']) {
    test(`PostgreSQL ${operation} refuses injected lifecycle before transaction/write`, async () => {
      const job = { id: 'pjob_review_server', tenant_id: ctx.tenantId, test_run_id: 'run_review_server',
        constraints: { reviewed_operation_binding: binding } };
      const before = structuredClone(job);
      const services = createPostgresProbeJobServices({
        probeJobs: { ...repository(PROBE_JOB_REPOSITORY_METHODS), getJobById: async () => job },
        validationEvidence: repository([...VALIDATION_EVIDENCE_REPOSITORY_METHODS, 'appendProbeResultEventIdempotent']),
        audit: repository(['appendAuditEvent', 'withTenantAuditLock']),
        killSwitch: { isKillSwitchActiveForTenant: async () => false },
      }, { reviewedSafeExecution: { available: true, ...repository(['ingestActivity', 'consumeExecution']) } });
      assert.deepEqual(await services[operation]({ ...ctx, workerId: 'worker_review' }, job.id, {}),
        { error: 'reviewed_operation_execution_unavailable', status: 409 });
      assert.deepEqual(job, before);
    });
  }
  for (const operation of ['reserveProbeExecution', 'ingestProbeResult']) {
    test(`dev ${operation} denies unwired reviewed job without mutation`, () => {
      const job = { id: 'pjob_review_server', tenant_id: ctx.tenantId, test_run_id: 'run_review_server',
        target_id: 'tgt_1', check_id: 'waf.fingerprint.safe', constraints: { reviewed_operation_binding: binding } };
      getStore().probeJobs.push(job);
      const before = structuredClone(getStore());
      const worker = { tenantId: ctx.tenantId, workerId: 'worker_review', role: 'probe_worker' };
      const result = operation === 'reserveProbeExecution'
        ? reserveProbeExecution(worker, job.id, { leased_at: new Date().toISOString() })
        : ingestProbeResult(worker, job.id, { external_result: 'connected', execution_grant: { verified: true } }, {});
      assert.equal(result.error, 'reviewed_operation_execution_unavailable');
      assert.equal(result.status, 409);
      assert.deepEqual(getStore(), before);
    });
    test(`PostgreSQL ${operation} denies unwired reviewed job before transaction/write`, async () => {
      const job = { id: 'pjob_review_server', tenant_id: ctx.tenantId, test_run_id: 'run_review_server',
        constraints: { reviewed_operation_binding: binding } };
      const before = structuredClone(job);
      const probeJobs = { ...repository(PROBE_JOB_REPOSITORY_METHODS), ...repository(['reserveExecution']),
        getJobById: async () => job };
      const services = createPostgresProbeJobServices({ probeJobs,
        validationEvidence: repository([...VALIDATION_EVIDENCE_REPOSITORY_METHODS, 'appendProbeResultEventIdempotent']),
        audit: repository(['appendAuditEvent', 'withTenantAuditLock']),
        killSwitch: { isKillSwitchActiveForTenant: async () => false } },
      { reviewedSafeExecution: { available: true, ...repository(['reserveAndIssue', 'ingestResult', 'ingestActivity', 'consumeExecution']) } });
      const result = await services[operation]({ tenantId: ctx.tenantId, workerId: 'worker_review', role: 'probe_worker' },
        job.id, operation === 'reserveProbeExecution' ? { leased_at: new Date().toISOString() }
          : { external_result: 'connected', execution_grant: { verified: true } });
      assert.equal(result.error, 'reviewed_operation_execution_unavailable');
      assert.equal(result.status, 409);
      assert.deepEqual(job, before);
    });
  }
  test('PostgreSQL ordinary reservation repository refuses reviewed jobs before acquiring a client', async () => {
    const pool = { connect() { throw new Error('unexpected client acquisition'); } };
    const repo = createProbeJobRepository(pool);
    assert.equal(await repo.reserveExecution(ctx, { constraints: { reviewed_operation_binding: binding } }, {}), null);
  });
  test('polling a reviewed job never requests ordinary unsigned execution authority', async (t) => {
    const at = Date.now();
    const job = { id: 'pjob_review_poll', tenant_id: ctx.tenantId, test_run_id: 'run_review_poll',
      target_id: 'tgt_review', check_id: 'unknown.safe', nonce_hash: 'a'.repeat(64),
      target: { id: 'tgt_review', kind: 'url', value: 'http://127.0.0.1/diagnostics' },
      leased_at: new Date(at).toISOString(), probe_profile: { kind: 'unknown' },
      constraints: { authority_version: 'probe-authority-v2', issued_at: new Date(at).toISOString(),
        not_after: new Date(at + 120_000).toISOString(), execution_attempts: 1,
        reviewed_operation_binding: binding } };
    job.job_signature = signProbeJob(job, secret);
    const requests = [];
    const server = createServer((req, res) => {
      requests.push(`${req.method} ${req.url}`);
      res.setHeader('content-type', 'application/json');
      if (req.method === 'GET' && req.url === '/internal/probe/jobs') {
        res.end(JSON.stringify({ jobs: [job] }));
      } else {
        res.statusCode = 201;
        res.end(JSON.stringify({ authorized: true, reservation_id: 'reservation_unsigned',
          not_after: job.constraints.not_after }));
      }
    });
    t.after(() => new Promise((resolve) => server.close(resolve)));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const results = await pollAndProcessOnce({ apiUrl: `http://127.0.0.1:${server.address().port}`,
      workerId: 'worker_review_poll', tenantId: ctx.tenantId, secret,
      reviewedExecutionEnabled: true, reviewedExecutionTrust: { available: true } });
    assert.deepEqual(requests, ['GET /internal/probe/jobs']);
    assert.deepEqual(results, [{ job_id: job.id, external_result: 'not_run',
      reason: 'reviewed_operation_execution_unavailable' }]);
  });
  for (const entry of ['direct', 'signed']) test(`${entry} reviewed worker entry refuses unwired grants before resolver/transport`, async () => {
    const at = Date.now();
    const job = { id: 'pjob_review', tenant_id: ctx.tenantId, test_run_id: 'run_review', check_id: 'waf.evasion_base64_wrap.safe',
      target_id: 'tgt_review', target: { id: 'tgt_review', kind: 'url', value: 'https://owned.example.test/diagnostics' },
      nonce_hash: 'a'.repeat(64), probe_profile: { kind: 'waf_evasion_marker_probe', timeout_ms: 1000, max_requests: 4 },
      constraints: { authority_version: 'probe-authority-v2', issued_at: new Date(at).toISOString(),
        not_after: new Date(at + 120_000).toISOString(), execution_attempts: 1, timeout_ms: 1000,
        max_probe_requests: 4, min_destination_resolver_attempts: 2, max_destination_resolver_attempts: 2,
        max_total_operations: 6, max_requests: 6, reviewed_operation_binding: binding } };
    job.job_signature = signProbeJob(job, secret);
    const before = structuredClone(job);
    let io = 0;
    const forbiddenIo = async () => { io++; throw new Error('unexpected destination I/O'); };
    const deps = { resolve4Fn: forbiddenIo, resolve6Fn: forbiddenIo, fetchFn: forbiddenIo,
      signedJobVerified: true, executionAuthorized: true, execution_grant: { verified: true },
      reviewedExecutionEnabled: true, reviewedExecutionTrust: { available: true },
      reviewedGrant: { verified: true }, reviewedClaim: { id: 'forged_claim' },
      claimReviewedExecution: forbiddenIo, reviewedAuthorityCheck: forbiddenIo };
    const result = entry === 'direct' ? await executeProbeForJob(job, deps)
      : await processJob({ secret, reviewedExecutionEnabled: true, reviewedExecutionTrust: {} }, job, deps);
    assert.equal(result.external_result, 'error');
    assert.equal(result.metadata.error_class, 'reviewed_operation_execution_unavailable');
    assert.equal(result.metadata.not_run, true);
    assert.equal(entry === 'signed' ? result.safety_attestation.requests_sent : result.requests_sent, 0);
    assert.equal(io, 0);
    assert.deepEqual(job, before);
  });
}
