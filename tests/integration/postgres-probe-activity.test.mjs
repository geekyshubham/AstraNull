import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { buildSignedProbeJobRecord, signProbeJob } from '../../src/lib/probeJobs.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createPgPool, closePgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { databaseUrlWithDatabase, resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

test('Postgres activity replays immutably under RLS, never publishes a verdict, and stops with its run', { timeout: 120_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) { t.skip(availability.reason); return; }
  await withEphemeralPostgres(async (owner, env) => {
    const ctx = { tenantId: 'ten_activity', userId: 'usr_activity', role: 'engineer', workerId: 'worker_activity' };
    const now = new Date();
    await owner.query(`INSERT INTO tenants (id, name) VALUES ('ten_activity', 'Activity'), ('ten_other', 'Other')`);
    await owner.query(`INSERT INTO environments (id, tenant_id, name) VALUES ('env_activity', 'ten_activity', 'test')`);
    await owner.query(`INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES ('tg_activity', 'ten_activity', 'env_activity', 'Activity')`);
    await owner.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value) VALUES ('tgt_activity', 'ten_activity', 'tg_activity', 'fqdn', 'owned.example.test', 'owned.example.test')`);
    await owner.query(`INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status) VALUES ('run_activity', 'ten_activity', 'tg_activity', 'tgt_activity', 'waf.fingerprint.safe', 'running')`);
    await withTenantContext(owner, ctx.tenantId, (client) => client.query(`INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
      VALUES ('proof_activity', 'ten_activity', 'tgt_activity', 'dns_verified', 'dns_txt', '{}', $1, 'usr_activity', 'audit_fixture')`, [now]));
    const baseUrl = availability.env.ASTRANULL_ADMIN_DATABASE_URL ?? availability.env.ASTRANULL_DATABASE_URL;
    const appUrl = new URL(databaseUrlWithDatabase(baseUrl, env.databaseName));
    appUrl.username = 'astranull_app'; appUrl.password = 'astranull_app_local_dev';
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl.toString() });
    try {
      const repositories = { audit: createAuditRepository(pool), coreCatalog: createCoreCatalogRepository(pool),
        validationEvidence: createValidationEvidenceRepository(pool), probeJobs: createProbeJobRepository(pool), killSwitch: createKillSwitchRepository(pool) };
      const jobs = createPostgresProbeJobServices(repositories);
      const validation = createPostgresValidationServices(repositories);
      const run = await repositories.validationEvidence.getTestRun(ctx, 'run_activity');
      const check = getCheckById('waf.fingerprint.safe');
      const record = buildSignedProbeJobRecord({ run, check,
        target: { id: 'tgt_activity', kind: 'fqdn', value: 'owned.example.test' },
        ownershipBinding: { state: 'dns_verified', kind: 'dns_txt', transitioned_at: now.toISOString() },
        probeWorkerSecret: '654a9a6a11d51db9336c5fc811d48d01d2e6779ee123888192641920a0db4c72', now, newId: () => 'job_activity' });
      await repositories.probeJobs.createProbeJob(ctx, record);
      await owner.query(`UPDATE test_runs SET correlation_json = jsonb_build_object('nonce_hash', $1::text) WHERE id = 'run_activity'`, [record.nonce_hash]);
      await owner.query(`UPDATE probe_jobs SET status = 'leased', leased_by = 'worker_activity', leased_at = $1 WHERE id = 'job_activity'`, [now]);
      const job = await repositories.probeJobs.getJobById(ctx, 'job_activity');
      const resultBody = { external_result: 'connected', metadata: { observation_only: true, readiness_conclusion: false },
        safety_attestation: { requests_sent: 3, probe_requests_sent: 1, destination_resolver_attempts: 2, total_operations: 3, duration_ms: 1 } };
      assert.equal((await jobs.ingestProbeResult(ctx, job.id, resultBody)).error, 'probe_execution_not_reserved');
      assert.equal((await jobs.reserveProbeExecution({ ...ctx, tenantId: 'ten_other' }, job.id, { leased_at: job.leased_at })).status, 404);
      assert.equal((await jobs.reserveProbeExecution({ ...ctx, workerId: 'worker_other' }, job.id, { leased_at: job.leased_at })).status, 403);
      const grants = await Promise.all(Array.from({ length: 5 }, () => jobs.reserveProbeExecution(ctx, job.id, { leased_at: job.leased_at })));
      assert.equal(grants.filter((grant) => grant.authorized).length, 1, JSON.stringify(grants));
      assert.equal(grants.filter((grant) => grant.error === 'probe_budget_already_reserved').length, 4);
      const reserved = await repositories.probeJobs.getJobById(ctx, job.id);
      assert.equal(reserved.worker_metadata.execution_reservation.max_total_operations, job.constraints.max_total_operations);
      const body = { leased_at: job.leased_at, items: [{ sequence: 1, at: now.toISOString(), stage: 'request_started', method: 'POST', url: 'https://owned.example.test/path?credential=hidden', request_content_type: 'application/json', request_payload_preview: '{"marker":"inert","token":"hidden-token"}' }] };
      const accepted = await jobs.ingestProbeActivity(ctx, job.id, body);
      assert.equal(accepted.accepted, 1, JSON.stringify(accepted));
      assert.equal((await jobs.ingestProbeActivity(ctx, job.id, body)).accepted, 0);
      assert.equal((await jobs.ingestProbeActivity(ctx, job.id, { ...body, items: [{ ...body.items[0], method: 'GET' }] })).status, 409);
      assert.equal((await jobs.ingestProbeActivity({ ...ctx, tenantId: 'ten_other' }, job.id, body)).status, 404);
      const read = await validation.testRuns.getRunActivity(ctx, run.id);
      assert.ok(read.items.some((item) => item.method === 'POST'));
      assert.ok(read.items.some((item) => item.vector_family === 'waf'));
      assert.ok(read.items.some((item) => item.request_payload_preview?.includes('inert')));
      assert.equal(JSON.stringify(read).includes('hidden'), false);
      assert.equal(await validation.testRuns.getRunActivity({ ...ctx, tenantId: 'ten_other' }, run.id), null);
      const counts = await owner.query(`SELECT (SELECT count(*) FROM verdicts)::int AS verdicts, (SELECT count(*) FROM evidence_vault)::int AS evidence, (SELECT count(*) FROM events WHERE signal_type = 'probe_activity')::int AS activity`);
      assert.deepEqual(counts.rows[0], { verdicts: 0, evidence: 0, activity: 1 });
      await assert.rejects(owner.query(`INSERT INTO events (id, tenant_id, signal_type, producer_kind, timestamp) VALUES ('spoof_activity', 'ten_activity', 'probe_activity', 'public_api', now())`), /events_probe_activity_producer_check/);
      const stopped = await validation.testRuns.cancelTestRun(ctx, run.id, { reason: 'Stop from execution activity' });
      assert.equal(stopped.run.status, 'cancelled');
      assert.equal((await jobs.ingestProbeActivity(ctx, job.id, { leased_at: job.leased_at, items: [] })).status, 409);
      const requested = await validation.testRuns.getRunActivity(ctx, run.id);
      assert.equal(requested.items.some((item) => item.stage === 'stop_requested'), true);
      assert.equal(requested.items.some((item) => item.stage === 'run_stopped'), false);
      assert.equal(requested.stop.state, 'requested');
      const stopBody = { leased_at: job.leased_at, reason: 'job_revoked' };
      assert.equal((await jobs.acknowledgeProbeStop({ ...ctx, tenantId: 'ten_other' }, job.id, stopBody)).status, 404);
      assert.equal((await jobs.acknowledgeProbeStop({ ...ctx, workerId: 'worker_other' }, job.id, stopBody)).status, 403);
      assert.equal((await jobs.acknowledgeProbeStop(ctx, job.id, { ...stopBody, leased_at: 'old-lease' })).status, 409);
      const acknowledged = await jobs.acknowledgeProbeStop(ctx, job.id, stopBody);
      assert.equal(acknowledged.acknowledged, true, JSON.stringify(acknowledged));
      assert.deepEqual(await jobs.acknowledgeProbeStop(ctx, job.id, stopBody), acknowledged);
      assert.equal((await validation.testRuns.getRunActivity(ctx, run.id)).stop.state, 'acknowledged');
      const ackAudits = await owner.query(`SELECT count(*)::int AS n FROM audit_logs WHERE action = 'probe_job.stop_acknowledged'`);
      assert.equal(ackAudits.rows[0].n, 1);
    } finally { await closePgPool(pool); }
  });
});

test('unwired reviewed jobs cannot consume ordinary reservations or publish accepted results under app-role RLS', { timeout: 120_000 }, async (t) => {
  await withEphemeralPostgres(async (owner, env) => {
    const ctx = { tenantId: 'ten_reviewed_denial', userId: 'usr_reviewed_denial', role: 'engineer', workerId: 'worker_reviewed_denial' };
    await owner.query("INSERT INTO tenants (id,name) VALUES ('ten_reviewed_denial','Reviewed denial'), ('ten_reviewed_other','Other')");
    const availability = await resolvePostgresHarnessAvailability(process.env);
    const baseUrl = availability.env.ASTRANULL_ADMIN_DATABASE_URL ?? availability.env.ASTRANULL_DATABASE_URL;
    const url = new URL(databaseUrlWithDatabase(baseUrl, env.databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const repositories = { audit: createAuditRepository(pool), probeJobs: createProbeJobRepository(pool),
      validationEvidence: createValidationEvidenceRepository(pool), killSwitch: createKillSwitchRepository(pool) };
    const service = createPostgresProbeJobServices(repositories);
    try {
      for (const [index, binding] of [null, {}, { version: 'reviewed-operation-binding.v1' }].entries()) {
        await t.test(`stored reviewed binding presence fails closed (${index})`, async () => {
          const now = new Date(), targetId = `target_reviewed_${index}`, groupId = `group_reviewed_${index}`;
          const runId = `run_reviewed_${index}`, jobId = `job_reviewed_${index}`, secret = 'a'.repeat(64);
          await owner.query("INSERT INTO target_groups(id,tenant_id,name) VALUES ($1,'ten_reviewed_denial',$1)", [groupId]);
          await owner.query(`INSERT INTO targets(id,tenant_id,target_group_id,kind,value,normalized_value)
            VALUES ($1,'ten_reviewed_denial',$2,'fqdn','owned.test','owned.test')`, [targetId, groupId]);
          await withTenantContext(owner, ctx.tenantId, (client) => client.query(`INSERT INTO target_verifications(id,tenant_id,target_id,state,source_kind,source_ref,transitioned_at,transitioned_by,audit_entry_id)
            VALUES ($1,'ten_reviewed_denial',$2,'dns_verified','dns_txt','{}',$3,'usr_reviewed_denial','audit_fixture')`, [`proof_reviewed_${index}`, targetId, now]));
          await owner.query(`INSERT INTO test_runs(id,tenant_id,target_group_id,target_id,check_id,status,created_at)
            VALUES ($1,'ten_reviewed_denial',$2,$3,'waf.fingerprint.safe','running',$4)`, [runId, groupId, targetId, now]);
          const run = await repositories.validationEvidence.getTestRun(ctx, runId);
          const record = buildSignedProbeJobRecord({ run, target: { id: targetId, kind: 'fqdn', value: 'owned.test' },
            check: getCheckById('waf.fingerprint.safe'), probeWorkerSecret: secret,
            ownershipBinding: { state: 'dns_verified', kind: 'dns_txt', transitioned_at: now.toISOString() },
            now, newId: () => jobId });
          await repositories.probeJobs.createProbeJob(ctx, record);
          await owner.query("UPDATE test_runs SET correlation_json = jsonb_build_object('nonce_hash',$2::text) WHERE id = $1", [runId, record.nonce_hash]);
          const stale = await repositories.probeJobs.claimPendingJobForWorker(ctx, jobId, ctx.workerId, now.toISOString());
          const constraints = { ...stale.constraints, reviewed_operation_binding: binding };
          const signature = signProbeJob({ ...stale, constraints }, secret);
          await owner.query('UPDATE probe_jobs SET constraints_json = $2::jsonb, job_signature = $3 WHERE id = $1', [jobId, JSON.stringify(constraints), signature]);
          const stored = await repositories.probeJobs.getJobById(ctx, jobId);
          const before = await owner.query(`SELECT (SELECT count(*) FROM events)::int AS events,
            (SELECT count(*) FROM evidence_vault)::int AS evidence, (SELECT count(*) FROM audit_logs)::int AS audits`);
          assert.equal((await service.reserveProbeExecution(ctx, jobId, { leased_at: stored.leased_at })).error, 'reviewed_operation_execution_unavailable');
          assert.equal((await service.ingestProbeResult(ctx, jobId, { external_result: 'connected',
            metadata: { execution_grant: { verified: true }, reviewed_operation_approved: true },
            safety_attestation: { requests_sent: 3, probe_requests_sent: 1, destination_resolver_attempts: 2, total_operations: 3, duration_ms: 1 } })).error,
          'reviewed_operation_execution_unavailable');
          // A pre-lock ordinary descriptor cannot bypass the guard against stored constraints.
          assert.equal(await repositories.probeJobs.reserveExecution(ctx, stale, { id: 'reservation_unsigned' }), null);
          assert.equal((await service.reserveProbeExecution({ ...ctx, tenantId: 'ten_reviewed_other' }, jobId, { leased_at: stored.leased_at })).status, 404);
          assert.equal((await service.ingestProbeResult({ ...ctx, tenantId: 'ten_reviewed_other' }, jobId, {})).status, 404);
          const after = await owner.query(`SELECT (SELECT count(*) FROM events)::int AS events,
            (SELECT count(*) FROM evidence_vault)::int AS evidence, (SELECT count(*) FROM audit_logs)::int AS audits`);
          assert.deepEqual(after.rows, before.rows);
          assert.deepEqual(await repositories.probeJobs.getJobById(ctx, jobId), stored);
        });
      }
    } finally { await closePgPool(pool); }
  });
});

test('durable execution grant rechecks ownership, destination, policy, Stop and absolute expiry after leasing', { timeout: 120_000 }, async () => {
  await withEphemeralPostgres(async (owner, env) => {
    const ctx = { tenantId: 'ten_grant', userId: 'usr_grant', role: 'engineer', workerId: 'worker_grant' };
    await owner.query("INSERT INTO tenants (id,name) VALUES ('ten_grant','Grant')");
    const availability = await resolvePostgresHarnessAvailability(process.env);
    const baseUrl = availability.env.ASTRANULL_ADMIN_DATABASE_URL ?? availability.env.ASTRANULL_DATABASE_URL;
    const url = new URL(databaseUrlWithDatabase(baseUrl, env.databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const repositories = { audit: createAuditRepository(pool), probeJobs: createProbeJobRepository(pool),
      validationEvidence: createValidationEvidenceRepository(pool), killSwitch: createKillSwitchRepository(pool) };
    try {
      const mutations = [
        ['value', "UPDATE targets SET value = 'changed.test' WHERE id = $1"],
        ['port', 'UPDATE targets SET port = 8443 WHERE id = $1'],
        ['protocol', "UPDATE targets SET protocol = 'http' WHERE id = $1"],
        ['ownership', "UPDATE target_verifications SET state = 'unverified' WHERE target_id = $1"],
        ['archive', 'UPDATE target_groups SET archived_at = now() WHERE id = $1'],
        ['stop', "UPDATE test_runs SET status = 'cancelled' WHERE id = $1"],
        ['expiry', null],
        ['kill', "INSERT INTO soc_kill_switch(tenant_id,active) VALUES ('ten_grant',true) ON CONFLICT(tenant_id) DO UPDATE SET active = true"],
        ['valid', null],
      ];
      for (const [name, sql] of mutations) {
        const now = new Date();
        const targetId = `target_grant_${name}`; const groupId = `group_grant_${name}`;
        const runId = `run_grant_${name}`; const jobId = `job_grant_${name}`;
        await owner.query(`INSERT INTO target_groups(id,tenant_id,name) VALUES ($1,'ten_grant',$2)`, [groupId, name]);
        await owner.query(`INSERT INTO targets(id,tenant_id,target_group_id,kind,value,normalized_value)
          VALUES ($1,'ten_grant',$2,'fqdn','owned.test','owned.test')`, [targetId, groupId]);
        await withTenantContext(owner, ctx.tenantId, (client) => client.query(`INSERT INTO target_verifications(id,tenant_id,target_id,state,source_kind,source_ref,transitioned_at,transitioned_by,audit_entry_id)
          VALUES ($1,'ten_grant',$2,'dns_verified','dns_txt','{}',$3,'usr_grant','audit_fixture')`, [`proof_${name}`, targetId, now]));
        await owner.query(`INSERT INTO test_runs(id,tenant_id,target_group_id,target_id,check_id,status,created_at)
          VALUES ($1,'ten_grant',$2,$3,'waf.fingerprint.safe','running',$4)`, [runId, groupId, targetId, now]);
        const run = await repositories.validationEvidence.getTestRun(ctx, runId);
        const record = buildSignedProbeJobRecord({ run, target: { id: targetId, kind: 'fqdn', value: 'owned.test' },
          check: getCheckById('waf.fingerprint.safe'), probeWorkerSecret: 'a'.repeat(64),
          ownershipBinding: { state: 'dns_verified', kind: 'dns_txt', transitioned_at: now.toISOString() },
          now, newId: () => jobId });
        await repositories.probeJobs.createProbeJob(ctx, record);
        await owner.query(`UPDATE test_runs SET correlation_json = jsonb_build_object('nonce_hash',$2::text) WHERE id = $1`, [runId, record.nonce_hash]);
        const job = await repositories.probeJobs.claimPendingJobForWorker(ctx, jobId, ctx.workerId, now.toISOString());
        assert.ok(job, `${name}: authorized at lease`);
        if (sql) await owner.query(sql, name === 'kill' ? [] : [name === 'archive' ? groupId : name === 'stop' ? runId : targetId]);
        const service = createPostgresProbeJobServices(repositories, { now: () => name === 'expiry' ? new Date(now.getTime() + 120_001) : now });
        const grant = await service.reserveProbeExecution(ctx, jobId, { leased_at: job.leased_at });
        if (name !== 'valid') {
          assert.ok(grant.error, `${name}: ${JSON.stringify(grant)}`);
          assert.equal((await repositories.probeJobs.getJobById(ctx, jobId)).worker_metadata.execution_reservation, undefined);
        } else {
          assert.equal(grant.authorized, true, JSON.stringify(grant));
          const capture = { version: 'probe-capture.v1', recorded_count: 0, last_sequence: 0,
            dropped_count: 0, delivery_failures: 0, finalized_at: now.toISOString() };
          assert.equal((await service.ingestProbeActivity(ctx, jobId, { leased_at: job.leased_at, items: [], capture })).error, undefined);
          const result = await service.ingestProbeResult(ctx, jobId, { external_result: 'connected',
            metadata: { observation_only: true, readiness_conclusion: false },
            safety_attestation: { requests_sent: 3, probe_requests_sent: 1, destination_resolver_attempts: 2, total_operations: 3, duration_ms: 1 } });
          assert.equal(result.error, undefined, JSON.stringify(result));
          const completed = await repositories.probeJobs.getJobById(ctx, jobId);
          assert.equal(completed.leased_at, job.leased_at, 'same-holder final result never changes the capture lease');
          assert.deepEqual(completed.worker_metadata.capture, capture);
        }
        if (name === 'kill') await owner.query("UPDATE soc_kill_switch SET active = false WHERE tenant_id = 'ten_grant'");
      }
    } finally { await closePgPool(pool); }
  });
});
