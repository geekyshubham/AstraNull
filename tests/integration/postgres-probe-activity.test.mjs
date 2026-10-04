import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { buildSignedProbeJobRecord } from '../../src/lib/probeJobs.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createPgPool, closePgPool } from '../../src/persistence/postgres/pool.mjs';
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
        probeWorkerSecret: '654a9a6a11d51db9336c5fc811d48d01d2e6779ee123888192641920a0db4c72', now, newId: () => 'job_activity' });
      await repositories.probeJobs.createProbeJob(ctx, record);
      await owner.query(`UPDATE test_runs SET correlation_json = jsonb_build_object('nonce_hash', $1::text) WHERE id = 'run_activity'`, [record.nonce_hash]);
      await owner.query(`UPDATE probe_jobs SET status = 'leased', leased_by = 'worker_activity', leased_at = $1 WHERE id = 'job_activity'`, [now]);
      const job = await repositories.probeJobs.getJobById(ctx, 'job_activity');
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
      assert.equal((await validation.testRuns.getRunActivity(ctx, run.id)).items.some((item) => item.stage === 'run_stopped'), true);
    } finally { await closePgPool(pool); }
  });
});
