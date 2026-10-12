import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import pg from 'pg';
import { test } from 'node:test';
import { withEphemeralPostgres, ensureHarnessAppRole } from '../helpers/pg-harness.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';

const ctx = { tenantId: 'ten_admission_complete', userId: 'user_admission', role: 'admin' };
const check = 'waf.fingerprint.safe';

test('application-role admission counts beyond display caps, serializes the last slot, and finds hidden cooldowns', { timeout: 120_000 }, async () => {
  await withEphemeralPostgres(async (owner) => {
    await ensureHarnessAppRole(owner);
    const appUrl = new URL(owner.options.connectionString);
    appUrl.username = 'astranull_app'; appUrl.password = 'astranull_app_local_dev';
    const pool = new pg.Pool({ ...owner.options, connectionString: appUrl.toString(), max: 1 });
    const evidence = createValidationEvidenceRepository(pool);
    const repositories = { validationEvidence: evidence, audit: createAuditRepository(pool),
      coreCatalog: createCoreCatalogRepository(pool), probeJobs: createProbeJobRepository(pool),
      killSwitch: createKillSwitchRepository(pool) };
    const now = new Date();
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => now });
    const start = (target) => testRuns.startTestRun(ctx,
      { target_group_id: 'policy_admission', target_id: target, check_id: check }, { probeMode: 'simulation' });
    try {
      await withTenantContext(owner, ctx.tenantId, async (client) => {
        await client.query("INSERT INTO tenants(id,name) VALUES ($1,'Admission')", [ctx.tenantId]);
        await client.query(`INSERT INTO target_groups(id,tenant_id,name,validation_mode,safety_policy)
          VALUES ('policy_admission',$1,'Admission','external_only','{"min_seconds_between_runs":0,"max_runs_per_hour":130}')`, [ctx.tenantId]);
        await client.query(`INSERT INTO targets(id,tenant_id,target_group_id,kind,value,normalized_value)
          SELECT 'admission_target_' || n, $1, 'policy_admission', 'fqdn',
            'admission-' || n || '.test', 'admission-' || n || '.test' FROM generate_series(1,5) n`, [ctx.tenantId]);
        await client.query(`INSERT INTO test_runs(id,tenant_id,target_group_id,target_id,check_id,status,created_at)
          SELECT 'admission_history_' || n, $1, 'policy_admission', 'admission_target_5', $2, 'cancelled',
            $3::timestamptz - n * interval '1 second' FROM generate_series(1,130) n`, [ctx.tenantId, check, now]);
      });
      assert.equal((await evidence.listTestRuns(ctx, { limit: 500 })).length, 100, 'public display cap remains unchanged');
      const usage = await evidence.readSafeAdmissionUsage(ctx, { now: now.toISOString(),
        targetId: 'admission_target_1', targetGroupId: 'policy_admission', customerCheckIds: [check] });
      assert.equal(usage.input_complete, true);
      assert.equal(usage.runs_last_hour, 130);
      assert.equal(usage.prior_run, null);
      assert.equal((await start('admission_target_1')).error, 'safe_rate_cap_exceeded');
      await withTenantContext(owner, ctx.tenantId, (client) => client.query(
        `UPDATE target_groups SET safety_policy = '{"min_seconds_between_runs":0,"max_runs_per_hour":131}'
          WHERE tenant_id = $1 AND id = 'policy_admission'`, [ctx.tenantId]));
      const raced = await Promise.all([start('admission_target_1'), start('admission_target_2')]);
      assert.equal(raced.filter((result) => result.run).length, 1, JSON.stringify(raced));
      assert.equal(raced.filter((result) => result.error === 'safe_rate_cap_exceeded').length, 1);
      await testRuns.cancelTestRun(ctx, raced.find((result) => result.run).run.id);
      await withTenantContext(owner, ctx.tenantId, async (client) => {
        await client.query(`UPDATE target_groups SET safety_policy = '{"min_seconds_between_runs":300,"max_runs_per_hour":1000}'
          WHERE tenant_id = $1 AND id = 'policy_admission'`, [ctx.tenantId]);
        await client.query(`INSERT INTO test_runs(id,tenant_id,target_group_id,target_id,check_id,status,created_at)
          VALUES ('admission_hidden_prior',$1,'policy_admission','admission_target_3',$2,'cancelled', $3::timestamptz - interval '4 minutes')`,
        [ctx.tenantId, check, now]);
      });
      assert.equal((await evidence.listTestRuns(ctx, { limit: 500 })).some((run) => run.id === 'admission_hidden_prior'), false);
      assert.equal((await start('admission_target_3')).error, 'safe_min_interval_active');
      assert.ok((await start('admission_target_4')).run, 'another declared target retains its independent cooldown');
      const audits = await withTenantContext(owner, ctx.tenantId, (client) => client.query(
        `SELECT action FROM audit_logs WHERE tenant_id = $1 AND action IN ('test_run.safe_rate_denied','test_run.safe_interval_denied')`, [ctx.tenantId]));
      assert.ok(audits.rows.length >= 3, 'safety denials are audited');
    } finally { await evidence.close(); await pool.end(); }
  });
});
