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
import { createPostgresValidationScanRepository } from '../../src/persistence/postgres/validationScanRepository.mjs';
import { createPostgresValidationScanServices } from '../../src/persistence/postgres/validationScanServiceAdapters.mjs';
import { createInitialEdgeDetectionRepository } from '../../src/persistence/postgres/initialEdgeDetectionRepository.mjs';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { createOwnershipVerificationRepository } from '../../src/persistence/postgres/ownershipVerificationRepository.mjs';

const ctx = { tenantId: 'ten_parallel', userId: 'user_parallel', role: 'admin' };
const config = { probeMode: 'simulation' };
const check = 'waf.fingerprint.safe';

test('Postgres enforces exact target concurrency and a durable tenant-scoped initial queue', { timeout: 120_000 }, async () => {
  await withEphemeralPostgres(async (pool) => {
    await ensureHarnessAppRole(pool);
    const appUrl = new URL(pool.options.connectionString);
    appUrl.username = 'astranull_app'; appUrl.password = 'astranull_app_local_dev';
    const appPool = new pg.Pool({ ...pool.options, connectionString: appUrl.toString() });
    const audit = createAuditRepository(appPool);
    const coreCatalog = createCoreCatalogRepository(appPool, { auditRepository: audit });
    const evidence = createValidationEvidenceRepository(appPool);
    const scanRepo = createPostgresValidationScanRepository(appPool, { auditRepository: audit });
    const repositories = { audit, coreCatalog, validationEvidence: evidence, validationScans: scanRepo,
      ownershipVerifications: createOwnershipVerificationRepository(appPool),
      probeJobs: createProbeJobRepository(appPool), killSwitch: createKillSwitchRepository(appPool) };
    const { testRuns } = createPostgresValidationServices(repositories);
    const scans = createPostgresValidationScanServices(repositories, { testRuns, runtimeConfig: config });
    const queue = createInitialEdgeDetectionRepository(appPool);
    try {
      assert.equal((await appPool.query('SELECT current_user')).rows[0].current_user, 'astranull_app');
      assert.equal(await evidence.withSafeStartLock(ctx, () => evidence.withSafeStartLock(ctx, async () => 'nested')), 'nested');
      await withTenantContext(pool, ctx.tenantId, async (client) => {
        await client.query("INSERT INTO tenants(id,name) VALUES ($1,'Parallel')", [ctx.tenantId]);
        await client.query("INSERT INTO target_groups(id,tenant_id,name,validation_mode,safety_policy) VALUES ('policy',$1,'Policy','external_only','{\"min_seconds_between_runs\":0,\"max_runs_per_hour\":100}')", [ctx.tenantId]);
      });
      const a = await coreCatalog.createTargetDirect(ctx, { kind: 'fqdn', value: 'a.test', target_group_id: 'policy' });
      const b = await coreCatalog.createTargetDirect(ctx, { kind: 'fqdn', value: 'b.test', target_group_id: 'policy' });
      assert.equal((await queue.read(ctx, a.id)).status, 'queued');
      assert.equal(await queue.read({ tenantId: 'another' }, a.id), null);
      const claims = await Promise.all([queue.claim(ctx, { limit: 1, now: new Date() }), queue.claim(ctx, { limit: 1, now: new Date() })]);
      assert.equal(new Set(claims.flat().map((row) => row.target_id)).size, 2);
      const run = (target) => testRuns.startTestRun(ctx, { target_group_id: 'policy', target_id: target.id, check_id: check }, config);
      const independent = await Promise.all([run(a), run(b)]);
      assert.ok(independent.every((result) => result.run?.id));
      assert.equal((await run(a)).error, 'concurrent_run_blocked');
      for (const result of independent) await testRuns.cancelTestRun(ctx, result.run.id);
      const race = await Promise.all([run(a), run(a)]);
      assert.equal(race.filter((result) => result.run).length, 1);
      assert.equal(race.filter((result) => result.error === 'concurrent_run_blocked').length, 1);
      await testRuns.cancelTestRun(ctx, race.find((result) => result.run).run.id);
      const scan = (id) => scans.createValidationScan(ctx, { target_id: id, check_ids: [check] }, config);
      const first = await scan(a.id); const second = await scan(b.id);
      assert.equal(first.status, 'running'); assert.equal(second.status, 'running');
      assert.equal((await scan(a.id)).error, 'concurrent_scan_blocked');
      assert.equal((await run(a)).error, 'concurrent_run_blocked');
      await scans.cancelValidationScan(ctx, first.id);
      await scans.cancelValidationScan(ctx, second.id);
      const multiRace = await Promise.all([
        scans.createValidationScan(ctx, { target_ids: [a.id, b.id], check_ids: [check] }, config), scan(b.id),
      ]);
      assert.equal(multiRace.filter((result) => result.id).length, 1);
      assert.equal(multiRace.filter((result) => result.error === 'concurrent_scan_blocked').length, 1);
      await scans.cancelValidationScan(ctx, multiRace.find((result) => result.id).id);
      await withTenantContext(pool, ctx.tenantId, async (client) => {
        await client.query(`INSERT INTO target_verifications(id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
          VALUES ('parent_verified', $1, $2, 'dns_verified', 'dns_txt', '{}', now(), 'user_parallel', 'audit_fixture')`, [ctx.tenantId, a.id]);
      });
      const child = await coreCatalog.createTargetDirect(ctx, { kind: 'fqdn', value: 'child.a.test',
        target_group_id: 'policy', tags: [`subdomain-of:${a.id}`] });
      const detail = await createPortalRevampRepository(appPool).getTargetDetailBundle(ctx, child.id);
      assert.equal(detail.verification.state, 'dns_verified');
      assert.equal(detail.verification.source_kind, 'inherited_parent');
      assert.equal(detail.verification.source_ref.inherited_from_target_id, a.id);
      const signed = await testRuns.startTestRun(ctx, { target_group_id: 'policy', target_id: child.id, check_id: check },
        { probeMode: 'signed-worker', probeWorkerSecret: 'a'.repeat(32) });
      assert.ok(signed.probe_job?.id, JSON.stringify(signed));
      const claimed = await repositories.probeJobs.claimPendingJobForWorker(ctx, signed.probe_job.id, 'worker_child', new Date().toISOString());
      assert.ok(claimed, 'fresh parent-inherited proof must allow claiming the child job');
      await testRuns.cancelTestRun(ctx, signed.run.id);
      const retrySigned = await testRuns.startTestRun(ctx, { target_group_id: 'policy', target_id: child.id, check_id: check },
        { probeMode: 'signed-worker', probeWorkerSecret: 'a'.repeat(32) });
      await withTenantContext(pool, ctx.tenantId, async (client) => {
        await client.query("UPDATE targets SET metadata_json = '{}' WHERE tenant_id = $1 AND id = $2", [ctx.tenantId, child.id]);
      });
      assert.equal(await repositories.probeJobs.claimPendingJobForWorker(ctx, retrySigned.probe_job.id, 'worker_child', new Date().toISOString()), null,
        'removing the parent relationship before claim must revoke inherited authorization');
      assert.equal((await repositories.probeJobs.leasePendingJobsForWorker(ctx, 'worker_child')).length, 0,
        'a revoked parent relationship must also prevent worker polling from leasing the child');
      await testRuns.cancelTestRun(ctx, retrySigned.run.id);
    } finally { await scanRepo.close(); await evidence.close(); await appPool.end(); }
  });
});
