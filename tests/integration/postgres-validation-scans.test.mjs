import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createPostgresValidationScanRepository } from '../../src/persistence/postgres/validationScanRepository.mjs';
import { createPostgresValidationScanServices } from '../../src/persistence/postgres/validationScanServiceAdapters.mjs';
import {
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_scan_int_a';
const OTHER_TENANT = 'ten_scan_int_b';
const ENVIRONMENT = 'env_scan_int_a';
const GROUP = 'tg_scan_int_a';
const TARGET_A = 'tgt_scan_int_a';
const TARGET_B = 'tgt_scan_int_b';
const AGENT = 'agt_scan_int_a';
const CHECK_ID = 'waf.fingerprint.safe';
const RUNTIME_CONFIG = { probeMode: 'simulation' };
const CTX = { tenantId: TENANT, userId: 'usr_scan_int', role: 'admin' };
const RUNNER_CTX = { tenantId: TENANT, userId: 'validation-scan-runner', role: 'system' };

function buildServices(pool) {
  const audit = createAuditRepository(pool);
  const repositories = {
    validationEvidence: createValidationEvidenceRepository(pool),
    audit,
    coreCatalog: createCoreCatalogRepository(pool),
    probeJobs: createProbeJobRepository(pool),
    killSwitch: createKillSwitchRepository(pool),
    validationScans: createPostgresValidationScanRepository(pool, { auditRepository: audit }),
  };
  const validation = createPostgresValidationServices(repositories);
  const scans = createPostgresValidationScanServices(repositories, {
    testRuns: validation.testRuns,
    runtimeConfig: RUNTIME_CONFIG,
  });
  return { repositories, testRuns: validation.testRuns, scans };
}

async function seedFixtures(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'scan tenant A'), ($2, 'scan tenant B')`, [TENANT, OTHER_TENANT]);
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'env')`, [ENVIRONMENT, TENANT]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name, validation_mode, safety_policy)
       VALUES ($1, $2, $3, 'scan group', 'external_only', '{"min_seconds_between_runs": 0, "max_runs_per_hour": 100}'::jsonb)`,
      [GROUP, TENANT, ENVIRONMENT],
    );
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
       VALUES ($1, $2, $3, 'fqdn', 'a.scan-int.test', 'a.scan-int.test'), ($4, $2, $3, 'fqdn', 'b.scan-int.test', 'b.scan-int.test')`,
      [TARGET_A, TENANT, GROUP, TARGET_B],
    );
    await client.query(
      `INSERT INTO agents (id, tenant_id, environment_id, target_group_id, name, status)
       VALUES ($1, $2, $3, $4, 'offline agent', 'offline')`,
      [AGENT, TENANT, ENVIRONMENT, GROUP],
    );
  });
}

async function readRun(pool, runId) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT id, status, scan_id, scan_step_id, summary_json FROM test_runs WHERE tenant_id = $1 AND id = $2`,
      [TENANT, runId],
    );
    return rows[0] ?? null;
  });
}

async function readAudits(pool, action) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT action, resource_type, resource_id, metadata_json FROM audit_logs
       WHERE tenant_id = $1 AND action = $2 ORDER BY sequence`,
      [TENANT, action],
    );
    return rows;
  });
}

function skipUnlessAvailable(t, availability) {
  if (availability.available) return false;
  t.skip(availability.reason);
  return true;
}

describe('postgres validation scans (service adapters over a live database)', () => {
  it('creates a scan, starts exactly one child run bound to the step, and refuses forged bindings', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (skipUnlessAvailable(t, availability)) return;
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);
      const { scans, testRuns, repositories } = buildServices(pool);

      const scan = await scans.createValidationScan(CTX, { target_group_id: GROUP, check_ids: [CHECK_ID] }, RUNTIME_CONFIG);
      assert.equal(scan.status, 'running');
      assert.equal(scan.steps.length, 2);
      assert.equal(scan.steps[0].status, 'collecting');
      assert.ok(scan.steps[0].test_run_id);
      assert.equal(scan.steps[1].status, 'pending');
      assert.equal(scan.steps[0].target_value, 'a.scan-int.test');

      const run = await readRun(pool, scan.steps[0].test_run_id);
      assert.equal(run.scan_id, scan.id);
      assert.equal(run.scan_step_id, scan.steps[0].step_id);
      assert.equal(run.status, 'collecting');

      const started = await readAudits(pool, 'test_run.started');
      assert.equal(started.length, 1);
      assert.equal(started[0].metadata_json.scan_id, scan.id);
      assert.equal(started[0].metadata_json.scan_step_id, scan.steps[0].step_id);
      const stepStarted = await readAudits(pool, 'validation_scan.step_started');
      assert.equal(stepStarted.length, 1);
      assert.equal(stepStarted[0].metadata_json.test_run_id, scan.steps[0].test_run_id);
      assert.equal(JSON.stringify(stepStarted).includes('a.scan-int.test'), false);

      const stored = await repositories.validationScans.getScan(CTX, scan.id);
      assert.equal(stored.lease_token, null);

      const blocked = await scans.createValidationScan(CTX, { target_group_id: GROUP, check_ids: [CHECK_ID] }, RUNTIME_CONFIG);
      assert.deepEqual(blocked, { error: 'concurrent_scan_blocked', status: 409 });

      const forged = await testRuns.startTestRun(
        CTX,
        { check_id: CHECK_ID, target_group_id: GROUP, target_id: TARGET_B },
        RUNTIME_CONFIG,
        { scanDispatch: { scan_id: scan.id, step_id: scan.steps[1].step_id, lease_token: 'forged' } },
      );
      assert.equal(forged.error, 'concurrent_run_blocked', 'concurrency gate fires before binding validation for a non-replay');
      await repositories.validationScans.updateScan(CTX, scan.id, {
        lease_token: 'lease_real',
        lease_owner: 'test',
        lease_expires_at: new Date(Date.now() + 60_000).toISOString(),
      });
      await repositories.validationScans.updateStep(CTX, scan.steps[1].step_id, { status: 'starting' });
      const replayProbe = await testRuns.startTestRun(
        CTX,
        { check_id: CHECK_ID, target_group_id: GROUP, target_id: TARGET_B },
        RUNTIME_CONFIG,
        { scanDispatch: { scan_id: scan.id, step_id: scan.steps[0].step_id, lease_token: 'lease_real' } },
      );
      assert.equal(replayProbe.error, 'scan_dispatch_invalid', 'a step that is not starting cannot be bound');
      const conflicting = await testRuns.startTestRun(
        CTX,
        { check_id: CHECK_ID, target_group_id: GROUP, target_id: TARGET_B, policy_id: 'pol_x' },
        RUNTIME_CONFIG,
        { scanDispatch: { scan_id: scan.id, step_id: scan.steps[1].step_id, lease_token: 'lease_real' } },
      );
      assert.equal(conflicting.error, 'concurrent_run_blocked');
      const listed = await scans.listValidationScans(CTX, {});
      assert.equal(listed.count, 1);
      const foreign = await scans.listValidationScans({ tenantId: OTHER_TENANT, userId: 'x', role: 'admin' }, {});
      assert.equal(foreign.count, 0);
    }, availability.env ?? process.env);
  });

  it('serializes executors per scan: a held lock yields not-acquired and never double-starts', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (skipUnlessAvailable(t, availability)) return;
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);
      const { scans, repositories } = buildServices(pool);
      const scan = await scans.createValidationScan(CTX, { target_group_id: GROUP, check_ids: [CHECK_ID] }, RUNTIME_CONFIG);

      let release;
      const held = new Promise((resolve) => { release = resolve; });
      const holder = repositories.validationScans.withScanLock(CTX, scan.id, async () => {
        const contended = await scans.advanceScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
        release();
        return contended;
      });
      await held;
      const lock = await holder;
      assert.equal(lock.acquired, true);
      assert.deepEqual(lock.result, { scan_id: scan.id, acquired: false, reason: 'locked' });

      const [first, second] = await Promise.all([
        scans.advanceScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG }),
        scans.advanceScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG }),
      ]);
      const acquired = [first, second].filter((result) => result.acquired);
      assert.ok(acquired.length >= 1);
      for (const result of acquired) assert.equal(result.waiting, true);
      const runs = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(`SELECT id FROM test_runs WHERE tenant_id = $1 AND scan_id = $2`, [TENANT, scan.id]);
        return rows;
      });
      assert.equal(runs.length, 1, 'concurrent advances must not start a second run for the same step');
    }, availability.env ?? process.env);
  });

  it('dispatches a due recurring scan exactly once and creates one next occurrence', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (skipUnlessAvailable(t, availability)) return;
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);
      const { scans } = buildServices(pool);
      const now = new Date();
      const scheduledFor = new Date(now.getTime() + 5 * 60_000).toISOString();
      const scan = await scans.createValidationScan(CTX, {
        target_group_id: GROUP,
        check_ids: [CHECK_ID],
        scheduled_for: scheduledFor,
        recurrence: { cadence: 'daily' },
      }, RUNTIME_CONFIG, { now });
      assert.equal(scan.status, 'scheduled');

      const early = await scans.dispatchDueValidationScans(RUNNER_CTX, { now, workerId: 'runner-1', runtimeConfig: RUNTIME_CONFIG });
      assert.deepEqual(early, []);
      const due = new Date(new Date(scheduledFor).getTime() + 1_000);
      const [a, b] = await Promise.all([
        scans.dispatchDueValidationScans(RUNNER_CTX, { now: due, workerId: 'runner-a', runtimeConfig: RUNTIME_CONFIG }),
        scans.dispatchDueValidationScans(RUNNER_CTX, { now: due, workerId: 'runner-b', runtimeConfig: RUNTIME_CONFIG }),
      ]);
      const dispatched = [...a, ...b];
      assert.equal(dispatched.length, 1);
      assert.equal(dispatched[0].dispatched, true);
      assert.equal(dispatched[0].advanced.acquired, true);
      const again = await scans.dispatchDueValidationScans(RUNNER_CTX, { now: due, workerId: 'runner-a', runtimeConfig: RUNTIME_CONFIG });
      assert.deepEqual(again, []);

      const all = await scans.listValidationScans(CTX, {});
      assert.equal(all.count, 2);
      const parent = all.items.find((row) => row.id === scan.id);
      const next = all.items.find((row) => row.id !== scan.id);
      assert.equal(parent.status, 'running');
      assert.equal(parent.next_scan_id, next.id);
      assert.equal(next.status, 'scheduled');
      assert.equal(next.previous_scan_id, scan.id);
      assert.equal(next.occurrence_index, 1);
      assert.equal(next.recurrence_series_id, scan.id);
      assert.equal(next.steps.length, 2);
      const runnable = await scans.listRunnableScans(RUNNER_CTX, {});
      assert.deepEqual(runnable.map((row) => row.id), [scan.id]);
      assert.equal((await readAudits(pool, 'validation_scan.dispatched')).length, 1);
      assert.equal((await readAudits(pool, 'validation_scan.scheduled')).length, 2);
    }, availability.env ?? process.env);
  });

  it('cancels the scan, the active child run, and its pending probe jobs', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (skipUnlessAvailable(t, availability)) return;
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);
      const { scans } = buildServices(pool);
      const scan = await scans.createValidationScan(CTX, { target_group_id: GROUP, check_ids: [CHECK_ID] }, RUNTIME_CONFIG);
      const runId = scan.steps[0].test_run_id;
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `INSERT INTO probe_jobs (id, tenant_id, test_run_id, target_id, check_id, status, nonce_hash, target_descriptor_json)
           VALUES ('pjob_scan_cancel', $1, $2, $3, $4, 'leased', 'nh_scan_cancel', '{"id":"tgt_scan_int_a","kind":"fqdn"}'::jsonb)`,
          [TENANT, runId, TARGET_A, CHECK_ID],
        );
      });

      const cancelled = await scans.cancelValidationScan(CTX, scan.id, { reason: 'operator stop' });
      assert.equal(cancelled.status, 'cancelled');
      assert.equal(cancelled.cancel_reason, 'operator stop');
      assert.deepEqual(cancelled.steps.map((step) => step.status), ['cancelled', 'skipped']);

      const run = await readRun(pool, runId);
      assert.equal(run.status, 'cancelled');
      assert.deepEqual(run.summary_json.cancellation, {
        reason: 'operator stop', by: CTX.userId, role: CTX.role, source: 'scan', scan_id: scan.id,
      });
      const jobs = await withTenantContext(pool, TENANT, async (client) => {
        const probe = await client.query(`SELECT status FROM probe_jobs WHERE id = 'pjob_scan_cancel'`);
        return { probe: probe.rows[0].status };
      });
      assert.equal(jobs.probe, 'cancelled');

      const runAudit = (await readAudits(pool, 'test_run.cancelled'))[0];
      assert.equal(runAudit.metadata_json.source, 'scan');
      assert.equal(runAudit.metadata_json.scan_id, scan.id);
      assert.equal(runAudit.metadata_json.cancelled_by, CTX.userId);
      assert.equal(runAudit.metadata_json.cancelled_by_role, CTX.role);
      assert.deepEqual(runAudit.metadata_json.cancelled_probe_job_ids, ['pjob_scan_cancel']);
      const scanAudit = (await readAudits(pool, 'validation_scan.cancelled'))[0];
      assert.equal(scanAudit.metadata_json.active_test_run_id, runId);
      assert.equal(scanAudit.metadata_json.cancelled_steps, 1);
      assert.equal(scanAudit.metadata_json.skipped_steps, 1);

      const runs = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(`SELECT id FROM test_runs WHERE tenant_id = $1 AND scan_id = $2`, [TENANT, scan.id]);
        return rows;
      });
      assert.equal(runs.length, 1, 'the cancel hook must not start the next step');
      const activity = await scans.getValidationScanActivity(CTX, scan.id, {});
      assert.ok(activity.items.some((item) => item.action === 'test_run.cancelled' && item.kind === 'run'));
      assert.equal(activity.items.at(-1).action, 'validation_scan.cancelled');
    }, availability.env ?? process.env);
  });

  it('advances the parent when the collection-window sweeper finalizes the child run', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (skipUnlessAvailable(t, availability)) return;
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);
      const { scans, testRuns } = buildServices(pool);
      const scan = await scans.createValidationScan(CTX, { target_group_id: GROUP, check_ids: [CHECK_ID] }, RUNTIME_CONFIG);
      const firstRunId = scan.steps[0].test_run_id;
      await withTenantContext(pool, TENANT, (client) => client.query(
        `UPDATE test_runs SET collection_deadline_at = now() - interval '5 minutes' WHERE tenant_id = $1 AND id = $2`,
        [TENANT, firstRunId],
      ));

      const summary = await testRuns.sweepExpiredCollectingRuns(RUNNER_CTX, {});
      assert.equal(summary.finalized, 1);
      assert.deepEqual(summary.errors, []);

      const after = await scans.getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
      assert.equal(after.steps[0].status, 'verdicted');
      assert.ok(after.steps[0].verdict);
      assert.equal(after.steps[1].status, 'collecting');
      assert.ok(after.steps[1].test_run_id);
      assert.notEqual(after.steps[1].test_run_id, firstRunId);
      assert.equal(after.status, 'running');
      assert.equal(after.summary.verdicted, 1);
      assert.equal(after.summary.running, 1);

      await withTenantContext(pool, TENANT, (client) => client.query(
        `UPDATE test_runs SET collection_deadline_at = now() - interval '5 minutes' WHERE tenant_id = $1 AND id = $2`,
        [TENANT, after.steps[1].test_run_id],
      ));
      const second = await testRuns.sweepExpiredCollectingRuns(RUNNER_CTX, {});
      assert.equal(second.finalized, 1);
      const done = await scans.getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
      assert.equal(done.status, 'completed');
      assert.equal(done.summary.verdicted, 2);
      assert.ok(done.completed_at);
      const completed = await readAudits(pool, 'validation_scan.completed');
      assert.equal(completed.length, 1);
      assert.equal(completed[0].metadata_json.summary.verdicted, 2);
      const stepCompleted = await readAudits(pool, 'validation_scan.step_completed');
      assert.equal(stepCompleted.length, 2);
      const inactive = await scans.advanceScan(RUNNER_CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
      assert.equal(inactive.acquired, false);
      assert.equal(inactive.reason, 'inactive');
    }, availability.env ?? process.env);
  });

  it('guards scan writes by status and lease, replaces steps atomically, and indexes scan activity', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (skipUnlessAvailable(t, availability)) return;
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedFixtures(pool);
      const { scans, repositories } = buildServices(pool);
      const repo = repositories.validationScans;
      const now = new Date();
      const scheduledFor = new Date(now.getTime() + 10 * 60_000).toISOString();
      const scan = await scans.createValidationScan(CTX, {
        target_group_id: GROUP,
        check_ids: [CHECK_ID],
        scheduled_for: scheduledFor,
        recurrence: { cadence: 'daily' },
      }, RUNTIME_CONFIG, { now });

      const leased = await repo.leaseDueScans(CTX, {
        now: new Date(now.getTime() + 11 * 60_000),
        workerId: 'w1',
        scanId: scan.id,
      });
      assert.equal(leased.length, 1);
      const editWhileLeased = await scans.patchValidationScan(CTX, scan.id, { name: 'late' }, { now });
      assert.deepEqual(editWhileLeased, { error: 'scan_not_editable', status: 409 });
      assert.equal(await repo.updateScan(CTX, scan.id, { name: 'forged' }, { expectedStatuses: ['scheduled'], leaseToken: 'forged' }), null);

      const cancelled = await scans.cancelValidationScan(CTX, scan.id, { reason: 'stop', now });
      assert.equal(cancelled.status, 'cancelled');
      const staleActivation = await repo.updateScanWithSteps(CTX, scan.id, {
        status: 'running',
        cancelled_at: null,
        lease_token: null,
        lease_owner: null,
        lease_expires_at: null,
      }, [], { expectedStatuses: ['scheduled'], leaseToken: leased[0].lease_token });
      assert.equal(staleActivation, null, 'a stale dispatcher cannot resurrect a cancelled scan');
      assert.equal((await repo.listSteps(CTX, scan.id)).length, 2, 'steps are untouched when the guard fails');

      const step = (await repo.listSteps(CTX, scan.id))[0];
      assert.equal(await repo.updateStep(CTX, step.id, { status: 'running' }, { expectedStatuses: ['starting'] }), null);
      // Cancelling a single occurrence (no cancel_series) of a recurring scan must keep the series
      // alive: the cancelled scan plus exactly one scheduled successor (finding 1).
      const series = await repo.listScans(CTX, { seriesId: scan.id });
      assert.equal(series.length, 2);
      const successor = series.find((row) => row.id !== scan.id);
      assert.equal(successor.status, 'scheduled');
      assert.equal(successor.previous_scan_id, scan.id);

      const catalog = await pool.query(
        `SELECT indexname FROM pg_indexes WHERE tablename = 'audit_logs'
           AND indexname IN ('idx_audit_tenant_metadata_scan_id', 'idx_audit_tenant_metadata_test_run_id')
         ORDER BY indexname`,
      );
      assert.deepEqual(catalog.rows.map((row) => row.indexname), [
        'idx_audit_tenant_metadata_scan_id',
        'idx_audit_tenant_metadata_test_run_id',
      ]);
      const column = await pool.query(
        `SELECT column_default FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'ingested_at'`,
      );
      assert.match(String(column.rows[0]?.column_default ?? ''), /now\(\)/);
    });
  });
});

