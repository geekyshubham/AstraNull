// Integration: PV-04 entry-path comparison lifecycle over Postgres (app role, RLS, row locks, transactional audit).
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { advanceEntryPathComparisonsForTenant } from '../../scripts/validation-scan-runner.mjs';
import {
  assertRlsPoliciesExist,
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT = 'ten_epc_pg';
const OTHER = 'ten_epc_pg_other';
const DECLARED = '2026-09-01T00:00:00.000Z';
const SCENARIO = 'waf.ssrf_marker.safe';
const CTX = { tenantId: TENANT, userId: 'usr_epc_admin', role: 'admin' };
const VIEWER = { tenantId: TENANT, userId: 'usr_epc_viewer', role: 'viewer' };
const SOC = { tenantId: TENANT, userId: 'usr_epc_soc', role: 'soc' };
const OTHER_CTX = { tenantId: OTHER, userId: 'usr_epc_other', role: 'admin' };
const FLAGS = { protectionValidationEnabled: true };
const SIMULATION = { probeMode: 'simulation', featureFlags: FLAGS };
const SIGNED = { probeMode: 'signed-worker', probeWorkerSecret: 'b'.repeat(32), featureFlags: FLAGS };
const GATE_OFF = { ...SIMULATION, featureFlags: { protectionValidationEnabled: false } };
const POLICIES = ['tenant_isolation_entry_path_comparisons', 'tenant_isolation_entry_path_comparison_items'];
const TARGETS = [
  ['tgt_epc_app', 'tg_epc_app', 'fqdn', 'app.example.test'],
  ['tgt_epc_alt', 'tg_epc_alt', 'fqdn', 'alt.example.test'],
  ['tgt_epc_origin', 'tg_epc_app', 'ip', '203.0.113.10'],
];

async function seed(ownerPool) {
  await withTenantContext(ownerPool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'EPC')`, [TENANT]);
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ('env_epc', $1, 'prod')`, [TENANT]);
    for (const group of ['tg_epc_app', 'tg_epc_alt']) {
      await client.query(
        `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode)
         VALUES ($1, $2, 'env_epc', $1, 'dns_verified', 'external_only')`,
        [group, TENANT],
      );
    }
    for (const [id, group, kind, value] of TARGETS) {
      await client.query(
        `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at)
         VALUES ($1, $2, $3, $4, $5, $5, $6::timestamptz)`,
        [id, TENANT, group, kind, value, DECLARED],
      );
      await client.query(
        `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
         VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', '{}'::jsonb, $4::timestamptz, 'usr_epc_admin', 'aud_seed')`,
        [`tv_${id}`, TENANT, id, DECLARED],
      );
    }
    await client.query(
      `INSERT INTO origin_bindings (id, tenant_id, protected_target_id, protected_target_group_id, origin_target_id, origin_target_group_id, host, sni, created_at)
       VALUES ('obind_epc', $1, 'tgt_epc_app', 'tg_epc_app', 'tgt_epc_origin', 'tg_epc_app', 'app.example.test', 'app.example.test', $2::timestamptz)`,
      [TENANT, DECLARED],
    );
  });
  await withTenantContext(ownerPool, OTHER, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Other')`, [OTHER]);
  });
}

async function appRolePool(ownerPool, databaseName) {
  await ensureHarnessAppRole(ownerPool);
  await ownerPool.query(`ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`);
  const url = new URL(databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName).replace(/^postgresql:/i, 'postgres:'));
  url.username = APP_ROLE_NAME;
  url.password = APP_ROLE_PASSWORD;
  const appUrl = url.toString().replace(/^postgres:/i, 'postgresql:');
  return { appUrl, appPool: createPgPool({ ASTRANULL_DATABASE_URL: appUrl }) };
}

async function withRuntime(t, runtimeConfig, callback) {
  const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
  if (!availability.available) {
    t.skip(availability.reason);
    return;
  }
  await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
    await assertRlsPoliciesExist(ownerPool, POLICIES);
    await seed(ownerPool);
    const { appUrl, appPool } = await appRolePool(ownerPool, databaseName);
    const env = {
      ...process.env,
      NODE_ENV: 'test',
      ASTRANULL_PERSISTENCE_MODE: 'postgres',
      ASTRANULL_DATABASE_URL: appUrl,
      ASTRANULL_PROTECTION_VALIDATION_ENABLED: '1',
      ASTRANULL_APPROVED_PROBE_SOURCES: '',
    };
    const runtime = await createPostgresRuntime(env, {
      createPool: () => appPool,
      closePool: async () => {},
      entryPathComparisonRuntimeConfig: runtimeConfig,
    });
    try {
      const pv = runtime.services.protectionValidation;
      for (const [entryTargetId, relationKind, extra] of [
        ['tgt_epc_app', 'primary_route', {}],
        ['tgt_epc_alt', 'alternate_hostname', {}],
        ['tgt_epc_origin', 'origin', { origin_binding_id: 'obind_epc' }],
      ]) {
        const created = await pv.createEntryPath(CTX, 'tgt_epc_app', {
          entry_target_id: entryTargetId,
          relation_kind: relationKind,
          owner: 'App Team',
          purpose: 'Declared route',
          expected_behavior: 'must_be_protected_by_layers',
          required_layers: ['waf'],
          ...extra,
        });
        assert.equal(created.error, undefined, JSON.stringify(created));
      }
      const paths = await pv.listEntryPaths(CTX, 'tgt_epc_app', { limit: 10 });
      const ids = Object.fromEntries(paths.items.map((row) => [row.entry_target_id, row.id]));
      await callback({ runtime, ownerPool, appPool, pv, comparisons: runtime.services.entryPathComparisons, ids });
    } finally {
      await runtime.close();
      await closePgPool(appPool);
    }
  });
}

function requestBody(ids, mode, extra = {}) {
  return {
    mode,
    anchor_target_id: 'tgt_epc_app',
    primary_entry_path_id: ids.tgt_epc_app,
    entry_path_ids: [ids.tgt_epc_app, ids.tgt_epc_alt, ids.tgt_epc_origin],
    expectation: { scenario: SCENARIO, layer_outcomes: { waf: 'enforce' } },
    ...extra,
  };
}

async function plan(pv, ids, runtimeConfig, extra = {}) {
  const planned = await pv.planOrStartEntryPathComparison(CTX, requestBody(ids, 'plan', extra), { runtimeConfig });
  assert.equal(planned.error, undefined, JSON.stringify(planned));
  assert.equal(planned.mode, 'plan');
  return planned;
}

async function start(pv, ids, runtimeConfig, options = {}, extra = {}) {
  const planned = await plan(pv, ids, runtimeConfig, extra);
  const started = await pv.planOrStartEntryPathComparison(
    CTX,
    requestBody(ids, 'start', { ...extra, reviewed_plan_digest: planned.plan_digest }),
    { runtimeConfig, ...options },
  );
  assert.equal(started.error, undefined, JSON.stringify(started));
  assert.equal(started.mode, 'start');
  return { planned, started };
}

async function count(ownerPool, sql, params = []) {
  const { rows } = await ownerPool.query(sql, params);
  return rows[0].n;
}

const audits = (ownerPool, action) => count(ownerPool, 'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = $2', [TENANT, action]);
const runs = (ownerPool, targetId = null) => count(
  ownerPool,
  'SELECT count(*)::int AS n FROM test_runs WHERE tenant_id = $1 AND ($2::text IS NULL OR target_id = $2)',
  [TENANT, targetId],
);

/** Finalizes collecting simulation runs through the run service, which fires the run-terminal hooks. */
async function finalizeOpenRuns(runtime, pv, comparisonId) {
  for (let pass = 0; pass < 6; pass += 1) {
    const view = await pv.getEntryPathComparison(CTX, comparisonId);
    if (view.status !== 'running') return view;
    const open = view.execution.filter((row) => row.execution_state === 'started' && row.test_run_id);
    for (const row of open) {
      const result = await runtime.services.testRuns.finalizeTestRun(CTX, row.test_run_id, { force: true });
      assert.equal(result?.error, undefined, JSON.stringify(result));
    }
  }
  return pv.getEntryPathComparison(CTX, comparisonId);
}

function executionState(view, entryPathId) {
  return view.execution.find((row) => row.entry_path_id === entryPathId);
}

describe('postgres entry-path comparison lifecycle', () => {
  it('plans passively, starts through the run service, completes, records the evaluation once, and stays tenant scoped', { timeout: 180_000 }, async (t) => {
    await withRuntime(t, SIMULATION, async ({ runtime, ownerPool, appPool, pv, ids }) => {
      const planned = await plan(pv, ids, SIMULATION);
      assert.equal(planned.eligible_count, 3);
      assert.equal(await runs(ownerPool), 0);
      assert.equal((await pv.planOrStartEntryPathComparison(VIEWER, requestBody(ids, 'plan'), { runtimeConfig: SIMULATION })).status, 403);

      const flipped = `${planned.plan_digest.slice(0, -1)}${planned.plan_digest.endsWith('0') ? '1' : '0'}`;
      const tampered = await pv.planOrStartEntryPathComparison(CTX, requestBody(ids, 'start', { reviewed_plan_digest: flipped }), { runtimeConfig: SIMULATION });
      assert.equal(tampered.error, 'reviewed_plan_mismatch');
      assert.equal(await runs(ownerPool), 0);
      assert.equal(await audits(ownerPool, 'entry_path_comparison.start_denied'), 1);

      const { started } = await start(pv, ids, SIMULATION, { idempotencyKey: 'epc-pg-1' });
      assert.equal(started.status, 'running', JSON.stringify(started));
      assert.equal(executionState({ execution: started.items }, ids.tgt_epc_origin).execution_state, 'pending');
      const finished = await finalizeOpenRuns(runtime, pv, started.id);
      assert.equal(finished.status, 'completed', JSON.stringify(finished.execution));
      assert.ok(finished.execution.every((item) => item.execution_state === 'finalized'), JSON.stringify(finished.execution));
      assert.equal(await runs(ownerPool), 3);
      assert.equal(await audits(ownerPool, 'entry_path_comparison.started'), 1);
      assert.equal(await audits(ownerPool, 'entry_path_comparison.completed'), 1);
      assert.equal(await audits(ownerPool, 'entry_path_comparison.evaluated'), 1);

      const view = await pv.getEntryPathComparison(VIEWER, { comparisonId: started.id });
      assert.equal(view.status, 'completed');
      assert.ok(view.evaluation_id, 'evaluation is linked');
      assert.ok(view.evaluation_digest);
      assert.equal(view.items.length, 3);
      const stored = await ownerPool.query(
        `SELECT e.id, e.reviewed_plan_digest, e.provenance_json->>'comparison_id' AS comparison_id
         FROM protection_comparison_evaluations e WHERE e.tenant_id = $1 AND e.kind = 'path_validation'`,
        [TENANT],
      );
      assert.equal(stored.rows.length, 1);
      assert.equal(stored.rows[0].id, view.evaluation_id);
      assert.equal(stored.rows[0].comparison_id, started.id);
      assert.equal(stored.rows[0].reviewed_plan_digest, started.plan_digest);
      const items = await ownerPool.query(
        `SELECT entry_path_id, status, test_run_id, probe_job_id, target_scope_hash FROM entry_path_comparison_items
         WHERE tenant_id = $1 AND comparison_id = $2 ORDER BY ordinal`,
        [TENANT, started.id],
      );
      assert.ok(items.rows.every((row) => row.status === 'completed' && row.test_run_id && /^[a-f0-9]{64}$/.test(row.target_scope_hash)));

      const replay = await pv.planOrStartEntryPathComparison(CTX, requestBody(ids, 'start', { reviewed_plan_digest: planned.plan_digest }), {
        runtimeConfig: SIMULATION, idempotencyKey: 'epc-pg-1',
      });
      assert.equal(replay.replayed, true);
      assert.equal(replay.id, started.id);
      assert.equal(await runs(ownerPool), 3);
      const otherPlan = await plan(pv, ids, SIMULATION, { entry_path_ids: [ids.tgt_epc_app, ids.tgt_epc_alt] });
      const reused = await pv.planOrStartEntryPathComparison(CTX, {
        ...requestBody(ids, 'start', { reviewed_plan_digest: otherPlan.plan_digest }),
        entry_path_ids: [ids.tgt_epc_app, ids.tgt_epc_alt],
      }, { runtimeConfig: SIMULATION, idempotencyKey: 'epc-pg-1' });
      assert.equal(reused.error, 'idempotency_conflict');
      assert.equal(reused.existing_id, started.id);

      const second = await start(pv, ids, SIMULATION);
      assert.notEqual(second.started.id, started.id);
      assert.equal((await finalizeOpenRuns(runtime, pv, second.started.id)).status, 'completed');
      const racePaths = { entry_path_ids: [ids.tgt_epc_app, ids.tgt_epc_alt] };
      const racePlan = await plan(pv, ids, SIMULATION, racePaths);
      const startedAudits = await audits(ownerPool, 'entry_path_comparison.started');
      const raced = await Promise.all(Array.from({ length: 4 }, () => pv.planOrStartEntryPathComparison(
        CTX,
        requestBody(ids, 'start', { ...racePaths, reviewed_plan_digest: racePlan.plan_digest }),
        { runtimeConfig: SIMULATION },
      )));
      assert.equal(raced.filter((row) => row.error).length, 0, JSON.stringify(raced));
      assert.equal(new Set(raced.map((row) => row.id)).size, 1);
      assert.equal(raced.filter((row) => row.replayed !== true).length, 1);
      assert.equal(await audits(ownerPool, 'entry_path_comparison.started'), startedAudits + 1);
      assert.equal((await finalizeOpenRuns(runtime, pv, raced[0].id)).status, 'completed');
      const page1 = await pv.listEntryPathComparisons(VIEWER, { anchor_target_id: 'tgt_epc_app', limit: 2 });
      assert.equal(page1.count, 2);
      assert.deepEqual(page1.items.map((row) => row.id), [raced[0].id, second.started.id]);
      assert.ok(page1.next_cursor);
      const page2 = await pv.listEntryPathComparisons(VIEWER, { anchor_target_id: 'tgt_epc_app', limit: 2, cursor: page1.next_cursor });
      assert.deepEqual(page2.items.map((row) => row.id), [started.id]);
      assert.equal(page2.next_cursor, null);
      assert.equal((await pv.listEntryPathComparisons(VIEWER, { limit: 1000 })).count, 3);

      assert.equal(await pv.getEntryPathComparison(OTHER_CTX, { comparisonId: started.id }), null);
      assert.equal((await pv.listEntryPathComparisons(OTHER_CTX, {})).count, 0);
      assert.equal((await pv.cancelEntryPathComparison(OTHER_CTX, { comparisonId: started.id })).status, 404);
      const hidden = await withTenantContext(appPool, OTHER, async (client) => (await client.query(
        'SELECT (SELECT count(*) FROM entry_path_comparisons)::int + (SELECT count(*) FROM entry_path_comparison_items)::int AS n',
      )).rows[0].n);
      assert.equal(hidden, 0);
      assert.equal((await pv.cancelEntryPathComparison(CTX, { comparisonId: started.id })).error, 'not_cancellable');

      await assert.rejects(
        withTenantContext(appPool, TENANT, (client) => client.query(
          `UPDATE entry_path_comparisons SET approved_scope_json = '{}'::jsonb WHERE id = $1`, [started.id],
        )),
        /immutable/,
      );
      await assert.rejects(
        withTenantContext(appPool, TENANT, (client) => client.query(
          `UPDATE entry_path_comparisons SET status = 'running', completed_at = NULL, evaluation_json = NULL, evaluation_id = NULL WHERE id = $1`, [started.id],
        )),
        /terminal and final/,
      );
      await assert.rejects(
        withTenantContext(appPool, TENANT, (client) => client.query(
          `UPDATE entry_path_comparison_items SET status = 'failed', skip_reason = 'x' WHERE comparison_id = $1`, [started.id],
        )),
        /terminal and final/,
      );
      await assert.rejects(
        withTenantContext(appPool, TENANT, (client) => client.query('DELETE FROM entry_path_comparisons WHERE id = $1', [started.id])),
        /retained history/,
      );
    });
  });

  it('defers on budgets, advances exactly once under concurrent ticks, and honors the feature gate', { timeout: 180_000 }, async (t) => {
    await withRuntime(t, SIMULATION, async ({ runtime, ownerPool, pv, comparisons, ids }) => {
      const pair = { entry_path_ids: [ids.tgt_epc_app, ids.tgt_epc_alt] };
      await ownerPool.query(`UPDATE target_groups SET safety_policy = '{"max_runs_per_hour": 1}'::jsonb WHERE id = 'tg_epc_alt'`);
      const { started } = await start(pv, ids, SIMULATION, {}, pair);
      assert.equal(started.status, 'running');
      const alt = started.items.find((row) => row.entry_path_id === ids.tgt_epc_alt);
      assert.equal(alt.execution_state, 'deferred', JSON.stringify(started.items));
      assert.ok(Date.parse(alt.deferred_until) > Date.now());
      assert.equal(await runs(ownerPool, 'tgt_epc_alt'), 0);
      const primary = started.items.find((row) => row.entry_path_id === ids.tgt_epc_app);
      assert.equal((await runtime.services.testRuns.finalizeTestRun(CTX, primary.test_run_id, { force: true }))?.error, undefined);

      await Promise.all(Array.from({ length: 3 }, () => comparisons.advanceDueEntryPathComparisons(CTX, { runtimeConfig: SIMULATION })));
      assert.equal(await runs(ownerPool, 'tgt_epc_alt'), 0);
      assert.equal(executionState(await pv.getEntryPathComparison(CTX, started.id), ids.tgt_epc_alt).execution_state, 'deferred');

      await ownerPool.query(`UPDATE target_groups SET safety_policy = '{}'::jsonb WHERE id = 'tg_epc_alt'`);
      await Promise.all(Array.from({ length: 4 }, () => comparisons.advanceDueEntryPathComparisons(CTX, { runtimeConfig: SIMULATION, now: alt.deferred_until })));
      assert.equal(await runs(ownerPool, 'tgt_epc_alt'), 1);
      const done = await finalizeOpenRuns(runtime, pv, started.id);
      assert.equal(done.status, 'completed');
      assert.equal(executionState(done, ids.tgt_epc_alt).execution_state, 'finalized');
      assert.equal(await audits(ownerPool, 'entry_path_comparison.completed'), 1);
      assert.equal(await audits(ownerPool, 'entry_path_comparison.evaluated'), 1);

      await ownerPool.query(`UPDATE target_groups SET safety_policy = '{"max_runs_per_hour": 1}'::jsonb WHERE id = 'tg_epc_alt'`);
      const gated = await start(pv, ids, SIMULATION, {}, pair);
      const gatedAlt = gated.started.items.find((row) => row.entry_path_id === ids.tgt_epc_alt);
      assert.equal(gatedAlt.execution_state, 'deferred');
      const before = await runs(ownerPool);
      comparisons.configureEntryPathComparisonRuntime(GATE_OFF);
      await comparisons.advanceDueEntryPathComparisons(CTX, { now: gatedAlt.deferred_until });
      const waiting = await pv.getEntryPathComparison(CTX, gated.started.id);
      assert.equal(waiting.status, 'running');
      assert.equal(waiting.cancel_reason, 'protection_validation_disabled');
      assert.equal(executionState(waiting, ids.tgt_epc_alt).skip_reason, 'protection_validation_disabled');
      assert.equal(executionState(waiting, ids.tgt_epc_alt).test_run_id, null);
      const off = await finalizeOpenRuns(runtime, pv, gated.started.id);
      assert.equal(off.status, 'cancelled');
      assert.equal(await runs(ownerPool), before);
      const row = await ownerPool.query(
        `SELECT status FROM entry_path_comparison_items WHERE tenant_id = $1 AND comparison_id = $2 AND entry_path_id = $3`,
        [TENANT, gated.started.id, ids.tgt_epc_alt],
      );
      assert.equal(row.rows[0].status, 'cancelled');
    });
  });

  it('settles late completions once, stops through the run cancel path, and cancels on the kill switch', { timeout: 180_000 }, async (t) => {
    await withRuntime(t, SIGNED, async ({ runtime, ownerPool, pv, comparisons, ids }) => {
      const first = await start(pv, ids, SIGNED);
      const startedItems = first.started.items.filter((row) => row.execution_state === 'started');
      assert.ok(startedItems.length >= 1, JSON.stringify(first.started.items));
      const jobs = await count(ownerPool, 'SELECT count(*)::int AS n FROM probe_jobs WHERE tenant_id = $1', [TENANT]);
      assert.equal(jobs, startedItems.length);
      const linked = await ownerPool.query(
        `SELECT count(*)::int AS n FROM entry_path_comparison_items WHERE tenant_id = $1 AND comparison_id = $2 AND probe_job_id IS NOT NULL`,
        [TENANT, first.started.id],
      );
      assert.equal(linked.rows[0].n, startedItems.length);

      const primary = startedItems.find((row) => row.entry_path_id === ids.tgt_epc_app) ?? startedItems[0];
      await ownerPool.query(`UPDATE test_runs SET status = 'verdicted', completed_at = NOW() WHERE tenant_id = $1 AND id = $2`, [TENANT, primary.test_run_id]);
      const run = await runtime.repositories.validationEvidence.getTestRun({ tenantId: TENANT }, primary.test_run_id);
      const runsBefore = await runs(ownerPool);
      await Promise.all([
        comparisons.onRunTerminal(run, { reason: 'verdicted' }),
        comparisons.onRunTerminal(run, { reason: 'verdicted' }),
        comparisons.advanceDueEntryPathComparisons(CTX, { runtimeConfig: SIGNED }),
      ]);
      const settled = await pv.getEntryPathComparison(CTX, first.started.id);
      assert.equal(executionState(settled, primary.entry_path_id).execution_state, 'finalized');
      const pendingBefore = first.started.items.filter((row) => row.execution_state === 'pending').length;
      assert.ok(await runs(ownerPool) - runsBefore <= pendingBefore);

      const stop = await pv.cancelEntryPathComparison(CTX, { comparisonId: first.started.id, reason: 'operator stop' });
      assert.equal(stop.status, 'cancelled', JSON.stringify(stop));
      const stopped = await pv.getEntryPathComparison(CTX, first.started.id);
      assert.ok(stopped.execution.every((row) => ['finalized', 'skipped'].includes(row.execution_state)));
      assert.equal(await count(ownerPool, `SELECT count(*)::int AS n FROM test_runs WHERE tenant_id = $1 AND status IN ('planned', 'running', 'collecting')`, [TENANT]), 0);
      assert.equal(await audits(ownerPool, 'entry_path_comparison.cancelled'), 1);
      assert.equal((await pv.cancelEntryPathComparison(CTX, { comparisonId: first.started.id })).error, 'not_cancellable');

      const second = await start(pv, ids, SIGNED);
      assert.equal(second.started.status, 'running');
      const killed = await runtime.services.highScale.setKillSwitch(SOC, true, 'incident');
      assert.equal(killed.error, undefined, JSON.stringify(killed));
      const view = await pv.getEntryPathComparison(CTX, second.started.id);
      assert.equal(view.status, 'cancelled', JSON.stringify(view.execution));
      assert.equal(view.cancel_reason, 'kill_switch_active');
      assert.ok(view.execution.every((row) => row.execution_state === 'skipped'));
      assert.ok(view.items.every((row) => row.outcome === 'skipped'));
      const denied = await pv.planOrStartEntryPathComparison(CTX, requestBody(ids, 'start', { reviewed_plan_digest: second.planned.plan_digest }), { runtimeConfig: SIGNED });
      assert.equal(denied.error, 'kill_switch_active');
    });
  });
  it('resumes deferred items and orphaned reconcile requests from the runner tick alone, and bounds repeated deferrals', { timeout: 180_000 }, async (t) => {
    await withRuntime(t, SIMULATION, async ({ runtime, ownerPool, pv, comparisons, ids }) => {
      const pair = { entry_path_ids: [ids.tgt_epc_app, ids.tgt_epc_alt] };
      await ownerPool.query(`UPDATE target_groups SET safety_policy = '{"max_runs_per_hour": 1}'::jsonb WHERE id = 'tg_epc_alt'`);
      const { started } = await start(pv, ids, SIMULATION, {}, pair);
      const primary = started.items.find((row) => row.entry_path_id === ids.tgt_epc_app);
      assert.equal(executionState({ execution: started.items }, ids.tgt_epc_alt).execution_state, 'deferred');

      for (let pass = 0; pass < 20; pass += 1) {
        const view = await pv.getEntryPathComparison(CTX, started.id);
        const deferredUntil = executionState(view, ids.tgt_epc_alt).deferred_until;
        const results = await comparisons.advanceDueEntryPathComparisons(CTX, { now: deferredUntil });
        assert.ok(results.every((row) => row.reason !== 'advance_failed'), JSON.stringify(results));
      }
      const attempts = await ownerPool.query(
        `SELECT attempts, status FROM entry_path_comparison_items WHERE tenant_id = $1 AND comparison_id = $2 AND entry_path_id = $3`,
        [TENANT, started.id, ids.tgt_epc_alt],
      );
      assert.equal(attempts.rows[0].status, 'deferred');
      assert.equal(attempts.rows[0].attempts, 0);
      assert.equal(await runs(ownerPool, 'tgt_epc_alt'), 0);

      await ownerPool.query(`UPDATE target_groups SET safety_policy = '{}'::jsonb WHERE id = 'tg_epc_alt'`);
      await ownerPool.query(
        `UPDATE entry_path_comparison_items SET deferred_until = NOW() - interval '1 second'
         WHERE tenant_id = $1 AND comparison_id = $2 AND entry_path_id = $3`,
        [TENANT, started.id, ids.tgt_epc_alt],
      );
      const tick = await advanceEntryPathComparisonsForTenant(comparisons, CTX, 25);
      assert.equal(tick.error, undefined, JSON.stringify(tick));
      assert.ok(tick.advanced.some((row) => row.comparison_id === started.id && row.advanced), JSON.stringify(tick));
      assert.equal(await runs(ownerPool, 'tgt_epc_alt'), 1);

      const lockClient = await ownerPool.connect();
      try {
        await lockClient.query('SELECT pg_advisory_lock(hashtext($1), hashtext($2))', ['entry_path_comparison', `${TENANT}:${started.id}`]);
        for (const runId of [primary.test_run_id, executionState(await pv.getEntryPathComparison(CTX, started.id), ids.tgt_epc_alt).test_run_id]) {
          assert.equal((await runtime.services.testRuns.finalizeTestRun(CTX, runId, { force: true }))?.error, undefined);
        }
        const blocked = await pv.getEntryPathComparison(CTX, started.id);
        assert.equal(blocked.status, 'running');
      } finally {
        await lockClient.query('SELECT pg_advisory_unlock(hashtext($1), hashtext($2))', ['entry_path_comparison', `${TENANT}:${started.id}`]);
        lockClient.release();
      }
      const settledTick = await advanceEntryPathComparisonsForTenant(comparisons, CTX, 25);
      assert.equal(settledTick.error, undefined, JSON.stringify(settledTick));
      const done = await pv.getEntryPathComparison(CTX, started.id);
      assert.equal(done.status, 'completed', JSON.stringify(done.execution));
      assert.ok(done.execution.every((row) => row.execution_state === 'finalized'));
      assert.ok(done.evaluation_id, 'runner tick also links the evaluation');

      await ownerPool.query(`UPDATE target_groups SET safety_policy = '{"max_runs_per_hour": 1}'::jsonb WHERE id = 'tg_epc_alt'`);
      const capped = await start(pv, ids, SIMULATION, {}, pair);
      const startedAt = Date.parse(capped.started.items.find((row) => row.entry_path_id === ids.tgt_epc_app).deferred_until ?? new Date().toISOString());
      const later = new Date(Math.max(startedAt, Date.now()) + 25 * 60 * 60 * 1000).toISOString();
      await comparisons.advanceDueEntryPathComparisons(CTX, { now: later });
      const bounded = await pv.getEntryPathComparison(CTX, capped.started.id);
      assert.equal(executionState(bounded, ids.tgt_epc_alt).skip_reason, 'deferral_limit_reached', JSON.stringify(bounded.execution));
    });
  });
});
