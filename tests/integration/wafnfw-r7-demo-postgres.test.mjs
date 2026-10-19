import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { CHECK_CATALOG, isCustomerRunnable, targetInputRefusal } from '../../src/contracts/checks.mjs';
import { planScanSteps } from '../../src/contracts/validationScanManagement.mjs';
import { demoMaxRunsPerHour } from '../../src/lib/demoAutoVerify.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createServer } from '../../src/server.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import {
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const DEMO_TENANT = 'ten_demo';
const PROD_TENANT = 'ten_r7_pg_prod';
const DEMO_GROUP = 'tg_r7_pg_demo';
const PROD_GROUP = 'tg_r7_pg_prod';
const DEMO_TARGET = 'tgt_r7_pg_demo_fqdn';
const PROD_TARGET = 'tgt_r7_pg_prod_fqdn';
const SECRET = randomBytes(32).toString('hex');

const demoAdmin = () => demoHeaders('admin', DEMO_TENANT, 'usr_admin');
const prodAdmin = () => demoHeaders('admin', PROD_TENANT, 'usr_r7_prod_admin');

async function seed(ownerPool) {
  await ownerPool.query(
    `INSERT INTO tenants (id, name) VALUES ($1, 'R7 Demo Tenant'), ($2, 'R7 Prod Tenant')`,
    [DEMO_TENANT, PROD_TENANT],
  );

  await withTenantContext(ownerPool, DEMO_TENANT, async (client) => {
    await client.query(
      `INSERT INTO environments (id, tenant_id, name) VALUES ('env_r7_pg_demo', $1, 'demo')`,
      [DEMO_TENANT],
    );
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode, safety_policy, safe_test_windows)
       VALUES ($1, $2, 'env_r7_pg_demo', 'Demo Group', 'user_confirmed', 'external_only',
               '{"min_seconds_between_runs":0,"max_runs_per_hour":60}'::jsonb, '[]'::jsonb)`,
      [DEMO_GROUP, DEMO_TENANT],
    );
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
       VALUES ($1, $2, $3, 'fqdn', 'app.demo.example.com', 'app.demo.example.com')`,
      [DEMO_TARGET, DEMO_TENANT, DEMO_GROUP],
    );
    await client.query(
      `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
       VALUES ('tv_r7_pg_demo', $1, $2, 'user_confirmed', 'manual_override', '{"method":"demo_auto_verify","demo":true}'::jsonb, now(), 'usr_r7_demo_admin', 'aud_seed_demo')`,
      [DEMO_TENANT, DEMO_TARGET],
    );
  });

  await withTenantContext(ownerPool, PROD_TENANT, async (client) => {
    await client.query(
      `INSERT INTO environments (id, tenant_id, name) VALUES ('env_r7_pg_prod', $1, 'prod')`,
      [PROD_TENANT],
    );
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode, safety_policy, safe_test_windows)
       VALUES ($1, $2, 'env_r7_pg_prod', 'Prod Group', 'dns_verified', 'external_only',
               '{"min_seconds_between_runs":0,"max_runs_per_hour":60}'::jsonb, '[]'::jsonb)`,
      [PROD_GROUP, PROD_TENANT],
    );
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
       VALUES ($1, $2, $3, 'fqdn', 'app.prod.example.com', 'app.prod.example.com')`,
      [PROD_TARGET, PROD_TENANT, PROD_GROUP],
    );
    await client.query(
      `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
       VALUES ('tv_r7_pg_prod', $1, $2, 'dns_verified', 'dns_txt', '{}'::jsonb, now(), 'usr_r7_prod_admin', 'aud_seed_prod')`,
      [PROD_TENANT, PROD_TARGET],
    );
  });
}

async function withR7PostgresServer(t, callback) {
  const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
  if (!availability.available) {
    t.skip(availability.reason);
    return;
  }
  const prevDemoEnv = process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
  process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = DEMO_TENANT;

  await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
    await seed(ownerPool);
    try {
      await ownerPool.query(`ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`);
    } catch (err) {
      if (!err?.message?.includes('concurrently updated')) throw err;
    }
    const url = new URL(databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName).replace(/^postgresql:/i, 'postgres:'));
    url.username = APP_ROLE_NAME;
    url.password = APP_ROLE_PASSWORD;
    const appUrl = url.toString().replace(/^postgres:/i, 'postgresql:');
    const appPool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl });
    const env = {
      ...process.env,
      NODE_ENV: 'test',
      ASTRANULL_PERSISTENCE_MODE: 'postgres',
      ASTRANULL_DATABASE_URL: appUrl,
      ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: DEMO_TENANT,
      ASTRANULL_RATE_LIMIT_DISABLED: '1',
      ASTRANULL_PROBE_WORKER_SECRET: SECRET,
      ASTRANULL_PROBE_MODE: 'signed-worker',
    };
    delete env.ASTRANULL_NO_PERSIST;

    const runtime = await createPostgresRuntime(env, { createPool: () => appPool, closePool: async () => {} });
    const server = createServer({ runtimeConfig: loadRuntimeConfig(env), env, services: runtime.services, runtimeHealth: runtime.health });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    try {
      await callback({ baseUrl, ownerPool, appPool });
    } finally {
      await closeServer(server);
      await runtime.close?.();
      await closePgPool(appPool);
      if (prevDemoEnv === undefined) {
        delete process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
      } else {
        process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = prevDemoEnv;
      }
    }
  });
}

describe('Ticket R7: demo tenant runs every customer check with no access or input gates (Postgres)', () => {
  it('verifies all R7 requirements (a)-(g) in Postgres runtime', { timeout: 180_000 }, async (t) => {
    await withR7PostgresServer(t, async ({ baseUrl, ownerPool }) => {
      // (a) GET /v1/checks?target_id= lists every customer-runnable check as runnable for demo; non-demo gets refusal codes
      const demoRes = await request(baseUrl, 'GET', `/v1/checks?target_id=${DEMO_TARGET}`, {
        headers: demoAdmin(),
      });
      assert.equal(demoRes.status, 200);
      const demoItems = demoRes.json.items;
      const customerRunnableTotal = CHECK_CATALOG.filter(isCustomerRunnable).length;
      assert.equal(demoItems.filter(isCustomerRunnable).length, customerRunnableTotal);
      for (const item of demoItems) {
        assert.equal(item.requires_additional_input, false);
        assert.equal(item.additional_input_reason, null);
      }

      const prodRes = await request(baseUrl, 'GET', `/v1/checks?target_id=${PROD_TARGET}`, {
        headers: prodAdmin(),
      });
      assert.equal(prodRes.status, 200);
      assert.ok(prodRes.json.items.length < customerRunnableTotal);

      const prodAllRes = await request(baseUrl, 'GET', `/v1/checks?target_id=${PROD_TARGET}&scope=all`, {
        headers: prodAdmin(),
      });
      assert.equal(prodAllRes.status, 200);
      const tcpCheck = prodAllRes.json.items.find((item) => item.check_id === 'nfw.declared_deny_tcp.safe');
      assert.ok(tcpCheck);
      assert.equal(tcpCheck.requires_additional_input, true);
      assert.equal(tcpCheck.additional_input_reason, 'declared_tcp_deny_required');

      // (b) Full-catalog scan plan excludes no customer-runnable check for missing input; SOC checks still excluded
      const customerChecks = CHECK_CATALOG.filter(isCustomerRunnable);
      const demoPlan = planScanSteps({
        checks: customerChecks,
        targets: [{ id: DEMO_TARGET, tenant_id: DEMO_TENANT, target_group_id: DEMO_GROUP, kind: 'fqdn', value: 'app.demo.example.com' }],
        targetInputRefusal,
        tenantId: DEMO_TENANT,
      });
      const demoMissingInputExclusions = demoPlan.excluded.filter((e) => e.reason !== 'target_kind_not_supported');
      assert.equal(demoMissingInputExclusions.length, 0);

      const prodPlan = planScanSteps({
        checks: customerChecks,
        targets: [{ id: PROD_TARGET, tenant_id: PROD_TENANT, target_group_id: PROD_GROUP, kind: 'fqdn', value: 'app.prod.example.com' }],
        targetInputRefusal,
        tenantId: PROD_TENANT,
      });
      const prodMissingInputExclusions = prodPlan.excluded.filter((e) => e.reason !== 'target_kind_not_supported');
      assert.ok(prodMissingInputExclusions.length > 0);
      assert.ok(prodMissingInputExclusions.some((e) => e.reason === 'declared_tcp_deny_required'));

      const demoScanRes = await request(baseUrl, 'POST', '/v1/validation-scans', {
        headers: demoAdmin(),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_ids: ['nfw.declared_deny_tcp.safe'],
        },
      });
      assert.equal(demoScanRes.status, 201);
      assert.equal(demoScanRes.json.steps.length, 1);
      assert.equal(demoScanRes.json.steps[0].check_id, 'nfw.declared_deny_tcp.safe');

      const socCheck = CHECK_CATALOG.find((c) => !isCustomerRunnable(c));
      assert.ok(socCheck);
      const prodSocScanRes = await request(baseUrl, 'POST', '/v1/validation-scans', {
        headers: prodAdmin(),
        body: {
          target_group_id: PROD_GROUP,
          target_id: PROD_TARGET,
          check_ids: [socCheck.check_id],
        },
      });
      assert.equal(prodSocScanRes.status, 403);
      assert.equal(prodSocScanRes.json.error, 'soc_gated_check');

      const prodScanRes = await request(baseUrl, 'POST', '/v1/validation-scans', {
        headers: prodAdmin(),
        body: {
          target_group_id: PROD_GROUP,
          target_id: PROD_TARGET,
          check_ids: ['nfw.declared_deny_tcp.safe'],
        },
      });
      assert.equal(prodScanRes.status, 400);
      assert.equal(prodScanRes.json.error, 'check_requires_additional_input');

      // (c) Starting nfw.declared_deny_tcp.safe on demo target finishes inconclusive with required_input_missing
      const res = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoAdmin(),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: 'nfw.declared_deny_tcp.safe',
        },
      });
      assert.equal(res.status, 201);
      assert.equal(res.json.jobs_dispatched, 0);

      const runId = res.json.run.id;
      const runRes = await request(baseUrl, 'GET', `/v1/test-runs/${runId}`, {
        headers: demoAdmin(),
      });
      assert.equal(runRes.status, 200);
      const run = runRes.json;
      assert.equal(run.status, 'verdicted');
      assert.equal(run.probe_external_result, 'unsupported_target');
      assert.equal(run.summary?.requests_sent, 0);
      assert.ok(run.verdict);
      assert.equal(run.verdict.verdict, 'inconclusive');
      assert.equal(run.verdict.confidence, 'external_only');
      assert.equal(run.verdict.explanation_reason, 'required_input_missing');
      assert.equal(run.verdict.explanation, 'No denied port is declared, so there was nothing to probe.');

      const eventsRes = await request(baseUrl, 'GET', `/v1/test-runs/${runId}/events`, {
        headers: demoAdmin(),
      });
      assert.equal(eventsRes.status, 200);
      assert.equal(eventsRes.json.items.length, 0);

      // (d) Demo hourly cap is dropped by default (uncapped) and env override works; non-demo keeps 60
      assert.equal(demoMaxRunsPerHour({}), Infinity);
      assert.equal(demoMaxRunsPerHour({ ASTRANULL_DEMO_MAX_RUNS_PER_HOUR: '2500' }), 2500);

      await withTenantContext(ownerPool, PROD_TENANT, async (client) => {
        for (let i = 0; i < 60; i += 1) {
          await client.query(
            `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, created_at, started_at)
             VALUES ($1, $2, $3, $4, 'dns.authoritative_response.safe', 'verdicted', now(), now())`,
            [`run_seed_pg_prod_${i}`, PROD_TENANT, PROD_GROUP, PROD_TARGET],
          );
        }
      });

      const prodBlockRes = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: prodAdmin(),
        body: {
          target_group_id: PROD_GROUP,
          target_id: PROD_TARGET,
          check_id: 'dns.authoritative_response.safe',
        },
      });
      assert.equal(prodBlockRes.status, 429);
      assert.equal(prodBlockRes.json.error, 'safe_rate_cap_exceeded');

      await withTenantContext(ownerPool, DEMO_TENANT, async (client) => {
        for (let i = 0; i < 60; i += 1) {
          await client.query(
            `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, created_at, started_at)
             VALUES ($1, $2, $3, $4, 'dns.authoritative_response.safe', 'verdicted', now(), now())`,
            [`run_seed_pg_demo_${i}`, DEMO_TENANT, DEMO_GROUP, DEMO_TARGET],
          );
        }
      });

      const demoAllowRes = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoAdmin(),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: 'dns.authoritative_response.safe',
        },
      });
      assert.equal(demoAllowRes.status, 201);

      // (e) Closed safe window does not block demo but still blocks non-demo
      const closedWindow = JSON.stringify([{ day: 'Mon', start_at: '2020-01-01T00:00:00Z', end_at: '2020-01-01T01:00:00Z' }]);
      await withTenantContext(ownerPool, PROD_TENANT, async (client) => {
        await client.query(`UPDATE target_groups SET safe_test_windows = $1::jsonb WHERE id = $2`, [closedWindow, PROD_GROUP]);
      });
      await withTenantContext(ownerPool, DEMO_TENANT, async (client) => {
        await client.query(`UPDATE target_groups SET safe_test_windows = $1::jsonb WHERE id = $2`, [closedWindow, DEMO_GROUP]);
        await client.query(`UPDATE test_runs SET status = 'verdicted' WHERE tenant_id = $1`, [DEMO_TENANT]);
      });

      const prodWindowBlockRes = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: prodAdmin(),
        body: {
          target_group_id: PROD_GROUP,
          target_id: PROD_TARGET,
          check_id: 'dns.authoritative_response.safe',
        },
      });
      assert.equal(prodWindowBlockRes.status, 429);
      assert.equal(prodWindowBlockRes.json.error, 'safe_window_closed');

      const demoWindowAllowRes = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoAdmin(),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: 'dns.authoritative_response.safe',
        },
      });
      assert.equal(demoWindowAllowRes.status, 201);

      // (f) SOC-gated checks give 403 soc_gated_check for non-demo; demo runs without SOC gates; kill switch blocks demo
      const prodSocRes = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: prodAdmin(),
        body: {
          target_group_id: PROD_GROUP,
          target_id: PROD_TARGET,
          check_id: socCheck.check_id,
        },
      });
      assert.equal(prodSocRes.status, 403);
      assert.equal(prodSocRes.json.error, 'soc_gated_check');

      await withTenantContext(ownerPool, DEMO_TENANT, async (client) => {
        await client.query(`UPDATE test_runs SET status = 'verdicted' WHERE tenant_id = $1`, [DEMO_TENANT]);
      });

      const demoSocRes = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoAdmin(),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: socCheck.check_id,
        },
      });
      assert.equal(demoSocRes.status, 201);

      await withTenantContext(ownerPool, DEMO_TENANT, async (client) => {
        await client.query(`UPDATE test_runs SET status = 'verdicted' WHERE tenant_id = $1`, [DEMO_TENANT]);
      });

      // Generic user in demo tenant without admin identity is blocked by SOC gate
      const demoGenericRes = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoHeaders('admin', DEMO_TENANT, 'usr_generic_demo'),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: socCheck.check_id,
        },
      });
      assert.equal(demoGenericRes.status, 403);
      assert.equal(demoGenericRes.json.error, 'soc_gated_check');

      await withTenantContext(ownerPool, DEMO_TENANT, async (client) => {
        await client.query(`UPDATE test_runs SET status = 'verdicted' WHERE tenant_id = $1`, [DEMO_TENANT]);
        await client.query(
          `INSERT INTO soc_kill_switch (tenant_id, active, reason, updated_at, updated_by)
           VALUES ($1, true, 'test kill switch', now(), 'usr_soc')
           ON CONFLICT (tenant_id) DO UPDATE SET active = true`,
          [DEMO_TENANT],
        );
      });

      const killRes = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoAdmin(),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: 'dns.authoritative_response.safe',
        },
      });
      assert.equal(killRes.status, 423);
      assert.equal(killRes.json.error, 'kill_switch_active');

      // (g) Demo bypass audit row exists when gates are bypassed and is omitted when none
      await withTenantContext(ownerPool, DEMO_TENANT, async (client) => {
        await client.query(`UPDATE soc_kill_switch SET active = false WHERE tenant_id = $1`, [DEMO_TENANT]);
        await client.query(`UPDATE target_groups SET safe_test_windows = '[]'::jsonb WHERE id = $1`, [DEMO_GROUP]);
        await client.query(`UPDATE test_runs SET created_at = now() - interval '2 hours' WHERE tenant_id = $1`, [DEMO_TENANT]);
      });

      const resClean = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoAdmin(),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: 'dns.authoritative_response.safe',
        },
      });
      assert.equal(resClean.status, 201);
      const cleanRunId = resClean.json.run.id;

      await withTenantContext(ownerPool, DEMO_TENANT, async (client) => {
        const { rows: bypassedRows } = await client.query(
          `SELECT metadata_json FROM audit_logs WHERE tenant_id = $1 AND action = 'test_run.demo_gates_bypassed' AND resource_id = $2`,
          [DEMO_TENANT, runId],
        );
        assert.equal(bypassedRows.length, 1);
        const metadata = typeof bypassedRows[0].metadata_json === 'string'
          ? JSON.parse(bypassedRows[0].metadata_json)
          : bypassedRows[0].metadata_json;
        assert.deepEqual(metadata.bypassed, ['input_requirement:declared_tcp_deny_required']);

        const { rows: cleanRows } = await client.query(
          `SELECT metadata_json FROM audit_logs WHERE tenant_id = $1 AND action = 'test_run.demo_gates_bypassed' AND resource_id = $2`,
          [DEMO_TENANT, cleanRunId],
        );
        assert.equal(cleanRows.length, 0);
      });

      // (h) Ticket R11: route-level feature flags in Postgres runtime honour demo and gate non-demo
      const r11DemoRoutes = [
        ['GET', '/v1/waf/validation-plans'],
        ['GET', '/v1/waf/validation-plans/scheduled'],
        ['GET', '/v1/waf/retests'],
        ['GET', '/v1/waf/drift-scans/latest'],
        ['GET', '/v1/waf/cve-pipeline'],
        ['GET', '/v1/waf/supply-chain/risks'],
      ];

      for (const [method, path] of r11DemoRoutes) {
        const demoRes = await request(baseUrl, method, path, { headers: demoAdmin() });
        assert.equal(demoRes.status, 200, `Expected ${method} ${path} to return 200 for demo in Postgres, got ${demoRes.status}`);
        assert.notEqual(demoRes.json?.error, 'waf_feature_disabled');

        const prodRes = await request(baseUrl, method, path, { headers: prodAdmin() });
        assert.equal(prodRes.status, 404, `Expected ${method} ${path} to return 404 for prod in Postgres, got ${prodRes.status}`);
        assert.equal(prodRes.json?.error, 'waf_feature_disabled');
      }

      // Bulk import with connector_id in Postgres mode
      const demoBulk = await request(baseUrl, 'POST', `/v1/target-groups/${DEMO_GROUP}/targets:bulk-import`, {
        headers: demoAdmin(),
        body: { connector_id: 'conn_nonexistent', targets: [] },
      });
      assert.equal(demoBulk.status, 404);
      assert.equal(demoBulk.json?.error, 'connector_not_found');

      const prodBulk = await request(baseUrl, 'POST', `/v1/target-groups/${PROD_GROUP}/targets:bulk-import`, {
        headers: prodAdmin(),
        body: { connector_id: 'conn_test', targets: [] },
      });
      assert.equal(prodBulk.status, 404);
      assert.equal(prodBulk.json?.error, 'connector_feature_disabled');

      // Deployment features matching route authorization in Postgres mode
      const demoFeat = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: demoAdmin() });
      assert.equal(demoFeat.status, 200);
      assert.deepEqual(demoFeat.json, {
        demo_tenant: true,
        waf_posture: true,
        external_discovery: true,
        connectors: true,
        protection_validation: true,
        origin_clues: false,
        assistant: false,
      });

      const prodFeat = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: prodAdmin() });
      assert.equal(prodFeat.status, 200);
      assert.deepEqual(prodFeat.json, {
        demo_tenant: false,
        waf_posture: false,
        external_discovery: false,
        connectors: false,
        protection_validation: false,
        origin_clues: false,
        assistant: false,
      });

      // Wildcard demo does not bypass feature gates in Postgres mode
      process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = '*';
      try {
        const wildcardPlans = await request(baseUrl, 'GET', '/v1/waf/validation-plans', { headers: demoHeaders('admin', DEMO_TENANT, 'usr_generic_demo') });
        assert.equal(wildcardPlans.status, 404);
        assert.equal(wildcardPlans.json?.error, 'waf_feature_disabled');

        const wildcardBulk = await request(baseUrl, 'POST', `/v1/target-groups/${DEMO_GROUP}/targets:bulk-import`, {
          headers: demoHeaders('admin', DEMO_TENANT, 'usr_generic_demo'),
          body: { connector_id: 'conn_test', targets: [] },
        });
        assert.equal(wildcardBulk.status, 404);
        assert.equal(wildcardBulk.json?.error, 'connector_feature_disabled');

        const wildcardFeat = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: demoHeaders('admin', DEMO_TENANT, 'usr_generic_demo') });
        assert.equal(wildcardFeat.status, 200);
        assert.deepEqual(wildcardFeat.json, {
          demo_tenant: false,
          waf_posture: false,
          external_discovery: false,
          connectors: false,
          protection_validation: false,
          origin_clues: false,
          assistant: false,
        });
      } finally {
        process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = DEMO_TENANT;
      }
    });
  });
});
