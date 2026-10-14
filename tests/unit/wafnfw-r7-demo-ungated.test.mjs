import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { CHECK_CATALOG, getCheckById, isCustomerRunnable, targetInputRefusal } from '../../src/contracts/checks.mjs';
import { planScanSteps } from '../../src/contracts/validationScanManagement.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { advanceScan, createValidationScan } from '../../src/services/validationScans.mjs';
import { demoMaxRunsPerHour } from '../../src/lib/demoAutoVerify.mjs';

describe('Ticket R7: demo tenant runs every customer check with no access or input gates (dev store)', () => {
  const DEMO_TENANT = 'ten_demo';
  const PROD_TENANT = 'ten_prod';
  const DEMO_GROUP = 'tg_demo';
  const PROD_GROUP = 'tg_prod';
  const DEMO_TARGET = 'tgt_demo_fqdn';
  const PROD_TARGET = 'tgt_prod_fqdn';

  let prevDemoEnv;
  let prevCapEnv;
  let server;
  let baseUrl;

  function seedStore() {
    const store = resetStoreForTests();
    store.tenants = [
      { id: DEMO_TENANT, name: 'Demo Tenant' },
      { id: PROD_TENANT, name: 'Prod Tenant' },
    ];
    store.environments = [
      { id: 'env_demo', tenant_id: DEMO_TENANT, name: 'demo' },
      { id: 'env_prod', tenant_id: PROD_TENANT, name: 'prod' },
    ];
    store.targetGroups = [
      {
        id: DEMO_GROUP,
        tenant_id: DEMO_TENANT,
        environment_id: 'env_demo',
        name: 'Demo Group',
        validation_mode: 'external_only',
        ownership_status: 'user_confirmed',
        safety_policy: { max_runs_per_hour: 60, min_seconds_between_runs: 0 },
        safe_test_windows: [],
        targets: [
          {
            id: DEMO_TARGET,
            tenant_id: DEMO_TENANT,
            target_group_id: DEMO_GROUP,
            kind: 'fqdn',
            value: 'app.demo.example.com',
            normalized_value: 'app.demo.example.com',
          },
        ],
      },
      {
        id: PROD_GROUP,
        tenant_id: PROD_TENANT,
        environment_id: 'env_prod',
        name: 'Prod Group',
        validation_mode: 'external_only',
        ownership_status: 'dns_verified',
        safety_policy: { max_runs_per_hour: 60, min_seconds_between_runs: 0 },
        safe_test_windows: [],
        targets: [
          {
            id: PROD_TARGET,
            tenant_id: PROD_TENANT,
            target_group_id: PROD_GROUP,
            kind: 'fqdn',
            value: 'app.prod.example.com',
            normalized_value: 'app.prod.example.com',
          },
        ],
      },
    ];
    store.targets = [
      store.targetGroups[0].targets[0],
      store.targetGroups[1].targets[0],
    ];
    store.targetVerifications = [
      {
        id: 'tv_demo',
        tenant_id: DEMO_TENANT,
        target_id: DEMO_TARGET,
        state: 'user_confirmed',
        source_kind: 'manual_override',
        source_ref: { method: 'demo_auto_verify', demo: true },
        transitioned_at: new Date().toISOString(),
      },
      {
        id: 'tv_prod',
        tenant_id: PROD_TENANT,
        target_id: PROD_TARGET,
        state: 'dns_verified',
        source_kind: 'dns_txt',
        source_ref: {},
        transitioned_at: new Date().toISOString(),
      },
    ];
    store.auditLog = [];
    store.testRuns = [];
    store.verdicts = [];
    store.events = [];
    store.validationScans = [];
    store.checkCatalog = [...CHECK_CATALOG];
  }

  beforeEach(() => {
    prevDemoEnv = process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
    prevCapEnv = process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR;
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = DEMO_TENANT;
    seedStore();
    server = createServer({
      env: {
        ...process.env,
        NODE_ENV: 'test',
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: DEMO_TENANT,
      },
    });
    server.listen(0);
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(async () => {
    await closeServer(server);
    if (prevDemoEnv === undefined) {
      delete process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
    } else {
      process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = prevDemoEnv;
    }
    if (prevCapEnv === undefined) {
      delete process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR;
    } else {
      process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR = prevCapEnv;
    }
  });

  it('(a) GET /v1/checks?target_id= lists every customer-runnable check as runnable for demo; non-demo gets refusal codes', async () => {
    const demoRes = await request(baseUrl, 'GET', `/v1/checks?target_id=${DEMO_TARGET}`, {
      headers: demoHeaders('admin', DEMO_TENANT),
    });
    assert.equal(demoRes.status, 200);
    const demoItems = demoRes.json.items;
    assert.ok(demoItems.length > 0);
    const customerRunnableTotal = CHECK_CATALOG.filter(isCustomerRunnable).length;
    assert.equal(demoItems.filter(isCustomerRunnable).length, customerRunnableTotal);
    for (const item of demoItems) {
      assert.equal(item.requires_additional_input, false);
      assert.equal(item.additional_input_reason, null);
    }

    const prodRes = await request(baseUrl, 'GET', `/v1/checks?target_id=${PROD_TARGET}`, {
      headers: demoHeaders('admin', PROD_TENANT),
    });
    assert.equal(prodRes.status, 200);
    const prodItems = prodRes.json.items;
    assert.ok(prodItems.length < customerRunnableTotal);

    const prodAllRes = await request(baseUrl, 'GET', `/v1/checks?target_id=${PROD_TARGET}&scope=all`, {
      headers: demoHeaders('admin', PROD_TENANT),
    });
    assert.equal(prodAllRes.status, 200);
    const tcpCheck = prodAllRes.json.items.find((item) => item.check_id === 'nfw.declared_deny_tcp.safe');
    assert.ok(tcpCheck);
    assert.equal(tcpCheck.requires_additional_input, true);
    assert.equal(tcpCheck.additional_input_reason, 'declared_tcp_deny_required');
  });

  it('(b) full-catalog scan plan for demo excludes no customer-runnable check for missing input; SOC checks still excluded', async () => {
    const customerChecks = CHECK_CATALOG.filter(isCustomerRunnable);
    const store = getStore();

    const demoPlan = planScanSteps({
      checks: customerChecks,
      targets: store.targets.filter((t) => t.tenant_id === DEMO_TENANT),
      targetInputRefusal,
      tenantId: DEMO_TENANT,
    });
    const demoMissingInputExclusions = demoPlan.excluded.filter((e) => e.reason !== 'target_kind_not_supported');
    assert.equal(demoMissingInputExclusions.length, 0);

    const prodPlan = planScanSteps({
      checks: customerChecks,
      targets: store.targets.filter((t) => t.tenant_id === PROD_TENANT),
      targetInputRefusal,
      tenantId: PROD_TENANT,
    });
    const prodMissingInputExclusions = prodPlan.excluded.filter((e) => e.reason !== 'target_kind_not_supported');
    assert.ok(prodMissingInputExclusions.length > 0);
    assert.ok(prodMissingInputExclusions.some((e) => e.reason === 'declared_tcp_deny_required'));

    const demoScanRes = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: demoHeaders('admin', DEMO_TENANT),
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
      headers: demoHeaders('admin', PROD_TENANT),
      body: {
        target_group_id: PROD_GROUP,
        target_id: PROD_TARGET,
        check_ids: [socCheck.check_id],
      },
    });
    assert.equal(prodSocScanRes.status, 403);
    assert.equal(prodSocScanRes.json.error, 'soc_gated_check');

    const prodScanRes = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: demoHeaders('admin', PROD_TENANT),
      body: {
        target_group_id: PROD_GROUP,
        target_id: PROD_TARGET,
        check_ids: ['nfw.declared_deny_tcp.safe'],
      },
    });
    assert.equal(prodScanRes.status, 400);
    assert.equal(prodScanRes.json.error, 'check_requires_additional_input');
  });

  it('(c) starting nfw.declared_deny_tcp.safe on demo target follows non-demo in simulation mode and short-circuits in signed-worker mode', async () => {
    // In simulation mode, demo follows non-demo by dispatching a simulated run without short-circuiting.
    const simRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: DEMO_TARGET,
        check_id: 'nfw.declared_deny_tcp.safe',
      },
    });
    assert.equal(simRes.status, 201);
    assert.equal(simRes.json.jobs_dispatched, 0);

    const simRunId = simRes.json.run.id;
    const simRunRes = await request(baseUrl, 'GET', `/v1/test-runs/${simRunId}`, {
      headers: demoHeaders('admin', DEMO_TENANT),
    });
    assert.equal(simRunRes.status, 200);
    assert.equal(simRunRes.json.status, 'collecting');
    assert.equal(simRunRes.json.probe_external_result, 'blocked');

    const simEventsRes = await request(baseUrl, 'GET', `/v1/test-runs/${simRunId}/events`, {
      headers: demoHeaders('admin', DEMO_TENANT),
    });
    assert.equal(simEventsRes.status, 200);
    assert.equal(simEventsRes.json.items.length, 1);

    // In signed-worker mode, missing required inputs trigger the short-circuit to required_input_missing.
    const signedServer = createServer({
      env: {
        ...process.env,
        NODE_ENV: 'test',
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: DEMO_TENANT,
        ASTRANULL_PROBE_MODE: 'signed-worker',
        ASTRANULL_PROBE_WORKER_SECRET: randomBytes(32).toString('hex'),
      },
    });
    signedServer.listen(0);
    const signedBaseUrl = `http://127.0.0.1:${signedServer.address().port}`;
    try {
      getStore().testRuns = [];
      const res = await request(signedBaseUrl, 'POST', '/v1/test-runs', {
        headers: demoHeaders('admin', DEMO_TENANT),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: 'nfw.declared_deny_tcp.safe',
        },
      });
      assert.equal(res.status, 201);
      assert.equal(res.json.jobs_dispatched, 0);

      const runId = res.json.run.id;
      const runRes = await request(signedBaseUrl, 'GET', `/v1/test-runs/${runId}`, {
        headers: demoHeaders('admin', DEMO_TENANT),
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

      const eventsRes = await request(signedBaseUrl, 'GET', `/v1/test-runs/${runId}/events`, {
        headers: demoHeaders('admin', DEMO_TENANT),
      });
      assert.equal(eventsRes.status, 200);
      assert.equal(eventsRes.json.items.length, 0);
    } finally {
      await closeServer(signedServer);
    }
  });

  it('(d) demo hourly cap is dropped by default (uncapped) and env override works; non-demo keeps 60', async () => {
    assert.equal(demoMaxRunsPerHour({}), Infinity);
    assert.equal(demoMaxRunsPerHour({ ASTRANULL_DEMO_MAX_RUNS_PER_HOUR: '2500' }), 2500);
    assert.equal(demoMaxRunsPerHour({ ASTRANULL_DEMO_MAX_RUNS_PER_HOUR: '9999' }), 5000);
    assert.equal(demoMaxRunsPerHour({ ASTRANULL_DEMO_MAX_RUNS_PER_HOUR: '-1' }), Infinity);

    const store = getStore();
    for (let i = 0; i < 60; i += 1) {
      store.testRuns.push({
        id: `run_seed_prod_${i}`,
        tenant_id: PROD_TENANT,
        target_group_id: PROD_GROUP,
        target_id: PROD_TARGET,
        check_id: 'dns.authoritative_response.safe',
        status: 'verdicted',
        created_at: new Date().toISOString(),
      });
    }

    const prodBlockRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', PROD_TENANT),
      body: {
        target_group_id: PROD_GROUP,
        target_id: PROD_TARGET,
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(prodBlockRes.status, 429);
    assert.equal(prodBlockRes.json.error, 'safe_rate_cap_exceeded');

    for (let i = 0; i < 60; i += 1) {
      store.testRuns.push({
        id: `run_seed_demo_${i}`,
        tenant_id: DEMO_TENANT,
        target_group_id: DEMO_GROUP,
        target_id: DEMO_TARGET,
        check_id: 'dns.authoritative_response.safe',
        status: 'verdicted',
        created_at: new Date().toISOString(),
      });
    }

    const demoAllowRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: DEMO_TARGET,
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(demoAllowRes.status, 201);
  });

  it('(e) closed safe window does not block demo but still blocks non-demo', async () => {
    const store = getStore();
    const closedWindow = [{ day: 'Mon', start_at: '2020-01-01T00:00:00Z', end_at: '2020-01-01T01:00:00Z' }];
    store.targetGroups.find((g) => g.id === DEMO_GROUP).safe_test_windows = closedWindow;
    store.targetGroups.find((g) => g.id === PROD_GROUP).safe_test_windows = closedWindow;

    const prodRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', PROD_TENANT),
      body: {
        target_group_id: PROD_GROUP,
        target_id: PROD_TARGET,
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(prodRes.status, 429);
    assert.equal(prodRes.json.error, 'safe_window_closed');

    const demoRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: DEMO_TARGET,
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(demoRes.status, 201);
  });

  it('(f) SOC-gated checks give 403 soc_gated_check for non-demo; demo runs without SOC gates; kill switch blocks demo', async () => {
    const socCheck = CHECK_CATALOG.find((c) => !isCustomerRunnable(c));
    assert.ok(socCheck);

    const prodRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', PROD_TENANT),
      body: {
        target_group_id: PROD_GROUP,
        target_id: PROD_TARGET,
        check_id: socCheck.check_id,
      },
    });
    assert.equal(prodRes.status, 403);
    assert.equal(prodRes.json.error, 'soc_gated_check');

    const demoRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT, 'admin@demo.astranull.local'),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: DEMO_TARGET,
        check_id: socCheck.check_id,
      },
    });
    assert.equal(demoRes.status, 201);

    getStore().socKillSwitch = { active: true, reason: 'test kill switch', updated_at: new Date().toISOString() };
    const killRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT, 'admin@demo.astranull.local'),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: DEMO_TARGET,
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(killRes.status, 423);
    assert.equal(killRes.json.error, 'kill_switch_active');
  });

  it('(g) demo bypass audit row exists when gates are bypassed and is omitted when none', async () => {
    const signedServer = createServer({
      env: {
        ...process.env,
        NODE_ENV: 'test',
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: DEMO_TENANT,
        ASTRANULL_PROBE_MODE: 'signed-worker',
        ASTRANULL_PROBE_WORKER_SECRET: randomBytes(32).toString('hex'),
      },
    });
    signedServer.listen(0);
    const signedBaseUrl = `http://127.0.0.1:${signedServer.address().port}`;
    try {
      const resBypassed = await request(signedBaseUrl, 'POST', '/v1/test-runs', {
        headers: demoHeaders('admin', DEMO_TENANT),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: 'nfw.declared_deny_tcp.safe',
        },
      });
      assert.equal(resBypassed.status, 201);
      const runIdBypassed = resBypassed.json.run.id;

      const store = getStore();
      const auditRow = store.auditLog.find(
        (entry) => entry.action === 'test_run.demo_gates_bypassed' && entry.resource_id === runIdBypassed,
      );
      assert.ok(auditRow, 'Expected demo_gates_bypassed audit row');
      assert.deepEqual(auditRow.metadata.bypassed, ['input_requirement:declared_tcp_deny_required']);

      const resClean = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoHeaders('admin', DEMO_TENANT),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: DEMO_TARGET,
          check_id: 'dns.authoritative_response.safe',
        },
      });
      assert.equal(resClean.status, 201);
      const runIdClean = resClean.json.run.id;

      const auditClean = store.auditLog.find(
        (entry) => entry.action === 'test_run.demo_gates_bypassed' && entry.resource_id === runIdClean,
      );
      assert.equal(auditClean, undefined, 'Did not expect demo_gates_bypassed row when no gates bypassed');
    } finally {
      await closeServer(signedServer);
    }
  });

  it('(g) demo tenant and Astra-D1TrtI4HMTSrwKRW-9 bypass SOC gates on high-scale/soc checks', async () => {
    const socCheck = CHECK_CATALOG.find((c) => c.risk_class === 'soc_gated');
    assert.ok(socCheck, 'Expected at least one soc_gated check in catalog');

    // Customer runnable without tenant context is false for soc_gated
    assert.equal(isCustomerRunnable(socCheck), false);
    assert.equal(isCustomerRunnable(socCheck, PROD_TENANT), false);

    // Customer runnable with demo account context is true, generic demo tenant is false
    assert.equal(isCustomerRunnable(socCheck, DEMO_TENANT), false);
    assert.equal(isCustomerRunnable(socCheck, 'Astra-D1TrtI4HMTSrwKRW-9'), true);
    assert.equal(isCustomerRunnable(socCheck, { email: 'admin@demo.astranull.local' }), true);
    assert.equal(isCustomerRunnable(socCheck, { userId: 'admin@demo.astranull.local' }), true);
    assert.equal(isCustomerRunnable(socCheck, { userId: 'usr_admin' }), true);
    assert.equal(isCustomerRunnable(socCheck, { tenantId: DEMO_TENANT, userId: 'usr_admin' }), true);

    // Prod tenant is blocked by SOC gate
    const prodRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', PROD_TENANT),
      body: {
        target_group_id: PROD_GROUP,
        target_id: PROD_TARGET,
        check_id: socCheck.check_id,
      },
    });
    assert.equal(prodRes.status, 403);
    assert.equal(prodRes.json.error, 'soc_gated_check');

    // Generic demo tenant user is blocked by SOC gate
    const genericDemoRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT, 'usr_generic'),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: DEMO_TARGET,
        check_id: socCheck.check_id,
      },
    });
    assert.equal(genericDemoRes.status, 403);
    assert.equal(genericDemoRes.json.error, 'soc_gated_check');

    // Demo account bypasses SOC gate
    const demoRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT, 'admin@demo.astranull.local'),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: DEMO_TARGET,
        check_id: socCheck.check_id,
      },
    });
    assert.equal(demoRes.status, 201);
    assert.ok(demoRes.json.run.id);

    const store = getStore();
    const auditRow = store.auditLog.find(
      (entry) => entry.action === 'test_run.demo_gates_bypassed' && entry.resource_id === demoRes.json.run.id,
    );
    assert.ok(auditRow, 'Expected demo_gates_bypassed audit row for soc_gated run');
    assert.ok(auditRow.metadata.bypassed.includes('soc_gated'));
  });
});
