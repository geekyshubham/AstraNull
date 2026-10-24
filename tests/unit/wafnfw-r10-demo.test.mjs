import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  CHECK_CATALOG,
  customerSelectableChecks,
  demoMissingInputRefusal,
  formatMissingInputMessage,
  getCheckById,
  isCustomerRunnable,
  targetInputRefusal,
  checkRequiresAdditionalInput,
  checkAdditionalInputReason,
} from '../../src/contracts/checks.mjs';
import {
  isExplicitDemoTenant,
  isDemoAutoVerifyTenant,
  warnIfDemoAutoVerifyWildcard,
} from '../../src/lib/demoAutoVerify.mjs';
import { isWithinSafeTestWindow, normalizeSafetyPolicy } from '../../src/lib/safeTestGuards.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';

describe('Ticket R10: close remaining demo gates and hardening', () => {
  const DEMO_TENANT = 'ten_demo_r10';
  const PROD_TENANT = 'ten_prod_r10';
  const DEMO_GROUP = 'tg_demo_r10';
  const PROD_GROUP = 'tg_prod_r10';

  let prevDemoEnv;
  let server;
  let baseUrl;

  beforeEach(async () => {
    prevDemoEnv = process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = DEMO_TENANT;

    const store = resetStoreForTests();
    store.tenants = [
      { id: DEMO_TENANT, name: 'Demo Tenant R10' },
      { id: PROD_TENANT, name: 'Prod Tenant R10' },
    ];
    store.targetGroups = [
      {
        id: DEMO_GROUP,
        tenant_id: DEMO_TENANT,
        name: 'Demo Group R10',
        validation_mode: 'external_only',
        ownership_status: 'user_confirmed',
        safety_policy: { max_runs_per_hour: 60, min_seconds_between_runs: 30 },
        safe_test_windows: [],
        targets: [
          {
            id: 'tgt_demo_ip',
            tenant_id: DEMO_TENANT,
            target_group_id: DEMO_GROUP,
            kind: 'ip',
            value: '198.51.100.1',
            normalized_value: '198.51.100.1',
          },
          {
            id: 'tgt_demo_fqdn',
            tenant_id: DEMO_TENANT,
            target_group_id: DEMO_GROUP,
            kind: 'fqdn',
            value: 'demo.example.com',
            normalized_value: 'demo.example.com',
          },
        ],
      },
      {
        id: PROD_GROUP,
        tenant_id: PROD_TENANT,
        name: 'Prod Group R10',
        validation_mode: 'external_only',
        ownership_status: 'dns_verified',
        safety_policy: { max_runs_per_hour: 60, min_seconds_between_runs: 30 },
        safe_test_windows: [],
        targets: [
          {
            id: 'tgt_prod_ip',
            tenant_id: PROD_TENANT,
            target_group_id: PROD_GROUP,
            kind: 'ip',
            value: '198.51.100.2',
            normalized_value: '198.51.100.2',
          },
          {
            id: 'tgt_prod_fqdn',
            tenant_id: PROD_TENANT,
            target_group_id: PROD_GROUP,
            kind: 'fqdn',
            value: 'prod.example.com',
            normalized_value: 'prod.example.com',
          },
        ],
      },
    ];
    store.targets = [
      ...store.targetGroups[0].targets,
      ...store.targetGroups[1].targets,
    ];
    store.targetVerifications = [
      {
        id: 'tv_demo_ip',
        tenant_id: DEMO_TENANT,
        target_id: 'tgt_demo_ip',
        state: 'user_confirmed',
        source_kind: 'manual_override',
        source_ref: { method: 'demo_auto_verify', demo: true },
        transitioned_at: new Date().toISOString(),
      },
      {
        id: 'tv_demo_fqdn',
        tenant_id: DEMO_TENANT,
        target_id: 'tgt_demo_fqdn',
        state: 'user_confirmed',
        source_kind: 'manual_override',
        source_ref: { method: 'demo_auto_verify', demo: true },
        transitioned_at: new Date().toISOString(),
      },
      {
        id: 'tv_prod_ip',
        tenant_id: PROD_TENANT,
        target_id: 'tgt_prod_ip',
        state: 'dns_verified',
        source_kind: 'dns_txt',
        source_ref: {},
        transitioned_at: new Date().toISOString(),
      },
      {
        id: 'tv_prod_fqdn',
        tenant_id: PROD_TENANT,
        target_id: 'tgt_prod_fqdn',
        state: 'dns_verified',
        source_kind: 'dns_txt',
        source_ref: {},
        transitioned_at: new Date().toISOString(),
      },
    ];
    store.auditLog = [];

    server = createServer({
      runtimeConfig: {
        ...loadRuntimeConfig(),
        probeMode: 'signed-worker',
        probeWorkerSecret: 's'.repeat(32),
      },
    });
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(async () => {
    if (server) await closeServer(server);
    if (prevDemoEnv === undefined) delete process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
    else process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = prevDemoEnv;
  });

  it('F1: 3 origin checks on IP target dispatch jobs for demo and do not short-circuit', async () => {
    const originChecks = [
      'origin.direct_reachability.safe',
      'origin.direct_bypass.safe',
      'waf.origin_bypass.safe',
    ];
    const ipTarget = { id: 'tgt_demo_ip', tenant_id: DEMO_TENANT, kind: 'ip', value: '198.51.100.1' };

    for (const checkId of originChecks) {
      getStore().testRuns = [];
      const check = getCheckById(checkId);
      assert.ok(check, `Check ${checkId} exists`);
      const refusal = demoMissingInputRefusal(check, { target: ipTarget });
      assert.equal(refusal, null, `Demo check ${checkId} on IP target must not be refused`);

      const res = await request(baseUrl, 'POST', '/v1/test-runs', {
        headers: demoHeaders('admin', DEMO_TENANT),
        body: {
          target_group_id: DEMO_GROUP,
          target_id: 'tgt_demo_ip',
          check_id: checkId,
        },
      });
      assert.equal(res.status, 201);
      assert.ok(res.json.probe_job, `${checkId} should queue a probe job for demo on IP target`);
      assert.equal(res.json.run.status, 'running');
      assert.notEqual(res.json.run.status, 'verdicted');
    }
  });

  it('F1: 6 probe-path checks behave the same for demo and non-demo (dispatch probe)', async () => {
    const probePathChecks = [
      'l7.login_abuse_flow.safe',
      'l7.api_quota_exhaustion.safe',
      'l7.search_abuse.validation',
      'l7.export_abuse.validation',
      'l7.oauth_token_abuse.validation',
      'l7.signup_registration_abuse.validation',
    ];
    const fqdnTarget = { id: 'tgt_demo_fqdn', tenant_id: DEMO_TENANT, kind: 'fqdn', value: 'demo.example.com' };

    for (const checkId of probePathChecks) {
      const check = getCheckById(checkId);
      assert.ok(check);
      const demoRefusal = demoMissingInputRefusal(check, { target: fqdnTarget });
      assert.equal(demoRefusal, null, `${checkId} should not be refused by demoMissingInputRefusal`);
    }
  });

  it('F1: formatMissingInputMessage distinguishes Host/SNI direct address from origin bindings', () => {
    const directMsg = formatMissingInputMessage('target_bound_direct_address_required');
    assert.match(directMsg, /IP-literal target/);
    const originBindingMsg = formatMissingInputMessage('origin_binding_required');
    assert.match(originBindingMsg, /origin binding/);
  });

  it('F2: server route-level feature flags are advisory and no longer 404 anyone', async () => {
    const demoWaf = await request(baseUrl, 'GET', '/v1/waf/assets', {
      headers: demoHeaders('admin', DEMO_TENANT),
    });
    assert.notEqual(demoWaf.status, 404, 'Demo tenant must not get 404 on /v1/waf/assets');

    const prodWaf = await request(baseUrl, 'GET', '/v1/waf/assets', {
      headers: demoHeaders('admin', PROD_TENANT),
    });
    assert.notEqual(prodWaf.status, 404, 'Non-demo tenant must not get 404 on /v1/waf/assets');

    const demoConnectors = await request(baseUrl, 'GET', '/v1/connectors', {
      headers: demoHeaders('admin', DEMO_TENANT),
    });
    assert.notEqual(demoConnectors.status, 404, 'Demo tenant must not get 404 on /v1/connectors');

    const prodConnectors = await request(baseUrl, 'GET', '/v1/connectors', {
      headers: demoHeaders('admin', PROD_TENANT),
    });
    assert.notEqual(prodConnectors.status, 404, 'Non-demo tenant must not get 404 on /v1/connectors');

    const demoDiscovery = await request(baseUrl, 'GET', '/v1/discovery/candidates', {
      headers: demoHeaders('admin', DEMO_TENANT),
    });
    assert.notEqual(demoDiscovery.status, 404, 'Demo tenant must not get 404 on /v1/discovery/candidates');

    const prodDiscovery = await request(baseUrl, 'GET', '/v1/discovery/candidates', {
      headers: demoHeaders('admin', PROD_TENANT),
    });
    assert.notEqual(prodDiscovery.status, 404, 'Non-demo tenant must not get 404 on /v1/discovery/candidates');
  });

  it('Hardening 1: SOC-classified checks are selectable and start without a gate', async () => {
    const demoCatalog = customerSelectableChecks(CHECK_CATALOG, { tenantId: DEMO_TENANT });
    const prodCatalog = customerSelectableChecks(CHECK_CATALOG, { tenantId: PROD_TENANT });

    const demoSocChecks = demoCatalog.filter((c) => c.risk_class === 'soc_gated');
    const prodSocChecks = prodCatalog.filter((c) => c.risk_class === 'soc_gated');
    assert.ok(demoSocChecks.length > 0, 'Demo catalog must include SOC-classified checks');
    assert.equal(demoSocChecks.length, prodSocChecks.length, 'Demo and non-demo must see identical SOC checks');
    assert.ok(demoCatalog.every(isCustomerRunnable), 'Every catalogued check is customer selectable');

    const socCheck = demoSocChecks[0];
    const res = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: 'tgt_demo_fqdn',
        check_id: socCheck.check_id,
      },
    });
    assert.equal(res.status, 201);
  });

  it('Hardening 2: minimum interval bypass audits min_interval in demo_gates_bypassed', async () => {
    const store = getStore();
    store.testRuns.push({
      id: 'run_prior',
      tenant_id: DEMO_TENANT,
      target_group_id: DEMO_GROUP,
      target_id: 'tgt_demo_ip',
      check_id: 'origin.direct_reachability.safe',
      created_at: new Date().toISOString(),
      status: 'completed',
    });

    const res = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('admin', DEMO_TENANT),
      body: {
        target_group_id: DEMO_GROUP,
        target_id: 'tgt_demo_ip',
        check_id: 'origin.direct_reachability.safe',
      },
    });
    assert.equal(res.status, 201);

    const auditEntry = store.auditLog.find(
      (a) => a.action === 'test_run.demo_gates_bypassed' && a.resource_id === res.json.run.id,
    );
    assert.ok(auditEntry, 'Must log demo_gates_bypassed audit event');
    assert.ok(
      auditEntry.metadata.bypassed.includes('min_interval'),
      `Expected bypassed to contain 'min_interval', got: ${JSON.stringify(auditEntry.metadata.bypassed)}`,
    );
  });

  it('Hardening 3: wildcard in ASTRANULL_DEMO_AUTO_VERIFY_TENANTS does not lift new gates', () => {
    const wildcardEnv = { ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: '*' };
    assert.equal(isDemoAutoVerifyTenant('any_tenant', wildcardEnv), true, 'Wildcard applies to original bypass');
    assert.equal(isExplicitDemoTenant('any_tenant', wildcardEnv), false, 'Wildcard must NOT apply to new bypasses');
    assert.equal(isExplicitDemoTenant('*', wildcardEnv), false, 'Wildcard string itself is not a tenant');
    assert.equal(isExplicitDemoTenant('all', wildcardEnv), false);

    const explicitEnv = { ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: 'ten_explicit, *' };
    assert.equal(isExplicitDemoTenant('ten_explicit', explicitEnv), true, 'Explicitly named tenant is recognized');
    assert.equal(isExplicitDemoTenant('ten_other', explicitEnv), false, 'Other tenant not recognized under explicit');

    const warnings = [];
    const fakeLogger = { warn: (msg) => warnings.push(msg) };
    const warned = warnIfDemoAutoVerifyWildcard(wildcardEnv, fakeLogger);
    assert.equal(warned, true);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /Wildcard configured/);

    const normalizedPolicy = normalizeSafetyPolicy(
      { max_runs_per_hour: 60, min_seconds_between_runs: 30 },
      { tenantId: 'any_tenant', env: wildcardEnv },
    );
    assert.equal(normalizedPolicy.min_seconds_between_runs, 0, 'Runs are never spaced');
    assert.equal(normalizedPolicy.max_runs_per_hour, Infinity, 'No hourly cap by default');

    const windowClosedGroup = { safe_test_windows: [{ start_at: '2020-01-01', end_at: '2020-01-02' }] };
    assert.equal(
      isWithinSafeTestWindow(windowClosedGroup, Date.now(), { tenantId: 'any_tenant', env: wildcardEnv }),
      true,
      'Safe windows are advisory and never block',
    );
  });

  it('Hardening 5: origin lockdown listing never refuses, and resolution surfaces the keep-list error', () => {
    const check = getCheckById('nfw.origin_lockdown.safe');
    assert.ok(check);

    const target = { id: 'tgt_hostname', tenant_id: DEMO_TENANT, kind: 'fqdn', value: 'app.demo.example.com' };
    const privOrigin = { id: 'tgt_priv', tenant_id: DEMO_TENANT, kind: 'ip', value: '10.0.0.5' };
    const binding = { id: 'b1', tenant_id: DEMO_TENANT, protected_target_id: 'tgt_hostname', origin_target_id: 'tgt_priv', status: 'active', host: 'app.demo.example.com', sni: 'app.demo.example.com' };
    const originBindings = {
      bindings: [binding],
      records: {
        targets: [target, privOrigin],
        targetVerifications: [{ target_id: 'tgt_priv', state: 'dns_verified' }],
        wafConnectors: [],
        wafConnectorSnapshots: [],
      },
    };

    const refusal = targetInputRefusal(check, target, undefined, { originBindings, tenantId: DEMO_TENANT });
    assert.equal(refusal, null, 'Listing never refuses a target');

    const requiresInput = checkRequiresAdditionalInput(check, { target, originBindings, tenantId: DEMO_TENANT });
    assert.equal(requiresInput, false);

    const reason = checkAdditionalInputReason(check, { target, originBindings, tenantId: DEMO_TENANT });
    assert.equal(reason, null);
  });
});
