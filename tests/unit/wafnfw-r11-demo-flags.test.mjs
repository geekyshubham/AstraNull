import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import {
  wafPostureEnabledFor,
  connectorsEnabledFor,
  externalDiscoveryEnabledFor,
  protectionValidationEnabledFor,
} from '../../src/lib/tenantFeatureAccess.mjs';
import { presentWafPosture } from '../../src/lib/targetDetailRows.mjs';
import { createInitialEdgeDetectionService } from '../../src/services/initialEdgeDetections.mjs';
import { createServer } from '../../src/server.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';

describe('Ticket R11: every feature-flag gate honours explicit demo tenants', () => {
  const DEMO_TENANT = 'ten_demo_r11';
  const PROD_TENANT = 'ten_prod_r11';
  const DEMO_GROUP = 'tg_demo_r11';
  const PROD_GROUP = 'tg_prod_r11';

  let prevDemoEnv;
  let server;
  let baseUrl;

  beforeEach(async () => {
    prevDemoEnv = process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = DEMO_TENANT;

    const store = resetStoreForTests();
    store.tenants = [
      { id: DEMO_TENANT, name: 'Demo Tenant R11' },
      { id: PROD_TENANT, name: 'Prod Tenant R11' },
    ];
    store.targetGroups = [
      {
        id: DEMO_GROUP,
        tenant_id: DEMO_TENANT,
        name: 'Demo Group R11',
        validation_mode: 'external_only',
        ownership_status: 'user_confirmed',
        safety_policy: { max_runs_per_hour: 60, min_seconds_between_runs: 30 },
        safe_test_windows: [],
        targets: [
          {
            id: 'tgt_demo_r11',
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
        name: 'Prod Group R11',
        validation_mode: 'external_only',
        ownership_status: 'dns_verified',
        safety_policy: { max_runs_per_hour: 60, min_seconds_between_runs: 30 },
        safe_test_windows: [],
        targets: [
          {
            id: 'tgt_prod_r11',
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
        id: 'tv_demo_r11',
        tenant_id: DEMO_TENANT,
        target_id: 'tgt_demo_r11',
        state: 'user_confirmed',
        source_kind: 'manual_override',
        source_ref: { method: 'demo_auto_verify', demo: true },
        transitioned_at: new Date().toISOString(),
      },
      {
        id: 'tv_prod_r11',
        tenant_id: PROD_TENANT,
        target_id: 'tgt_prod_r11',
        state: 'dns_verified',
        source_kind: 'dns_txt',
        source_ref: {},
        transitioned_at: new Date().toISOString(),
      },
    ];
    store.auditLog = [];

    server = createServer({
      runtimeConfig: loadRuntimeConfig(),
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

  it('tenantFeatureAccess helpers grant access for explicit demo and gate wildcard-only or non-demo', () => {
    const emptyConfig = {};
    const envExplicit = { ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: DEMO_TENANT };
    const envWildcard = { ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: '*' };
    const envAll = { ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: 'all' };

    // Explicit demo tenant bypasses unset flags
    assert.equal(wafPostureEnabledFor(emptyConfig, DEMO_TENANT, envExplicit), true);
    assert.equal(connectorsEnabledFor(emptyConfig, DEMO_TENANT, envExplicit), true);
    assert.equal(externalDiscoveryEnabledFor(emptyConfig, DEMO_TENANT, envExplicit), true);
    assert.equal(protectionValidationEnabledFor(emptyConfig, DEMO_TENANT, envExplicit), true);

    // Non-demo tenant is gated when flags unset
    assert.equal(wafPostureEnabledFor(emptyConfig, PROD_TENANT, envExplicit), false);
    assert.equal(connectorsEnabledFor(emptyConfig, PROD_TENANT, envExplicit), false);
    assert.equal(externalDiscoveryEnabledFor(emptyConfig, PROD_TENANT, envExplicit), false);
    assert.equal(protectionValidationEnabledFor(emptyConfig, PROD_TENANT, envExplicit), false);

    // Wildcard-only never grants feature flags
    assert.equal(wafPostureEnabledFor(emptyConfig, DEMO_TENANT, envWildcard), false);
    assert.equal(connectorsEnabledFor(emptyConfig, DEMO_TENANT, envWildcard), false);
    assert.equal(externalDiscoveryEnabledFor(emptyConfig, DEMO_TENANT, envWildcard), false);
    assert.equal(protectionValidationEnabledFor(emptyConfig, DEMO_TENANT, envWildcard), false);

    assert.equal(wafPostureEnabledFor(emptyConfig, DEMO_TENANT, envAll), false);
    assert.equal(connectorsEnabledFor(emptyConfig, DEMO_TENANT, envAll), false);
    assert.equal(externalDiscoveryEnabledFor(emptyConfig, DEMO_TENANT, envAll), false);
    assert.equal(protectionValidationEnabledFor(emptyConfig, DEMO_TENANT, envAll), false);

    // Global flags still work for all tenants
    const globalConfig = {
      wafPostureEnabled: true,
      connectorsEnabled: true,
      externalDiscoveryEnabled: true,
      protectionValidationEnabled: true,
    };
    assert.equal(wafPostureEnabledFor(globalConfig, PROD_TENANT, envExplicit), true);
    assert.equal(connectorsEnabledFor(globalConfig, PROD_TENANT, envExplicit), true);
    assert.equal(externalDiscoveryEnabledFor(globalConfig, PROD_TENANT, envExplicit), true);
    assert.equal(protectionValidationEnabledFor(globalConfig, PROD_TENANT, envExplicit), true);

    // Per-tenant lists still work for listed tenants
    const perTenantConfig = {
      wafPostureEnabledTenants: [PROD_TENANT],
      connectorsEnabledTenants: [PROD_TENANT],
      externalDiscoveryEnabledTenants: [PROD_TENANT],
      protectionValidationEnabledTenants: [PROD_TENANT],
    };
    assert.equal(wafPostureEnabledFor(perTenantConfig, PROD_TENANT, envExplicit), true);
    assert.equal(connectorsEnabledFor(perTenantConfig, PROD_TENANT, envExplicit), true);
    assert.equal(externalDiscoveryEnabledFor(perTenantConfig, PROD_TENANT, envExplicit), true);
    assert.equal(protectionValidationEnabledFor(perTenantConfig, PROD_TENANT, envExplicit), true);
    assert.equal(wafPostureEnabledFor(perTenantConfig, 'other_tenant', envExplicit), false);
  });

  it('Defect D1: explicit demo tenant is not blocked by 404/400 feature_disabled with flags unset', async () => {
    const demoHdrs = demoHeaders('admin', DEMO_TENANT);

    const routes = [
      ['GET', '/v1/waf/validation-plans', 200],
      ['GET', '/v1/waf/validation-plans/scheduled', 200],
      ['GET', '/v1/waf/retests', 200],
      ['GET', '/v1/waf/drift-scans/latest', 200],
      ['GET', '/v1/waf/cve-pipeline', 200],
      ['GET', '/v1/waf/supply-chain/risks', 200],
      ['GET', '/v1/waf/assets', 200],
      ['GET', '/v1/waf/coverage', 200],
      ['GET', '/v1/waf/coverage/summary', 200],
      ['GET', '/v1/waf/products', 200],
      ['GET', '/v1/waf/offensive-suites', 200],
      ['GET', '/v1/waf/validations', 200],
      ['GET', '/v1/waf/drift-events', 200],
      ['GET', '/v1/waf/action-items', 200],
      ['GET', '/v1/connectors', 200],
      ['GET', '/v1/discovery/entities', 200],
      ['GET', '/v1/discovery/candidates', 200],
      ['GET', '/v1/discovery/inbox', 200],
      ['GET', '/v1/discovery/reports/summary', 200],
    ];

    for (const [method, path, expectedStatus] of routes) {
      const res = await request(baseUrl, method, path, { headers: demoHdrs });
      assert.equal(
        res.status,
        expectedStatus,
        `Expected ${method} ${path} to return ${expectedStatus} for demo tenant, got ${res.status}: ${res.text}`,
      );
      assert.notEqual(res.json?.error, 'waf_feature_disabled');
      assert.notEqual(res.json?.error, 'connector_feature_disabled');
      assert.notEqual(res.json?.error, 'discovery_feature_disabled');
    }

    // Edge detection route for demo tenant passes feature gate (not waf_feature_disabled)
    const edgeRes = await request(baseUrl, 'GET', `/v1/waf/edge-detection/tgt_demo_r11`, {
      headers: demoHdrs,
    });
    assert.notEqual(edgeRes.json?.error, 'waf_feature_disabled');

    // Bulk import with connector_id on demo: must not be connector_feature_disabled
    const bulkRes = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${DEMO_GROUP}/targets:bulk-import`,
      {
        headers: demoHdrs,
        body: { connector_id: 'conn_nonexistent', targets: [] },
      },
    );
    assert.equal(bulkRes.status, 404);
    assert.equal(bulkRes.json?.error, 'connector_not_found');

    // Deployment features for demo tenant
    const featRes = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', {
      headers: demoHdrs,
    });
    assert.equal(featRes.status, 200);
    assert.deepEqual(featRes.json, {
      demo_tenant: true,
      all_checks_customer_runnable: false,
      waf_posture: true,
      external_discovery: true,
      connectors: true,
      protection_validation: true,
      origin_clues: false,
      assistant: false,
    });
  });

  it('non-demo tenant remains gated with 404/400 feature_disabled when flags unset', async () => {
    const prodHdrs = demoHeaders('admin', PROD_TENANT);

    const wafRoutes = [
      ['GET', '/v1/waf/validation-plans'],
      ['GET', '/v1/waf/validation-plans/scheduled'],
      ['GET', '/v1/waf/retests'],
      ['GET', '/v1/waf/drift-scans/latest'],
      ['GET', '/v1/waf/cve-pipeline'],
      ['GET', '/v1/waf/supply-chain/risks'],
      ['GET', '/v1/waf/assets'],
      ['GET', '/v1/waf/coverage'],
      ['GET', '/v1/waf/coverage/summary'],
      ['GET', '/v1/waf/products'],
      ['GET', '/v1/waf/offensive-suites'],
      ['GET', '/v1/waf/validations'],
      ['GET', '/v1/waf/drift-events'],
      ['GET', '/v1/waf/action-items'],
      ['GET', '/v1/waf/edge-detection/tgt_prod_r11'],
      ['GET', '/v1/connectors'],
    ];

    for (const [method, path] of wafRoutes) {
      const res = await request(baseUrl, method, path, { headers: prodHdrs });
      assert.equal(res.status, 404, `Expected 404 on ${path} for non-demo, got ${res.status}`);
      assert.equal(res.json?.error, 'waf_feature_disabled');
    }

    // Discovery routes return 404 discovery_feature_disabled for non-demo
    const discRoutes = [
      '/v1/discovery/entities',
      '/v1/discovery/candidates',
      '/v1/discovery/inbox',
      '/v1/discovery/reports/summary',
    ];
    for (const path of discRoutes) {
      const res = await request(baseUrl, 'GET', path, { headers: prodHdrs });
      assert.equal(res.status, 404, `Expected 404 on ${path} for non-demo, got ${res.status}`);
      assert.equal(res.json?.error, 'discovery_feature_disabled');
    }

    // Bulk import with connector_id on prod: 404 connector_feature_disabled
    const bulkRes = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PROD_GROUP}/targets:bulk-import`,
      {
        headers: prodHdrs,
        body: { connector_id: 'conn_test', targets: [] },
      },
    );
    assert.equal(bulkRes.status, 404);
    assert.equal(bulkRes.json?.error, 'connector_feature_disabled');

    // Deployment features for non-demo tenant
    const featRes = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', {
      headers: prodHdrs,
    });
    assert.equal(featRes.status, 200);
    assert.deepEqual(featRes.json, {
      demo_tenant: false,
      all_checks_customer_runnable: false,
      waf_posture: false,
      external_discovery: false,
      connectors: false,
      protection_validation: false,
      origin_clues: false,
      assistant: false,
    });
  });

  it('wildcard-only demo configuration does not bypass feature flags', async () => {
    // Switch env to wildcard
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = '*';

    const demoHdrs = demoHeaders('admin', DEMO_TENANT);

    const resPlans = await request(baseUrl, 'GET', '/v1/waf/validation-plans', {
      headers: demoHdrs,
    });
    assert.equal(resPlans.status, 404);
    assert.equal(resPlans.json?.error, 'waf_feature_disabled');

    const resSc = await request(baseUrl, 'GET', '/v1/waf/supply-chain/risks', {
      headers: demoHdrs,
    });
    assert.equal(resSc.status, 404);
    assert.equal(resSc.json?.error, 'waf_feature_disabled');

    const resBulk = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${DEMO_GROUP}/targets:bulk-import`,
      {
        headers: demoHdrs,
        body: { connector_id: 'conn_test', targets: [] },
      },
    );
    assert.equal(resBulk.status, 404);
    assert.equal(resBulk.json?.error, 'connector_feature_disabled');

    const resFeat = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', {
      headers: demoHdrs,
    });
    assert.equal(resFeat.status, 200);
    assert.deepEqual(resFeat.json, {
      demo_tenant: false,
      all_checks_customer_runnable: false,
      waf_posture: false,
      external_discovery: false,
      connectors: false,
      protection_validation: false,
      origin_clues: false,
      assistant: false,
    });
  });

  it('target detail posture presentation and initial edge detections allow demo tenant when flags unset', async () => {
    const config = loadRuntimeConfig();

    const posture = {
      asset_id: 'ast_1',
      vendor: 'cloudflare',
      raw_context_yaml: 'secret_key: supersecret',
      connector: { id: 'conn_1', state: 'active' },
    };

    const presentedDemo = presentWafPosture(posture, { tenantId: DEMO_TENANT, role: 'admin' });
    const presentedProd = presentWafPosture(posture, { tenantId: PROD_TENANT, role: 'admin' });

    assert.equal(presentedDemo.configuration_access, 'allowed');
    assert.equal(presentedDemo.configuration_disabled_reason, null);
    assert.ok(presentedDemo.connector);

    assert.equal(presentedProd.configuration_access, 'redacted');
    assert.equal(presentedProd.configuration_disabled_reason, 'feature_disabled');
    assert.equal(presentedProd.connector, null);

    // Initial edge detections dispatching for demo vs prod
    let dispatchedDemo = false;
    const demoService = createInitialEdgeDetectionService({
      claim: async () => [{ target_id: 'tgt_demo_1', lease_token: 'l1', requested_at: new Date().toISOString() }],
      getTarget: async () => ({ id: 'tgt_demo_1', target_group_id: 'tg_1' }),
      latestRun: async () => null,
      activeScan: async () => false,
      ownership: async () => true,
      startTestRun: async () => {
        dispatchedDemo = true;
        return { run: { id: 'run_demo_1' } };
      },
      read: async () => null,
      finish: async () => ({}),
    });

    const demoOutcomes = await demoService.dispatchPending({ tenantId: DEMO_TENANT }, { runtimeConfig: config });
    assert.equal(dispatchedDemo, true);
    assert.equal(demoOutcomes[0]?.status, 'dispatched');
    assert.notEqual(demoOutcomes[0]?.blocked_reason, 'waf_feature_disabled');

    const prodService = createInitialEdgeDetectionService({
      claim: async () => [{ target_id: 'tgt_prod_1', lease_token: 'l2', requested_at: new Date().toISOString() }],
      getTarget: async () => ({ id: 'tgt_prod_1', target_group_id: 'tg_2' }),
      latestRun: async () => null,
      activeScan: async () => false,
      ownership: async () => true,
      startTestRun: async () => ({ run: { id: 'run_prod_1' } }),
      read: async () => null,
      finish: async () => ({}),
    });

    const prodOutcomes = await prodService.dispatchPending({ tenantId: PROD_TENANT }, { runtimeConfig: config });
    assert.equal(prodOutcomes[0]?.status, 'queued');
    assert.equal(prodOutcomes[0]?.blocked_reason, 'waf_feature_disabled');
  });
});
