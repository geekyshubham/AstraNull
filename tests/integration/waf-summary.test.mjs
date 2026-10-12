import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { mintSignedSessionToken } from '../../src/context.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import {
  refreshWafCoverageSummaryForTenant,
  runCoverageRollup,
} from '../../src/services/wafCoverageRollupWorker.mjs';
import { attachToFinding } from '../../src/services/remediation.mjs';
import { closeServer, demoHeaders, request, signedSessionHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

import { assuredPosture } from '../helpers/assurance-fixtures.mjs';

const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function wafEnabledEnv() {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
  };
}

async function startServer(env = wafEnabledEnv()) {
  const runtimeConfig = loadRuntimeConfig(env);
  const server = createServer({ runtimeConfig, env });
  // Match the client's address family: on Darwin an IPv6 wildcard listener can
  // share a port with an unrelated IPv4 listener that receives the HTTP requests.
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

function seedWafCoverageFixture(tenantId = 'ten_demo') {
  const store = getStore();
  if (!Array.isArray(store.wafAssets)) store.wafAssets = [];
  if (!Array.isArray(store.wafPostureSnapshots)) store.wafPostureSnapshots = [];
  if (!Array.isArray(store.wafConnectors)) store.wafConnectors = [];
  const assetIds = ['wa_cov_1', 'wa_cov_2', 'wa_cov_3', 'wa_cov_4'];
  for (const [index, id] of assetIds.entries()) {
    const asset = {
      id,
      tenant_id: tenantId,
      target_group_id: 'tg_1',
      canonical_url: `https://asset-${index + 1}.example.com`,
      status: 'unknown', created_at: '2026-01-01T00:00:00.000Z',
    };
    store.wafAssets.push(asset);
    store.wafPostureSnapshots.push({
      ...assuredPosture(asset, index < 3 ? 'protected' : 'underprotected', new Date().toISOString()),
      id: `snap_${id}`,
      tenant_id: tenantId,
      waf_asset_id: id,
      status: index < 3 ? 'protected' : 'underprotected',
      detected_vendor: index < 2 ? 'cloudflare' : 'aws',
      is_current: true,
      created_at: new Date().toISOString(),
    });
  }
  store.wafConnectors.push(
    { id: 'conn_1', tenant_id: tenantId, provider: 'cloudflare', status: 'active' },
    { id: 'conn_2', tenant_id: tenantId, provider: 'aws', status: 'error' },
    { id: 'conn_3', tenant_id: tenantId, provider: 'azure', status: 'disabled' },
  );
}

describe('WAF coverage summary portal integration (FT-WAF-01..04)', () => {
  let server;
  let baseUrl;

  before(async () => {
    freshStore();
    applyEnv();
    ({ server, baseUrl } = await startServer());
  });

  after(async () => {
    await closeServer(server);
    restoreEnv();
  });

  function applyEnv() {
    Object.assign(process.env, wafEnabledEnv());
  }

  afterEach(() => {
    freshStore();
    applyEnv();
  });

  it('binds the HTTP fixture to the same IPv4 loopback host used by its client', () => {
    assert.equal(server.address().address, new URL(baseUrl).hostname);
    assert.equal(server.address().family, 'IPv4');
  });

  it('FT-WAF-01 coverage_pct matches protected/assets_total*100', async () => {
    seedWafCoverageFixture();
    runCoverageRollup({ tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' });

    const res = await request(baseUrl, 'GET', '/v1/waf/coverage/summary', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 200, res.text);
    const expectedPct = Math.round((res.json.protected / res.json.assets_total) * 10000) / 100;
    assert.equal(res.json.coverage_pct, expectedPct);
    assert.equal(res.json.assets_total, 4);
    assert.equal(res.json.protected, 3);
  });

  it('FT-WAF-02 by_vendor asset counts sum to assets_total', async () => {
    seedWafCoverageFixture();
    runCoverageRollup({ tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' });

    const res = await request(baseUrl, 'GET', '/v1/waf/coverage/summary', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 200, res.text);
    const vendorTotal = Object.values(res.json.by_vendor).reduce(
      (sum, bucket) => sum + Number(bucket.assets),
      0,
    );
    assert.equal(vendorTotal, res.json.assets_total);
  });

  it('FT-WAF-03 summary reflects posture change after rollup refresh', async () => {
    seedWafCoverageFixture();
    runCoverageRollup({ tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' });

    const before = await request(baseUrl, 'GET', '/v1/waf/coverage/summary', {
      headers: demoHeaders('admin'),
    });
    assert.equal(before.status, 200, before.text);
    assert.equal(before.json.protected, 3);

    const store = getStore();
    const snap = store.wafPostureSnapshots.find((row) => row.waf_asset_id === 'wa_cov_1');
    const asset = store.wafAssets.find((row) => row.id === snap.waf_asset_id);
    Object.assign(snap, assuredPosture(asset, 'underprotected', new Date().toISOString()));
    refreshWafCoverageSummaryForTenant('ten_demo');

    const after = await request(baseUrl, 'GET', '/v1/waf/coverage/summary', {
      headers: demoHeaders('admin'),
    });
    assert.equal(after.status, 200, after.text);
    assert.equal(after.json.protected, 2);
    assert.ok(after.json.refreshed_at);
    assert.notEqual(after.json.coverage_pct, before.json.coverage_pct);
  });

  it('FT-WAF-04 deliver flips linked finding_remediations to delivered', async () => {
    const headers = demoHeaders('engineer');
    const assetRes = await request(baseUrl, 'POST', '/v1/waf/assets', {
      headers,
      body: {
        target_group_id: 'tg_1',
        canonical_url: 'https://deliver-remediation.example.com',
        owner_hint: 'edge-team',
      },
    });
    assert.equal(assetRes.status, 201, assetRes.text);

    const findingId = 'fnd_deliver_cov';
    getStore().findings.push({
      id: findingId,
      tenant_id: 'ten_demo',
      check_id: `waf.posture.${assetRes.json.asset.id}`,
      target_group_id: 'tg_1',
      status: 'open',
      severity: 'medium',
      title: 'Deliver remediation coverage test',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    attachToFinding(
      { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' },
      findingId,
      { action_slug: 'origin_restrict', owner_group: 'edge-sre' },
    );

    const created = await request(baseUrl, 'POST', '/v1/waf/action-items', {
      headers,
      body: { finding_id: findingId },
    });
    assert.equal(created.status, 201, created.text);
    const actionItemId = created.json.action_item.action_item_id;

    const delivered = await request(
      baseUrl,
      'POST',
      `/v1/waf/action-items/${actionItemId}/deliver`,
      { headers, body: { channel: 'jira', target_ref: 'WAF-9001' } },
    );
    assert.equal(delivered.status, 200, delivered.text);
    assert.equal(delivered.json.delivery.channel, 'jira');

    const remediation = getStore().findingRemediations.find((row) => row.finding_id === findingId);
    assert.ok(remediation);
    assert.equal(remediation.state, 'delivered');
    assert.ok(remediation.delivered_at);
    assert.equal(remediation.delivered_via, 'jira');
    assert.equal(remediation.delivered_ref, 'WAF-9001');
  });
});

describe('WAF summary signed-session authorization boundary', () => {
  const sessionSecret = 'waf-summary-integration-session-secret-32chars';
  let server;
  let baseUrl;

  before(async () => {
    freshStore();
    Object.assign(process.env, wafEnabledEnv());
    ({ server, baseUrl } = await startServer({
      ...wafEnabledEnv(),
      ASTRANULL_AUTH_MODE: 'signed-session',
      ASTRANULL_SESSION_SECRET: sessionSecret,
    }));
    seedWafCoverageFixture();
    runCoverageRollup({ tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' });
  });

  after(async () => {
    await closeServer(server);
    restoreEnv();
  });

  it('rejects missing session headers before returning a coverage summary', async () => {
    const res = await request(baseUrl, 'GET', '/v1/waf/coverage/summary');
    assert.equal(res.status, 401, res.text);
    assert.equal(res.json.error, 'unauthorized');
    assert.equal(res.json.assets_total, undefined);
  });

  it('denies and audits viewer writes even with spoofed admin headers', async () => {
    const assetsBefore = getStore().wafAssets.length;
    const res = await request(baseUrl, 'POST', '/v1/waf/assets', {
      headers: {
        ...demoHeaders('admin'),
        ...signedSessionHeaders('viewer', 'ten_demo', 'usr_waf_view', sessionSecret, mintSignedSessionToken),
      },
      body: {
        target_group_id: 'tg_1',
        canonical_url: 'https://must-not-create.example.com',
      },
    });
    assert.equal(res.status, 403, res.text);
    assert.equal(res.json.error, 'forbidden');
    assert.equal(res.json.permission, 'waf:write');
    assert.equal(getStore().wafAssets.length, assetsBefore);
    assert.ok(getStore().auditLog.some((entry) => (
      entry.action === 'rbac.denied'
      && entry.tenant_id === 'ten_demo'
      && entry.actor_user_id === 'usr_waf_view'
      && entry.actor_role === 'viewer'
      && entry.metadata.permission === 'waf:write'
    )));
  });

  it('does not expose another tenant summary through spoofed tenant headers', async () => {
    const res = await request(baseUrl, 'GET', '/v1/waf/coverage/summary', {
      headers: {
        ...demoHeaders('admin', 'ten_demo'),
        ...signedSessionHeaders('viewer', 'ten_other', 'usr_waf_other', sessionSecret, mintSignedSessionToken),
      },
    });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.assets_total, 0);
    assert.equal(res.json.protected, 0);
    assert.equal(getStore().wafCoverageSummaries.ten_demo.assets_total, 4);
  });
});
