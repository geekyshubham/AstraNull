import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { isConnectorsEnabledForTenant, loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function wafEnabledEnv(extra = {}) {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
    ...extra,
  };
}

function startServer(env) {
  const runtimeConfig = loadRuntimeConfig(env);
  const server = createServer({ runtimeConfig, env });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}`, runtimeConfig };
}

describe('connector feature flag runtime config', () => {
  after(() => {
    restoreEnv();
  });

  it('leaves connectors on for every tenant whatever the deployment flag says', () => {
    const env = {
      NODE_ENV: 'test',
      ASTRANULL_NO_PERSIST: '1',
      ASTRANULL_CONNECTORS_ENABLED: '0',
      ASTRANULL_CONNECTORS_ENABLED_TENANTS: JSON.stringify({ ten_demo: true, ten_other: false }),
    };
    const cfg = loadRuntimeConfig(env);
    for (const tenant of ['ten_demo', 'ten_other', 'ten_missing']) {
      assert.equal(isConnectorsEnabledForTenant(cfg, tenant), true, tenant);
    }
  });
});

describe('connector API is not flag-gated', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    ({ server, baseUrl } = startServer(wafEnabledEnv({
      ASTRANULL_CONNECTORS_ENABLED: '0',
      ASTRANULL_CONNECTORS_ENABLED_TENANTS: JSON.stringify({ ten_demo: true }),
    })));
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  it('serves connector routes for a tenant the old override list excluded', async () => {
    const res = await request(baseUrl, 'GET', '/v1/connectors', {
      headers: demoHeaders('admin', 'ten_other'),
    });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.json.items));
  });

  it('allows connector routes when tenant override is on', async () => {
    const res = await request(baseUrl, 'GET', '/v1/connectors', {
      headers: demoHeaders('admin', 'ten_demo'),
    });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.json.items));
  });
});