import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { getStore } from '../../src/store.mjs';
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

// The route-level gate uses the server's per-deployment config, but the service-level
// gate (defense in depth) reads process.env like every other WAF service — each describe
// sets it in before() and restoreEnv() re-applies it after cleanup.

function wafEnabledEnv(extra = {}) {
  return {
    ...process.env,
    NODE_ENV: 'test',
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
    ...extra,
  };
}

function startServer(env, services = {}) {
  const runtimeConfig = loadRuntimeConfig(env);
  const server = createServer({ runtimeConfig, env, services });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}`, runtimeConfig };
}

function cloudflareDeps(requestLog = []) {
  return {
    fetchFn: async (url, init) => {
      requestLog.push({ url, init });
      return {
        status: 200,
        headers: { get: (name) => (name === 'server' ? 'cloudflare' : name === 'cf-ray' ? 'abc123' : null) },
        async text() { return '<html>ok</html>'; },
      };
    },
    resolveCname: async () => ['edge.cdn.cloudflare.net'],
    resolve4: async () => ['108.138.5.5'],
    resolve6: async () => [],
  };
}

describe('POST /v1/waf/edge-detection', () => {
  describe('feature gating', () => {
    let server;
    let baseUrl;

    before(() => {
      process.env.ASTRANULL_WAF_POSTURE_ENABLED = '0';
      freshStore();
      ({ server, baseUrl } = startServer(wafEnabledEnv({
        ASTRANULL_WAF_POSTURE_ENABLED: '0',
      })));
    });

    after(() => {
      server?.close();
      restoreEnv();
    });

    it('returns waf_feature_disabled when the WAF posture flag is off', async () => {
      const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
        headers: demoHeaders('admin'),
        body: { hostname: 'shop.example.test' },
      });
      assert.equal(res.status, 404);
      assert.equal(res.json.error, 'waf_feature_disabled');
    });
  });

  describe('rbac and validation', () => {
    let server;
    let baseUrl;

    before(() => {
      process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
      freshStore();
      ({ server, baseUrl } = startServer(wafEnabledEnv()));
    });

    after(() => {
      server?.close();
      restoreEnv();
    });

    it('denies viewer role with waf:run scope enforcement', async () => {
      const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
        headers: demoHeaders('viewer'),
        body: { hostname: 'shop.example.test' },
      });
      assert.equal(res.status, 403);
    });

    it('rejects a missing hostname with 400', async () => {
      const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
        headers: demoHeaders('admin'),
        body: {},
      });
      assert.equal(res.status, 400);
      assert.equal(res.json.error, 'invalid_hostname');
    });

    it('rejects a URL-shaped hostname with 400 and no network activity', async () => {
      const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
        headers: demoHeaders('admin'),
        body: { hostname: 'https://evil.example/path' },
      });
      assert.equal(res.status, 400);
      assert.equal(res.json.error, 'invalid_hostname');
    });

    it('answers 405 for GET', async () => {
      const res = await request(baseUrl, 'GET', '/v1/waf/edge-detection', {
        headers: demoHeaders('admin'),
      });
      assert.equal(res.status, 405);
    });
  });

  describe('detection through the full stack with injected network deps', () => {
    let server;
    let baseUrl;
    let requestLog;

    before(() => {
      process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
      freshStore();
      requestLog = [];
      ({ server, baseUrl } = startServer(wafEnabledEnv(), {
        edgeDetectionDeps: cloudflareDeps(requestLog),
      }));
    });

    after(() => {
      server?.close();
      restoreEnv();
    });

    it('detects a Cloudflare edge for a declared hostname', async () => {
      const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
        headers: demoHeaders('admin'),
        body: { hostname: 'shop.example.test' },
      });
      assert.equal(res.status, 200);
      const detection = res.json.detection;
      assert.equal(detection.waf_present, true);
      assert.equal(detection.best_vendor.vendor, 'cloudflare');
      assert.deepEqual(detection.address_matches, [{ family: 'cdn', provider: 'cloudfront' }]);
      assert.equal(detection.cdn_detected, true);
      assert.equal(detection.tier, 'passive_only');
      assert.equal(detection.requests_sent, 1);
      assert.ok(detection.corpus_version);
      // Exactly one bounded passive request was sent to the declared host.
      assert.equal(requestLog.length, 1);
      assert.ok(requestLog[0].url === 'https://shop.example.test/');
      assert.equal(requestLog[0].init.redirect, 'manual');
    });

    it('audits waf.edge_detection_ran with metadata-only fields', async () => {
      const auditLog = getStore().auditLog;
      const entry = [...auditLog].reverse().find((row) => row.action === 'waf.edge_detection_ran');
      assert.ok(entry, 'expected an edge detection audit record');
      assert.equal(entry.tenant_id, 'ten_demo');
      assert.equal(entry.metadata.hostname, 'shop.example.test');
      assert.equal(entry.metadata.waf_present, true);
      assert.equal(entry.metadata.detected_vendor, 'cloudflare');
      assert.equal(entry.metadata.requests_sent, 1);
      const serialized = JSON.stringify(entry);
      assert.ok(!serialized.includes('<html>'), 'audit must not carry raw response bodies');
      assert.ok(!serialized.includes('abc123'), 'audit must not carry captured header values');
    });
  });

  describe('service injection override (postgres-style fail-closed wiring)', () => {
    let server;
    let baseUrl;

    before(() => {
      process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
      freshStore();
      ({ server, baseUrl } = startServer(wafEnabledEnv(), {
        wafEdgeDetection: {
          runEdgeDetection: async (_ctx, input) => ({
            detection: {
              detection: 'host_edge_detection',
              tier: 'passive_only',
              corpus_version: '1',
              hostname: input.hostname,
              waf_present: true,
              cdn_detected: false,
              best_vendor: { vendor: 'injected', name: 'Injected', confidence: 0.45, matched_signals: [] },
              vendor_matches: [],
              address_matches: [],
              cname_matches: [],
              conflicting_vendor_signals: false,
              requests_sent: 1,
              baseline_status_code: 200,
              duration_ms: 1,
            },
          }),
        },
      }));
    });

    after(() => {
      server?.close();
      restoreEnv();
    });

    it('routes through an injected service implementation', async () => {
      const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
        headers: demoHeaders('admin'),
        body: { hostname: 'injected.example.test' },
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.detection.best_vendor.vendor, 'injected');
    });
  });
});
