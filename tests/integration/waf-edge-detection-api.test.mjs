import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { WAF_EDGE_DETECTION_CHECK_ID } from '../../src/lib/edgeDetection.mjs';
import { createServer } from '../../src/server.mjs';
import { probeWorkerAuthHeaders } from '../../src/services/probeCoordinator.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const envSnapshot = { ...process.env };
const WORKER_SECRET = 'e'.repeat(32);

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

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

function edgeRun(id, overrides = {}) {
  return {
    id,
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    check_id: WAF_EDGE_DETECTION_CHECK_ID,
    status: 'running',
    ...overrides,
  };
}

describe('WAF edge detection feature gate', () => {
  let server;
  let baseUrl;
  let starts = 0;

  before(() => {
    freshStore();
    ({ server, baseUrl } = startServer(wafEnabledEnv({
      ASTRANULL_WAF_POSTURE_ENABLED: '0',
    }), {
      testRuns: {
        startTestRun: async () => { starts += 1; },
      },
    }));
  });

  after(async () => {
    await closeServer(server);
    restoreEnv();
  });

  it('returns waf_feature_disabled without dispatching', async () => {
    const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: { target_group_id: 'tg_1', target_id: 'tgt_1' },
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'waf_feature_disabled');
    assert.equal(starts, 0);
  });
});

describe('WAF edge detection delegated API', () => {
  let server;
  let baseUrl;
  let runtimeConfig;
  let networkTouched = false;
  const calls = [];
  const runs = new Map();
  const events = new Map();

  before(() => {
    freshStore();
    const testRuns = {
      async startTestRun(ctx, body, receivedConfig) {
        calls.push({ ctx, body, runtimeConfig: receivedConfig });
        await new Promise((resolve) => setTimeout(resolve, 5));
        const run = edgeRun(`run_${calls.length}`, {
          target_group_id: body.target_group_id,
          target_id: body.target_id,
        });
        runs.set(run.id, run);
        events.set(run.id, []);
        return { run, probe_job: { id: `pjob_${calls.length}`, status: 'pending' } };
      },
      async getTestRun(ctx, id) {
        const run = runs.get(id);
        return run?.tenant_id === ctx.tenantId ? run : null;
      },
      async getRunEvents(ctx, id) {
        const run = runs.get(id);
        if (run?.tenant_id !== ctx.tenantId) return null;
        return events.get(id) ?? [];
      },
    };
    ({ server, baseUrl, runtimeConfig } = startServer(wafEnabledEnv(), {
      testRuns,
      // A regression that consults the former dependency bag will fail these tests.
      edgeDetectionDeps: {
        fetchFn: async () => {
          networkTouched = true;
          throw new Error('control-plane network must not run');
        },
        resolve4: async () => {
          networkTouched = true;
          return ['127.0.0.1'];
        },
      },
    }));
  });

  after(async () => {
    await closeServer(server);
    restoreEnv();
  });

  it('keeps waf:run RBAC enforcement', async () => {
    const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('viewer'),
      body: { target_group_id: 'tg_1', target_id: 'tgt_1' },
    });
    assert.equal(res.status, 403);
    assert.equal(calls.length, 0);
  });

  it('rejects raw hostname and private-IP input before any service or network activity', async () => {
    const rawHostname = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: {
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        hostname: 'http://169.254.169.254/latest/meta-data/',
      },
    });
    assert.equal(rawHostname.status, 400);
    assert.equal(rawHostname.json.error, 'raw_hostname_not_allowed');

    const privateIpAsId = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: { target_group_id: 'tg_1', target_id: '10.0.0.8' },
    });
    assert.equal(privateIpAsId.status, 400);
    assert.equal(privateIpAsId.json.error, 'invalid_target_id');
    assert.equal(calls.length, 0);
    assert.equal(networkTouched, false);
  });

  it('requires both tenant-bound IDs and rejects arbitrary probe controls', async () => {
    const missing = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: { target_group_id: 'tg_1' },
    });
    assert.equal(missing.status, 400);
    assert.equal(missing.json.error, 'invalid_target_id');

    const override = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: { target_group_id: 'tg_1', target_id: 'tgt_1', timeout_ms: 999_999 },
    });
    assert.equal(override.status, 400);
    assert.equal(override.json.error, 'unsupported_fields');
    assert.deepEqual(override.json.fields, ['timeout_ms']);
    assert.equal(calls.length, 0);
  });

  it('returns 202 only after passing the exact binding to startTestRun', async () => {
    const res = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: { target_group_id: 'tg_1', target_id: 'tgt_1' },
    });

    assert.equal(res.status, 202);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].body, {
      check_id: WAF_EDGE_DETECTION_CHECK_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.strictEqual(calls[0].runtimeConfig, runtimeConfig);
    assert.equal(res.json.detection_request.status, 'pending');
    assert.equal(res.json.detection_request.test_run_id, 'run_1');
    assert.equal(res.headers.location, '/v1/waf/edge-detection/run_1');
    assert.equal(res.headers['retry-after'], '2');
    assert.equal(networkTouched, false);
  });

  it('returns pending while durable worker evidence has not arrived', async () => {
    const res = await request(baseUrl, 'GET', '/v1/waf/edge-detection/run_1', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.status, 'pending');
    assert.equal(res.json.reason, 'worker_result_pending');
    assert.equal(res.json.detection, null);
  });

  it('projects successful WAF vendor and CDN provider signals from run events', async () => {
    runs.set('run_detected', edgeRun('run_detected', { status: 'verdicted' }));
    events.set('run_detected', [{
      id: 'evt_detected',
      tenant_id: 'ten_demo',
      test_run_id: 'run_detected',
      target_id: 'tgt_1',
      check_id: WAF_EDGE_DETECTION_CHECK_ID,
      source: 'probe_worker',
      signal_type: 'probe_result',
      timestamp: '2026-08-29T15:10:00.000Z',
      metadata: {
        probe_kind: 'outside_in_waf_scan',
        external_result: 'blocked',
        edge_signature_corpus_version: '1',
        edge_signature: {
          waf_present: true,
          cdn_detected: true,
          best_vendor: { vendor: 'cloudflare', confidence: 0.97 },
          address_matches: [{ family: 'cdn', provider: 'cloudfront' }],
          cname_matches: [],
        },
      },
    }]);

    const res = await request(baseUrl, 'GET', '/v1/waf/edge-detection/run_detected', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.status, 'detected');
    assert.equal(res.json.detection.waf.vendor, 'cloudflare');
    assert.equal(res.json.detection.cdn.provider, 'cloudfront');
  });

  it('keeps worker errors distinct from an explicit successful fingerprint no-match', async () => {
    runs.set('run_error', edgeRun('run_error', { status: 'verdicted' }));
    events.set('run_error', [{
      check_id: WAF_EDGE_DETECTION_CHECK_ID,
      source: 'probe_worker',
      signal_type: 'probe_result',
      metadata: { external_result: 'timeout', error_class: 'probe_timeout' },
    }]);
    runs.set('run_no_match', edgeRun('run_no_match', { status: 'verdicted' }));
    events.set('run_no_match', [{
      check_id: WAF_EDGE_DETECTION_CHECK_ID,
      source: 'probe_worker',
      signal_type: 'probe_result',
      metadata: {
        external_result: 'connected',
        edge_signature: { waf_present: false, cdn_detected: false },
      },
    }]);

    const failed = await request(baseUrl, 'GET', '/v1/waf/edge-detection/run_error', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(failed.status, 200);
    assert.equal(failed.json.status, 'error');
    assert.equal(failed.json.reason, 'worker_result_error');
    assert.equal(failed.json.detection, null);

    const noMatch = await request(baseUrl, 'GET', '/v1/waf/edge-detection/run_no_match', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(noMatch.status, 200);
    assert.equal(noMatch.json.status, 'not_detected');
    assert.equal(noMatch.json.reason, 'completed_no_signature_match');
    assert.equal(noMatch.json.detection.waf.status, 'not_detected');
    assert.equal(noMatch.json.detection.cdn.status, 'not_detected');
    assert.ok(!noMatch.text.includes('"waf_present":false'));
    assert.ok(!noMatch.text.includes('"cdn_detected":false'));
  });

  it('does not expose unrelated test runs through the read path', async () => {
    runs.set('run_other_check', edgeRun('run_other_check', { check_id: 'http.baseline.safe' }));
    events.set('run_other_check', []);
    const res = await request(baseUrl, 'GET', '/v1/waf/edge-detection/run_other_check', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'edge_detection_not_found');
  });

  it('answers 405 for unsupported collection/detail methods', async () => {
    const collection = await request(baseUrl, 'GET', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
    });
    const detail = await request(baseUrl, 'POST', '/v1/waf/edge-detection/run_1', {
      headers: demoHeaders('admin'),
      body: {},
    });
    assert.equal(collection.status, 405);
    assert.equal(detail.status, 405);
  });
});

describe('WAF edge detection signed-worker safety path', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    getStore().agents.push({
      id: 'ag_edge_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      status: 'online',
      capabilities: ['heartbeat'],
      last_token_validation_status: 'valid',
    });
    ({ server, baseUrl } = startServer(wafEnabledEnv({
      ASTRANULL_PROBE_MODE: 'signed-worker',
      ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
    })));
    // createServer hydrates a developer-demo verdict; this focused fixture measures only
    // records created by the edge-detection requests below.
    getStore().testRuns.length = 0;
    getStore().probeJobs.length = 0;
    getStore().events.length = 0;
  });

  after(async () => {
    await closeServer(server);
    restoreEnv();
  });

  it('blocks unverified scope, then creates a signed job for the exact verified target', async () => {
    getStore().targetGroups[0].ownership_status = 'unverified';
    const denied = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: { target_group_id: 'tg_1', target_id: 'tgt_1' },
    });
    assert.equal(denied.status, 409);
    assert.equal(denied.json.error, 'ownership_not_verified');
    assert.equal(getStore().probeJobs.length, 0);
    assert.equal(getStore().testRuns.length, 0);

    getStore().targetVerifications.push({
      id: 'tv_edge_target_verified',
      tenant_id: 'ten_demo',
      target_id: 'tgt_1',
      state: 'dns_verified',
      source_kind: 'dns_txt',
      source_ref: { challenge_id: 'dns_edge_fixture' },
      transitioned_at: new Date().toISOString(),
      transitioned_by: 'usr_admin',
    });
    const accepted = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: { target_group_id: 'tg_1', target_id: 'tgt_1' },
    });

    assert.equal(accepted.status, 202);
    assert.equal(getStore().probeJobs.length, 1);
    const job = getStore().probeJobs[0];
    const run = getStore().testRuns.find((item) => item.id === job.test_run_id);
    assert.equal(run.target_group_id, 'tg_1');
    assert.equal(run.target_id, 'tgt_1');
    assert.equal(job.target_id, 'tgt_1');
    assert.equal(job.check_id, WAF_EDGE_DETECTION_CHECK_ID);
    assert.equal(job.status, 'pending');
    assert.ok(job.job_signature);
    assert.equal(
      getStore().events.some((event) => event.test_run_id === accepted.json.detection_request.test_run_id),
      false,
      'the control plane must not fabricate or execute the worker result',
    );
    assert.ok(getStore().auditLog.some((entry) => (
      entry.action === 'test_run.started'
      && entry.resource_id === accepted.json.detection_request.test_run_id
    )));

    const resultBody = {
      external_result: 'blocked',
      safety_attestation: { requests_sent: 1, duration_ms: 75 },
      metadata: {
        probe_kind: 'outside_in_waf_scan',
        waf_detected: true,
        detected_vendor: 'cloudflare',
        requests_sent: 1,
        edge_signature_corpus_version: '1',
        edge_signature: {
          waf_present: true,
          cdn_detected: true,
          conflicting_vendor_signals: false,
          best_vendor: { vendor: 'cloudflare', confidence: 0.99 },
          address_matches: [{ family: 'cdn', provider: 'cloudflare' }],
          cname_matches: [],
        },
      },
    };
    const resultPath = `/internal/probe/jobs/${job.id}/result`;
    const resultHeaders = probeWorkerAuthHeaders(
      'worker-edge-1',
      {
        method: 'POST',
        path: resultPath,
        bodyText: JSON.stringify(resultBody),
        tenantId: 'ten_demo',
      },
      WORKER_SECRET,
    );
    const ingested = await request(baseUrl, 'POST', resultPath, {
      headers: resultHeaders,
      body: resultBody,
    });
    assert.equal(ingested.status, 201);

    // Probe ingestion precedes asynchronous run finalization. Edge evidence is projected only
    // after the shared finalizer makes the run successfully terminal.
    assert.equal(run.status, 'collecting');
    run.status = 'verdicted';

    const detected = await request(
      baseUrl,
      'GET',
      `/v1/waf/edge-detection/${accepted.json.detection_request.test_run_id}`,
      { headers: demoHeaders('viewer') },
    );
    assert.equal(detected.status, 200);
    assert.equal(detected.json.status, 'detected');
    assert.equal(detected.json.detection.waf.vendor, 'cloudflare');
    assert.equal(detected.json.detection.cdn.provider, 'cloudflare');
    assert.ok(getStore().auditLog.some((entry) => entry.action === 'probe_job.result_ingested'));
  });
});


describe('WAF edge detection Postgres service parity', () => {
  let server;
  let baseUrl;
  const calls = [];
  const run = edgeRun('run_pg_1', { status: 'verdicted' });
  const workerEvent = {
    id: 'evt_pg_1',
    tenant_id: 'ten_demo',
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: WAF_EDGE_DETECTION_CHECK_ID,
    source: 'probe_worker',
    signal_type: 'probe_result',
    metadata: {
      external_result: 'blocked',
      edge_signature: {
        waf_present: true,
        cdn_detected: true,
        best_vendor: { vendor: 'fastly', confidence: 0.88 },
        cname_matches: [{ type: 'cdn', provider: 'fastly' }],
      },
    },
  };

  before(() => {
    const runtimeConfig = {
      ...loadRuntimeConfig(wafEnabledEnv()),
      persistenceMode: 'postgres',
      databaseUrlConfigured: true,
    };
    server = createServer({
      env: wafEnabledEnv(),
      runtimeConfig,
      services: {
        testRuns: {
          async startTestRun(ctx, body, receivedConfig) {
            calls.push({ ctx, body, runtimeConfig: receivedConfig });
            return { run };
          },
          async getTestRun(ctx, id) {
            return ctx.tenantId === 'ten_demo' && id === run.id ? run : null;
          },
          async getRunEvents(ctx, id) {
            return ctx.tenantId === 'ten_demo' && id === run.id ? [workerEvent] : null;
          },
        },
      },
    });
    server.listen(0);
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await closeServer(server);
    restoreEnv();
  });

  it('queues and reads through injected Postgres test-run services', async () => {
    const queued = await request(baseUrl, 'POST', '/v1/waf/edge-detection', {
      headers: demoHeaders('admin'),
      body: { target_group_id: 'tg_1', target_id: 'tgt_1' },
    });
    assert.equal(queued.status, 202);
    assert.deepEqual(calls[0].body, {
      check_id: WAF_EDGE_DETECTION_CHECK_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });

    const detected = await request(baseUrl, 'GET', '/v1/waf/edge-detection/run_pg_1', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(detected.status, 200);
    assert.equal(detected.json.status, 'detected');
    assert.equal(detected.json.detection.waf.vendor, 'fastly');
    assert.equal(detected.json.detection.cdn.provider, 'fastly');
  });
});
