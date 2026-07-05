import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES } from '../../src/contracts/wafOffensive.mjs';
import { createServer } from '../../src/server.mjs';
import { sha256Hex } from '../../src/lib/authorizationArtifactLedger.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';

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

function startServer() {
  const runtimeConfig = loadRuntimeConfig(wafEnabledEnv());
  const server = createServer({ runtimeConfig, env: wafEnabledEnv() });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

function offensiveArtifactBody(type) {
  return {
    type,
    content_sha256: sha256Hex(`wof-artifact:${type}`),
    reference_uri: 'metadata://wof/demo',
    approval_reference: 'REF-WOF-001',
    approver: 'Customer Approver',
    valid_window: {
      valid_from: new Date().toISOString(),
      valid_to: new Date(Date.now() + 86400000 * 30).toISOString(),
    },
    approved_targets: ['tg_1'],
    approved_scenario_families: ['sqli_offensive'],
    emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
    abort_criteria: { threshold: 'waf_bypass_detected', auto_stop: true },
  };
}

async function createDemoAsset(baseUrl, headers) {
  const created = await request(baseUrl, 'POST', '/v1/waf/assets', {
    headers,
    body: {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      canonical_url: 'https://waf-offensive.example.com',
      owner_hint: 'edge-team',
    },
  });
  assert.equal(created.status, 201);
  return created.json.asset;
}

async function acceptOffensiveArtifacts(baseUrl, requestId, socHeaders) {
  for (const type of WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES) {
    const up = await request(baseUrl, 'POST', `/v1/waf/offensive-requests/${requestId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: offensiveArtifactBody(type),
    });
    assert.equal(up.status, 201, `upload ${type}`);
    const review = await request(
      baseUrl,
      'POST',
      `/internal/soc/waf-offensive/${requestId}/artifacts/${up.json.artifact.id}/review`,
      { headers: socHeaders, body: { status: 'accepted' } },
    );
    assert.equal(review.status, 200, `review ${type}`);
  }
}

describe('waf offensive API', () => {
  let server;
  let baseUrl;
  const adminHeaders = demoHeaders('admin');
  const socHeadersA = demoHeaders('soc', 'ten_demo', 'usr_soc_a');
  const socHeadersB = demoHeaders('soc', 'ten_demo', 'usr_soc_b');

  before(() => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    ({ server, baseUrl } = startServer());
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  it('exposes offensive suite catalog and blocks customer self-service checks', async () => {
    const suites = await request(baseUrl, 'GET', '/v1/waf/offensive-suites', { headers: adminHeaders });
    assert.equal(suites.status, 200);
    assert.ok(suites.json.suites.some((s) => s.suite_id === 'sqli_offensive'));

    const blocked = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: adminHeaders,
      body: {
        check_id: 'waf.offensive_sqli.soc',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.json.error, 'soc_gated_check');
  });

  it('runs SOC-gated offensive request workflow end to end', async () => {
    const asset = await createDemoAsset(baseUrl, adminHeaders);
    const created = await request(baseUrl, 'POST', '/v1/waf/offensive-requests', {
      headers: adminHeaders,
      body: {
        waf_asset_id: asset.id,
        objective: 'Validate real SQLi/XSS blocking on staging',
        requested_suites: ['sqli_offensive', 'xss_offensive'],
        emergency_contacts: ['ops@example.invalid'],
        stop_criteria: 'Stop on origin impact or customer signal',
        scope_confirmation: true,
        staging_only: true,
      },
    });
    assert.equal(created.status, 201);
    const requestId = created.json.offensive_request.id;

    await acceptOffensiveArtifacts(baseUrl, requestId, socHeadersA);

    const approve1 = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/approve`, {
      headers: socHeadersA,
    });
    assert.equal(approve1.status, 200);
    assert.equal(approve1.json.offensive_request.state, 'under_review');

    const approve2 = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/approve`, {
      headers: socHeadersB,
    });
    assert.equal(approve2.status, 200);
    assert.equal(approve2.json.offensive_request.state, 'approved');

    const windowStart = new Date(Date.now() - 60_000).toISOString();
    const windowEnd = new Date(Date.now() + 3_600_000).toISOString();
    const scheduled = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/schedule`, {
      headers: socHeadersA,
      body: { window_start: windowStart, window_end: windowEnd },
    });
    assert.equal(scheduled.status, 200);
    assert.equal(scheduled.json.offensive_request.state, 'scheduled');

    const started = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/start`, {
      headers: socHeadersA,
    });
    assert.equal(started.status, 200);
    assert.equal(started.json.offensive_request.state, 'running');
    assert.ok(started.json.offensive_request.waf_validation_run_id);

    const results = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/results`, {
      headers: socHeadersA,
      body: {
        suite_results: [
          {
            suite_id: 'sqli_offensive',
            observed_action: 'block',
            passed: true,
            confidence: 0.95,
            evidence_summary: { block_page_signature_id: 'vendor-403' },
            probes_attempted: 10,
            blocked_count: 10,
          },
          {
            suite_id: 'xss_offensive',
            observed_action: 'block',
            passed: true,
            confidence: 0.9,
            evidence_summary: { challenge_detected: true },
            probes_attempted: 8,
            blocked_count: 8,
          },
        ],
      },
    });
    assert.equal(results.status, 200);
    assert.equal(results.json.suite_results.length, 2);

    const stopped = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/stop`, {
      headers: socHeadersA,
    });
    assert.equal(stopped.status, 200);
    assert.equal(stopped.json.offensive_request.state, 'stopped');

    const report = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/post-test-report`, {
      headers: socHeadersA,
      body: {
        executive_summary: 'WAF blocked all approved offensive probes before origin.',
        blocking_verdict: 'effective',
      },
    });
    assert.equal(report.status, 201);

    const closed = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/close`, {
      headers: socHeadersA,
    });
    assert.equal(closed.status, 200);
    assert.equal(closed.json.offensive_request.state, 'closed');
  });
});