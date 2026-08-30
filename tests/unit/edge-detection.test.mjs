import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  validateEdgeDetectionRequest,
  WAF_EDGE_DETECTION_CHECK_ID,
} from '../../src/lib/edgeDetection.mjs';
import { runEdgeDetection } from '../../src/services/wafEdgeDetection.mjs';

const RUNTIME_CONFIG = {
  probeMode: 'signed-worker',
  featureFlags: { wafPostureEnabled: true },
};

function edgeRun(overrides = {}) {
  return {
    id: 'run_edge_1',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    check_id: WAF_EDGE_DETECTION_CHECK_ID,
    status: 'running',
    ...overrides,
  };
}

describe('edge-detection target binding validation', () => {
  it('accepts only opaque target group and target identifiers', () => {
    assert.deepEqual(
      validateEdgeDetectionRequest({ target_group_id: 'tg_1', target_id: 'target-123' }),
      { target_group_id: 'tg_1', target_id: 'target-123' },
    );
  });

  it('rejects raw destinations and arbitrary probe controls', () => {
    assert.equal(
      validateEdgeDetectionRequest({
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        hostname: '127.0.0.1',
      }).error,
      'raw_hostname_not_allowed',
    );
    for (const targetId of ['10.0.0.7', '169.254.169.254', '[::1]', 'https://internal.example']) {
      assert.equal(
        validateEdgeDetectionRequest({ target_group_id: 'tg_1', target_id: targetId }).error,
        'invalid_target_id',
      );
    }
    assert.equal(
      validateEdgeDetectionRequest({ target_group_id: 'https://internal.example', target_id: 'tgt_1' }).error,
      'invalid_target_group_id',
    );
    assert.deepEqual(
      validateEdgeDetectionRequest({
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        timeout_ms: 60_000,
        probe_profile: { direct_ip: '127.0.0.1' },
      }),
      { error: 'unsupported_fields', status: 400, fields: ['probe_profile', 'timeout_ms'] },
    );
  });

  it('rejects non-object and incomplete requests', () => {
    assert.deepEqual(validateEdgeDetectionRequest(null), { error: 'invalid_request', status: 400 });
    assert.deepEqual(validateEdgeDetectionRequest([]), { error: 'invalid_request', status: 400 });
    assert.deepEqual(validateEdgeDetectionRequest({ target_group_id: 'tg_1' }), {
      error: 'invalid_target_id',
      status: 400,
    });
  });
});

describe('edge-detection service delegation', () => {
  it('passes only the bound target and fixed safe check to awaited startTestRun', async () => {
    const calls = [];
    let startFinished = false;
    const testRuns = {
      async startTestRun(ctx, body, runtimeConfig) {
        calls.push({ ctx, body, runtimeConfig });
        await new Promise((resolve) => setTimeout(resolve, 5));
        startFinished = true;
        return { run: edgeRun() };
      },
    };
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };

    const result = await runEdgeDetection(ctx, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    }, { testRuns, runtimeConfig: RUNTIME_CONFIG });

    assert.equal(startFinished, true, 'the durable test-run/audit path must finish before acceptance');
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].body, {
      check_id: WAF_EDGE_DETECTION_CHECK_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.strictEqual(calls[0].runtimeConfig, RUNTIME_CONFIG);
    assert.deepEqual(result.request, {
      status: 'pending',
      test_run_id: 'run_edge_1',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: WAF_EDGE_DETECTION_CHECK_ID,
      run_status: 'running',
      test_run_url: '/v1/test-runs/run_edge_1',
      events_url: '/v1/test-runs/run_edge_1/events',
    });
  });

  it('rejects raw host/private-IP input before startTestRun can run', async () => {
    let starts = 0;
    const testRuns = { startTestRun: async () => { starts += 1; } };

    const hostname = await runEdgeDetection({}, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      hostname: 'localhost',
    }, { testRuns, runtimeConfig: RUNTIME_CONFIG });
    const privateIp = await runEdgeDetection({}, {
      target_group_id: 'tg_1',
      target_id: '192.168.1.20',
    }, { testRuns, runtimeConfig: RUNTIME_CONFIG });

    assert.equal(hostname.error, 'raw_hostname_not_allowed');
    assert.equal(privateIp.error, 'invalid_target_id');
    assert.equal(starts, 0);
  });

  it('preserves feature failure and missing-runtime fail-closed behavior', async () => {
    let starts = 0;
    const disabled = await runEdgeDetection({}, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    }, {
      runtimeConfig: { ...RUNTIME_CONFIG, featureFlags: { wafPostureEnabled: false } },
      testRuns: { startTestRun: async () => { starts += 1; } },
    });
    const unavailable = await runEdgeDetection({}, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    }, { runtimeConfig: RUNTIME_CONFIG });

    assert.deepEqual(disabled, { skipped: true, reason: 'waf_feature_disabled' });
    assert.deepEqual(unavailable, { error: 'edge_detection_test_runs_unavailable', status: 503 });
    assert.equal(starts, 0);
  });

  it('passes through governed start denials unchanged', async () => {
    const denial = { error: 'ownership_not_verified', status: 409 };
    const result = await runEdgeDetection({}, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    }, {
      runtimeConfig: RUNTIME_CONFIG,
      testRuns: { startTestRun: async () => denial },
    });
    assert.strictEqual(result, denial);
  });

  it('fails closed when the injected service returns a mismatched run binding', async () => {
    for (const run of [
      null,
      edgeRun({ check_id: 'http.baseline.safe' }),
      edgeRun({ target_group_id: 'tg_other' }),
      edgeRun({ target_id: 'tgt_other' }),
    ]) {
      const result = await runEdgeDetection({}, {
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      }, {
        runtimeConfig: RUNTIME_CONFIG,
        testRuns: { startTestRun: async () => ({ run }) },
      });
      assert.deepEqual(result, { error: 'edge_detection_dispatch_invalid_response', status: 502 });
    }
  });
});
