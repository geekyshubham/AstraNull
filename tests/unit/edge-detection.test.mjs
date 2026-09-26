import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  validateEdgeDetectionRequest,
  WAF_EDGE_DETECTION_CHECK_ID,
} from '../../src/lib/edgeDetection.mjs';
import {
  getEdgeDetection,
  runEdgeDetection,
} from '../../src/services/wafEdgeDetection.mjs';

const RUNTIME_CONFIG = {
  probeMode: 'signed-worker',
  featureFlags: { wafPostureEnabled: true },
};

const EDGE_NONCE = 'sha256:edge-detection-test';

function edgeRun(overrides = {}) {
  return {
    id: 'run_edge_1',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    check_id: WAF_EDGE_DETECTION_CHECK_ID,
    status: 'running',
    correlation: { nonce_hash: EDGE_NONCE },
    ...overrides,
  };
}

function trustedEdgeEvent(runId = 'run_edge_1', overrides = {}) {
  return {
    id: 'event_signed',
    test_run_id: runId,
    signal_type: 'probe_result',
    producer_kind: 'signed_probe',
    source: 'probe_worker',
    check_id: WAF_EDGE_DETECTION_CHECK_ID,
    nonce_hash: EDGE_NONCE,
    metadata: {
      external_result: 'blocked',
      edge_signature: { waf_present: true, cdn_detected: false },
    },
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

  it('quarantines legacy-untrusted worker events from edge detection', async () => {
    const run = edgeRun({ status: 'completed' });
    const result = await getEdgeDetection(
      { tenantId: 'ten_demo' },
      run.id,
      {
        runtimeConfig: RUNTIME_CONFIG,
        testRuns: {
          getTestRun: async () => run,
          getRunEvents: async () => [{
            id: 'event_legacy',
            signal_type: 'probe_result',
            producer_kind: 'legacy_untrusted',
            source: 'probe_worker',
            check_id: WAF_EDGE_DETECTION_CHECK_ID,
            nonce_hash: null,
            metadata: {
              external_result: 'blocked',
              waf_fingerprint_detected: true,
            },
          }],
        },
      },
    );

    assert.equal(result.status, 'inconclusive');
    assert.equal(result.reason, 'worker_result_not_observed');
    assert.equal(result.detection, null);

    const active = await getEdgeDetection(
      { tenantId: 'ten_demo' },
      run.id,
      {
        runtimeConfig: RUNTIME_CONFIG,
        testRuns: {
          getTestRun: async () => edgeRun({ status: 'collecting' }),
          getRunEvents: async () => [{
            id: 'event_signed_early',
            signal_type: 'probe_result',
            producer_kind: 'signed_probe',
            source: 'probe_worker',
            check_id: WAF_EDGE_DETECTION_CHECK_ID,
            metadata: { external_result: 'blocked', waf_fingerprint_detected: true },
          }],
        },
      },
    );
    assert.equal(active.status, 'pending');
    assert.equal(active.reason, 'worker_result_pending');
    assert.equal(active.detection, null);

    const cancelled = await getEdgeDetection(
      { tenantId: 'ten_demo' },
      run.id,
      {
        runtimeConfig: RUNTIME_CONFIG,
        testRuns: {
          getTestRun: async () => edgeRun({ status: 'cancelled' }),
          getRunEvents: async () => [{
            id: 'event_signed',
            signal_type: 'probe_result',
            producer_kind: 'signed_probe',
            source: 'probe_worker',
            check_id: WAF_EDGE_DETECTION_CHECK_ID,
            metadata: { external_result: 'blocked', waf_fingerprint_detected: true },
          }],
        },
      },
    );
    assert.equal(cancelled.status, 'error');
    assert.equal(cancelled.reason, 'test_run_failed');
    assert.equal(cancelled.detection, null);
  });

  it('rejects missing and wrong event run IDs even when every other provenance field matches', async () => {
    const run = edgeRun({ status: 'verdicted' });
    for (const decoy of [
      trustedEdgeEvent(undefined, { test_run_id: undefined }),
      trustedEdgeEvent('run_edge_decoy'),
    ]) {
      const result = await getEdgeDetection(
        { tenantId: 'ten_demo' },
        run.id,
        {
          runtimeConfig: RUNTIME_CONFIG,
          testRuns: {
            getTestRun: async () => run,
            getRunEvents: async () => [decoy],
          },
        },
      );
      assert.equal(result.status, 'inconclusive');
      assert.equal(result.reason, 'worker_result_not_observed');
      assert.equal(result.detection, null);
    }

    const exact = await getEdgeDetection(
      { tenantId: 'ten_demo' },
      run.id,
      {
        runtimeConfig: RUNTIME_CONFIG,
        testRuns: {
          getTestRun: async () => run,
          getRunEvents: async () => [
            trustedEdgeEvent('run_edge_decoy'),
            trustedEdgeEvent(run.id),
          ],
        },
      },
    );
    assert.equal(exact.status, 'detected');
    assert.equal(exact.detection.waf.status, 'detected');
  });

  it('exposes effectiveness without promoting monitor-only or timeout results', async () => {
    const run = edgeRun({ status: 'completed' });
    const service = {
      getTestRun: async () => run,
      getRunEvents: async () => [trustedEdgeEvent(run.id, {
        metadata: {
          external_result: 'connected',
          posture_status: 'protected',
          agent_corroborated: true,
          marker_probes: [
            { family: 'sqli_marker', variant: 'plain', blocked: false, allowed: true },
            { family: 'xss_marker', variant: 'plain', blocked: false, allowed: true },
            { family: 'path_traversal_marker', variant: 'plain', blocked: false, allowed: true },
          ],
          edge_signature: { waf_present: true, cdn_detected: false },
        },
      })],
    };
    const monitorOnly = await getEdgeDetection(
      { tenantId: 'ten_demo' },
      run.id,
      { runtimeConfig: RUNTIME_CONFIG, testRuns: service },
    );
    assert.equal(monitorOnly.status, 'detected');
    assert.equal(monitorOnly.detection.effectiveness.status, 'present_but_not_effective');
    assert.equal(monitorOnly.detection.protection.status, 'underprotected');

    service.getRunEvents = async () => [trustedEdgeEvent(run.id, {
      metadata: {
        external_result: 'not_run',
        posture_status: 'inconclusive',
        probe_validation_passed: false,
        marker_probes: [],
        edge_signature: { waf_present: true, cdn_detected: false },
      },
    })];
    const presenceOnly = await getEdgeDetection(
      { tenantId: 'ten_demo' },
      run.id,
      { runtimeConfig: RUNTIME_CONFIG, testRuns: service },
    );
    assert.equal(presenceOnly.status, 'detected');
    assert.equal(presenceOnly.detection.waf.status, 'detected');
    assert.equal(presenceOnly.detection.effectiveness.status, 'inconclusive');
    assert.equal(presenceOnly.detection.protection.status, 'inconclusive');

    service.getRunEvents = async () => [trustedEdgeEvent(run.id, {
      metadata: {
        external_result: 'timeout',
        error_class: 'probe_timeout',
        edge_signature: { waf_present: true, cdn_detected: false },
      },
    })];
    const timeout = await getEdgeDetection(
      { tenantId: 'ten_demo' },
      run.id,
      { runtimeConfig: RUNTIME_CONFIG, testRuns: service },
    );
    assert.equal(timeout.status, 'error');
    assert.equal(timeout.reason, 'worker_result_error');
    assert.equal(timeout.detection, null);
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
