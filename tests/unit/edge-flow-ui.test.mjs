import assert from 'node:assert/strict';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createServer as createViteServer } from 'vite';

const CHECK_ID = 'waf.fingerprint.safe';
const NONCE = 'sha256:edge-flow-test';
const REQUEST = {
  status: 'pending',
  test_run_id: 'run_edge_ui_1',
  target_group_id: 'tg_1',
  target_id: 'tgt_1',
  check_id: CHECK_ID,
};

function run(status = 'running', overrides = {}) {
  return {
    id: REQUEST.test_run_id,
    target_group_id: REQUEST.target_group_id,
    target_id: REQUEST.target_id,
    check_id: CHECK_ID,
    status,
    correlation: { nonce_hash: NONCE },
    ...overrides,
  };
}

function event(metadata, overrides = {}) {
  return {
    id: 'evt_edge_ui_1',
    test_run_id: REQUEST.test_run_id,
    target_id: REQUEST.target_id,
    check_id: CHECK_ID,
    source: 'probe_worker',
    signal_type: 'probe_result',
    nonce_hash: NONCE,
    timestamp: '2026-08-29T15:10:00.000Z',
    metadata: {
      probe_kind: 'outside_in_waf_scan',
      ...metadata,
    },
    ...overrides,
  };
}

describe('target-group WAF/CDN edge result projection', () => {
  let vite;
  let project;

  before(async () => {
    vite = await createViteServer({
      configFile: path.resolve('vite.config.ts'),
      server: { middlewareMode: true },
      appType: 'custom',
      logLevel: 'silent',
    });
    ({ projectEdgeDetectionResult: project } = await vite.ssrLoadModule(
      '/src/pages/target-group-detail-view.tsx',
    ));
  });

  after(async () => {
    await vite?.close();
  });

  it('keeps an active run pending and reports a terminal run with no trusted result as not observed', () => {
    assert.equal(project(REQUEST, run('running'), { items: [] }).status, 'pending');
    const terminal = project(REQUEST, run('verdicted'), { items: [] });
    assert.equal(terminal.status, 'not_observed');
    assert.equal(terminal.reason, 'worker_result_not_observed');
  });

  it('separates worker errors, incomplete evidence, and simulation from no-match', () => {
    const workerError = project(REQUEST, run('collecting'), {
      items: [event({ external_result: 'timeout', error_class: 'probe_timeout' })],
    });
    assert.equal(workerError.status, 'error');
    assert.equal(workerError.error_class, 'probe_timeout');

    const incomplete = project(REQUEST, run('collecting'), {
      items: [event({ external_result: 'connected' })],
    });
    assert.equal(incomplete.status, 'inconclusive');
    assert.equal(incomplete.reason, 'edge_signature_incomplete');

    const simulation = project(REQUEST, run('collecting'), {
      items: [event(
        { external_result: 'blocked', waf_detected: true },
        { source: 'probe_simulation_stub' },
      )],
    });
    assert.equal(simulation.status, 'inconclusive');
    assert.equal(simulation.reason, 'simulation_not_detection');
  });

  it('uses not_detected only for an explicit successful WAF and CDN no-match', () => {
    const result = project(REQUEST, run('collecting'), {
      items: [event({
        external_result: 'connected',
        waf_detected: false,
        cdn_detected: false,
        requests_sent: 4,
        edge_signature_corpus_version: '2',
        edge_signature: {
          waf_present: false,
          cdn_detected: false,
          address_matches: [],
          cname_matches: [],
        },
      })],
    });

    assert.equal(result.status, 'not_detected');
    assert.equal(result.reason, null);
    assert.equal(result.detection.waf.status, 'not_detected');
    assert.equal(result.detection.cdn.status, 'not_detected');
    assert.equal(result.detection.requests_sent, 4);
    assert.equal(result.detection.corpus_version, '2');
  });

  it('keeps WAF and CDN provider/type evidence independent, including cdncheck CNAME type', () => {
    const result = project(REQUEST, run('collecting'), {
      items: [event({
        external_result: 'blocked',
        detected_product: 'Kona Site Defender',
        waf_detected: true,
        cdn_detected: true,
        edge_signature: {
          waf_present: true,
          cdn_detected: true,
          address_matches: [{ family: 'cdn', provider: 'cloudfront' }],
          cname_matches: [{ type: 'waf', provider: 'akamai', suffix: 'edgekey.net' }],
        },
      })],
    });

    assert.equal(result.status, 'detected');
    assert.deepEqual(result.detection.waf, {
      status: 'detected',
      provider: 'akamai',
      type: 'Kona Site Defender',
    });
    assert.deepEqual(result.detection.cdn, {
      status: 'detected',
      provider: 'cloudfront',
      type: 'address_range',
    });
  });

  it('does not trust tenant-ingested or nonce-mismatched events', () => {
    const tenantEvent = event({ external_result: 'blocked', waf_detected: true }, {
      source: 'tenant_event_ingest',
    });
    const wrongNonce = event({ external_result: 'blocked', waf_detected: true }, {
      nonce_hash: 'sha256:not-this-run',
    });
    for (const untrusted of [tenantEvent, wrongNonce]) {
      const result = project(REQUEST, run('verdicted'), { items: [untrusted] });
      assert.equal(result.status, 'not_observed');
      assert.equal(result.detection, null);
    }
  });

  it('marks contradictory edge booleans inconclusive instead of asserting detection or absence', () => {
    const result = project(REQUEST, run('collecting'), {
      items: [event({
        external_result: 'connected',
        waf_detected: false,
        waf_fingerprint_detected: true,
        cdn_detected: false,
        edge_signature: { cdn_detected: false },
      })],
    });
    assert.equal(result.status, 'inconclusive');
    assert.equal(result.reason, 'conflicting_edge_signals');
    assert.equal(result.detection.waf.status, 'inconclusive');
  });
});
