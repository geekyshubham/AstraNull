import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { classifyDirectOriginObservation } from '../../src/lib/externalObservationOutcomes.mjs';
import { deriveWafSignalsFromBoundEvents } from '../../src/lib/wafBoundRunCorrelation.mjs';

const HEALTHY_BASELINE = { status_code: 200, server_header: 'edge' };
const responseWith = (status, headers = {}) => ({ status, headers: { get: (name) => headers[String(name).toLowerCase()] ?? null } });
const deniedOriginObservation = () => classifyDirectOriginObservation({
  response: responseWith(403, { 'x-origin-lockdown': 'cdn-only' }),
  baseline: HEALTHY_BASELINE,
  scope: { host: 'shop.example.test', path: '/' },
  declaredLockdown: { status_code: 403, header: { name: 'x-origin-lockdown', value: 'cdn-only' } },
});

describe('waf bound run correlation (outside-in, external-only)', () => {
  it('classifies a fail external result as validation failed', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_1',
        nonce_hash: 'sha256:leak',
        metadata: { external_result: 'allowed' },
      }],
    });

    assert.equal(derived.validationPassed, false);
    assert.equal(derived.validationFailed, true);
    assert.equal(derived.source_external, true);
    assert.equal(derived.scenarioResults.length, 1);
    assert.equal(derived.scenarioResults[0].passed, false);
    assert.equal(derived.scenarioResults[0].observed_action, 'allow');
  });

  it('stays inconclusive when blocked externally without a WAF fingerprint', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_2',
        nonce_hash: 'sha256:blocked_only',
        metadata: { external_result: 'blocked' },
      }],
    });

    assert.equal(derived.validationPassed, false);
    assert.equal(derived.validationFailed, false);
    assert.equal(derived.scenarioResults[0].passed, null);
    assert.equal(derived.scenarioResults[0].observed_action, 'inconclusive');
  });

  it('classifies fingerprinted external block as edge-protected only', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_2b',
        nonce_hash: 'sha256:blocked_fingerprint',
        metadata: {
          external_result: 'blocked',
          waf_fingerprint_detected: true,
          waf_product_hint: 'cloudflare',
        },
      }],
    });

    assert.equal(derived.validationPassed, false);
    assert.equal(derived.edgeProtected, true);
    assert.equal(derived.originLockdownConfirmed, false);
    assert.equal(derived.scenarioResults[0].passed, true);
    assert.equal(derived.scenarioResults[0].observed_action, 'block');
  });

  it('classifies protected when an edge block is paired with external origin-lockdown evidence', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_confirmed',
        nonce_hash: 'sha256:blocked_locked',
        metadata: {
          external_result: 'blocked',
          waf_fingerprint_detected: true,
          origin_lockdown_confirmed: true,
          origin_observation: deniedOriginObservation(),
        },
      }],
    });
    assert.equal(derived.validationPassed, true);
    assert.equal(derived.edgeProtected, true);
    assert.equal(derived.originLockdownConfirmed, true);
    assert.equal(derived.validationFailed, false);
    assert.equal(derived.scenarioResults[0].evidence_summary.origin_lockdown_confirmed, true);
  });

  it('marks origin bypass confirmed only when the origin echoed the nonce-bound canary over a healthy baseline', () => {
    const observation = classifyDirectOriginObservation({
      response: responseWith(200, { 'x-astranull-canary-echo': 'nonce-1' }),
      baseline: HEALTHY_BASELINE,
      expectedNonce: 'nonce-1',
    });
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_bypass',
        nonce_hash: 'sha256:reached',
        metadata: { external_result: 'reached_origin', origin_bypass_confirmed: true, origin_observation: observation },
      }],
    });
    assert.equal(derived.originBypassConfirmed, true);
    assert.equal(derived.validationFailed, true);
  });

  it('never confirms origin bypass from a legacy flag or a shared Server header', () => {
    const headerOnly = classifyDirectOriginObservation({
      response: responseWith(200, { server: 'edge' }),
      baseline: HEALTHY_BASELINE,
    });
    for (const metadata of [
      { external_result: 'reached_origin', origin_bypass_confirmed: true },
      { external_result: 'connected', origin_bypass_confirmed: true, origin_observation: headerOnly },
    ]) {
      const derived = deriveWafSignalsFromBoundEvents({
        probes: [{ id: 'evt_probe_header', nonce_hash: 'sha256:header', metadata }],
      });
      assert.equal(derived.originBypassConfirmed, false);
    }
  });

  it('never confirms origin lockdown from a legacy flag or a silent origin leg', () => {
    const silent = classifyDirectOriginObservation({
      error: Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }),
      baseline: HEALTHY_BASELINE,
    });
    for (const metadata of [
      { external_result: 'blocked', waf_fingerprint_detected: true, origin_lockdown_confirmed: true },
      { external_result: 'blocked', waf_fingerprint_detected: true, origin_lockdown_confirmed: true, origin_observation: silent },
    ]) {
      const derived = deriveWafSignalsFromBoundEvents({
        probes: [{ id: 'evt_probe_silent', nonce_hash: 'sha256:silent', metadata }],
      });
      assert.equal(derived.originLockdownConfirmed, false);
      assert.equal(derived.validationPassed, false);
      assert.equal(derived.edgeProtected, true);
    }
  });

  it('keeps a direct-origin denial out of edge WAF blocks', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_origin',
        nonce_hash: 'sha256:origin',
        metadata: {
          probe_kind: 'host_sni_bypass',
          external_result: 'blocked',
          waf_fingerprint_detected: true,
          origin_observation: classifyDirectOriginObservation({ response: responseWith(403, { 'x-origin-lockdown': 'cdn-only' }), declaredLockdown: { status_code: 403, header: { name: 'x-origin-lockdown', value: 'cdn-only' } } }),
        },
      }],
    });
    assert.equal(derived.edgeProtected, false);
    assert.equal(derived.scenarioResults[0].scenario_family, 'origin_bypass');
    assert.equal(derived.scenarioResults[0].observed_action, 'deny');
    assert.equal(derived.scenarioResults[0].passed, null);
  });

  it('never counts a direct-origin response as an edge WAF marker failure', () => {
    const generic502 = classifyDirectOriginObservation({
      response: responseWith(502, { server: 'awselb/2.0' }),
      scope: { host: 'shop.example.test', path: '/' },
    });
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [
        { id: 'evt_edge', nonce_hash: 'sha256:edge', metadata: { external_result: 'blocked', waf_product_hint: 'provider_a' } },
        { id: 'evt_origin', nonce_hash: 'sha256:origin', metadata: { probe_kind: 'host_sni_bypass', external_result: 'connected', origin_observation: generic502 } },
      ],
    });
    assert.deepEqual(derived.scenarioResults.map((row) => [row.scenario_family, row.observed_action, row.passed]), [
      ['marker', 'block', true],
      ['origin_bypass', 'origin_response', null],
    ]);
    assert.equal(derived.validationFailed, false);
    assert.equal(derived.edgeProtected, true);
    assert.equal(derived.originBypassConfirmed, false);
  });

  it('confirms a direct-origin bypass only from application identity without failing edge markers', () => {
    const canary = classifyDirectOriginObservation({
      response: responseWith(200, { 'x-astranull-canary-echo': 'nonce-2' }),
      baseline: HEALTHY_BASELINE,
      expectedNonce: 'nonce-2',
    });
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{ id: 'evt_origin_bypass', nonce_hash: 'sha256:o', metadata: { profile_kind: 'host_sni_bypass', external_result: 'connected', origin_observation: canary } }],
    });
    assert.equal(derived.originBypassConfirmed, true);
    assert.equal(derived.validationFailed, false);
    assert.equal(derived.scenarioResults[0].scenario_family, 'origin_bypass');
    assert.equal(derived.scenarioResults[0].passed, false);
  });
});
