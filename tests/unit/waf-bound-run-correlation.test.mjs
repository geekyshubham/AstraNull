import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { deriveWafSignalsFromBoundEvents } from '../../src/lib/wafBoundRunCorrelation.mjs';

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
        },
      }],
    });
    assert.equal(derived.validationPassed, true);
    assert.equal(derived.edgeProtected, true);
    assert.equal(derived.originLockdownConfirmed, true);
    assert.equal(derived.validationFailed, false);
    assert.equal(derived.scenarioResults[0].evidence_summary.origin_lockdown_confirmed, true);
  });

  it('marks origin bypass confirmed when an external probe reached the origin', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_bypass',
        nonce_hash: 'sha256:reached',
        metadata: { external_result: 'reached_origin', origin_bypass_confirmed: true },
      }],
    });
    assert.equal(derived.originBypassConfirmed, true);
    assert.equal(derived.validationFailed, true);
  });
});
