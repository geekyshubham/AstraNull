import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { deriveWafSignalsFromBoundEvents } from '../../src/lib/wafBoundRunCorrelation.mjs';
import {
  EVENT_PRODUCER_KINDS,
  isTrustedProducerEvent,
} from '../../src/lib/trustedEventProvenance.mjs';

describe('trusted event producer provenance', () => {
  it('rejects legacy/public reserved signals and accepts only their authenticated paths', () => {
    assert.equal(isTrustedProducerEvent({
      signal_type: 'probe_result',
      producer_kind: EVENT_PRODUCER_KINDS.LEGACY_UNTRUSTED,
    }), false);
    assert.equal(isTrustedProducerEvent({
      signal_type: 'probe_result',
      producer_kind: EVENT_PRODUCER_KINDS.PUBLIC_API,
    }), false);
    assert.equal(isTrustedProducerEvent({
      signal_type: 'probe_result',
      producer_kind: EVENT_PRODUCER_KINDS.SIGNED_PROBE,
    }), true);
    assert.equal(isTrustedProducerEvent({
      signal_type: 'ownership_observation',
      producer_kind: EVENT_PRODUCER_KINDS.LEGACY_UNTRUSTED,
    }), false);
    assert.equal(isTrustedProducerEvent({
      signal_type: 'ownership_observation',
      producer_kind: EVENT_PRODUCER_KINDS.SIGNED_PROBE,
    }), true);
    // ADR-0008: agents are removed, so ownership observations are no longer trusted from
    // any authenticated agent — only from signed probes.
    assert.equal(isTrustedProducerEvent({
      signal_type: 'ownership_observation',
      producer_kind: 'authenticated_agent',
    }), false);
  });

  it('does not derive WAF detection or protection from pre-upgrade forged signals', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_legacy_probe',
        signal_type: 'probe_result',
        producer_kind: 'legacy_untrusted',
        nonce_hash: 'nonce_1',
        metadata: { external_result: 'blocked', waf_fingerprint_detected: true },
      }],
    });

    assert.equal(derived.wafDetected, false);
    assert.equal(derived.validationPassed, false);
    assert.equal(derived.edgeProtected, false);
    assert.equal(derived.source_external, false);
    assert.deepEqual(derived.scenarioResults, []);
  });
});
