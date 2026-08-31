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
      signal_type: 'agent_observation',
      producer_kind: EVENT_PRODUCER_KINDS.AUTHENTICATED_AGENT,
    }), true);
    assert.equal(isTrustedProducerEvent({
      signal_type: 'ownership_observation',
      producer_kind: EVENT_PRODUCER_KINDS.LEGACY_UNTRUSTED,
    }), false);
    assert.equal(isTrustedProducerEvent({
      signal_type: 'ownership_observation',
      producer_kind: EVENT_PRODUCER_KINDS.SIGNED_PROBE,
    }), true);
    assert.equal(isTrustedProducerEvent({
      signal_type: 'agent_no_observation',
      producer_kind: EVENT_PRODUCER_KINDS.AUTHENTICATED_AGENT,
    }), false);
    assert.equal(isTrustedProducerEvent({
      signal_type: 'agent_no_observation',
      producer_kind: EVENT_PRODUCER_KINDS.INTERNAL_CONTROL_PLANE,
    }), true);
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
      agents: [{
        id: 'evt_legacy_agent',
        signal_type: 'agent_observation',
        producer_kind: 'legacy_untrusted',
        nonce_hash: 'nonce_1',
        metadata: { waf_marker: true, observed_action: 'not_reached_origin' },
      }],
    });

    assert.equal(derived.wafDetected, false);
    assert.equal(derived.validationPassed, false);
    assert.equal(derived.edgeProtected, false);
    assert.equal(derived.source_external, false);
    assert.equal(derived.source_agent, false);
    assert.deepEqual(derived.scenarioResults, []);
  });
});
