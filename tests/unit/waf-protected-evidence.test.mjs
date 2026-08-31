import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildCorroborationFromEvents,
  buildWafEvidenceCorroboration,
  corroborateEdgeProtectedScenarioEvidence,
  corroborateProtectedScenarioEvidence,
  protectedFinalizeEvidenceRequired,
  stripClientAssertedAgentEvidence,
} from '../../src/lib/wafProtectedEvidence.mjs';

describe('waf protected evidence corroboration', () => {
  it('strips client-asserted observed_at_agent from evidence summaries', () => {
    assert.deepEqual(
      stripClientAssertedAgentEvidence({ nonce_hash: 'abc', observed_at_agent: true, blocked: true }),
      { nonce_hash: 'abc', blocked: true },
    );
  });

  it('classifies a bound external block as edge-only without agent corroboration', () => {
    const corroboration = buildWafEvidenceCorroboration({
      probes: [{
        id: 'evt_probe_1',
        nonce_hash: 'nonce_1',
        metadata: {
          external_result: 'blocked',
          waf_fingerprint_detected: true,
        },
      }],
      agents: [],
    });
    const scenario = {
      passed: true,
      evidence_summary_json: { nonce_hash: 'nonce_1', request_id: 'evt_probe_1' },
    };
    assert.equal(corroborateProtectedScenarioEvidence(scenario, corroboration), false);
    assert.equal(corroborateEdgeProtectedScenarioEvidence(scenario, corroboration), true);
    const gate = protectedFinalizeEvidenceRequired({
      validationPassed: true,
      normalizedScenarios: [scenario],
      corroboration,
    });
    assert.equal(gate?.downgrade_to_edge_protected, true);
  });

  it('accepts protected only with matching agent blocked or not-reached-origin evidence', () => {
    const scenario = {
      passed: true,
      evidence_summary_json: { nonce_hash: 'nonce_1', request_id: 'evt_probe_1' },
    };
    const corroboration = buildWafEvidenceCorroboration({
      probes: [{
        id: 'evt_probe_1',
        nonce_hash: 'nonce_1',
        metadata: { external_result: 'blocked', waf_fingerprint_detected: true },
      }],
      agents: [{
        id: 'evt_agent_1',
        nonce_hash: 'nonce_1',
        metadata: { waf_marker: true, observed_action: 'not_reached_origin' },
      }],
    });
    assert.equal(corroborateProtectedScenarioEvidence(scenario, corroboration), true);
    assert.equal(protectedFinalizeEvidenceRequired({
      validationPassed: true,
      normalizedScenarios: [scenario],
      corroboration,
    }), null);
  });

  it('rejects self-asserted agent observation without stored agent events', () => {
    const corroboration = buildWafEvidenceCorroboration({ probes: [], agents: [] });
    const scenario = {
      passed: true,
      evidence_summary_json: { nonce_hash: 'nonce_1', observed_at_agent: true },
    };
    assert.equal(corroborateProtectedScenarioEvidence(scenario, corroboration), false);
    const gate = protectedFinalizeEvidenceRequired({
      validationPassed: true,
      normalizedScenarios: [scenario],
      corroboration,
    });
    assert.equal(gate?.error, 'waf_validation_evidence_required');
  });

  it('rejects stored agent marker block without qualifying external probe evidence', () => {
    const corroboration = buildWafEvidenceCorroboration({
      probes: [],
      agents: [{
        id: 'evt_agent_1',
        nonce_hash: 'nonce_1',
        metadata: {
          waf_marker: true,
          observed_action: 'block',
          waf_blocked: true,
        },
      }],
    });
    const scenario = {
      passed: true,
      evidence_summary_json: { nonce_hash: 'nonce_1' },
    };
    assert.equal(corroborateProtectedScenarioEvidence(scenario, corroboration), false);
    const gate = protectedFinalizeEvidenceRequired({
      validationPassed: true,
      normalizedScenarios: [scenario],
      corroboration,
    });
    assert.equal(gate?.error, 'waf_validation_evidence_required');
  });

  it('buildCorroborationFromEvents scopes to bound test run events', () => {
    const corroboration = buildCorroborationFromEvents(
      [
        {
          test_run_id: 'run_a',
          signal_type: 'probe_result',
          nonce_hash: 'nonce_a',
          id: 'evt_a',
          metadata: { external_result: 'blocked', waf_fingerprint_detected: true },
        },
        {
          test_run_id: 'run_b',
          signal_type: 'probe_result',
          nonce_hash: 'nonce_b',
          id: 'evt_b',
          metadata: { external_result: 'blocked', waf_fingerprint_detected: true },
        },
      ],
      'run_a',
      [{ evidence_summary_json: { nonce_hash: 'nonce_a' } }],
    );
    assert.equal(corroboration.probesByNonce.has('nonce_a'), true);
    assert.equal(corroboration.probesByNonce.has('nonce_b'), false);
  });

  it('does not corroborate unbound scenarios by nonce across same-tenant events', () => {
    const corroboration = buildCorroborationFromEvents(
      [{
        test_run_id: 'run_other_target',
        signal_type: 'probe_result',
        nonce_hash: 'shared_nonce',
        id: 'evt_other_target',
        metadata: { external_result: 'blocked', waf_fingerprint_detected: true },
      }],
      null,
      [{ evidence_summary_json: { nonce_hash: 'shared_nonce' } }],
    );

    assert.equal(corroboration.probesByNonce.size, 0);
    assert.equal(corroboration.agentsByNonce.size, 0);
  });
});
