import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildVerdictExplanationFields,
  normalizeVerdictKey,
  resolveRemediationTemplate,
  summarizeExternalProbeEvidence,
  summarizeObservationMode,
  summarizePlacementConfidence,
  trafficHopState,
} from '../../apps/web/react/src/lib/verdict-explanation.ts';

describe('verdict-explanation (React portal)', () => {
  it('summarizeExternalProbeEvidence reads external_result from metadata', () => {
    const summary = summarizeExternalProbeEvidence([
      {
        signal_type: 'probe_result',
        timestamp: '2026-01-01T00:00:00Z',
        metadata: { external_result: 'tcp_connect_ok' },
      },
    ]);
    assert.match(summary, /external_result tcp_connect_ok/);
  });

  it('buildVerdictExplanationFields prefers backend placement_confidence', () => {
    const fields = buildVerdictExplanationFields(
      {
        remediation_template: 'Fix edge path.',
        verdict: {
          verdict: 'bypassable',
          confidence: 'high',
          explanation: 'Marker reached origin.',
          placement_confidence: { level: 'high', observation_mode: 'packet_metadata' },
        },
        correlation: { nonce_hash: 'n1' },
      },
      [
        { signal_type: 'probe_result', metadata: { external_result: 'ok' } },
        { signal_type: 'agent_observation', nonce_hash: 'n1', agent_id: 'ag_1' },
      ],
    );

    const labels = fields.map((field) => field.label);
    assert.deepEqual(labels, [
      'External probe evidence',
      'Internal agent evidence',
      'Observation mode',
      'Placement confidence',
      'Conclusion',
      'Remediation',
    ]);
    const placement = fields.find((field) => field.label === 'Placement confidence');
    assert.match(placement?.value ?? '', /high/);
    assert.match(placement?.value ?? '', /packet_metadata/);
    const conclusion = fields.find((field) => field.label === 'Conclusion');
    assert.match(conclusion?.value ?? '', /bypassable/);
    const remediation = fields.find((field) => field.label === 'Remediation');
    assert.equal(remediation?.value, 'Fix edge path.');
  });

  it('buildVerdictExplanationFields returns empty array without verdict payload', () => {
    assert.deepEqual(buildVerdictExplanationFields({}, []), []);
    assert.deepEqual(buildVerdictExplanationFields(null, []), []);
  });

  it('summarizePlacementConfidence falls back when backend placement is absent', () => {
    const supported = summarizePlacementConfidence(
      [{ signal_type: 'agent_observation', nonce_hash: 'n1' }],
      [],
      undefined,
    );
    assert.match(supported, /supported by job-bound agent observation/);

    const limited = summarizePlacementConfidence(
      [],
      [{ signal_type: 'agent_no_observation' }],
      undefined,
    );
    assert.match(limited, /limited/);
  });

  it('normalizeVerdictKey and trafficHopState support visualization helpers', () => {
    assert.equal(normalizeVerdictKey('misplaced_agent'), 'misplaced');
    assert.equal(trafficHopState('origin', 'bypassable'), 'danger');
    assert.equal(trafficHopState('edge', 'protected'), 'ok');
  });

  it('summarizeObservationMode uses agent_no_observation metadata reason', () => {
    const summary = summarizeObservationMode([
      {
        signal_type: 'agent_no_observation',
        metadata: { reason: 'bounded_observation_window_elapsed' },
      },
    ]);
    assert.match(summary, /bounded_observation_window_elapsed/);
    assert.doesNotMatch(summary, /^agent_no_observation$/);
  });

  it('resolveRemediationTemplate expands waf_posture_remediation from finding and run evidence', () => {
    const guidance = resolveRemediationTemplate('waf_posture_remediation', {
      finding: {
        title: 'WAF posture unprotected: http://34.28.182.129/',
        notes: 'Posture status: unprotected. Reason codes: insufficient_validation_evidence.',
      },
      detail: {
        verdict: {
          placement_confidence: {
            level: 'invalid',
            observation_mode: 'unbound',
            reason: 'No agent is bound to this target group; internal path proof is unavailable.',
          },
        },
      },
      events: [
        {
          signal_type: 'probe_result',
          metadata: { external_result: 'error' },
        },
        {
          signal_type: 'agent_no_observation',
          metadata: { reason: 'bounded_observation_window_elapsed' },
        },
      ],
    });
    assert.match(guidance, /Enable WAF coverage/);
    assert.match(guidance, /reachable from external probes/);
    assert.match(guidance, /Bind an outbound agent/);
    assert.doesNotMatch(guidance, /waf_posture_remediation/);
  });

  it('buildVerdictExplanationFields resolves known remediation template keys for findings', () => {
    const fields = buildVerdictExplanationFields(
      {
        remediation_template: 'waf_posture_remediation',
        verdict: {
          verdict: 'inconclusive',
          confidence: 'low',
          explanation: 'Agent is offline or not bound to the target group; internal observation evidence is unavailable.',
          placement_confidence: {
            level: 'invalid',
            observation_mode: 'unbound',
            reason: 'No agent is bound to this target group; internal path proof is unavailable.',
          },
        },
      },
      [
        { signal_type: 'probe_result', metadata: { external_result: 'error' } },
        { signal_type: 'agent_no_observation', metadata: { reason: 'bounded_observation_window_elapsed' } },
      ],
      {
        finding: {
          title: 'WAF posture unprotected: http://34.28.182.129/',
          remediation_template: 'waf_posture_remediation',
        },
      },
    );

    const remediation = fields.find((field) => field.label === 'Remediation');
    assert.match(remediation?.value ?? '', /Bind an outbound agent/);
    assert.doesNotMatch(remediation?.value ?? '', /waf_posture_remediation/);

    const observationMode = fields.find((field) => field.label === 'Observation mode');
    assert.match(observationMode?.value ?? '', /bounded_observation_window_elapsed/);
  });
});