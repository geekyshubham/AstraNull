import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  containsAgentPlacementVocabulary,
  scrubAgentPlacementText,
  scrubPlacementConfidenceForCustomer,
  scrubVerdictForCustomer,
} from '../../src/lib/outsideInEvidence.mjs';

describe('outside-in evidence scrubbing (EVIDENCE-01 / ADR-0008)', () => {
  it('rewrites the agent-observed-traffic explanation to external-probe wording', () => {
    const original =
      'External response indicated block/timeout but the agent observed traffic — possible penetration with silent drop downstream.';
    const scrubbed = scrubAgentPlacementText(original);
    assert.ok(!containsAgentPlacementVocabulary(scrubbed), `still has agent/placement: ${scrubbed}`);
    assert.match(scrubbed, /external probe recorded traffic reaching the declared path/);
    assert.match(scrubbed, /possible penetration with silent drop downstream/);
  });

  it('rewrites the agent-placement remediation copy without leaving a dangling conjunction', () => {
    const scrubbed = scrubAgentPlacementText('Review edge protection and agent placement for this vector.');
    assert.ok(!containsAgentPlacementVocabulary(scrubbed));
    assert.equal(scrubbed, 'Review edge protection for this vector.');
  });

  it('rewrites a "Bound online agent" placement reason', () => {
    const scrubbed = scrubAgentPlacementText(
      'Bound online agent reported unknown observation; path evidence is broader than host-level.',
    );
    assert.ok(!containsAgentPlacementVocabulary(scrubbed));
    assert.match(scrubbed, /^External probe reported unknown observation/);
  });

  it('strips agent identifiers and scrubs the reason from placement_confidence', () => {
    const scrubbed = scrubPlacementConfidenceForCustomer({
      level: 'Medium',
      reason: 'Bound online agent reported unknown observation; path evidence is broader than host-level.',
      status: 'observed_this_run',
      agent_id: 'agt_e563ad3b5baa04fd',
      observation_mode: 'unknown',
      evidence_event_id: 'evt_69904bb30d1df772',
    });
    assert.equal('agent_id' in scrubbed, false, 'agent_id must be dropped');
    assert.equal('observation_mode' in scrubbed, false, 'observation_mode must be dropped');
    // Non-agent fields are preserved verbatim.
    assert.equal(scrubbed.level, 'Medium');
    assert.equal(scrubbed.status, 'observed_this_run');
    assert.equal(scrubbed.evidence_event_id, 'evt_69904bb30d1df772');
    assert.ok(!containsAgentPlacementVocabulary(scrubbed.reason));
  });

  it('null placement_confidence passes through as null', () => {
    assert.equal(scrubPlacementConfidenceForCustomer(null), null);
    assert.equal(scrubPlacementConfidenceForCustomer(undefined), null);
  });

  it('scrubVerdictForCustomer rewrites explanation and nested placement without mutating the input', () => {
    const stored = {
      test_run_id: 'run_1',
      verdict: 'penetrated',
      confidence: 'high',
      explanation: 'External response indicated block/timeout but the agent observed traffic.',
      placement_confidence: { level: 'Medium', reason: 'Bound online agent reported unknown observation.', agent_id: 'agt_x' },
      evidence_ids: ['evt_1'],
    };
    const out = scrubVerdictForCustomer(stored);
    // Output is clean.
    assert.ok(!containsAgentPlacementVocabulary(out.explanation));
    assert.equal('agent_id' in out.placement_confidence, false);
    assert.ok(!containsAgentPlacementVocabulary(out.placement_confidence.reason));
    // Verdict/confidence/evidence are never fabricated or altered.
    assert.equal(out.verdict, 'penetrated');
    assert.equal(out.confidence, 'high');
    assert.deepEqual(out.evidence_ids, ['evt_1']);
    // The stored record is untouched (internal/historical evidence preserved).
    assert.match(stored.explanation, /the agent observed traffic/);
    assert.equal(stored.placement_confidence.agent_id, 'agt_x');
  });

  it('leaves already-external-only wording unchanged', () => {
    const clean = 'External probe reached the declared path; the edge did not block traffic before origin.';
    assert.equal(scrubAgentPlacementText(clean), clean);
  });
});
