import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { addWafNfwDemoEvidence } from '../../scripts/seed-dev-portal-demo.mjs';
import { buildVerdictReplay, rederiveVerdict } from '../../src/lib/verdictReplay.mjs';
import { WAF_GRADING_VERSION, SIGNATURE_CORPUS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';
import { addAssuredObservation, assuranceWorld } from '../helpers/assurance-fixtures.mjs';

function demoReplayInput(index) {
  const ids = { tenantId: 'ten_replay', targetGroupId: 'grp_replay', targetId: 'tgt_replay', frozenAt: '2026-10-08T12:00:00.000Z' };
  const store = addWafNfwDemoEvidence({ targets: [{ id: ids.targetId, tenant_id: ids.tenantId, kind: 'fqdn', value: 'replay.example.test' }] }, ids);
  return {
    run: store.testRuns.find((row) => row.id === `run_wafnfw_${index}`),
    storedVerdict: store.verdicts.find((row) => row.test_run_id === `run_wafnfw_${index}`),
    probeEvent: store.events.find((row) => row.test_run_id === `run_wafnfw_${index}`),
    declarations: store.targets[0].metadata.control_declarations,
  };
}

function assertCurrentCorrelation(input, reason) {
  const before = structuredClone(input);
  const replay = buildVerdictReplay(input);
  assert.equal(replay.stored.verdict, input.storedVerdict.verdict);
  assert.equal(replay.rederived.verdict, 'inconclusive');
  assert.match(replay.rederived.explanation, reason);
  assert.equal(replay.rederived.creates_finding, false);
  assert.equal(replay.rederived.severity, null);
  assert.equal(replay.changed, true);
  const record = {
    check_id: input.run.check_id,
    metadata: input.probeEvent.metadata,
    verdict: input.storedVerdict.verdict,
    grading_version: input.storedVerdict.grading_version,
    signature_corpus_version: input.storedVerdict.signature_corpus_version,
  };
  const recordBefore = structuredClone(record);
  const rederived = rederiveVerdict(record);
  assert.equal(rederived.derived.verdict, 'inconclusive');
  assert.match(rederived.derived.explanation, reason);
  assert.equal(rederived.derived.createsFinding, false);
  assert.equal(rederived.matches, false);
  assert.deepEqual(record, recordBefore);
  assert.deepEqual(input, before, 'replay must not rewrite stored verdicts, evidence, runs or declarations');
  return replay;
}

describe('Replay projection preserves current correlation gates', () => {
  it('old demo CRLF features cannot restore a Gap found verdict without attested I/O', () => {
    const replay = assertCurrentCorrelation(demoReplayInput(7), /no attested probe I\/O/);
    assert.equal(replay.regraded, false);
    assert.equal(replay.regrade_unavailable_reason, 'insufficient_features');
    assert.equal(replay.retest_required, true);
  });

  it('old features cannot restore a custom-token enforcement conclusion even with attested I/O', () => {
    const input = demoReplayInput(7);
    input.probeEvent.metadata.safety_attestation = { probe_requests_sent: 5 };
    const replay = assertCurrentCorrelation(input, /inert-token observation only/);
    assert.equal(replay.regraded, false);
    assert.equal(replay.regrade_unavailable_reason, 'insufficient_features');
  });

  it('previous-corpus demo without response features downgrades only the projected Protected verdict', () => {
    const replay = assertCurrentCorrelation(demoReplayInput(12), /no attested probe I\/O/);
    assert.equal(replay.regraded, false);
    assert.equal(replay.regrade_unavailable_reason, 'missing_response_features');
    assert.equal(replay.grading_version_gap, 'grading_version_mismatch');
  });

  it('old managed-rule features without attested I/O do not preserve protection either', () => {
    const input = demoReplayInput(7);
    input.run.check_id = 'waf.sqli_managed_marker.safe';
    input.probeEvent.metadata.assurance_scope = 'managed_rule_marker';
    input.storedVerdict.verdict = 'protected';
    assertCurrentCorrelation(input, /no attested probe I\/O/);
  });

  it('insufficient old features reapply correlation to original outcomes without mixing verdict and explanation', () => {
    const metadata = {
      ...addAssuredObservation(assuranceWorld()).event.metadata,
      assurance_scope: 'managed_rule_marker',
      probe_kind: 'waf_class_marker_probe',
      grading_version: WAF_GRADING_VERSION,
      signature_corpus_version: SIGNATURE_CORPUS_VERSION,
      safety_attestation: { probe_requests_sent: 3 },
      planned_marker_legs: 1,
      attempted_marker_legs: 1,
      completed_marker_legs: 1,
      graded_marker_legs: 1,
      baseline: { status_code: 200, header_subset: {} },
      placements: [{ placement: 'query', outcome: 'blocked', status_code: 403, signature_id: 'old_body_signature' }],
      enforcement: 'enforced',
      external_result: 'blocked',
      response_features: [{ placement: 'header', status_code: 403, header_subset: {} }],
    };
    const input = {
      run: { id: 'run_old_managed', check_id: 'waf.sqli_managed_marker.safe' },
      storedVerdict: { verdict: 'protected' },
      probeEvent: { metadata },
    };
    const before = structuredClone(input);
    const replay = buildVerdictReplay(input);
    assert.equal(replay.regraded, false);
    assert.equal(replay.regrade_unavailable_reason, 'insufficient_features');
    assert.equal(replay.rederived.verdict, 'protected');
    assert.equal(replay.changed, false);
    assert.match(replay.rederived.explanation, /enforced/);
    assert.deepEqual(replay.placements, metadata.placements, 'logic-only replay must expose the original outcomes, not discarded re-grades');
    const record = { check_id: input.run.check_id, metadata, verdict: 'protected' };
    const result = rederiveVerdict(record);
    assert.equal(result.derived.verdict, 'protected');
    assert.equal(result.matches, true);
    assert.match(result.derived.explanation, /enforced/);
    assert.deepEqual(input, before);
  });
});
