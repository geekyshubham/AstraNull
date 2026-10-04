import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  addTargetTag,
  apiErrorCode,
  edgeDetectionLockedReason,
  edgeDetectionReasonExplanation,
  edgeFamilyProviderSummary,
  isActiveDnsChallenge,
  isLoaScopeEligible,
  isSignedLoaState,
  isTargetRunEligible,
  normalizeTargetTag,
  ownershipMethodLabel,
  ownershipStepStatus,
  parseOptionalPort,
  removeTargetTag,
  targetDeclarationProvenanceLabel,
  targetDisplayValue,
  uniqueAppliedChecks,
  uniqueRecentRuns,
  uniqueVerificationHistory,
} from '../../apps/web/react/src/lib/target-detail.mjs';

const DETAIL_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url),
  'utf8',
);

describe('target-detail truthfulness helpers', () => {
  it('allows run eligibility for all domains', () => {
    assert.equal(isTargetRunEligible('eligible', 'dns_verified'), true);
    assert.equal(isTargetRunEligible('eligible', 'provider_verified'), true);
    assert.equal(isTargetRunEligible('eligible', 'agent_verified'), true);
    assert.equal(isTargetRunEligible('eligible', 'pending'), true);
    assert.equal(isTargetRunEligible('unknown', 'dns_verified'), true);
    assert.equal(isTargetRunEligible('not_eligible', 'dns_verified'), true);
    assert.equal(isTargetRunEligible('', ''), true);
  });

  it('keeps LOA signed and scope states explicit', () => {
    assert.equal(isSignedLoaState('signed'), true);
    assert.equal(isSignedLoaState('active'), true);
    assert.equal(isSignedLoaState('required'), false);
    assert.equal(isLoaScopeEligible('user_confirmed'), true);
    assert.equal(isLoaScopeEligible('dns_verified'), false);
  });

  it('treats only unexpired pending DNS challenges as active and exposes API conflict codes', () => {
    const now = Date.parse('2026-08-30T00:00:00.000Z');
    assert.equal(isActiveDnsChallenge({ state: 'pending', expires_at: '2026-08-30T00:01:00.000Z' }, now), true);
    assert.equal(isActiveDnsChallenge({ state: 'pending', expires_at: '2026-08-29T23:59:00.000Z' }, now), false);
    assert.equal(isActiveDnsChallenge({ state: 'pending' }, now), false);
    assert.equal(isActiveDnsChallenge({ state: 'resolved', expires_at: '2026-08-30T00:01:00.000Z' }, now), false);
    assert.equal(apiErrorCode({ status: 409, payload: { error: 'challenge_active' } }), 'challenge_active');
  });

  it('labels declaration provenance without presenting connector IDs as provider names', () => {
    assert.equal(targetDeclarationProvenanceLabel({}), 'Manual declaration');
    assert.equal(
      targetDeclarationProvenanceLabel({ source: 'import', import_integration: 'hetzner_dns' }),
      'Imported · Hetzner DNS',
    );
    assert.equal(
      targetDeclarationProvenanceLabel({ metadata: { connector_id: 'conn_123' } }),
      'Imported from connector inventory',
    );
    assert.equal(targetDeclarationProvenanceLabel({ source: 'api' }), 'Declared through API');
  });

  it('keeps IP persistence canonical while displaying validated port metadata', () => {
    assert.deepEqual(parseOptionalPort('443'), { port: '443', error: '' });
    assert.deepEqual(parseOptionalPort('00080'), { port: '80', error: '' });
    assert.match(parseOptionalPort('65536').error, /1 to 65535/);
    assert.match(parseOptionalPort('443/tcp').error, /whole number/);
    assert.equal(targetDisplayValue({ kind: 'ip', value: '203.0.113.10', metadata: { port: '443' } }), '203.0.113.10:443');
    assert.equal(targetDisplayValue({ kind: 'ip', value: '203.0.113.10', metadata: { port: '70000' } }), '203.0.113.10');
    assert.equal(targetDisplayValue({ kind: 'ip', value: '2001:db8::10', metadata: { port: '443' } }), '[2001:db8::10]:443');
  });

  it('deduplicates check, run, and verification history by canonical identity', () => {
    assert.deepEqual(
      uniqueAppliedChecks([{ check_id: 'check.a' }, { check_id: 'check.a' }, { check_id: 'check.b' }]).map((row) => row.check_id),
      ['check.a', 'check.b'],
    );
    assert.deepEqual(
      uniqueRecentRuns([{ run_id: 'run_1', status: 'running' }, { run_id: 'run_1', status: 'complete' }, { run_id: 'run_2' }]).map((row) => row.run_id),
      ['run_1', 'run_2'],
    );
    assert.equal(uniqueVerificationHistory([
      { state: 'pending', transitioned_at: '2026-01-01T00:00:00Z' },
      { transitioned_at: '2026-01-01T00:00:00Z', state: 'pending' },
      { state: 'dns_verified', transitioned_at: '2026-01-02T00:00:00Z' },
    ]).length, 2);
  });

  it('derives ownership method only from reported evidence', () => {
    assert.equal(ownershipMethodLabel({ state: 'dns_verified', source_kind: 'dns_txt' }), 'DNS TXT record');
    assert.equal(ownershipMethodLabel({ state: 'agent_verified', source_kind: 'agent_observation' }), 'Agent observation');
    assert.equal(ownershipMethodLabel({ state: 'agent_verified' }), 'Ownership method not reported');
    assert.equal(ownershipMethodLabel({ state: 'unverified' }), 'No ownership proof recorded');
  });
});

describe('target-detail edge presentation helpers', () => {
  it('labels non-asserted providers coherently instead of hiding the asserted one as none reported', () => {
    assert.deepEqual(edgeFamilyProviderSummary('cloudflare', ['cloudflare']), { label: 'Other providers', value: 'None' });
    assert.deepEqual(edgeFamilyProviderSummary('cloudflare', ['cloudflare', 'fastly']), { label: 'Other providers', value: 'fastly' });
    assert.deepEqual(edgeFamilyProviderSummary('', ['akamai', 'fastly']), { label: 'Reported providers', value: 'akamai, fastly' });
    assert.deepEqual(edgeFamilyProviderSummary('', []), { label: 'Reported providers', value: 'None reported' });
  });

  it('explains simulation-mode edge results with the signed-worker runbook pointer', () => {
    assert.match(edgeDetectionReasonExplanation('simulation_not_detection'), /Simulation mode/);
    assert.match(edgeDetectionReasonExplanation('simulation_not_detection'), /operator-local-runbook\.md "Real probe results locally"/);
    assert.equal(edgeDetectionReasonExplanation('made_up_reason'), '');
    assert.equal(edgeDetectionReasonExplanation(''), '');
  });

  it('explains why Detect edge is locked using the reported ownership state', () => {
    assert.match(edgeDetectionLockedReason('pending'), /ownership is pending/);
    assert.match(edgeDetectionLockedReason(''), /ownership is unverified/);
  });
});

describe('target-detail tag + ownership-step helpers', () => {
  it('normalizes tags to the ADR-0008 server rule and rejects invalid input', () => {
    assert.equal(normalizeTargetTag('  Env:Prod '), 'env:prod');
    assert.equal(normalizeTargetTag('tier-1_edge.v2'), 'tier-1_edge.v2');
    assert.equal(normalizeTargetTag('has space'), '');
    assert.equal(normalizeTargetTag('-leadingdash'), '');
    assert.equal(normalizeTargetTag('a'.repeat(49)), '');
  });

  it('adds and removes tags with dedupe, cap, and error messages', () => {
    assert.deepEqual(addTargetTag(['env:prod'], 'team:edge'), { tags: ['env:prod', 'team:edge'], error: '' });
    assert.deepEqual(addTargetTag(['env:prod'], 'env:prod'), { tags: ['env:prod'], error: '' });
    assert.match(addTargetTag([], 'bad tag').error, /lowercase/);
    const sixteen = Array.from({ length: 16 }, (_, i) => `t${i}`);
    assert.match(addTargetTag(sixteen, 't99').error, /at most 16/);
    assert.deepEqual(removeTargetTag(['env:prod', 'team:edge'], 'env:prod'), ['team:edge']);
  });

  it('derives the ownership step state only from verification + challenge, never inventing it', () => {
    assert.deepEqual(ownershipStepStatus('dns_verified', null), { tone: 'success', label: 'Ownership proven', done: true });
    assert.deepEqual(ownershipStepStatus('provider_verified', null), { tone: 'success', label: 'Ownership proven', done: true });
    // ADR-0008: a legacy `agent_verified` state is not proof of control and stays unproven.
    assert.deepEqual(ownershipStepStatus('agent_verified', null), { tone: 'warn', label: 'Not proven yet', done: false });
    assert.equal(ownershipStepStatus('unverified', { state: 'pending' }).label, 'Waiting on DNS record');
    assert.equal(ownershipStepStatus('unverified', { state: 'expired' }).done, false);
    assert.equal(ownershipStepStatus('unverified', null).label, 'Not proven yet');
  });
});

describe('target-detail React contract', () => {
  it('leads with a stateful validation path and explicit check selection', () => {
    const queue = readFileSync(new URL('../../apps/web/react/src/components/targets/domain-protection.tsx', import.meta.url), 'utf8');
    assert.match(DETAIL_SOURCE, /Validate this target/);
    assert.match(DETAIL_SOURCE, /check_id: effectiveSelectedCheckId/);
    // Selection is one explicit radio per check in the shared check queue; starting needs a review.
    assert.match(queue, /type="radio"/);
    assert.match(DETAIL_SOURCE, /setReview\(\{ mode: 'single', checkId: effectiveSelectedCheckId \}\)/);
    assert.doesNotMatch(DETAIL_SOURCE, /checks_applied\?\.\[0\]|checks_applied\[0\]/);
    assert.doesNotMatch(DETAIL_SOURCE, /shouldAutoDetectEdge/, 'opening a target never starts a probe');
  });

  it('removes all agent / placement language now that verdicts are external-probe only', () => {
    assert.doesNotMatch(DETAIL_SOURCE, /agent_binding|agentBinding|Agent binding|Observed from inside|Agent observation recorded/);
    assert.doesNotMatch(DETAIL_SOURCE, /environment_id|Environment<\/td>/);
  });

  it('surfaces the exact DNS TXT ownership record with copy and check-now actions', () => {
    assert.match(DETAIL_SOURCE, /record_name/);
    assert.match(DETAIL_SOURCE, /record_value/);
    assert.match(DETAIL_SOURCE, /Check now/);
    assert.match(DETAIL_SOURCE, /CopyButton/);
    assert.match(DETAIL_SOURCE, /issueOwnershipChallenge|issueOwnership/);
  });

  it('keeps run eligibility fail-closed and the run action disabled until ownership passes', () => {
    assert.match(DETAIL_SOURCE, /isTargetRunEligible\(eligibility, verificationState\)/);
    assert.match(DETAIL_SOURCE, /disabled=\{!targetEligible \|\| !effectiveSelectedCheckId/);
    assert.match(DETAIL_SOURCE, /className="content target-detail-view"/);
  });

  it('backs recent-run verdicts with API evidence ids and groups posture under tabs', () => {
    assert.doesNotMatch(DETAIL_SOURCE, /hasEvidenceBackedVerdict\(item, \[\]\)/);
    assert.match(DETAIL_SOURCE, /evidence_ids: run\.evidence_ids/);
    assert.match(DETAIL_SOURCE, /<Tabs/);
    // Unified target tabs; legacy Protection path / edge / runs links resolve through targetTabFromParam.
    for (const label of ['Overview', 'Validate', 'Findings', 'Changes & history']) {
      assert.match(DETAIL_SOURCE, new RegExp(`label: '${label}'`));
    }
    assert.match(DETAIL_SOURCE, /targetTabFromParam\(getRouteParam\('tab'\)\)/);
    assert.match(DETAIL_SOURCE, /edgeDetectionReasonExplanation/);
    assert.doesNotMatch(DETAIL_SOURCE, /buildDetailHref\('run-detail'|buildDetailHref\('scan-detail'/, 'results open in place, not a run page');
  });
});
