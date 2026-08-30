import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  apiErrorCode,
  isActiveDnsChallenge,
  isLoaScopeEligible,
  isSignedLoaState,
  isTargetRunEligible,
  ownershipMethodLabel,
  parseOptionalPort,
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
  it('fails run eligibility closed unless eligibility and ownership are explicitly affirmative', () => {
    assert.equal(isTargetRunEligible('eligible', 'dns_verified'), true);
    assert.equal(isTargetRunEligible('eligible', 'agent_verified'), true);
    assert.equal(isTargetRunEligible('eligible', 'pending'), false);
    assert.equal(isTargetRunEligible('unknown', 'agent_verified'), false);
    assert.equal(isTargetRunEligible('not_eligible', 'agent_verified'), false);
    assert.equal(isTargetRunEligible('', ''), false);
  });

  it('keeps LOA signed and scope states explicit', () => {
    assert.equal(isSignedLoaState('signed'), true);
    assert.equal(isSignedLoaState('active'), true);
    assert.equal(isSignedLoaState('required'), false);
    assert.equal(isLoaScopeEligible('agent_verified'), true);
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

describe('target-detail React contract', () => {
  it('uses explicit check selection and never treats catalog timestamps as target history', () => {
    assert.match(DETAIL_SOURCE, /check_id: effectiveSelectedRunCheckId/);
    assert.match(DETAIL_SOURCE, /type="radio"/);
    assert.doesNotMatch(DETAIL_SOURCE, /checks_applied\?\.\[0\]|checks_applied\[0\]/);
    assert.doesNotMatch(DETAIL_SOURCE, /Last verdict|Last ran/);
  });

  it('keeps page spacing, eligibility, links, and canonical history truthful', () => {
    assert.match(DETAIL_SOURCE, /className="content target-detail-view"/);
    assert.doesNotMatch(DETAIL_SOURCE, /className="content stack-tight"/);
    assert.match(DETAIL_SOURCE, /isTargetRunEligible\(eligibility, verificationState\)/);
    assert.match(DETAIL_SOURCE, /const eligibilityDisplay = targetEligible \? 'Eligible' : 'Locked'/);
    assert.match(DETAIL_SOURCE, /value=\{eligibilityDisplay\}/);
    assert.match(DETAIL_SOURCE, /\{eligibilityDisplay\}<\/Badge> for validation/);
    assert.doesNotMatch(DETAIL_SOURCE, /value=\{formatTargetLabel\(eligibility\)\}/);
    assert.doesNotMatch(DETAIL_SOURCE, /!eligibility\.startsWith/);
    assert.match(DETAIL_SOURCE, /event\.stopPropagation\(\)/);
    assert.match(DETAIL_SOURCE, /uniqueRecentRuns/);
    assert.match(DETAIL_SOURCE, /Recorded outcome \/ status/);
  });
});
