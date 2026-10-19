import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer as createViteServer } from 'vite';
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
const OWNERSHIP_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/components/targets/ownership-proof.tsx', import.meta.url),
  'utf8',
);
const QUEUE_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/components/targets/domain-protection.tsx', import.meta.url),
  'utf8',
);

describe('target-detail truthfulness helpers', () => {
  it('fails closed: only proven ownership unlocks checks, whatever the reported eligibility string says', () => {
    for (const state of ['dns_verified', 'provider_verified', 'user_confirmed', 'verified', ' DNS_VERIFIED ']) {
      for (const eligibility of ['eligible', 'unknown', 'not_eligible', '']) {
        assert.equal(isTargetRunEligible(eligibility, state), true, `${eligibility}/${state}`);
      }
    }
    for (const state of ['pending', 'agent_verified', 'unverified', '', null, undefined]) {
      assert.equal(isTargetRunEligible('eligible', state), false, `eligible/${state}`);
    }
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
    assert.equal(ownershipStepStatus('unverified', null).label, 'Not proven yet');
  });

  it('separates a live DNS challenge from one that silently expired', () => {
    const now = Date.parse('2026-08-30T00:00:00.000Z');
    const live = { state: 'pending', expires_at: '2026-08-30T00:10:00.000Z' };
    const lapsed = { state: 'pending', expires_at: '2026-08-29T23:59:00.000Z' };
    const expired = { tone: 'warn', label: 'Challenge expired — issue a new one', done: false };
    assert.deepEqual(ownershipStepStatus('unverified', live, now), { tone: 'info', label: 'Waiting on DNS record', done: false });
    assert.deepEqual(ownershipStepStatus('unverified', lapsed, now), expired);
    assert.deepEqual(ownershipStepStatus('unverified', { state: 'pending' }, now), expired, 'a missing expiry fails closed');
    assert.deepEqual(ownershipStepStatus('unverified', { state: 'expired', expires_at: '2026-08-30T00:10:00.000Z' }, now), expired);
    assert.equal(ownershipStepStatus('dns_verified', lapsed, now).done, true);
  });
});

describe('target-detail React contract', () => {
  it('leads with a stateful validation path and explicit check selection', () => {
    assert.match(DETAIL_SOURCE, /aria-label="Start the selected check"/);
    assert.match(DETAIL_SOURCE, /review\.checkId !== startCheckId/);
    assert.match(DETAIL_SOURCE, /const reviewedCheckId = review\.checkId/);
    assert.match(DETAIL_SOURCE, /body: \{ target_id: entityId, check_id: reviewedCheckId \}/);
    assert.match(DETAIL_SOURCE, /const created = asDataItem\(accepted\.run\) \?\? accepted/);
    assert.match(DETAIL_SOURCE, /test_run_id: runId/);
    assert.match(DETAIL_SOURCE, /record: created/);
    // Expanding a row inspects it; a separate checkbox includes it in a run. Starting needs a review.
    assert.match(QUEUE_SOURCE, /type="checkbox"/);
    assert.match(QUEUE_SOURCE, /aria-label=\{`Include \$\{row\.name\} in run`\}/);
    assert.doesNotMatch(QUEUE_SOURCE, /type="radio"/);
    assert.match(DETAIL_SOURCE, /\{ mode: 'selected', checkIds: selectedRunIds \} : \{ mode: 'single', checkId: startCheckId \}/);
    assert.match(DETAIL_SOURCE, /body: \{ target_id: entityId, check_ids: checkIds, name: name\.slice\(0, 120\) \}/);
    assert.match(DETAIL_SOURCE, /\.slice\(0, MAX_SCAN_CHECKS\)/);
    assert.doesNotMatch(DETAIL_SOURCE, /checks_applied\?\.\[0\]|checks_applied\[0\]/);
    assert.doesNotMatch(DETAIL_SOURCE, /shouldAutoDetectEdge/, 'opening a target never starts a probe');
  });

  it('removes all agent / placement language now that verdicts are external-probe only', () => {
    assert.doesNotMatch(DETAIL_SOURCE, /agent_binding|agentBinding|Agent binding|Observed from inside|Agent observation recorded/);
    assert.doesNotMatch(DETAIL_SOURCE, /environment_id|Environment<\/td>/);
  });

  it('surfaces the exact DNS TXT ownership record with copy and check-now actions', () => {
    assert.match(OWNERSHIP_SOURCE, /record_name/);
    assert.match(OWNERSHIP_SOURCE, /record_value/);
    assert.match(OWNERSHIP_SOURCE, /Check now/);
    assert.match(OWNERSHIP_SOURCE, /CopyButton/);
    assert.match(OWNERSHIP_SOURCE, /Copy instructions/);
    assert.match(DETAIL_SOURCE, /<OwnershipProof/);
    assert.match(DETAIL_SOURCE, /issueOwnershipChallenge|issueOwnership/);
  });

  it('keeps ownership errors persistent in the panel and re-checks only a live challenge', () => {
    assert.match(DETAIL_SOURCE, /setOwnershipError\(apiErrorMessage\(err, 'Could not issue a DNS TXT record\.'\)\)/);
    assert.match(DETAIL_SOURCE, /setOwnershipError\(apiErrorMessage\(err, 'Could not check the DNS record\.'\)\)/);
    assert.doesNotMatch(DETAIL_SOURCE, /Could not issue an ownership challenge/);
    assert.match(DETAIL_SOURCE, /apiErrorCode\(err\) === 'challenge_expired'/);
    assert.match(DETAIL_SOURCE, /!isActiveDnsChallenge\(challenge, Date\.now\(\)\)\) return undefined/);
    assert.match(OWNERSHIP_SOURCE, /<div className="form-banner" role="alert">\{error\}<\/div>/);
    assert.match(OWNERSHIP_SOURCE, /Stopped re-checking\. Choose Check now after your DNS change is live\./);
  });

  it('keeps run eligibility fail-closed and the run action disabled until ownership passes', () => {
    assert.match(DETAIL_SOURCE, /isTargetRunEligible\(eligibility, verificationState\)/);
    assert.match(DETAIL_SOURCE, /disabled=\{!targetEligible \|\| busy !== '' \|\| scanActive \|\| \(!multiSelected && Boolean\(singleDisabledReason\)\)\}/);
    assert.match(DETAIL_SOURCE, /if \(!targetEligible\) \{ setReview\(null\); return; \}/);
    assert.match(DETAIL_SOURCE, /confirmDisabled=\{review !== null && review\.mode !== 'detect' && \(!ownershipDone \|\| Boolean\(reviewSlotReason\) \|\| \(review\.mode === 'all' && Boolean\(runAllBlockedReason\)\)\)\}/);
    assert.match(DETAIL_SOURCE, /Prove ownership first\. External checks stay blocked until this target is verified\./);
    assert.match(DETAIL_SOURCE, /canStartBoundedRun && !targetEligible \? 'Prove ownership first\.'/);
    assert.match(QUEUE_SOURCE, /disabled=\{runAllCount === 0 \|\| Boolean\(runAllReason\)\}/);
    assert.match(DETAIL_SOURCE, /className="content target-detail-view"/);
  });

  it('badges the header from the fail-closed eligibility, never a blanket unlock', () => {
    assert.match(DETAIL_SOURCE, /<Badge tone=\{targetEligible \? 'success' : 'warn'\}/);
    assert.match(DETAIL_SOURCE, /\{targetEligible \? 'Ownership verified' : 'Ownership not verified'\}/);
    assert.match(DETAIL_SOURCE, /const proveOwnershipFirst = canStartBoundedRun && !ownershipDone && !scanActive && !activeStandalone/);
    assert.match(DETAIL_SOURCE, /variant=\{proveOwnershipFirst \? 'secondary' : 'default'\}/);
  });

  it('blocks Review all while a standalone check holds the execution slot', () => {
    assert.match(DETAIL_SOURCE, /is running on this target\. Wait for it to finish or stop it before starting all checks\./);
    assert.match(DETAIL_SOURCE, /if \(scanActive \|\| activeStandalone\) \{ setReview\(null\); return; \}/);
    assert.match(QUEUE_SOURCE, /aria-describedby=\{runAllReason \? 'td-run-all-reason' : undefined\}/);
  });

  it('blocks a single or recommended check while another check holds the execution slot', () => {
    assert.match(DETAIL_SOURCE, /is running on this target\. Wait for it to finish or stop it before starting another check\./);
    assert.match(DETAIL_SOURCE, /: !startCheckId\s*\? 'Select a check in the list first\.'\s*: !runnableIds\.has\(startCheckId\)\s*\? startPrerequisite\?\.detail \|\| 'This check is visible for reference but cannot be started here\.'\s*: reviewSlotReason;/);
    assert.match(DETAIL_SOURCE, /if \(!ownershipDone\) \{ setReview\(null\); return; \}\s*if \(scanActive \|\| activeStandalone\) \{ setReview\(null\); return; \}\s*if \(review\.mode === 'single'\)/);
    assert.match(DETAIL_SOURCE, /recommendedRow=\{activeStandalone \? null : recommendedRow\}/);
    assert.match(DETAIL_SOURCE, /recommendedStarterRow\(checkRows\.filter\(\(row\) => runnableIds\.has\(row\.checkId\)\)\)/);
    assert.match(DETAIL_SOURCE, /const runnableIds = useMemo\(\(\) => new Set\(selectableChecks\.map/);
    assert.match(DETAIL_SOURCE, /checkIds\.some\(\(id\) => !runnableIds\.has\(id\)\)/);
    assert.match(DETAIL_SOURCE, /reviewSlotReason \? <p className="td-form-error" role="alert">\{reviewSlotReason\}<\/p>/);
    assert.match(QUEUE_SOURCE, /canRun && !scanActive && !runAllBlockedReason \? \(/);
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

describe('ownership proof rendering', () => {
  let vite;
  let OwnershipProof;
  const NOW = Date.parse('2026-08-30T00:00:00.000Z');
  const base = { hostname: 'shop.example', now: NOW, panelId: 'td-ownership-panel', canWrite: true, busy: '', error: '', watching: false, watchStopped: false, onIssue() {}, onCheck() {} };
  const challenge = (expiresAt, state = 'pending') => ({ id: 'och_1', state, record_name: '_astranull-challenge.shop.example', record_value: 'astranull-verify=stale-token-123', expires_at: expiresAt, last_checked_at: null });
  const render = (props) => renderToStaticMarkup(createElement(OwnershipProof, { ...base, ...props }));

  before(async () => {
    vite = await createViteServer({ configFile: path.resolve('vite.config.ts'), server: { middlewareMode: true }, appType: 'custom', logLevel: 'silent' });
    ({ OwnershipProof } = await vite.ssrLoadModule('/src/components/targets/ownership-proof.tsx'));
  });
  after(async () => { await vite?.close(); });

  it('never offers DNS TXT proof for an IP target and points to origin relations instead', () => {
    const html = render({ kind: 'ip', challenge: null });
    assert.doesNotMatch(html, /Issue DNS TXT record/);
    assert.doesNotMatch(html, /We only check the declared hostname/);
    assert.match(html, /DNS TXT proof applies to hostnames and URLs/);
    assert.match(html, /declare this address under Origin relations/);
    assert.match(html, /href="#targets"/);
    assert.match(html, /prove you control this target\./);
  });

  it('explains that zone and canary targets have no DNS TXT proof yet', () => {
    for (const kind of ['dns_zone', 'canary']) {
      const html = render({ kind, challenge: null });
      assert.doesNotMatch(html, /Issue DNS TXT record/);
      assert.match(html, /DNS TXT ownership proof is not available for this target kind yet\./);
    }
  });

  it('keeps the TXT flow for hostnames and URLs', () => {
    for (const kind of ['fqdn', 'url']) {
      const html = render({ kind, challenge: null });
      assert.match(html, /Issue DNS TXT record/);
      assert.match(html, /We only check the declared hostname/);
    }
  });

  it('shows a live challenge with its expiry and hides Reissue until it expires', () => {
    const html = render({ kind: 'fqdn', challenge: challenge('2026-08-30T00:12:00.000Z') });
    assert.match(html, /astranull-verify=stale-token-123/);
    assert.match(html, /Check now/);
    assert.match(html, /Valid for 15 minutes · expires/);
    assert.match(html, /\(in 12 min\)/);
    assert.match(html, /Copy instructions/);
    assert.match(html, /You can issue a new value after it expires\./);
    assert.match(html, /Checks run only while this page is open\./);
    assert.doesNotMatch(html, /Reissue/);
    assert.doesNotMatch(html, /Issue a new record/);
  });

  it('withholds an expired value, hides Check now and offers a new record as the primary action', () => {
    for (const record of [challenge('2026-08-29T23:50:00.000Z'), challenge('2026-08-29T23:50:00.000Z', 'expired')]) {
      const html = render({ kind: 'fqdn', challenge: record });
      assert.doesNotMatch(html, /stale-token-123/);
      assert.doesNotMatch(html, /Check now/);
      assert.doesNotMatch(html, /Copy instructions/);
      assert.doesNotMatch(html, /aria-label="Copy DNS record value"/);
      assert.match(html, /Expired /);
      assert.match(html, /This record expired and can no longer prove ownership\. Issue a new record and publish its value\./);
      assert.match(html, /Issue a new record/);
      assert.match(html, /data-expired="true"/);
    }
  });

  it('never prints an expiry date for an expired challenge that has none recorded', () => {
    for (const expiresAt of [undefined, '', 'not-a-date']) {
      const html = render({ kind: 'fqdn', challenge: challenge(expiresAt) });
      assert.match(html, /Expired · no expiry recorded/);
      assert.doesNotMatch(html, /Expired Not recorded|Expired not-a-date|Expired Invalid/);
      assert.doesNotMatch(html, /stale-token-123/);
      assert.match(html, /Issue a new record/);
    }
    assert.doesNotMatch(render({ kind: 'fqdn', challenge: challenge('2026-08-29T23:50:00.000Z') }), /no expiry recorded/);
  });

  it('renders ownership errors as a persistent alert inside the panel', () => {
    const html = render({ kind: 'fqdn', challenge: null, error: 'This DNS TXT value expired.' });
    assert.match(html, /<div class="form-banner" role="alert">This DNS TXT value expired\.<\/div>/);
  });

  it('says when automatic re-checks stopped at the cap', () => {
    const html = render({ kind: 'fqdn', challenge: challenge('2026-08-30T00:12:00.000Z'), watchStopped: true });
    assert.match(html, /Stopped re-checking\. Choose Check now after your DNS change is live\./);
  });
});
