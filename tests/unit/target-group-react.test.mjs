import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/target-group-detail-view.tsx', import.meta.url),
  'utf8',
);

describe('target-group React truthfulness contract', () => {
  it('binds every DNS issue to an explicit target and chains domain creation from the returned ID', () => {
    assert.match(SOURCE, /body: \{ target_id: targetId \}/);
    assert.match(SOURCE, /const targetId = getString\(created, \['id'\], ''\)/);
    assert.match(SOURCE, /issueDnsChallenge\(targetId, getString\(created, \['value'\], targetId\)\)/);
    assert.match(SOURCE, /verifyDnsChallenge\(getString\(existing, \['id', 'challenge_id'\], ''\), id\)/);
    assert.match(SOURCE, /did not bind the challenge to the selected target/);
    assert.doesNotMatch(SOURCE, /issueDnsChallenge\(\)/);
  });

  it('retains confirmed DNS state and conflict-proofs challenge issuance', () => {
    assert.match(SOURCE, /dnsChallengesRef\.current = items;[\s\S]*setDnsChallenges\(items\)/);
    assert.match(SOURCE, /Could not refresh DNS challenges[\s\S]*Previously confirmed challenge state is retained/);
    assert.match(SOURCE, /return dnsChallengesRef\.current/);
    assert.match(SOURCE, /const selectedVerifiedChallenge = verifiedChallenge[\s\S]*target_id[\s\S]*=== selectedDnsTargetId/);
    assert.match(SOURCE, /const activeChallengeVerifiedByResponse = selectedVerifiedChallenge !== null[\s\S]*dnsVerifyResult\?\.verified === true/);
    assert.match(SOURCE, /const selectedTargetOwnershipState = selectedDnsTarget[\s\S]*targetVerificationState\(selectedDnsTarget\)/);
    assert.match(SOURCE, /const dnsIssueBlocked = !selectedDnsTargetId[\s\S]*\|\| dnsOwnershipConfirmed[\s\S]*\|\| busy\.startsWith\('dns-'\)/);
    assert.match(SOURCE, /if \(targetAlreadyDnsVerified\)[\s\S]*No new challenge was issued/);
    assert.match(SOURCE, /if \(isActiveDnsChallenge\(knownChallenge\)\)[\s\S]*no replacement was issued/);
    assert.match(SOURCE, /DNS ownership is confirmed, but the target-group refresh failed[\s\S]*confirmed state is retained/);
    assert.match(SOURCE, /busy\.startsWith\('dns-'\) \|\| dnsIssueInFlightTargetRef\.current/);
    assert.match(SOURCE, /dnsIssueInFlightTargetRef\.current = targetId/);
    assert.match(SOURCE, /if \(dnsIssueInFlightTargetRef\.current === targetId\) dnsIssueInFlightTargetRef\.current = ''/);
    assert.match(SOURCE, /disabled=\{dnsIssueBlocked\}/);
    assert.match(SOURCE, /actionLabel=\{busy\.startsWith\('dns-'\) \? undefined : 'Issue DNS challenge'\}/);
    assert.match(SOURCE, /selectedDnsTarget && dnsOwnershipConfirmed[\s\S]*title="DNS ownership confirmed"/);
    assert.match(SOURCE, /apiErrorCode\(err\) === 'challenge_active'/);
    assert.match(SOURCE, /Reuse it or wait until it expires; no replacement was issued/);
    assert.match(SOURCE, /\{dnsError \? <div className="form-banner error" role="alert">/);
    assert.match(SOURCE, /Automatic DNS recheck failed/);
    assert.match(SOURCE, /The expected TXT value was not observed\. The challenge remains pending/);
  });

  it('keeps an active pending challenge distinct from previously verified target ownership', () => {
    const start = SOURCE.indexOf('function challengeChipState');
    const end = SOURCE.indexOf('function pickActiveChallenge', start);
    const helper = SOURCE.slice(start, end);
    assert.ok(start >= 0 && end > start);
    assert.ok(helper.indexOf("state === 'pending'") < helper.indexOf("verified === true) return 'dns_verified'"));
    assert.match(SOURCE, /const targetOwnershipDnsVerified = selectedTargetOwnershipState === 'dns_verified'/);
    assert.match(SOURCE, /const challengeResolved = activeChallengeState === 'resolved' \|\| activeChallengeVerifiedByResponse/);
    assert.match(SOURCE, /challengeChipState\(activeChallenge, challengeResolved\)/);
    assert.match(SOURCE, /const dnsOwnershipConfirmed = targetOwnershipDnsVerified \|\| challengeResolved/);
    assert.match(SOURCE, /dnsChipState === 'dns_verified'/);
    assert.match(SOURCE, /Target ownership remains DNS verified from prior target evidence/);
    assert.match(SOURCE, /activeChallengeIsPending \? 'Challenge active' : dnsOwnershipConfirmed \? 'Ownership confirmed'/);
    assert.doesNotMatch(SOURCE, /challengeChipState\(activeChallenge, dnsVerified\)/);
  });

  it('captures the modal invoker and restores focus after close or Escape', () => {
    assert.match(SOURCE, /const invokerRef = useRef<HTMLElement \| null>\(null\)/);
    assert.match(SOURCE, /invokerRef\.current = activeElement instanceof HTMLElement \? activeElement : null/);
    assert.match(SOURCE, /const invoker = invokerRef\.current;[\s\S]*invoker\?\.isConnected[\s\S]*invoker\.focus\(\{ preventScroll: true \}\)/);
    assert.match(SOURCE, /onCancel=\{\(event\) => \{[\s\S]*event\.preventDefault\(\);[\s\S]*onClose\(\)/);
    assert.match(SOURCE, /onClick=\{onClose\} aria-label="Close dialog"/);
  });

  it('captures explicit LOA scope and custody-relevant fields before reporting signed', () => {
    assert.match(SOURCE, /form\.getAll\('scope_ack'\)/);
    assert.match(SOURCE, /name="scope_ack" value=\{id\} disabled=\{!eligible\}/);
    assert.doesNotMatch(SOURCE, /name="scope_ack"[^>]*defaultChecked/);
    assert.match(SOURCE, /none are selected automatically/);
    assert.match(SOURCE, /requestedScope\.filter\(\(targetId\) => eligibleScopeIds\.has\(targetId\)\)/);
    assert.match(SOURCE, /signer_email:/);
    assert.match(SOURCE, /emergency_contact:/);
    assert.match(SOURCE, /custody_artifact_id/);
    assert.match(SOURCE, /custody_digest_sha256/);
    assert.match(SOURCE, /isSignedLoaState/);
    assert.match(SOURCE, /data-loa-state=\{loaSigned \? 'signed' : 'required'\}/);
    assert.match(SOURCE, /background: color-mix\(in oklab, var\(--surface\), var\(--success\) 8%\)/);
    assert.doesNotMatch(SOURCE, /name="signed_date"/);
  });

  it('runs the user-selected safe rule rather than the first runnable catalog entry', () => {
    assert.match(SOURCE, /check_id: effectiveSelectedPolicyCheckId/);
    assert.match(SOURCE, /Select a customer-runnable rule/);
    assert.doesNotMatch(SOURCE, /customerRunnableChecks\[0\]|safeCheckId|firstRunnableCheckId/);
  });

  it('persists a bare IP with optional port metadata', () => {
    assert.match(SOURCE, /'ip',\s*ip,\s*String\(form\.get\('expected_behavior'\)/s);
    assert.match(SOURCE, /\{ port: parsedPort\.port, notes:/);
    assert.doesNotMatch(SOURCE, /port \? `\$\{ip\}:\$\{port\}` : ip/);
  });

  it('keeps imported provenance and target actions truthful without stealing the native row', () => {
    assert.match(SOURCE, /import_source: importIntegration/);
    assert.match(SOURCE, /connector_id: inventoryProvider/);
    assert.match(SOURCE, /targetDeclarationProvenanceLabel\(item\)/);
    assert.match(SOURCE, /href=\{buildDetailHref\('target-detail', id\)\}/);
    assert.match(SOURCE, /aria-label={`Open target \$\{getString\(item, \['value'\], id\)\}`}/);
    assert.match(SOURCE, />\s*Verify\s*<\/Button>[\s\S]*>\s*Run test\s*<\/Button>[\s\S]*Remove/m);
    assert.doesNotMatch(SOURCE, /targetRowNavProps|tg-target-row|isNestedInteractiveTarget/);
  });

  it('uses normal page spacing and bounds rule discovery rather than rendering the full catalog', () => {
    assert.match(SOURCE, /className="content tg-detail-view"/);
    assert.match(SOURCE, /const visibleRuleChecks = filteredRuleChecks\.slice\(0, ruleLimit\)/);
    assert.match(SOURCE, /items=\{visibleRuleChecks\}/);
    assert.match(SOURCE, /Search customer-runnable rules/);
    assert.match(SOURCE, /Show 12 more/);
    assert.doesNotMatch(SOURCE, /className="content stack-tight tg-detail-view"/);
  });
});
