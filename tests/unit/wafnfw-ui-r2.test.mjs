import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, checkAdditionalInputReason, checkRequiresAdditionalInput, getCheckById, targetInputRefusal } from '../../src/contracts/checks.mjs';
import { controlDeclarationsEtag } from '../../src/contracts/controlDeclarations.mjs';
import { catalogRuleCoverage } from '../../src/contracts/ruleCoverage.mjs';
import {
  checkPrerequisite,
  declarationsDraftDiff,
  declarationsEtag,
  declarationsSaveConflict,
  draftFromDeclarations,
  emptyNetworkRule,
  prerequisiteCta,
  targetRequirementForReason,
  targetRunnableIndex,
} from '../../apps/web/react/src/lib/control-declarations.mjs';
import { selectableChecks, withTargetDependentChecks } from '../../apps/web/react/src/lib/check-picker.mjs';
import { individualChecks, rowEvidenceState, wafRuleEnforcement, withTargetRunnableChecks } from '../../apps/web/react/src/lib/domain-checks.mjs';
import { NOT_RUNNABLE_REASON_COPY, normalizeRuleCoverage } from '../../apps/web/react/src/lib/rule-coverage.mjs';
import { PERSPECTIVE_UNAUTHENTICATED, probeEvidenceModel, versionGapLabel } from '../../apps/web/react/src/lib/probe-evidence.mjs';
import { verdictReplayErrorMessage, verdictReplayModel } from '../../apps/web/react/src/lib/verdict-replay.mjs';

const FQDN = { id: 'tgt_fqdn', kind: 'fqdn', value: 'shop.example.test' };
const HOST_PORT = { id: 'tgt_tcp', kind: 'tcp', value: 'shop.example.test:2222' };
const DENY_TCP = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };
const ALLOW_UDP = { version: 1, network_policy: [{ protocol: 'udp', port: 161, action: 'allow', address_family: 'any' }] };
const EMPTY = { version: 1 };

/** What `GET /v1/checks?scope=all&target_id=` returns for one check on one target. */
function serverItem(check, target, declarations) {
  const context = { target, declarations, env: {} };
  const requires = checkRequiresAdditionalInput(check, context);
  return { ...check, requires_additional_input: requires, additional_input_reason: requires ? checkAdditionalInputReason(check, context) : null };
}

describe('declarations concurrency', () => {
  it('sends the same entity tag the server issues for a revision', () => {
    assert.equal(declarationsEtag({ version: 1, revision: 4 }), controlDeclarationsEtag(4));
    assert.equal(declarationsEtag({ version: 1 }), controlDeclarationsEtag(0), 'a never-saved document is revision 0');
    assert.equal(declarationsEtag(null), controlDeclarationsEtag(0));
  });

  it('classifies 412 and 428 responses and ignores other failures', () => {
    assert.deepEqual(declarationsSaveConflict({ status: 412, payload: { error: 'declarations_conflict', revision: 3, etag: '"decl-r3"' } }), { kind: 'conflict', revision: 3, etag: '"decl-r3"' });
    assert.equal(declarationsSaveConflict({ status: 428, payload: { error: 'precondition_required' } }).kind, 'precondition');
    assert.equal(declarationsSaveConflict({ status: 400, payload: { error: 'invalid_control_declarations' } }), null);
    assert.equal(declarationsSaveConflict(new Error('offline')), null);
  });

  it('names what differs between their saved version and the draft, item by item', () => {
    const base = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };
    const theirs = { ...base, network_policy: [...base.network_policy, { protocol: 'udp', port: 161, action: 'deny', address_family: 'any' }], origin: { lockdown_expected: true } };
    const draft = draftFromDeclarations(base);
    draft.network_policy.push({ ...emptyNetworkRule(), port: '8443' });
    const diff = declarationsDraftDiff(theirs, draft);
    assert.deepEqual(diff.map((row) => row.section), ['network', 'origin']);
    assert.match(diff[0].theirs, /not in your draft: UDP 161 deny/);
    assert.match(diff[0].yours, /not in their version: TCP 8443 deny/);
    assert.equal(diff[1].yours, 'Not declared');
    assert.deepEqual(declarationsDraftDiff(base, draftFromDeclarations(base)), []);
  });
});

describe('per-target runnability follows the server', () => {
  const requirementChecks = CHECK_CATALOG.filter((check) => (check.runnable_requires ?? []).some((value) => ['port', 'port_or_declared_tcp_deny'].includes(value)));

  it('agrees with the server refusal for every target-dependent check, target and declaration set', () => {
    assert.ok(requirementChecks.length >= 2);
    for (const check of requirementChecks) {
      for (const target of [FQDN, HOST_PORT]) {
        for (const declarations of [EMPTY, DENY_TCP, ALLOW_UDP]) {
          const refusal = targetInputRefusal(check, target, declarations);
          const served = checkPrerequisite(check, { serverRunnableIndex: targetRunnableIndex([serverItem(check, target, declarations)]) });
          assert.equal(served.state === 'ready', !refusal, `${check.check_id} on ${target.kind} with ${JSON.stringify(declarations.network_policy ?? [])}`);
          if (refusal) assert.equal(served.reason, refusal.error);
        }
      }
    }
  });

  it('labels from the server reason code and never guesses before the answer loads', () => {
    const deny = getCheckById('l3.basic_deny_rule.safe');
    assert.equal(checkPrerequisite(deny, { declarations: DENY_TCP, target: FQDN }).state, 'checking');
    const blocked = checkPrerequisite(deny, { serverRunnable: { runnable: false, reason: 'port_or_declared_deny_required' } });
    assert.equal(blocked.state, 'needs_deny_or_port');
    assert.equal(blocked.label, 'Needs a declared deny rule or a host:port target');
    assert.equal(prerequisiteCta(blocked), 'Declare a denied TCP port');
    assert.equal(checkPrerequisite(deny, { declarations: EMPTY, target: FQDN, serverRunnableIndex: new Map([[deny.check_id, { runnable: true, reason: '' }]]) }).state, 'ready');
    assert.equal(targetRequirementForReason('port_required').label, 'Needs a port');
    assert.equal(targetRequirementForReason('port_or_declared_deny_required').label, 'Needs a declared deny rule or a host:port target');
    assert.equal(targetRequirementForReason('incompatible_target'), null);
  });

  it('unlocks target-dependent checks in the runnable list from the target-scoped catalog', () => {
    const portless = getCheckById('l3.tcp_flag_anomaly.readiness');
    const runnable = [serverItem(portless, FQDN, DENY_TCP)];
    const blocked = [serverItem(portless, FQDN, EMPTY)];
    assert.deepEqual(targetRunnableIndex(runnable).get(portless.check_id), { runnable: true, reason: '' });
    assert.deepEqual(individualChecks(withTargetRunnableChecks([], runnable), FQDN).map((check) => check.check_id), [portless.check_id]);
    assert.deepEqual(individualChecks(withTargetRunnableChecks([], blocked), FQDN).map((check) => check.check_id), [portless.check_id]);
    assert.deepEqual(individualChecks([portless], FQDN), [], 'without the server answer the check waits');
    const merged = withTargetDependentChecks([], [blocked, runnable]);
    assert.equal(merged.length, 1);
    assert.deepEqual(selectableChecks(merged).checks.map((check) => check.check_id), [portless.check_id], 'a port-less check is not hidden as unsupported delivery');
  });
});

describe('custom canary rollup members use the server freshness answer', () => {
  const recent = new Date(Date.UTC(2030, 0, 1, 12)).toISOString();
  const nowMs = Date.UTC(2030, 0, 1, 13);
  const row = (checkId, status) => ({ checkId, status, finishedAt: recent, readinessCapable: true, category: { id: 'waf' }, probeKind: 'waf_class_marker_probe', assuranceScope: 'custom_canary_rule', markerClass: checkId });
  const coverage = {
    pairs: [{ check_id: 'waf.crlf_injection_marker.safe', custom_canary_rollup: true, state: 'conclusive' }],
    custom_canary_rollups: [{
      check_id: 'waf.crlf_injection_marker.safe',
      rolled_up_pairs: [
        { check_id: 'waf.crlf_injection_marker.safe', state: 'conclusive', fresh: true, version_gap: null, verdict: 'exposed', observed_at: recent },
        { check_id: 'waf.open_redirect_marker.safe', state: 'partial', fresh: false, version_gap: 'signature_corpus_version_mismatch', verdict: 'protected', observed_at: recent },
        { check_id: 'waf.nosql_injection_marker.safe', state: 'stale', fresh: false, version_gap: null, verdict: 'protected', observed_at: recent },
      ],
    }],
  };

  it('ignores version-gapped and stale members even when the run looks recent', () => {
    assert.equal(rowEvidenceState(row('waf.crlf_injection_marker.safe', 'failed'), { coverage, nowMs }), 'fresh');
    assert.equal(rowEvidenceState(row('waf.open_redirect_marker.safe', 'passed'), { coverage, nowMs }), 'version_gap');
    assert.equal(rowEvidenceState(row('waf.nosql_injection_marker.safe', 'passed'), { coverage, nowMs }), 'stale');
    const tally = wafRuleEnforcement([row('waf.crlf_injection_marker.safe', 'failed'), row('waf.open_redirect_marker.safe', 'passed'), row('waf.nosql_injection_marker.safe', 'passed')], { coverage, nowMs });
    assert.deepEqual({ enforced: tally.custom.enforced, notEnforced: tally.custom.notEnforced, ignored: tally.custom.ignored }, { enforced: 0, notEnforced: 1, ignored: 2 });
  });
});

describe('rule coverage uses server copy', () => {
  it('shows plain server strings and maps only the not-runnable code', () => {
    const model = normalizeRuleCoverage(catalogRuleCoverage());
    for (const category of model.categories) {
      for (const value of [category.description, category.reason, category.assuranceReason]) {
        assert.doesNotMatch(value, /\b[a-z]+_[a-z_]+\b/, `${category.id}: ${value}`);
      }
    }
    assert.match(model.categories.find((category) => category.id === 'icmp_policy').reason, /AstraNull sends no ICMP probes/);
    assert.deepEqual(Object.keys(NOT_RUNNABLE_REASON_COPY), ['two_perspectives_required']);
  });
});

describe('network evidence and verdict replay', () => {
  const metadata = {
    probe_kind: 'tcp_connect', protocol: 'tcp', port: 22, tcp_outcome: 'handshake',
    port_results: [
      { protocol: 'tcp', port: 22, tcp_outcome: 'handshake', parity: 'mismatch' },
      { protocol: 'tcp', port: 3389, tcp_outcome: 'timeout', parity: 'match' },
    ],
    declared_deny_ports: [22, 3389, 5900], ports_probed: [22, 3389], unprobed_deny_ports: [5900],
    source_perspective: { id: 'default', label: 'Primary' }, claimed_perspective_id: 'default', perspective_authenticated: false,
  };

  it('builds a per-port table merged with the published per-port result', () => {
    const model = probeEvidenceModel(metadata, { verdictPortResults: [{ protocol: 'tcp', port: 22, outcome: 'handshake', result: 'violated', severity: 'high' }, { protocol: 'tcp', port: 3389, outcome: 'timeout', result: 'no_violation_observed' }] });
    assert.deepEqual(model.network.portResults.map((row) => [row.port, row.outcomeLabel, row.resultLabel]), [[22, 'Handshake completed', 'Violates your deny rule'], [3389, 'No reply', 'No violation seen']]);
    assert.deepEqual(model.network.unprobedDenyPorts, [5900]);
    assert.equal(probeEvidenceModel(metadata).network.portResults[0].resultLabel, '', 'no result is inferred without the verdict');
  });

  it('flags an unauthenticated perspective and names version gaps', () => {
    const model = probeEvidenceModel(metadata);
    assert.deepEqual(model.perspective, { id: 'default', label: 'Primary', claimedId: 'default', authenticated: false });
    assert.equal(PERSPECTIVE_UNAUTHENTICATED, 'Perspective not authenticated — result cannot prove an allowlist gap');
    assert.equal(versionGapLabel('signature_corpus_version_mismatch'), 'Grading rules changed — re-run to restore credit');
    assert.equal(versionGapLabel('retest_required'), 'Grading rules changed — re-run to restore credit');
  });

  it('reads a replay as unchanged, changed, no stored verdict or no evidence', () => {
    const stored = { verdict: 'protected', grading_version: 'waf-grading.v2', signature_corpus_version: 'waf-signatures.old' };
    const rederived = { verdict: 'protected', grading_version: 'waf-grading.v2', signature_corpus_version: 'waf-signatures.new', evidence_available: true, declarations_applied: true };
    const same = verdictReplayModel({ stored, rederived, changed: false, grading_version_gap: 'signature_corpus_version_mismatch' });
    assert.equal(same.state, 'unchanged');
    assert.equal(same.versionGap.label, 'Grading rules changed — re-run to restore credit');
    assert.equal(same.storedVersions, 'waf-grading.v2 · waf-signatures.old');
    const changed = verdictReplayModel({ stored, rederived: { ...rederived, verdict: 'exposed' }, changed: true, grading_version_gap: null });
    assert.equal(changed.state, 'changed');
    assert.equal(changed.nowLabel, 'Gap found');
    assert.equal(changed.versionGap, null);
    assert.equal(verdictReplayModel({ stored: null, rederived, changed: null }).state, 'no_stored');
    assert.equal(verdictReplayModel({ stored, rederived: { ...rederived, evidence_available: false }, changed: false }).state, 'no_evidence');
    assert.equal(verdictReplayModel(null), null);
    assert.match(verdictReplayErrorMessage({ status: 404 }), /No replay is available/);
  });
});
