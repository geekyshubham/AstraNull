import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  ADDITIONAL_INPUT_REASON_COPY,
  additionalInputReasonCopy,
  checkPrerequisite,
  controlsHref,
  prerequisiteCta,
  prerequisiteSection,
  prerequisiteTone,
  targetFixableReason,
  targetRunnableIndex,
} from '../../apps/web/react/src/lib/control-declarations.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { customCanaryMembers } from '../../apps/web/react/src/lib/domain-checks.mjs';
import { FIX_VERIFIED_BASIS_LABELS, fixVerifiedBasis, fixVerifiedBasisHint } from '../../apps/web/react/src/lib/finding-lifecycle.mjs';

describe('closure basis from the finding', () => {
  it('prefers the finding field over the audit fallback', () => {
    const audit = [{ action: 'finding.fix_verified', ts: '2030-01-02T00:00:00Z', metadata: { verification_basis: 'passing_retest' } }];
    const result = fixVerifiedBasis({ status: 'fix_verified', verification_basis: 'violation_not_reproduced' }, audit);
    assert.equal(result.source, 'finding');
    assert.equal(result.label, FIX_VERIFIED_BASIS_LABELS.violation_not_reproduced);
    assert.equal(fixVerifiedBasis({ status: 'fix_verified' }, audit).source, 'audit');
  });

  it('gives a short list hint only when a fix-verified finding carries a known basis', () => {
    assert.equal(fixVerifiedBasisHint({ status: 'fix_verified', verification_basis: 'violation_not_reproduced' }), 'No longer reproduced');
    assert.equal(fixVerifiedBasisHint({ state: 'fix_verified', verification_basis: 'passing_retest' }), 'Passing retest');
    assert.equal(fixVerifiedBasisHint({ status: 'fix_verified' }), '');
    assert.equal(fixVerifiedBasisHint({ status: 'fix_verified', verification_basis: 'something_new' }), '');
    assert.equal(fixVerifiedBasisHint({ status: 'open', verification_basis: 'passing_retest' }), '', 'a reopened finding shows no closure hint');
  });
});

describe('origin_binding_required refusal', () => {
  it('has plain copy and deep-links to Origin relations before the server emits it', () => {
    const copy = additionalInputReasonCopy('origin_binding_required');
    assert.equal(copy.label, 'Needs one verified origin binding');
    assert.doesNotMatch(copy.detail, /\b[a-z]+_[a-z_]+\b/);
    assert.equal(ADDITIONAL_INPUT_REASON_COPY.origin_binding_required.section, 'origin_relations');
    assert.equal(controlsHref('tgt_fqdn', copy.section), '#target-detail?id=tgt_fqdn&tab=overview&section=origin-relations');
    assert.equal(controlsHref('tgt_fqdn', 'origin'), '#target-detail?id=tgt_fqdn&tab=controls&section=origin');
    assert.equal(targetFixableReason('origin_binding_required'), true);
  });

  it('labels the origin-lockdown check from a served reason and keeps the customer CTA', () => {
    const check = { ...getCheckById('nfw.origin_lockdown.safe'), requires_additional_input: true, additional_input_reason: 'origin_binding_required' };
    const prerequisite = checkPrerequisite(check, { serverRunnableIndex: targetRunnableIndex([check]) });
    assert.equal(prerequisite.label, 'Needs one verified origin binding');
    assert.equal(prerequisiteSection(prerequisite), 'origin_relations');
    assert.equal(prerequisiteCta(prerequisite), 'Open Origin relations');
    assert.equal(prerequisiteTone(prerequisite), 'warn');
  });
});

describe('scanner marker is never a custom-canary member', () => {
  const coverage = {
    custom_canary_rollups: [{
      custom_canary_rollup: true,
      rolled_up_pairs: [
        { check_id: 'waf.scanner_signature_marker.safe', last_run_id: 'run_a', state: 'conclusive', fresh: true, verdict: 'protected' },
        { check_id: 'waf.sqli_canary.safe', last_run_id: 'run_b', state: 'conclusive', fresh: true, verdict: 'protected' },
        { check_id: 'waf.other_managed.safe', last_run_id: 'run_c', state: 'conclusive', fresh: true, assurance_scope: 'managed_rule_marker' },
      ],
    }],
  };

  it('drops it from old rollup data, by id, by member scope and by the catalog', () => {
    assert.deepEqual(customCanaryMembers(coverage).map((member) => member.checkId), ['waf.sqli_canary.safe']);
    const legacy = { custom_canary_rollups: [{ rolled_up_pairs: [{ check_id: 'waf.custom_managed.safe', last_run_id: 'run_d', fresh: true }] }] };
    assert.equal(customCanaryMembers(legacy).length, 1);
    assert.equal(customCanaryMembers(legacy, { checks: [{ checkId: 'waf.custom_managed.safe', assuranceScope: 'managed_rule_marker' }] }).length, 0);
    assert.equal(customCanaryMembers(legacy, { checks: [{ check_id: 'waf.custom_managed.safe', probe_profile: { assurance_scope: 'managed_rule_marker' } }] }).length, 0);
  });
});
