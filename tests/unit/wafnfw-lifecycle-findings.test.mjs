import '../helpers/dev-data-dir.mjs';
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { FINDING_LIFECYCLE, planFixVerifiedFromRetest, planFindingPatch } from '../../src/lib/findingLifecycle.mjs';
import { projectReadiness } from '../../src/lib/readinessProjection.mjs';
import { protectionFindingClosureSignal } from '../../src/lib/protectionValidationFindings.mjs';
import { applyPassingRetestToFindings, upsertFindingFromVerdict } from '../../src/services/findings.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { WAF_GRADING_VERSION, SIGNATURE_CORPUS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';
import { approvedScenarioVersion, deriveCheckDefinitionVersion, deriveRunEvidenceStamp, gradingSignatureVersionGap } from '../../src/lib/checkDefinitionVersion.mjs';
import { recordEvidence } from '../../src/services/evidence.mjs';
import { rederiveVerdict } from '../../src/lib/verdictReplay.mjs';
import { versionGapFor } from '../../src/lib/protectionCoverage.mjs';
import { getCheckById, WAF_SAFE_CHECK_IDS } from '../../src/contracts/checks.mjs';

const NOW = new Date('2026-10-13T12:00:00.000Z');
const CTX = { tenantId: 'ten_demo', userId: 'usr_eng', role: 'engineer' };

function seedOpenFinding(extra = {}) {
  freshStore();
  const run = {
    id: 'run_origin',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    target_id: getStore().targets[0].id,
    check_id: 'origin.direct_bypass.safe',
    status: 'verdicted',
    check_version: '1.0.0',
    grading_version: WAF_GRADING_VERSION,
  };
  const verdict = {
    id: 'vd_origin',
    tenant_id: 'ten_demo',
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: run.check_id,
    verdict: 'exposed',
    severity: 'high',
    explanation: 'Origin answered directly.',
    evidence_ids: ['ev_1'],
    grading_version: WAF_GRADING_VERSION,
    created_at: NOW.toISOString(),
  };
  getStore().testRuns.push(run);
  const finding = upsertFindingFromVerdict(CTX, verdict, run, getStore().targets[0]);
  Object.assign(finding, extra);
  return { finding, run, verdict };
}

describe('wafnfw finding fix_verified lifecycle', () => {
  beforeEach(() => freshStore());

  it('includes fix_verified in the lifecycle vocabulary', () => {
    assert.ok(FINDING_LIFECYCLE.includes('fix_verified'));
    const planned = planFindingPatch({ status: 'fix_verified' }, CTX, { now: NOW });
    assert.equal(planned.patch.status, 'fix_verified');
    assert.ok(planned.patch.closed_at);
  });

  it('closes an open finding on a complete passing retest of the same check, target, scope and versions', () => {
    const { finding, run } = seedOpenFinding();
    const retest = {
      ...run,
      id: 'run_retest',
      check_version: '1.0.0',
      grading_version: WAF_GRADING_VERSION,
    };
    const verdict = {
      id: 'vd_pass',
      verdict: 'protected',
      check_id: run.check_id,
      target_id: run.target_id,
      grading_version: WAF_GRADING_VERSION,
      metadata: { complete: true, comparison_complete: true },
    };
    const applied = applyPassingRetestToFindings(CTX, { verdict, run: retest, target: getStore().targets[0], now: NOW });
    assert.deepEqual(applied.closed, [finding.id]);
    assert.equal(getStore().findings[0].status, 'fix_verified');
    assert.equal(getStore().findings[0].verifying_run_id, 'run_retest');
    const audit = getStore().auditLog.find((row) => row.action === 'finding.fix_verified');
    assert.equal(audit.resource_id, finding.id);
    assert.equal(audit.metadata.verifying_run_id, 'run_retest');
  });

  it('never closes on a partial or inconclusive retest', () => {
    const { finding, run } = seedOpenFinding();
    const inconclusive = planFixVerifiedFromRetest({
      finding, run, verdict: { id: 'vd_inc', verdict: 'inconclusive', check_id: run.check_id }, now: NOW,
    });
    assert.equal(inconclusive.action, 'none');
    const partial = planFixVerifiedFromRetest({
      finding,
      run,
      verdict: { id: 'vd_part', verdict: 'protected', check_id: run.check_id, metadata: { comparison_complete: false } },
      now: NOW,
    });
    assert.equal(partial.action, 'none');
    assert.equal(partial.reason, 'partial_or_inconclusive');
    applyPassingRetestToFindings(CTX, {
      verdict: { id: 'vd_inc', verdict: 'inconclusive', check_id: run.check_id },
      run,
      target: getStore().targets[0],
    });
    assert.equal(getStore().findings[0].status, 'open');
    assert.equal(finding.id, getStore().findings[0].id);
  });

  it('does not close when check definition or grading versions differ', () => {
    const { finding, run } = seedOpenFinding({ check_version: '1.0.0', grading_version: WAF_GRADING_VERSION });
    assert.equal(planFixVerifiedFromRetest({
      finding,
      run: { ...run, id: 'run_v2', check_version: '2.0.0' },
      verdict: { id: 'vd', verdict: 'protected', check_id: run.check_id, grading_version: WAF_GRADING_VERSION },
      now: NOW,
    }).reason, 'check_definition_version_mismatch');
    assert.equal(planFixVerifiedFromRetest({
      finding,
      run: { ...run, id: 'run_g', check_version: '1.0.0' },
      verdict: { id: 'vd', verdict: 'protected', check_id: run.check_id, grading_version: 'waf-grading.v1' },
      now: NOW,
    }).reason, 'grading_version_mismatch');
  });

  it('does not close a protection finding whose retest scope drifted', () => {
    const { finding, run } = seedOpenFinding({
      source: 'protection_validation',
      protection_validation: {
        comparison_kind: 'path_validation',
        observed_route: { origin_binding_id: 'bind_1' },
      },
    });
    const applied = applyPassingRetestToFindings(CTX, {
      verdict: { id: 'vd', verdict: 'protected', check_id: run.check_id, metadata: { complete: true } },
      run: { ...run, id: 'run_other_scope', origin_binding_id: 'bind_2' },
      target: getStore().targets[0],
      now: NOW,
    });
    assert.deepEqual(applied.closed, []);
    assert.equal(finding.status, 'open');
  });

  it('does not close from a passing observation that is not a complete retest', () => {
    const signal = protectionFindingClosureSignal({
      finding: { id: 'fnd_1', status: 'open', dedupe_key: 'k' },
      passingObservation: { dedupe_key: 'k', observation: 'consistent_enforcement' },
    });
    assert.equal(signal.close, false);
    assert.equal(signal.action, 'none');
  });
});

describe('wafnfw accepted risk scoring', () => {
  it('does not subtract unexpired accepted_risk and subtracts again after expiry', () => {
    const asOf = '2026-10-04T12:00:00.000Z';
    const base = {
      tenantId: 'ten_demo',
      asOf,
      input_complete: true,
      groups: [],
      targets: [],
      runs: [],
      verdicts: [],
      findings: [
        {
          id: 'f_acc',
          tenant_id: 'ten_demo',
          status: 'accepted_risk',
          severity: 'critical',
          created_at: '2026-10-01T00:00:00.000Z',
          risk_acceptance: { review_at: '2026-12-01T00:00:00.000Z' },
        },
      ],
    };
    const current = projectReadiness(base);
    assert.equal(current.findings.accepted_risk_count, 1);
    assert.equal(current.findings.unresolved_count, 0);
    assert.equal(current.findings.severity_penalty, 0);
    const expired = projectReadiness({
      ...base,
      findings: [{
        ...base.findings[0],
        risk_acceptance: { review_at: '2026-10-01T00:00:00.000Z' },
      }],
    });
    assert.equal(expired.findings.accepted_risk_count, 0);
    assert.equal(expired.findings.unresolved_count, 1);
    assert.equal(expired.findings.severity_penalty, 20);
  });
});

describe('wafnfw versioned verdicts and replay', () => {
  it('stamps grading and signature corpus versions on the run evidence stamp', () => {
    const stamp = deriveRunEvidenceStamp({
      check_id: 'waf.marker.sqli',
      version: '1.2.0',
      default_expected_behavior: 'must_block_at_edge',
    }, {}, { probeMode: 'signed-worker' });
    assert.equal(stamp.grading_version, WAF_GRADING_VERSION);
    assert.equal(stamp.signature_corpus_version, SIGNATURE_CORPUS_VERSION);
    assert.equal(stamp.provenance_json.grading_version, WAF_GRADING_VERSION);
  });

  it('treats a grading or signature corpus gap like a check-definition gap', () => {
    assert.equal(gradingSignatureVersionGap({}, {}), 'missing_grading_version');
    assert.equal(gradingSignatureVersionGap({ grading_version: 'waf-grading.v1' }, {}), 'grading_version_mismatch');
    assert.equal(gradingSignatureVersionGap({
      grading_version: WAF_GRADING_VERSION,
      signature_corpus_version: 'old-corpus',
    }, {}), 'signature_corpus_version_mismatch');
    assert.equal(gradingSignatureVersionGap({
      grading_version: WAF_GRADING_VERSION,
      provenance_json: { signature_corpus_version: SIGNATURE_CORPUS_VERSION },
    }, {}), null);
  });

  it('persists redacted response_features on the evidence record and rederives a matching verdict', () => {
    freshStore();
    const recorded = recordEvidence(CTX, {
      test_run_id: 'run_1',
      metadata: {
        probe_kind: 'http_head',
        external_result: 'timeout',
        safety_attestation: { probe_requests_sent: 1 },
        response_features: [{
          placement: 'path',
          status_code: 403,
          header_subset: { server: 'cloudflare', authorization: 'secret' },
          body_length_bucket: '0-64',
          signature_id: 'sig_1',
        }],
      },
      verdict: 'inconclusive',
      expected_behavior: 'must_block_at_edge',
    });
    assert.ok(Array.isArray(recorded.response_features));
    assert.equal(recorded.response_features[0].placement, 'path');
    const replay = rederiveVerdict({ ...recorded, verdict: 'inconclusive' });
    assert.equal(typeof replay.derived.verdict, 'string');
    assert.equal(replay.matches, replay.derived.verdict === 'inconclusive');
    const mismatch = rederiveVerdict({ ...recorded, verdict: 'protected' });
    assert.equal(mismatch.matches, false);
  });

  it('treats a recorded grading or corpus mismatch as a coverage version gap', () => {
    const check = getCheckById('waf.marker_rule.safe');
    const current = deriveCheckDefinitionVersion(check);
    const scenario = approvedScenarioVersion(check);
    const stamped = {
      check_version: current.check_version,
      ...(scenario ? { scenario_version: scenario } : {}),
    };
    assert.equal(versionGapFor(check, stamped, {}), null);
    assert.equal(versionGapFor(check, { ...stamped, grading_version: 'waf-grading.v1' }, {}), 'grading_version_mismatch');
    assert.equal(versionGapFor(check, {
      ...stamped,
      grading_version: WAF_GRADING_VERSION,
      signature_corpus_version: 'old-corpus',
    }, {}), 'signature_corpus_version_mismatch');
  });

  it('includes managed marker checks on the safe WAF allowlist', () => {
    assert.ok(WAF_SAFE_CHECK_IDS.includes('waf.sqli_managed_marker.safe'));
    assert.ok(WAF_SAFE_CHECK_IDS.includes('waf.xss_managed_marker.safe'));
    assert.ok(WAF_SAFE_CHECK_IDS.includes('waf.path_traversal_managed_marker.safe'));
  });
});
