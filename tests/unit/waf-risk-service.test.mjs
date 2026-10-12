import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  WAF_RISK_METHOD,
  assignPriorityBand,
  computeAssetRiskAssessment,
  enrichSnapshotWithRisk,
} from '../../src/services/wafRiskService.mjs';

import { assuredPosture, exactOriginProof } from '../helpers/assurance-fixtures.mjs';

describe('wafRiskService', () => {
  it('scores unprotected payment assets into tier_1 with explainable factors', () => {
    const assessment = computeAssetRiskAssessment({
      asset: {
        id: 'asset_payment', canonical_url: 'https://pay.example.test', tenant_id: 'ten_demo',
        business_criticality: 'payment',
        traffic_tier: 'high',
        asset_kind: 'checkout',
        compliance_tags: ['pci'],
      },
      snapshot: assuredPosture({ id: 'asset_payment', canonical_url: 'https://pay.example.test', tenant_id: 'ten_demo' }, 'unprotected', '2026-07-02T00:00:00Z'),
      computedAt: '2026-07-03T00:00:00.000Z',
    });

    assert.equal(assessment.method, WAF_RISK_METHOD);
    assert.ok(assessment.risk_score >= 65);
    assert.equal(assessment.priority_band, 'tier_1');
    assert.ok(assessment.factors.some((f) => f.factor === 'protection_state'));
    assert.ok(assessment.factors.some((f) => f.factor === 'business_criticality'));
    assert.equal(assessment.recommended_action, 'deploy_waf_blocking');
  });

  it('promotes only resolved fresh scoped origin evidence, never booleans or reason codes', () => {
    const asset = { id: 'asset_bypass', canonical_url: 'https://app.example.test/path', tenant_id: 'ten_demo', business_criticality: 'low', traffic_tier: 'low' };
    const snapshot = assuredPosture(asset, 'underprotected'); snapshot.reason_codes = ['origin_bypass_confirmed'];
    const unproved = computeAssetRiskAssessment({ asset, snapshot, validationSummary: { origin_bypass_confirmed: true }, computedAt: '2026-10-08T12:00:00Z' });
    assert.ok(!unproved.factors.some((f) => f.factor === 'origin_bypass')); assert.notEqual(unproved.recommended_action, 'close_origin_bypass');
    snapshot.evidence_json.origin_bypass_evidence = exactOriginProof(snapshot);
    const assessment = computeAssetRiskAssessment({ asset, snapshot, computedAt: '2026-10-08T12:00:00Z' });
    assert.equal(assessment.priority_band, 'tier_1'); assert.equal(assessment.recommended_action, 'close_origin_bypass');
    assert.ok(assessment.factors.some((f) => f.factor === 'origin_bypass' && f.contribution === 25));
    const originEvent = snapshot.evidence_json.origin_bypass_evidence.result_events[0];
    const ingestion = originEvent.ingested_at;
    delete originEvent.ingested_at;
    assert.equal(computeAssetRiskAssessment({ asset, snapshot, computedAt: '2026-10-08T12:00:00Z' }).factors.some((f) => f.factor === 'origin_bypass'), false);
    originEvent.ingested_at = ingestion;
    snapshot.evidence_json.origin_bypass_evidence.result_events = []; assert.equal(computeAssetRiskAssessment({ asset, snapshot, computedAt: '2026-10-08T12:00:00Z' }).factors.some((f) => f.factor === 'origin_bypass'), false);
  });
  it('does not turn retained protected posture into current risk protection credit after actual contradiction or missing ingestion', () => {
    const asset = { id: 'contradicted', tenant_id: 'ten_demo', canonical_url: 'https://app.example.test/path' };
    for (const mutate of [
      (snapshot) => { snapshot.evidence_json.result_events[0].metadata.enforcement = 'not_enforced'; },
      (snapshot) => { delete snapshot.evidence_json.result_events[0].ingested_at; },
    ]) {
      const snapshot = assuredPosture(asset); mutate(snapshot);
      const custody = JSON.stringify(snapshot);
      const result = computeAssetRiskAssessment({ asset, snapshot, computedAt: '2026-10-08T12:00:00Z' });
      assert.equal(result.current_assurance.status, 'unknown');
      assert.equal(result.current_assurance.historical_status, 'protected');
      assert.equal(result.current_assurance.retest_required, true);
      assert.equal(JSON.stringify(snapshot), custody);
    }
  });
  it('edge-only observations never prove origin lockdown or invent confidence', () => {
    const asset = { id: 'edge', tenant_id: 'ten_demo', canonical_url: 'https://edge.example.test', business_criticality: 'low' };
    const snapshot = assuredPosture(asset, 'edge_protected'); const result = computeAssetRiskAssessment({ asset, snapshot, cveMatches: [{ confidence: 1 }], computedAt: '2026-10-08T12:00:00Z' });
    assert.equal(result.edge_only, true); assert.equal(result.origin_lockdown, 'not_established'); assert.equal(result.confidence, null); assert.equal(result.current_assurance.current_assurance, 'edge_only_tested_scenario'); assert.equal(result.score_role, 'review_prioritization_not_protection_assurance');
  });
  it('does not allow new summaries or unresolved evidence IDs to renew assurance', () => {
    const asset = { id: 'legacy', tenant_id: 'ten_demo', canonical_url: 'https://legacy.example.test' }; const snapshot = assuredPosture(asset, 'protected', '2026-09-01T00:00:00Z');
    const result = computeAssetRiskAssessment({ asset, snapshot, validationSummary: { validation_passed: true, complete: true, producer_kind: 'signed_probe', observed_at: '2026-10-08T00:00:00Z', evidence_ids: ['unresolved'] }, computedAt: '2026-10-08T12:00:00Z' }); assert.equal(result.current_assurance.status, 'unknown'); assert.equal(result.current_assurance.reason, 'stale'); assert.notEqual(result.factors.find((f) => f.factor === 'validation_result').value, 'passed');
  });

  it('assigns tier_4 for excluded assets', () => {
    const band = assignPriorityBand({
      riskScore: 90,
      asset: { business_criticality: 'payment' },
      snapshot: { status: 'excluded', reason_codes: ['policy_exception_active'] },
      factors: [],
    });
    assert.equal(band, 'tier_4');
  });

  it('clamps scores to 0-100 and persists on snapshots', () => {
    const assessment = computeAssetRiskAssessment({
      asset: {
        id: 'asset_max',
        business_criticality: 'payment',
        traffic_tier: 'high',
        asset_kind: 'admin',
        compliance_tags: ['pci', 'hipaa'],
      },
      snapshot: {
        status: 'unprotected',
        reason_codes: ['origin_bypass_confirmed'],
      },
      validationSummary: {
        validation_failed: true,
        origin_bypass_confirmed: true,
      },
      cveMatches: [{ validation_status: 'exposed', risk_score: 90, known_exploited: true }],
      targetGroup: { settings_json: { hosting_environment: 'unknown' } },
    });

    assert.ok(assessment.risk_score <= 100);
    const enriched = enrichSnapshotWithRisk({ risk_score: 0 }, assessment);
    assert.equal(enriched.risk_score, assessment.risk_score);
    assert.deepEqual(enriched.risk_factors_json, assessment.factors);
    assert.equal(enriched.priority_band, assessment.priority_band);
  });
});