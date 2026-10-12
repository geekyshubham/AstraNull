import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computeWafCoverageSummaryRow,
  mapWafCoverageSummaryRow,
} from '../../src/lib/wafCoverageSummary.mjs';

import { assessPostureAssurance } from '../../src/lib/wafPostureAssurance.mjs';
import { assuredPosture, ASSURANCE_NOW } from '../helpers/assurance-fixtures.mjs';

describe('WAF dashboard coverage summary', () => {
  it('returns a finite zero percentage when there are no assets', () => {
    const summary = computeWafCoverageSummaryRow({
      assets: [],
      currentSnapshotsByAsset: new Map(),
      refreshedAt: '2026-08-31T00:00:00.000Z',
    });
    assert.equal(summary.assets_total, 0);
    assert.equal(summary.coverage_pct, 0);
    assert.equal(Number.isFinite(summary.coverage_pct), true);
  });

  it('keeps edge-protected assets separate from full protected coverage', () => {
    const assets = [
      { id: 'asset_protected', canonical_url: 'https://protected.example.test', tenant_id: 'ten_demo' },
      { id: 'asset_edge', canonical_url: 'https://edge.example.test', tenant_id: 'ten_demo' },
      { id: 'asset_under', canonical_url: 'https://under.example.test', tenant_id: 'ten_demo' },
      { id: 'asset_unknown' },
    ];
    const currentSnapshotsByAsset = new Map([
      ['asset_protected', { ...assuredPosture(assets[0], 'protected', '2026-08-30T00:00:00Z'), detected_vendor: 'vendor-a' }],
      ['asset_edge', { ...assuredPosture(assets[1], 'edge_protected', '2026-08-30T00:00:00Z'), detected_vendor: 'vendor-a' }],
      ['asset_under', { ...assuredPosture(assets[2], 'underprotected', '2026-08-30T00:00:00Z'), detected_vendor: 'vendor-b' }],
    ]);

    const summary = computeWafCoverageSummaryRow({
      assets,
      currentSnapshotsByAsset,
      refreshedAt: '2026-08-31T00:00:00.000Z',
    });

    assert.equal(summary.assets_total, 4);
    assert.equal(summary.protected, 1);
    assert.equal(summary.edge_protected, 1);
    assert.equal(summary.underprotected, 1);
    assert.equal(summary.unknown, 1);
    assert.equal(summary.coverage_pct, 25);
    assert.deepEqual(summary.by_vendor['vendor-a'], {
      assets: 2,
      protected: 1,
      edge_protected: 1,
    });

    const mapped = mapWafCoverageSummaryRow(summary);
    assert.equal(mapped.edge_protected, 1);
    assert.equal(mapped.protected, 1);
    assert.equal(mapped.coverage_pct, 25);
  });
});

it('keeps SQL legacy summary counts explicitly nonauthoritative and does not renew evidence', () => {
  const legacy = mapWafCoverageSummaryRow({ assets_total: 10, protected: 10, coverage_pct: 100, refreshed_at: '2026-10-08T00:00:00Z' }); assert.equal(legacy.authoritative, false); assert.equal(legacy.assurance_version, 'legacy_materialized_summary');
  const asset = { id: 'a', canonical_url: 'https://a.example.test', tenant_id: 'ten_demo' }; const snapshot = assuredPosture(asset, 'protected'); const current = computeWafCoverageSummaryRow({ assets: [asset], currentSnapshotsByAsset: new Map([[asset.id,snapshot]]), refreshedAt: '2026-11-01T00:00:00Z' }); assert.equal(current.protected, 0); assert.equal(current.unknown, 1);
});


describe('posture actual positive outcome and immutable availability', () => {
  const asset = { id: 'asset_fixture', tenant_id: 'ten_demo', canonical_url: 'https://app.example.test/path' };
  it('keeps independently scoped protected and edge-only current positives from actual enforced evidence', () => {
    for (const status of ['protected', 'edge_protected']) {
      const snapshot = assuredPosture(asset, status);
      const custody = JSON.stringify(snapshot);
      const result = assessPostureAssurance({ asset, snapshot, asOf: ASSURANCE_NOW });
      assert.equal(result.status, status);
      assert.equal(result.current_assurance, status === 'protected' ? 'tested_scenario_only' : 'edge_only_tested_scenario');
      assert.equal(result.retest_required, false);
      assert.equal(result.origin_lockdown, 'not_established');
      assert.equal(JSON.stringify(snapshot), custody);
    }
  });
  it('rejects contradictory or missing actual enforcement despite an unchanged protected envelope, preserving historical custody', () => {
    for (const status of ['protected', 'edge_protected']) for (const enforcement of ['not_enforced', 'partial', 'unknown', null]) {
      const snapshot = assuredPosture(asset, status);
      const metadata = snapshot.evidence_json.result_events[0].metadata;
      if (enforcement == null) delete metadata.enforcement;
      else metadata.enforcement = enforcement;
      assert.equal(snapshot.evidence_json.enforcement, 'enforced', 'retained envelope alone cannot supply outcome');
      const custody = JSON.stringify(snapshot);
      const result = assessPostureAssurance({ asset, snapshot, asOf: ASSURANCE_NOW });
      assert.equal(result.status, 'unknown'); assert.equal(result.historical_status, status);
      assert.equal(result.current_assurance, 'not_established'); assert.equal(result.retest_required, true);
      assert.equal(result.reason, 'actual_positive_outcome_mismatch');
      const counts = computeWafCoverageSummaryRow({ assets: [asset], currentSnapshotsByAsset: new Map([[asset.id, snapshot]]), refreshedAt: ASSURANCE_NOW });
      assert.equal(counts.protected, 0); assert.equal(counts.edge_protected, 0); assert.equal(counts.unknown, 1);
      assert.equal(JSON.stringify(snapshot), custody);
    }
  });
  it('requires every actual signed leg to agree, including metadata_json records', () => {
    const snapshot = assuredPosture(asset);
    const event = snapshot.evidence_json.result_events[0];
    const second = structuredClone(event); second.id = 'contradictory_actual_leg';
    second.metadata_json = { ...second.metadata, enforcement: 'not_enforced' }; delete second.metadata;
    snapshot.evidence_json.result_events.push(second); snapshot.evidence_json.evidence_ids.push(second.id);
    assert.equal(assessPostureAssurance({ asset, snapshot, asOf: ASSURANCE_NOW }).reason, 'actual_positive_outcome_mismatch');
  });
  it('requires finite immutable ingestion even when an observation or created timestamp supplies a fallback', () => {
    for (const ingestion of [undefined, null, 'not-a-timestamp', '2026-10-09T00:00:00.000Z']) {
      const snapshot = assuredPosture(asset);
      const event = snapshot.evidence_json.result_events[0];
      event.created_at = event.timestamp; event.ingested_at = ingestion;
      const custody = JSON.stringify(snapshot);
      const result = assessPostureAssurance({ asset, snapshot, asOf: ASSURANCE_NOW });
      assert.equal(result.status, 'unknown'); assert.equal(result.historical_status, 'protected');
      assert.equal(result.reason, 'referenced_posture_evidence_unverified'); assert.equal(result.retest_required, true);
      assert.equal(JSON.stringify(snapshot), custody);
    }
  });
});
