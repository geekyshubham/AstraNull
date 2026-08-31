import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computeWafCoverageSummaryRow,
  mapWafCoverageSummaryRow,
} from '../../src/lib/wafCoverageSummary.mjs';

describe('WAF dashboard coverage summary', () => {
  it('keeps edge-protected assets separate from full protected coverage', () => {
    const assets = [
      { id: 'asset_protected' },
      { id: 'asset_edge' },
      { id: 'asset_under' },
      { id: 'asset_unknown' },
    ];
    const currentSnapshotsByAsset = new Map([
      ['asset_protected', { status: 'protected', detected_vendor: 'vendor-a' }],
      ['asset_edge', { status: 'edge_protected', detected_vendor: 'vendor-a' }],
      ['asset_under', { status: 'underprotected', detected_vendor: 'vendor-b' }],
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
