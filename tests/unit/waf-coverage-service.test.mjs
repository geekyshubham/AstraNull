import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildCoverageSummary,
  computeCoverageDailyRollup,
  buildCriticalityRollup,
  buildEntityRollup,
  buildGeographyRollup,
  buildRiskRoadmap,
  buildVendorBreakdown,
  buildVendorConsolidation,
} from '../../src/services/wafCoverageService.mjs';

import { assuredPosture } from '../helpers/assurance-fixtures.mjs';
const now = new Date('2026-07-03T12:00:00.000Z');
const assets = [
  {
    id: 'asset_a', tenant_id: 'ten_demo', created_at: '2026-07-01T00:00:00.000Z',
    canonical_url: 'https://pay.example.com',
    owner_hint: 'payments',
    business_criticality: 'payment',
    target_group_id: 'tg_1',
  },
  {
    id: 'asset_b', tenant_id: 'ten_demo', created_at: '2026-07-01T00:00:00.000Z',
    canonical_url: 'https://www.example.com',
    owner_hint: 'marketing',
    business_criticality: 'low',
    target_group_id: 'tg_2',
  },
];

const snapshots = new Map(assets.map((asset, index) => [asset.id, { ...assuredPosture(asset, index ? 'protected' : 'unprotected', '2026-07-03T10:00:00.000Z'), detected_vendor: index ? 'akamai' : 'cloudflare', detected_product: index ? 'Akamai WAF' : 'Cloudflare WAF' }]));

describe('audited historical coverage regressions', () => {
  it('does not backfill a present snapshot or status into an earlier cutoff', () => {
    const summary = buildCoverageSummary({
      assets: [{ id: 'later', created_at: '2026-07-01T00:00:00.000Z', status: 'protected' }],
      currentSnapshotsByAsset: new Map([['later', assuredPosture({ id: 'later', canonical_url: 'https://later.example.test', tenant_id: 'ten_demo' }, 'protected', '2026-07-03T10:00:00.000Z')]]),
      now: new Date('2026-07-03T12:00:00.000Z'), windowDays: 3,
    });
    assert.equal(summary.trend[0].protected, 0);
    assert.equal(summary.trend[0].unknown, 1);
  });
});

describe('wafCoverageService', () => {
  it('builds coverage summary ratio and trend buckets', () => {
    const summary = buildCoverageSummary({
      assets,
      currentSnapshotsByAsset: snapshots, now,
      historicalSnapshots: [...snapshots.values()],
      windowDays: 7,
      now: new Date('2026-07-03T12:00:00.000Z'),
    });

    assert.equal(summary.total, 2);
    assert.equal(summary.total_assets, 2);
    assert.equal(summary.protected, 1);
    assert.equal(summary.unprotected, 1);
    assert.equal(summary.coverage_ratio, 0.5);
    assert.equal(summary.trend.length, 7);
    assert.equal(summary.trend.at(-1).protected, 1);
  });

  it('computes a single-day coverage rollup bucket', () => {
    const rollup = computeCoverageDailyRollup({
      assets,
      currentSnapshotsByAsset: snapshots, now,
      rollupDate: '2026-07-03',
    });
    assert.equal(rollup.rollup_date, '2026-07-03');
    assert.equal(rollup.total_assets, 2);
    assert.equal(rollup.protected, 1);
    assert.equal(rollup.unprotected, 1);
    assert.equal(rollup.coverage_ratio, 0.5);
  });

  it('uses persisted daily rollups for coverage trend when provided', () => {
    const summary = buildCoverageSummary({
      assets,
      currentSnapshotsByAsset: snapshots, now,
      coverageRollups: [
        {
          rollup_date: '2026-07-01',
          total_assets: 10,
          protected: 4,
          underprotected: 1,
          unprotected: 3,
          unknown: 2,
          excluded: 0,
          coverage_ratio: 0.4,
        },
        {
          rollup_date: '2026-07-02',
          total_assets: 10,
          protected: 5,
          underprotected: 1,
          unprotected: 2,
          unknown: 2,
          excluded: 0,
          coverage_ratio: 0.5,
        },
      ],
      windowDays: 7,
      now: new Date('2026-07-03T12:00:00.000Z'),
    });

    assert.equal(summary.trend.length, 2);
    assert.deepEqual(summary.trend.map((entry) => entry.date), ['2026-07-01', '2026-07-02']);
    assert.equal(summary.trend[0].coverage_ratio, 0.4);
    assert.equal(summary.trend[1].total_assets, 10);
    assert.equal(summary.protected, 1);
  });

  it('rolls up vendor mix for executive charts', () => {
    const vendors = buildVendorBreakdown({
      assets,
      currentSnapshotsByAsset: snapshots, now,
    });

    assert.equal(vendors.items.length, 2);
    assert.ok(vendors.vendor_mix.some((entry) => entry.vendor === 'cloudflare'));
    assert.equal(
      vendors.items.find((entry) => entry.vendor === 'cloudflare').unprotected_count,
      1,
    );
  });

  it('rolls up criticality buckets with critical gap counts', () => {
    const criticality = buildCriticalityRollup({
      assets,
      currentSnapshotsByAsset: snapshots, now,
    });

    const payment = criticality.items.find((item) => item.business_criticality === 'payment');
    assert.ok(payment);
    assert.equal(payment.asset_count, 1);
    assert.equal(payment.unprotected, 1);
    assert.equal(payment.critical_gap_count, 1);
    assert.equal(payment.coverage_ratio, 0);

    const low = criticality.items.find((item) => item.business_criticality === 'low');
    assert.ok(low);
    assert.equal(low.protected, 1);
    assert.equal(low.critical_gap_count, 0);
  });

  it('rolls up entities from owner hints', () => {
    const entities = buildEntityRollup({
      assets,
      currentSnapshotsByAsset: snapshots, now,
      targetGroups: [
        { id: 'tg_1', name: 'Payments', settings_json: {} },
        { id: 'tg_2', name: 'Marketing', settings_json: {} },
      ],
    });

    assert.ok(entities.items.some((item) => item.name === 'payments'));
    assert.ok(entities.items.some((item) => item.critical_gap_count >= 1));
  });

  it('rolls up geography from declared target-group metadata', () => {
    const geography = buildGeographyRollup({
      assets,
      currentSnapshotsByAsset: snapshots, now,
      targetGroups: [
        {
          id: 'tg_1',
          name: 'Payments',
          environment_id: 'env_us',
          settings_json: { region_code: 'us-east', region_label: 'US East' },
        },
        {
          id: 'tg_2',
          name: 'Marketing',
          settings_json: { region_code: 'eu-west', region_label: 'EU West' },
        },
      ],
      environments: [{ id: 'env_us', name: 'US Prod', data_region: 'us-east' }],
    });

    assert.ok(geography.items.some((item) => item.region_code === 'us-east'));
    assert.ok(geography.items.some((item) => item.region_code === 'eu-west'));
  });

  it('keeps edge-only protection visible in entity, criticality, and geography rollups', () => {
    const edgeAsset = {
      id: 'asset_edge', tenant_id: 'ten_demo', canonical_url: 'https://edge.example.test',
      target_group_id: 'tg_edge',
      owner_hint: 'edge-team',
      business_criticality: 'high',
    };
    const edgeSnapshots = new Map([
      ['asset_edge', assuredPosture(edgeAsset, 'edge_protected', '2026-07-03T10:00:00.000Z')],
    ]);
    const targetGroups = [{
      id: 'tg_edge',
      name: 'Edge',
      settings_json: { region_code: 'us-edge', region_label: 'US Edge' },
    }];

    const entity = buildEntityRollup({
      assets: [edgeAsset],
      currentSnapshotsByAsset: edgeSnapshots, now,
      targetGroups,
    }).items[0];
    const criticality = buildCriticalityRollup({
      assets: [edgeAsset],
      currentSnapshotsByAsset: edgeSnapshots, now,
    }).items[0];
    const geography = buildGeographyRollup({
      assets: [edgeAsset],
      currentSnapshotsByAsset: edgeSnapshots, now,
      targetGroups,
    }).items[0];

    for (const item of [entity, criticality, geography]) {
      assert.equal(item.asset_count, 1);
      assert.equal(item.edge_protected, 1);
      assert.equal(item.coverage_ratio, 0);
    }
    assert.equal(entity.protected, 0);
    assert.equal(criticality.protected, 0);
  });

  it('builds tiered roadmap with recommended actions', () => {
    const roadmap = buildRiskRoadmap({
      assets,
      currentSnapshotsByAsset: snapshots, now,
      validationSummaryByAsset: new Map([
        ['asset_a', { validation_failed: true }],
        ['asset_b', { validation_passed: true }],
      ]),
      generatedAt: '2026-07-03T12:00:00.000Z',
    });

    assert.equal(roadmap.method, 'waf_risk_v2');
    assert.ok(roadmap.tiers.tier_1.length >= 1);
    assert.equal(roadmap.tiers.tier_1[0].waf_asset_id, 'asset_a');
    assert.ok(roadmap.tiers.tier_1[0].risk_score >= 50);
  });

  it('returns read-only vendor consolidation advisory metadata', () => {
    const advisory = buildVendorConsolidation({
      assets: [
        assets[0],
        {
          ...assets[1],
          canonical_url: 'https://api.example.com',
          id: 'asset_c',
        },
      ],
      currentSnapshotsByAsset: new Map([
        ...snapshots.entries(),
        [
          'asset_c',
          {
            waf_asset_id: 'asset_c',
            status: 'protected',
            detected_vendor: 'cloudflare',
            detected_product: 'Cloudflare WAF',
          },
        ],
      ]),
      connectors: [{ provider: 'cloudflare', status: 'active' }],
      driftEvents: [],
    });

    assert.ok(advisory.vendor_footprint.length >= 1);
    assert.ok(advisory.consolidation_opportunities[0].advisory === 'non_prescriptive');
    assert.ok(advisory.operating_cost_signals[0].advisory === 'read_only_operating_cost_signal');
  });
});


describe('immutable posture coverage and event-time history', () => {
  it('never upgrades a fresh unsigned legacy status or absent snapshot into assurance', () => {
    const asset = { id: 'legacy', canonical_url: 'https://legacy.example.test', tenant_id: 'ten_demo', created_at: '2026-07-01T00:00:00Z', status: 'protected' };
    const summary = buildCoverageSummary({ assets: [asset], currentSnapshotsByAsset: new Map([[asset.id, { status: 'protected', created_at: now.toISOString() }]]), now });
    assert.equal(summary.protected, 0); assert.equal(summary.unknown, 1); assert.equal(summary.coverage_ratio, 0);
  });
  it('respects declaration retirement and evidence availability at each daily cutoff', () => {
    const a = { id: 'a', canonical_url: 'https://a.example.test', tenant_id: 'ten_demo', created_at: '2026-07-01T00:00:00Z', retired_at: '2026-07-03T00:00:00Z' };
    const b = { id: 'b', canonical_url: 'https://b.example.test', tenant_id: 'ten_demo', created_at: '2026-07-02T00:00:00Z' };
    const late = assuredPosture(b, 'protected', '2026-07-02T10:00:00Z'); late.created_at = '2026-07-03T00:00:00Z';
    const history = buildCoverageSummary({ assets: [a,b], historicalSnapshots: [assuredPosture(a, 'protected', '2026-07-01T10:00:00Z'), late], now, windowDays: 3 }).trend;
    assert.deepEqual(history.map((r) => r.total_assets), [1,2,1]); assert.deepEqual(history.map((r) => r.protected), [1,1,1]); assert.equal(history[1].unknown, 1);
    assert.equal(history[0].semantics_version, 'waf-coverage-history.v2');
  });
  it('uses immutable observations, not summary refresh, and detects material URL changes', () => {
    const before = structuredClone(snapshots); const summary = buildCoverageSummary({ assets, currentSnapshotsByAsset: snapshots, now: new Date('2026-08-03T12:00:00Z') }); assert.equal(summary.protected, 0); assert.equal(summary.unknown, 2); assert.deepEqual(snapshots, before);
    const changed = buildCoverageSummary({ assets: assets.map((a) => ({ ...a, canonical_url: a.canonical_url + '/changed' })), currentSnapshotsByAsset: snapshots, now }); assert.equal(changed.unknown, 2);
  });
  it('rejects future dates and normalized impossible calendar days', () => {
    for (const rollupDate of ['2026-07-04', '2026-02-30', 'not-a-date']) assert.throws(() => computeCoverageDailyRollup({ now, rollupDate }), /invalid_or_future_rollup_date/);
  });
  it('labels preserved materialized trend history as noncurrent assurance', () => {
    const summary = buildCoverageSummary({ assets, currentSnapshotsByAsset: snapshots, now, coverageRollups: [{ rollup_date: '2026-07-02', protected: 100, total_assets: 100, coverage_ratio: 1 }] }); assert.equal(summary.protected, 1); assert.equal(summary.trend[0].semantics_version, 'legacy_persisted_rollup');
  });
});
