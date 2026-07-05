import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computeFindingKpis,
  filterFindingsByTab,
  formatVectorFamilyLabel,
  groupFindingsByTargetGroup,
  groupFindingsByVector,
  isFindingSlaBreach,
  resolveFindingRetestAction
} from '../../apps/web/react/src/lib/findings-helpers.ts';

const NOW = Date.parse('2026-07-05T12:00:00.000Z');

describe('findings-helpers', () => {
  it('computes KPI rollups from live finding records', () => {
    const findings = [
      { id: 'f1', status: 'open', severity: 'critical', created_at: '2026-07-01T00:00:00.000Z' },
      { id: 'f2', status: 'open', severity: 'high', created_at: '2026-07-05T10:00:00.000Z' },
      { id: 'f3', status: 'accepted_risk', severity: 'medium', created_at: '2026-06-01T00:00:00.000Z' },
      { id: 'f4', status: 'closed', severity: 'low', created_at: '2026-06-01T00:00:00.000Z', updated_at: '2026-07-04T00:00:00.000Z' }
    ];

    const kpis = computeFindingKpis(findings, NOW);
    assert.equal(kpis.openCount, 2);
    assert.match(kpis.openSeverityBreakdown, /1 critical/);
    assert.match(kpis.openSeverityBreakdown, /1 high/);
    assert.equal(kpis.acceptedRiskCount, 1);
    assert.equal(kpis.closed30dCount, 1);
    assert.equal(kpis.slaBreachCount, 1);
  });

  it('filters findings by UX tab ids including vector and SLA views', () => {
    const findings = [
      { id: 'f1', status: 'open', severity: 'critical', created_at: '2026-07-01T00:00:00.000Z', target_group_id: 'tg_a', check_id: 'origin.safe' },
      { id: 'f2', status: 'accepted_risk', severity: 'high', created_at: '2026-07-01T00:00:00.000Z', target_group_id: 'tg_b', check_id: 'dns.safe' },
      { id: 'f3', status: 'closed', severity: 'low', created_at: '2026-06-01T00:00:00.000Z', updated_at: '2026-07-04T00:00:00.000Z' }
    ];
    const checks = [
      { check_id: 'origin.safe', vector_family: 'origin' },
      { check_id: 'dns.safe', vector_family: 'dns' }
    ];

    assert.equal(filterFindingsByTab(findings, 'open', checks, NOW).length, 1);
    assert.equal(filterFindingsByTab(findings, 'accepted-risk', checks, NOW).length, 1);
    assert.equal(filterFindingsByTab(findings, 'closed', checks, NOW).length, 1);
    assert.equal(filterFindingsByTab(findings, 'sla', checks, NOW).length, 1);
    assert.equal(filterFindingsByTab(findings, 'vector', checks, NOW).length, 1);
    assert.equal(filterFindingsByTab(findings, 'target-group', checks, NOW).length, 1);
  });

  it('groups open findings by target group and vector family', () => {
    const findings = [
      { id: 'f1', status: 'open', target_group_id: 'tg_a', check_id: 'origin.safe' },
      { id: 'f2', status: 'open', target_group_id: 'tg_a', check_id: 'dns.safe' },
      { id: 'f3', status: 'open', target_group_id: 'tg_b', check_id: 'l7.safe', vector_family: 'l7' }
    ];
    const targetGroups = [{ id: 'tg_a', name: 'Retail Checkout' }];
    const checks = [
      { check_id: 'origin.safe', vector_family: 'origin' },
      { check_id: 'dns.safe', vector_family: 'dns' },
      { check_id: 'l7.safe', vector_family: 'l7' }
    ];

    const byGroup = groupFindingsByTargetGroup(findings, targetGroups);
    assert.equal(byGroup.length, 2);
    assert.equal(byGroup.find((group) => group.groupId === 'tg_a')?.label, 'Retail Checkout');
    assert.equal(byGroup.find((group) => group.groupId === 'tg_a')?.items.length, 2);

    const byVector = groupFindingsByVector(findings, checks);
    assert.deepEqual(
      byVector.map((group) => group.label).sort(),
      ['DNS', 'L7/API', 'Origin']
    );
  });

  it('formats vector labels and resolves retest actions', () => {
    assert.equal(formatVectorFamilyLabel('l3_l4'), 'L3/L4');
    assert.equal(formatVectorFamilyLabel('high_scale'), 'High-scale');

    assert.deepEqual(resolveFindingRetestAction({
      check_id: 'waf.posture.asset_1'
    }), { kind: 'waf-validation', wafAssetId: 'asset_1' });

    assert.deepEqual(resolveFindingRetestAction({
      check_id: 'cve.pipeline.item_1',
      cve_pipeline_item_id: 'item_1'
    }), { kind: 'cve-retest', pipelineId: 'item_1' });

    assert.deepEqual(resolveFindingRetestAction({
      check_id: 'origin.direct_bypass.safe'
    }), { kind: 'safe-run', checkId: 'origin.direct_bypass.safe' });
  });

  it('flags SLA breach only for open findings past severity window', () => {
    const breached = {
      status: 'open',
      severity: 'critical',
      created_at: '2026-07-01T00:00:00.000Z'
    };
    const fresh = {
      status: 'open',
      severity: 'critical',
      created_at: '2026-07-05T08:00:00.000Z'
    };
    const closed = {
      status: 'closed',
      severity: 'critical',
      created_at: '2026-07-01T00:00:00.000Z'
    };

    assert.equal(isFindingSlaBreach(breached, NOW), true);
    assert.equal(isFindingSlaBreach(fresh, NOW), false);
    assert.equal(isFindingSlaBreach(closed, NOW), false);
  });
});