import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computeFindingKpis,
  filterFindingsByTab,
  countFindingAssets,
  findingAssetLabel,
  findingObservedAt,
  findingRuleDetailHash,
  findingRuleKey,
  findingRuleSiblings,
  findingRuleTitle,
  findingSeverityRank,
  formatVectorFamilyLabel,
  groupFindingsByRule,
  groupFindingsByTargetGroup,
  groupFindingsByVector,
  findingStatus,
  previewRuleAssets,
  findingAssetIdentity,
  findingClosedAt,
  findingRuleSlaMeta,
  sortFindingRuleGroups,
  summarizeFindingStatuses,
  isFindingOpen,
  isFindingSlaBreach,
  resolveFindingRetestAction,
  normalizeSeverity,
  findingSlaHours
} from '../../apps/web/react/src/lib/findings-helpers.ts';
import { findingGroupSlaHours } from '../../apps/web/react/src/lib/finding-groups.mjs';

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

  it('counts S1-S4 severities in the same class the severity badge shows', () => {
    const findings = [
      { id: 's2-open', status: 'open', severity: 's2', created_at: '2026-07-05T10:00:00.000Z' },
      { id: 's1-open', status: 'open', severity: 'S1', created_at: '2026-07-05T10:00:00.000Z' },
      { id: 'moderate-open', status: 'open', severity: 'moderate', created_at: '2026-07-05T10:00:00.000Z' },
      { id: 'odd-open', status: 'open', severity: 'sev-x', created_at: '2026-07-05T10:00:00.000Z' }
    ];

    const kpis = computeFindingKpis(findings, NOW);
    assert.equal(kpis.openCount, 4);
    assert.match(kpis.openSeverityBreakdown, /1 critical/);
    assert.match(kpis.openSeverityBreakdown, /1 high/);
    assert.match(kpis.openSeverityBreakdown, /1 medium/);
    assert.match(kpis.openSeverityBreakdown, /1 unknown/);
    assert.doesNotMatch(kpis.openSeverityBreakdown, /low/);
    assert.equal(normalizeSeverity(' S2 '), 'high');
    assert.equal(normalizeSeverity('s4'), 'low');
    assert.equal(normalizeSeverity(undefined), 'unknown');
    assert.equal(findingSlaHours('s2'), 48);
    assert.equal(findingGroupSlaHours('s2'), 48);
  });

  it('normalizes state-only lifecycle records from the portal API', () => {
    const findings = [
      { id: 'state-open', state: ' Open ', severity: 'critical', created_at: '2026-07-01T00:00:00.000Z' },
      { id: 'state-accepted', state: ' ACCEPTED ', severity: 'medium', created_at: '2026-07-02T00:00:00.000Z' },
      { id: 'state-closed', state: ' closed ', severity: 'low', created_at: '2026-06-01T00:00:00.000Z', updated_at: '2026-07-04T00:00:00.000Z' }
    ];

    const kpis = computeFindingKpis(findings, NOW);
    assert.equal(kpis.openCount, 1);
    assert.equal(kpis.acceptedRiskCount, 1);
    assert.equal(kpis.closed30dCount, 1);
    assert.equal(kpis.slaBreachCount, 1);
    assert.deepEqual(filterFindingsByTab(findings, 'open', [], NOW).map((finding) => finding.id), ['state-open']);
    assert.deepEqual(filterFindingsByTab(findings, 'accepted-risk', [], NOW).map((finding) => finding.id), ['state-accepted']);
    assert.deepEqual(filterFindingsByTab(findings, 'closed', [], NOW).map((finding) => finding.id), ['state-closed']);
    assert.equal(findingStatus({ status: ' CLOSED ', state: 'open' }), 'closed');
    assert.equal(findingStatus({ status: '   ', state: ' Resolved ' }), 'resolved');
    assert.equal(isFindingOpen({ state: ' oPeN ' }), true);
    assert.equal(isFindingOpen({ state: ' closed ' }), false);
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

  describe('rule grouping', () => {
    const targets = [
      { id: 'tgt_api', value: 'api.example.com' },
      { id: 'tgt_web', value: 'www.example.com' },
      { id: 'tgt_ip', value: '203.0.113.10' }
    ];
    const findings = [
      { id: 'f_api', check_id: 'origin.leak_scan.safe', target_id: 'tgt_api', target_group_id: 'tg_a', title: 'Finding: edge_exposed on api.example.com', severity: 'medium', status: 'open', created_at: '2026-07-02T00:00:00.000Z', updated_at: '2026-07-04T00:00:00.000Z' },
      { id: 'f_web', check_id: 'origin.leak_scan.safe', target_id: 'tgt_web', target_group_id: 'tg_b', title: 'Finding: edge_exposed on www.example.com', severity: 'critical', status: 'open', created_at: '2026-07-03T00:00:00.000Z' },
      { id: 'f_ip', check_id: 'origin.leak_scan.safe', target_id: 'tgt_ip', target_group_id: 'tg_a', title: 'Finding: edge_exposed on 203.0.113.10', severity: 'low', status: 'accepted_risk', created_at: '2026-07-01T00:00:00.000Z' },
      { id: 'f_dns', check_id: 'dns.authoritative_response.safe', target_id: 'tgt_api', title: 'Finding: edge_exposed on api.example.com', severity: 'high', status: 'open', created_at: '2026-07-01T00:00:00.000Z' },
      { id: 'f_title_a', title: 'Rate limit drift', severity: 's3', state: 'open' },
      { id: 'f_title_b', title: '  rate LIMIT   drift ', severity: 's2', state: 'closed' }
    ];

    it('collapses findings that share an outcome into one rule regardless of severity or check', () => {
      const groups = groupFindingsByRule(findings, { targets });
      // edge_exposed from the origin and DNS checks is one "Direct server access was found" rule.
      assert.equal(groups.length, 2);
      const origin = groups.find((group) => group.checkId === 'origin.leak_scan.safe');
      assert.ok(origin);
      assert.equal(origin.title, 'Direct server access was found');
      assert.equal(origin.members.length, 4);
      assert.equal(origin.worstSeverity, 'critical');
      assert.deepEqual(origin.assets.map((asset) => asset.label), ['www.example.com', 'api.example.com', '203.0.113.10']);
      assert.deepEqual(origin.statusCounts, { open: 3, accepted_risk: 1 });
      assert.deepEqual(origin.checkIds, ['origin.leak_scan.safe', 'dns.authoritative_response.safe']);
      assert.deepEqual(origin.targetGroupIds.sort(), ['tg_a', 'tg_b']);
      assert.equal(origin.representativeId, 'f_web');
      assert.equal(origin.lastObservedAt, Date.parse('2026-07-04T00:00:00.000Z'));
      assert.equal(origin.firstOpenedAt, Date.parse('2026-07-01T00:00:00.000Z'));
      assert.equal(origin.lastOpenedAt, Date.parse('2026-07-03T00:00:00.000Z'));
      // Earliest SLA among open members only: high 48h from 07-01 beats critical 24h from 07-03.
      assert.equal(origin.earliestOpenSlaDueAt, Date.parse('2026-07-03T00:00:00.000Z'));
      assert.equal(groups.filter((group) => group.title === 'Direct server access was found').length, 1);

      const titled = groups.find((group) => group.title === 'Rate limit drift');
      assert.equal(titled?.members.length, 2);
      assert.equal(titled?.worstSeverity, 's2');
    });

    it('keeps different outcomes of the same check as separate rules', () => {
      const split = groupFindingsByRule([
        { id: 'a', check_id: 'origin.leak_scan.safe', verdict: 'edge_exposed', target_id: 'tgt_api' },
        { id: 'b', check_id: 'origin.leak_scan.safe', verdict: 'bypassable', target_id: 'tgt_web' }
      ], { targets });
      assert.equal(split.length, 2);
    });

    it('counts only the filtered members it is given', () => {
      const openOnly = findings.filter(isFindingOpen);
      const origin = groupFindingsByRule(openOnly, { targets }).find((group) => group.checkId === 'origin.leak_scan.safe');
      assert.equal(origin?.members.length, 3);
      assert.deepEqual(origin?.statusCounts, { open: 3 });
      assert.equal(origin?.assets.length, 2);
      const lowOnly = groupFindingsByRule(findings.filter((finding) => finding.severity === 'low'), { targets });
      assert.equal(lowOnly.length, 1);
      assert.equal(lowOnly[0].worstSeverity, 'low');
      assert.equal(groupFindingsByRule([], { targets }).length, 0);
    });

    it('labels assets from target records, generated titles, then target-group scope', () => {
      assert.equal(findingAssetLabel({ target_id: 'tgt_ip' }, targets), '203.0.113.10');
      assert.equal(findingAssetLabel({ target_id: 'tgt_missing', title: 'Finding: exposed on cdn.example.com' }, targets), 'cdn.example.com');
      assert.equal(findingAssetLabel({ target_hostname: 'edge.example.com', target_id: 'tgt_api' }, targets), 'edge.example.com');
      assert.equal(findingAssetLabel({ target_group_id: 'tg_a' }, targets), 'Target-group scope tg_a');
      assert.equal(findingAssetLabel({ target_group_id: 'tg_a' }, targets, [{ id: 'tg_a', name: 'Payments' }]), 'Payments (target-group scope)');
      assert.equal(findingAssetLabel({}, targets), 'Asset not recorded');
      assert.equal(findingRuleTitle({ title: 'Origin direct bypass' }), 'Origin direct bypass');
    });

    it('falls back to check id, then finding id, when no outcome or title is recorded', () => {
      assert.equal(findingRuleKey({ id: 'x', check_id: 'tls.cert.safe' }), findingRuleKey({ id: 'y', check_id: 'tls.cert.safe' }));
      assert.notEqual(findingRuleKey({ id: 'x' }), findingRuleKey({ id: 'y' }));
      assert.equal(findingRuleKey({ verdict: 'exposed' }), findingRuleKey({ title: 'Finding: edge_exposed on a.example.com' }));
    });

    it('prefers last_observed_at for observation time and sorts recent by latest opening', () => {
      assert.equal(findingObservedAt({ last_observed_at: '2026-07-05T00:00:00.000Z', updated_at: '2026-07-01T00:00:00.000Z' }), Date.parse('2026-07-05T00:00:00.000Z'));
      const groups = groupFindingsByRule(findings, { targets });
      assert.equal(sortFindingRuleGroups(groups, 'recent')[0].checkId, 'origin.leak_scan.safe');
    });

    it('sorts groups and summarizes statuses and asset previews', () => {
      const groups = groupFindingsByRule(findings, { targets });
      assert.equal(sortFindingRuleGroups(groups, 'severity')[0].worstSeverity, 'critical');
      assert.equal(sortFindingRuleGroups(groups, 'assets')[0].assets.length, 3);
      assert.deepEqual(sortFindingRuleGroups(groups, 'title').map((group) => group.title), [...groups.map((group) => group.title)].sort((a, b) => a.localeCompare(b)));
      assert.equal(summarizeFindingStatuses({ closed: 1, accepted_risk: 2, open: 3 }), '3 open, 2 accepted risk, 1 closed');
      assert.deepEqual(previewRuleAssets([{ key: 'a', label: 'a' }, { key: 'b', label: 'b' }, { key: 'c', label: 'c' }]), { shown: ['a', 'b'], remaining: 1 });
      assert.equal(findingSeverityRank('S1'), 0);
      assert.equal(findingSeverityRank('nonsense'), 9);
    });

    it('opens single-asset rules directly and multi-asset rules on the affected-asset list', () => {
      const groups = groupFindingsByRule(findings, { targets });
      const origin = groups.find((group) => group.checkId === 'origin.leak_scan.safe');
      const [single] = groupFindingsByRule([findings[3]], { targets });
      assert.equal(findingRuleDetailHash(origin), 'finding-detail?id=f_web&focus=rule-assets');
      assert.equal(findingRuleDetailHash(single), 'finding-detail?id=f_dns');
      assert.equal(findingRuleDetailHash({ representativeId: '', assets: [], members: [] }), '');
    });

    it('lists rule siblings for the detail view, including a finding missing from the list', () => {
      const siblings = findingRuleSiblings(findings[0], findings, targets);
      assert.deepEqual(siblings.map((finding) => finding.id), ['f_web', 'f_dns', 'f_api', 'f_ip']);
      const orphan = { id: 'f_new', check_id: 'origin.leak_scan.safe', title: 'Finding: edge_exposed on new.example.com', status: 'open' };
      assert.equal(findingRuleSiblings(orphan, findings, targets).length, 5);
      // Two findings on tgt_api (origin and DNS checks) are one affected asset.
      assert.equal(countFindingAssets(siblings, targets), 3);
      assert.equal(findingRuleKey(orphan), findingRuleKey(findings[0]));
    });
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

  describe('asset identity (F07)', () => {
    const groupScoped = [
      { id: 'f_g1', title: 'Rate limit drift', target_group_id: 'g1', status: 'open', severity: 'high' },
      { id: 'f_g2', title: 'Rate limit drift', target_group_id: 'g2', status: 'open', severity: 'high' }
    ];

    it('counts two group-scoped findings in different groups as two assets', () => {
      const [group] = groupFindingsByRule(groupScoped, { targetGroups: [{ id: 'g1', name: 'Payments' }] });
      assert.deepEqual(group.assets, [
        { key: 'group:g1', label: 'Payments (target-group scope)' },
        { key: 'group:g2', label: 'Target-group scope g2' }
      ]);
      assert.equal(countFindingAssets(groupScoped), 2);
    });

    it('merges findings scoped to the same group into one asset', () => {
      const same = [groupScoped[0], { ...groupScoped[1], id: 'f_g1b', target_group_id: 'g1' }];
      assert.equal(groupFindingsByRule(same)[0].assets.length, 1);
      assert.equal(countFindingAssets(same), 1);
    });

    it('never merges unscoped records with each other', () => {
      const unscoped = [
        { id: 'f_u1', title: 'Rate limit drift', status: 'open' },
        { id: 'f_u2', title: 'Rate limit drift', status: 'open' }
      ];
      const [group] = groupFindingsByRule(unscoped);
      assert.deepEqual(group.assets.map((asset) => asset.key), ['finding:f_u1', 'finding:f_u2']);
      assert.equal(countFindingAssets(unscoped), 2);
    });

    it('keys resolved targets by target id even when the group differs', () => {
      const targets = [{ id: 'tgt_api', value: 'api.example.com' }];
      const resolved = [
        { id: 'f_a', title: 'Rate limit drift', target_id: 'tgt_api', target_group_id: 'g1', status: 'open' },
        { id: 'f_b', title: 'Rate limit drift', target_id: 'tgt_api', target_group_id: 'g2', status: 'closed' }
      ];
      assert.deepEqual(findingAssetIdentity(resolved[0], targets), { key: 'target:tgt_api', label: 'api.example.com' });
      const [group] = groupFindingsByRule(resolved, { targets });
      assert.equal(group.assets.length, 1);
      assert.equal(countFindingAssets(resolved, targets), group.assets.length);
    });

    it('agrees between rule cards and detail counts on mixed records', () => {
      const targets = [{ id: 'tgt_api', value: 'api.example.com' }];
      const mixed = [
        ...groupScoped,
        { id: 'f_t', title: 'Rate limit drift', target_id: 'tgt_api' },
        { id: 'f_h', title: 'Rate limit drift', target_hostname: 'edge.example.com', target_group_id: 'g1' },
        { id: 'f_u', title: 'Rate limit drift' }
      ];
      const [group] = groupFindingsByRule(mixed, { targets });
      assert.equal(group.assets.length, 5);
      assert.equal(countFindingAssets(findingRuleSiblings(mixed[0], mixed, targets), targets), group.assets.length);
    });
  });

  describe('rule SLA lifecycle (F08)', () => {
    const fmt = (value) => new Date(value).toISOString();
    const observed = '2026-10-01T00:00:00.000Z';
    const slaFor = (members) => findingRuleSlaMeta(groupFindingsByRule(members)[0], fmt, NOW);

    it('reads closure time only from recorded closure fields on closed lifecycles', () => {
      assert.equal(findingClosedAt({ status: 'closed', closed_at: '2026-07-01T00:00:00.000Z' }), Date.parse('2026-07-01T00:00:00.000Z'));
      assert.equal(findingClosedAt({ state: 'resolved', resolved_at: '2026-07-02T00:00:00.000Z' }), Date.parse('2026-07-02T00:00:00.000Z'));
      assert.equal(findingClosedAt({ status: 'closed', last_observed_at: observed, updated_at: observed }), null);
      assert.equal(findingClosedAt({ status: 'accepted_risk', closed_at: '2026-07-01T00:00:00.000Z' }), null);
    });

    it('labels accepted-risk-only groups as risk accepted with no closure date', () => {
      const sla = slaFor([{ id: 'a1', title: 'Drift', status: 'accepted_risk', last_observed_at: observed, updated_at: observed }]);
      assert.deepEqual(sla, { label: 'Risk accepted', tone: 'muted', due: 'No active SLA' });
      assert.doesNotMatch(`${sla.label} ${sla.due}`, /closed/i);
    });

    it('shows no active SLA for mixed accepted and closed groups, with the recorded closure only', () => {
      const closedAt = '2026-07-03T00:00:00.000Z';
      const sla = slaFor([
        { id: 'a1', title: 'Drift', status: 'accepted', last_observed_at: observed },
        { id: 'c1', title: 'Drift', status: 'closed', closed_at: closedAt, last_observed_at: observed }
      ]);
      assert.equal(sla.label, 'No active SLA');
      assert.equal(sla.due, `Last closed ${fmt(Date.parse(closedAt))}`);
      const undated = slaFor([
        { id: 'a1', title: 'Drift', status: 'accepted', last_observed_at: observed },
        { id: 'c1', title: 'Drift', status: 'closed', last_observed_at: observed }
      ]);
      assert.deepEqual(undated, { label: 'No active SLA', tone: 'muted', due: '' });
    });

    it('shows closed without a date when no closure timestamp was recorded', () => {
      const sla = slaFor([{ id: 'c1', title: 'Drift', status: 'closed', last_observed_at: observed, updated_at: observed }]);
      assert.deepEqual(sla, { label: 'Closed', tone: 'muted', due: '' });
    });

    it('shows the latest recorded closure date for closed and resolved groups', () => {
      const sla = slaFor([
        { id: 'c1', title: 'Drift', status: 'closed', closed_at: '2026-07-01T00:00:00.000Z', last_observed_at: observed },
        { id: 'c2', title: 'Drift', status: 'resolved', resolved_at: '2026-07-04T00:00:00.000Z' }
      ]);
      assert.equal(sla.label, `Closed ${fmt(Date.parse('2026-07-04T00:00:00.000Z'))}`);
    });

    it('keeps open-member SLA behavior for active groups', () => {
      const overdue = slaFor([{ id: 'o1', title: 'Drift', status: 'open', severity: 'critical', created_at: '2026-07-01T00:00:00.000Z' }]);
      assert.equal(overdue.label, 'Overdue');
      assert.equal(overdue.tone, 'danger');
      const fresh = slaFor([{ id: 'o2', title: 'Drift', status: 'open', severity: 'critical', created_at: '2026-07-05T08:00:00.000Z' }]);
      assert.equal(fresh.label, '20h left');
    });
  });
});
