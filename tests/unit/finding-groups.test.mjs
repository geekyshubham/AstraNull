import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  FINDING_GROUP_SLA_HOURS,
  assetHasLifecycle,
  assetMembersInLifecycle,
  createFindingGroupIndex,
  findGroupByKey,
  findingGroupHref,
  findingGroupKey,
  findingIssueIdentity,
  findingSlaState,
  findingStatusBucket,
  groupFindings,
  groupSlaSummary,
  matchesFindingFilters,
  sortFindingGroups,
} from '../../apps/web/react/src/lib/finding-groups.mjs';
import { FINDING_SLA_HOURS } from '../../apps/web/react/src/lib/findings-helpers.ts';
import { designVariantStorageKey, parseDesignVariant } from '../../apps/web/react/src/lib/design-variant.ts';

const NOW = Date.parse('2026-01-10T00:00:00Z');
const checks = [
  { check_id: 'origin.leak_scan.safe', name: 'Origin leak scan', vector_family: 'origin', description: 'Bounded origin reachability probe.' },
  { check_id: 'tls.posture.safe', name: 'TLS posture', vector_family: 'tls' },
];
const targets = [
  { id: 'tgt_a', value: 'a.example.test', target_group_id: 'tg_1' },
  { id: 'tgt_b', value: 'b.example.test', name: 'Checkout edge', target_group_id: 'tg_2' },
];
const targetGroups = [
  { id: 'tg_1', name: 'Public web' },
  { id: 'tg_2', name: 'Payments' },
];

function generated(id, verdict, targetId, host, extra = {}) {
  return {
    id,
    check_id: 'origin.leak_scan.safe',
    verdict,
    target_id: targetId,
    target_group_id: targetId === 'tgt_a' ? 'tg_1' : 'tg_2',
    title: `Finding: ${verdict} on ${host}`,
    status: 'open',
    ...extra,
  };
}

describe('finding group keys', () => {
  it('treats the same check and outcome on different targets as one alert', () => {
    const a = generated('f1', 'bypassable', 'tgt_a', 'a.example.test');
    const b = generated('f2', 'Bypassable', 'tgt_b', 'b.example.test');
    assert.equal(findingGroupKey(a), findingGroupKey(b));
    assert.equal(findingGroupKey(a), 'origin.leak_scan.safe|v%3Abypassable');
    assert.notEqual(findingGroupKey(a), findingGroupKey(generated('f3', 'protected', 'tgt_a', 'a.example.test')));
  });

  it('strips target-specific tokens from custom titles', () => {
    const one = { check_id: 'tls.posture.safe', target_id: 'tgt_a', title: 'Weak TLS ciphers on a.example.test' };
    const two = { check_id: 'tls.posture.safe', target_id: 'tgt_b', title: 'Weak TLS ciphers on Checkout edge' };
    const keyOne = findingGroupKey(one, { targets });
    assert.equal(keyOne, findingGroupKey(two, { targets }));
    assert.equal(findingIssueIdentity(one, { targets }).title, 'Weak TLS ciphers');
    assert.equal(findingIssueIdentity(one, { targets }).source, 'title');
  });

  it('only removes whole target tokens, never parts of words', () => {
    const shortTarget = [{ id: 'tgt_web', name: 'web' }];
    const identity = findingIssueIdentity({ check_id: 'x', target_id: 'tgt_web', title: 'Webhook endpoint exposed on web' }, { targets: shortTarget });
    assert.equal(identity.title, 'Webhook endpoint exposed');
  });

  it('falls back to vector family, then none, when no title or verdict exists', () => {
    assert.equal(findingGroupKey({ check_id: 'origin.leak_scan.safe' }, { checks }), 'origin.leak_scan.safe|f%3Aorigin');
    assert.equal(findingGroupKey({ check_id: 'unknown.check' }), 'unknown.check|none');
    assert.equal(findingGroupKey(null), 'unknown-check|none');
  });

  it('keeps keys deterministic and hash safe', () => {
    const finding = { check_id: 'a|b c#d', verdict: 'gap?x&y' };
    const key = findingGroupKey(finding);
    assert.equal(key, findingGroupKey({ ...finding }));
    assert.equal(key.split('|').length, 2);
    assert.doesNotMatch(key, /[#?&\s]/);
    const href = findingGroupHref(key);
    assert.match(href, /^#finding-group-detail\?key=/);
    assert.equal(new URLSearchParams(href.split('?')[1]).get('key'), key);
  });
});

describe('groupFindings', () => {
  const findings = [
    generated('f1', 'bypassable', 'tgt_a', 'a.example.test', { severity: 'medium', created_at: '2026-01-02T00:00:00Z', assignee: 'sre@example.test' }),
    generated('f2', 'bypassable', 'tgt_b', 'b.example.test', { severity: 'critical', status: 'closed', created_at: '2026-01-01T00:00:00Z' }),
    generated('f4', 'bypassable', 'tgt_a', 'a.example.test', { severity: 'low', status: 'accepted_risk', created_at: '2026-01-05T00:00:00Z' }),
    generated('f3', 'protected', 'tgt_a', 'a.example.test', { status: 'closed' }),
  ];
  const groups = groupFindings(findings, { targets, checks, targetGroups, now: NOW });
  const bypass = groups.find((group) => group.verdict === 'bypassable');

  it('collapses members into one group with plain-language, target-agnostic labels', () => {
    assert.equal(groups.length, 2);
    assert.ok(bypass);
    assert.equal(bypass.title, 'A bypass path reached your server');
    assert.equal(bypass.checkLabel, 'Origin leak scan');
    assert.equal(bypass.checkDescription, 'Bounded origin reachability probe.');
    assert.equal(bypass.vectorFamily, 'origin');
    assert.equal(bypass.representativeId, 'f1');
    assert.deepEqual(bypass.findingIds, ['f1', 'f2', 'f4']);
  });

  it('rolls severity up to the worst member', () => {
    assert.equal(bypass.severity, 'critical');
  });

  it('counts statuses by lifecycle bucket', () => {
    assert.deepEqual(bypass.statusCounts, { open: 1, accepted: 1, closed: 1, other: 0 });
    assert.equal(bypass.openCount, 1);
    assert.deepEqual(bypass.statusBreakdown, { open: 1, closed: 1, accepted_risk: 1 });
  });

  it('de-duplicates affected assets and resolves them against the targets dataset', () => {
    assert.equal(bypass.assets.length, 2);
    const [first, second] = bypass.assets;
    assert.equal(first.targetId, 'tgt_a');
    assert.equal(first.host, 'a.example.test');
    assert.equal(first.label, 'a.example.test');
    assert.equal(first.targetGroupName, 'Public web');
    assert.equal(first.findingId, 'f1');
    assert.deepEqual(first.findingIds, ['f1', 'f4']);
    assert.equal(first.statusBucket, 'open');
    assert.equal(first.resolved, true);
    assert.equal(second.label, 'Checkout edge');
    assert.equal(second.host, 'b.example.test');
    assert.equal(second.targetGroupName, 'Payments');
    assert.equal(bypass.openAssetCount, 1);
    assert.deepEqual(bypass.targetGroupIds, ['tg_1', 'tg_2']);
  });

  it('reports owners, dates and SLA from recorded fields only', () => {
    assert.deepEqual(bypass.owners, ['sre@example.test']);
    assert.equal(bypass.unassignedCount, 2);
    assert.equal(bypass.earliestOpenedAt, '2026-01-01T00:00:00.000Z');
    // Only the open medium member carries an SLA clock: created Jan 2 + 72h = Jan 5, breached by Jan 10.
    assert.equal(bypass.nearestSlaDueAt, '2026-01-05T00:00:00.000Z');
    assert.equal(bypass.slaBreachCount, 1);
    assert.equal(bypass.hasSlaBreach, true);
    assert.equal(bypass.assets[0].slaState, 'breached');
    assert.equal(bypass.assets[1].slaState, 'inactive');
  });

  it('sorts groups with open findings first and finds them by key', () => {
    assert.equal(groups[0], bypass);
    assert.equal(findGroupByKey(groups, bypass.key), bypass);
    assert.equal(findGroupByKey(groups, 'missing'), null);
    assert.equal(findGroupByKey(groups, ''), null);
    assert.equal(sortFindingGroups(groups, 'title')[0].title, 'A bypass path reached your server');
    assert.equal(sortFindingGroups(groups, 'assets')[0], bypass);
  });

  it('tolerates malformed input', () => {
    assert.deepEqual(groupFindings(null), []);
    assert.deepEqual(groupFindings([null, 'x', 3]), []);
    const [group] = groupFindings([{ id: 'x' }]);
    assert.equal(group.verdictLabel, 'No conclusion yet');
    assert.equal(group.title, 'Evidence-backed finding');
    assert.equal(group.assets.length, 1);
    assert.equal(group.assets[0].label, 'Target not recorded');
    assert.equal(group.assets[0].resolved, false);
  });
});

describe('finding SLA and filters', () => {
  it('matches the findings-helpers SLA table', () => {
    assert.deepEqual({ ...FINDING_GROUP_SLA_HOURS }, FINDING_SLA_HOURS);
  });

  it('classifies SLA position', () => {
    assert.equal(findingSlaState({ status: 'open', severity: 'critical', created_at: '2026-01-09T12:00:00Z' }, NOW).state, 'due_soon');
    assert.equal(findingSlaState({ status: 'open', severity: 'low', created_at: '2026-01-09T00:00:00Z' }, NOW).state, 'on_track');
    assert.equal(findingSlaState({ status: 'open' }, NOW).state, 'undated');
    assert.equal(findingSlaState({ status: 'closed', created_at: '2026-01-01T00:00:00Z' }, NOW).state, 'inactive');
  });

  it('buckets lifecycle aliases like the classic status tabs', () => {
    assert.equal(findingStatusBucket({}), 'open');
    assert.equal(findingStatusBucket({ state: 'resolved' }), 'closed');
    assert.equal(findingStatusBucket({ status: 'accepted_risk' }), 'accepted');
    assert.equal(findingStatusBucket({ status: 'remediation_pending' }), 'other');
  });

  it('applies status, severity, owner, group and search filters', () => {
    const finding = { id: 'f1', status: 'open', severity: 'high', assignee: 'ops', target_group_id: 'tg_1', check_id: 'tls.posture.safe' };
    assert.equal(matchesFindingFilters(finding, { status: 'open' }), true);
    assert.equal(matchesFindingFilters(finding, { status: 'closed' }), false);
    assert.equal(matchesFindingFilters(finding, { severity: 'low' }), false);
    assert.equal(matchesFindingFilters(finding, { owner: 'ops', targetGroup: 'tg_1' }), true);
    assert.equal(matchesFindingFilters({ status: 'open' }, { owner: 'unassigned' }), true);
    assert.equal(matchesFindingFilters(finding, { search: 'TLS.POSTURE' }), true);
    assert.equal(matchesFindingFilters(finding, { search: 'payments' }), false);
    assert.equal(matchesFindingFilters(finding, { search: 'payments' }, { searchText: () => 'Payments group' }), true);
  });
});

describe('asset members keep their own lifecycle (F06)', () => {
  // One asset, three findings for the same alert: open, accepted and closed, with different owners and groups.
  const members = [
    generated('m_closed', 'bypassable', 'tgt_a', 'a.example.test', { status: 'closed', severity: 'critical', created_at: '2026-01-01T00:00:00Z', assignee: 'net@example.test' }),
    generated('m_accepted', 'bypassable', 'tgt_a', 'a.example.test', { status: 'accepted_risk', severity: 'high', created_at: '2026-01-03T00:00:00Z', assignee: 'risk@example.test', target_group_id: 'tg_2' }),
    generated('m_open', 'bypassable', 'tgt_a', 'a.example.test', { status: 'open', severity: 'low', created_at: '2026-01-05T00:00:00Z' }),
  ];
  const [group] = groupFindings(members, { targets, checks, targetGroups, now: NOW });
  const [asset] = group.assets;

  it('keeps every member record and per-asset lifecycle counts', () => {
    assert.equal(group.assets.length, 1);
    assert.deepEqual(asset.members.map((member) => member.findingId), ['m_open', 'm_closed', 'm_accepted']);
    assert.deepEqual(asset.statusCounts, { open: 1, accepted: 1, closed: 1, other: 0 });
    assert.deepEqual(asset.statusBreakdown, { open: 1, closed: 1, accepted_risk: 1 });
    assert.deepEqual(asset.owners, ['net@example.test', 'risk@example.test']);
    assert.equal(asset.unassignedCount, 1);
    const accepted = asset.members.find((member) => member.findingId === 'm_accepted');
    assert.equal(accepted.statusBucket, 'accepted');
    assert.equal(accepted.owner, 'risk@example.test');
    assert.equal(accepted.targetGroupName, 'Payments');
  });

  it('filters an asset by "has a member in this lifecycle"', () => {
    for (const lifecycle of ['all', 'open', 'accepted', 'closed']) {
      assert.equal(assetHasLifecycle(asset, lifecycle), true, lifecycle);
    }
    assert.equal(assetHasLifecycle(asset, 'other'), false);
    assert.equal(assetHasLifecycle(null, 'all'), false);
  });

  it('exposes a navigable member for each finding, per lifecycle', () => {
    assert.deepEqual(assetMembersInLifecycle(asset, 'all').map((member) => member.findingId), ['m_open', 'm_closed', 'm_accepted']);
    assert.deepEqual(assetMembersInLifecycle(asset, 'accepted').map((member) => member.findingId), ['m_accepted']);
    assert.deepEqual(assetMembersInLifecycle(asset, 'closed').map((member) => member.findingId), ['m_closed']);
    assert.deepEqual(assetMembersInLifecycle({}, 'open'), []);
  });

  it('aggregates group membership from all members, not asset representatives', () => {
    assert.deepEqual(asset.targetGroupIds, ['tg_1', 'tg_2']);
    assert.deepEqual(asset.targetGroupNames, ['Public web', 'Payments']);
    assert.deepEqual([...group.targetGroupIds].sort(), ['tg_1', 'tg_2']);
    assert.equal(group.openAssetCount, 1);
  });

  it('counts an asset as open when a non-representative member is open', () => {
    const [onlyClosedLead] = groupFindings([
      generated('c1', 'bypassable', 'tgt_b', 'b.example.test', { status: 'closed', severity: 'critical' }),
      generated('c2', 'bypassable', 'tgt_b', 'b.example.test', { status: 'remediation_pending', severity: 'critical' }),
    ], { targets, checks, targetGroups, now: NOW });
    assert.equal(onlyClosedLead.assets[0].statusCounts.other, 1);
    assert.equal(assetHasLifecycle(onlyClosedLead.assets[0], 'closed'), true);
    assert.equal(onlyClosedLead.openAssetCount, 0);
  });

  it('wires the detail page to per-member links and lifecycle filtering', () => {
    const source = readFileSync(new URL('../../apps/web/react/src/pages/refined/finding-group-detail.tsx', import.meta.url), 'utf8');
    assert.match(source, /assetMembersInLifecycle\(asset, assetFilter\)/);
    assert.match(source, /assetHasLifecycle\(asset, assetFilter\)/);
    assert.match(source, /buildDetailHref\('finding-detail', member\.findingId\)/);
    assert.doesNotMatch(source, /asset\.statusBucket === assetFilter/);
  });
});

describe('group SLA summary keeps unknown deadlines visible (F09)', () => {
  const open = (id, extra) => generated(id, 'bypassable', 'tgt_a', 'a.example.test', { severity: 'high', ...extra });

  it('reports all-undated open members as SLA unknown, never Within SLA', () => {
    const [group] = groupFindings([open('u1', {}), open('u2', { target_id: 'tgt_b' })], { targets, checks, now: NOW });
    assert.equal(group.openUndatedCount, 2);
    assert.equal(group.openDatedCount, 0);
    const summary = groupSlaSummary(group, NOW);
    assert.equal(summary.state, 'unknown');
    assert.equal(summary.assessment, 'unknown');
    assert.equal(summary.label, 'SLA unknown');
    assert.notEqual(summary.label, 'Within SLA');
  });

  it('reports mixed dated and undated members as partially assessed', () => {
    const [group] = groupFindings([
      open('d1', { created_at: '2026-01-09T12:00:00Z', target_id: 'tgt_b' }),
      open('u1', {}),
    ], { targets, checks, now: NOW });
    const summary = groupSlaSummary(group, NOW);
    assert.equal(summary.assessment, 'partial');
    assert.equal(summary.label, 'Partially assessed');
    assert.equal(summary.datedOpenCount, 1);
    assert.equal(summary.undatedOpenCount, 1);
    assert.equal(summary.nearestDueAt, '2026-01-11T12:00:00.000Z');
  });

  it('still surfaces a known breach when undated members are mixed in', () => {
    const [group] = groupFindings([
      open('b1', { created_at: '2026-01-01T00:00:00Z', target_id: 'tgt_b' }),
      open('u1', {}),
    ], { targets, checks, now: NOW });
    const summary = groupSlaSummary(group, NOW);
    assert.equal(summary.state, 'breached');
    assert.equal(summary.label, '1 overdue');
    assert.equal(summary.assessment, 'partial');
    assert.equal(summary.undatedOpenCount, 1);
  });

  it('says Within SLA only when every open member is dated and none is breached', () => {
    const [group] = groupFindings([open('d1', { created_at: '2026-01-09T00:00:00Z' })], { targets, checks, now: NOW });
    const summary = groupSlaSummary(group, NOW);
    assert.equal(summary.assessment, 'complete');
    assert.equal(summary.label, 'Within SLA');
    const [closed] = groupFindings([open('c1', { status: 'closed' })], { targets, checks, now: NOW });
    assert.equal(groupSlaSummary(closed, NOW).label, 'No clock');
    assert.equal(groupSlaSummary(closed, NOW).assessment, 'none');
  });

  it('keeps the detail page off the old affirmative fallback', () => {
    const source = readFileSync(new URL('../../apps/web/react/src/pages/refined/finding-group-detail.tsx', import.meta.url), 'utf8');
    assert.match(source, /groupSlaSummary\(group\)/);
    assert.doesNotMatch(source, /openCount > 0 \? 'Within SLA'/);
  });
});

describe('recently opened sorts by the newest member (F10)', () => {
  const longLived = [
    { id: 'a1', check_id: 'tls.posture.safe', verdict: 'weak', target_id: 'tgt_a', created_at: '2025-01-01T00:00:00Z' },
    { id: 'a2', check_id: 'tls.posture.safe', verdict: 'weak', target_id: 'tgt_b', created_at: '2025-10-01T00:00:00Z' },
  ];
  const newer = [{ id: 'b1', check_id: 'origin.leak_scan.safe', verdict: 'bypassable', target_id: 'tgt_a', created_at: '2025-09-01T00:00:00Z' }];
  const groups = groupFindings([...longLived, ...newer], { targets, checks, now: NOW });
  const groupA = groups.find((group) => group.checkId === 'tls.posture.safe');
  const groupB = groups.find((group) => group.checkId === 'origin.leak_scan.safe');

  it('tracks both the first and the latest member opening', () => {
    assert.equal(groupA.earliestOpenedAt, '2025-01-01T00:00:00.000Z');
    assert.equal(groupA.latestOpenedAt, '2025-10-01T00:00:00.000Z');
    assert.equal(groupB.latestOpenedAt, '2025-09-01T00:00:00.000Z');
  });

  it('ranks a long-lived alert with a new member above a newer, quiet alert', () => {
    assert.deepEqual(sortFindingGroups(groups, 'recent').map((group) => group.key), [groupA.key, groupB.key]);
  });

  it('keeps oldest-first on the first opening', () => {
    assert.deepEqual(sortFindingGroups(groups, 'oldest').map((group) => group.key), [groupA.key, groupB.key]);
    const [onlyB] = sortFindingGroups([groupB, { ...groupA, earliestOpenedAt: '2025-12-01T00:00:00.000Z' }], 'oldest');
    assert.equal(onlyB, groupB);
  });
});

describe('shared index', () => {
  it('produces the same groups as a plain context', () => {
    const findings = [
      generated('f1', 'bypassable', 'tgt_a', 'a.example.test', { created_at: '2026-01-02T00:00:00Z' }),
      generated('f2', 'bypassable', 'tgt_b', 'b.example.test'),
      { id: 'f3', check_id: 'tls.posture.safe', target_id: 'tgt_b', title: 'Weak TLS ciphers on Checkout edge' },
    ];
    const context = { targets, checks, targetGroups, now: NOW };
    const index = createFindingGroupIndex(context);
    assert.deepEqual(groupFindings(findings, index), groupFindings(findings, context));
    assert.equal(findingGroupKey(findings[2], index), findingGroupKey(findings[2], { targets }));
  });
});

describe('design variant', () => {
  it('parses only the two supported variants', () => {
    assert.equal(parseDesignVariant('Refined'), 'refined');
    assert.equal(parseDesignVariant('classic'), 'classic');
    assert.equal(parseDesignVariant('premium'), null);
    assert.equal(parseDesignVariant(undefined), null);
  });

  it('stores each page under its own key', () => {
    assert.equal(designVariantStorageKey('runs'), 'astranull.design-variant.runs');
    assert.equal(designVariantStorageKey('test-policies'), 'astranull.design-variant.test-policies');
  });
});
