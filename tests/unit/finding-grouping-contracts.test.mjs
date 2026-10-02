import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  findingRuleDetailHash,
  findingRuleKey,
  findingRuleSiblings,
  groupFindingsByRule,
} from '../../apps/web/react/src/lib/findings-helpers.ts';
import {
  findGroupByKey,
  findingGroupHref,
  findingGroupKey,
  groupFindings,
} from '../../apps/web/react/src/lib/finding-groups.mjs';

/**
 * G02 / ADR-0009: Classic "rule" and Refined "alert" are different grouping entities.
 * These fixtures pin both identity contracts so a change to either key is deliberate.
 */

const targets = [
  { id: 'tgt_a', value: 'a.acme.com', target_group_id: 'tg_1' },
  { id: 'tgt_b', value: 'b.acme.com', target_group_id: 'tg_1' },
];
const checks = [
  { check_id: 'origin.leak_scan.safe', name: 'Origin leak scan' },
  { check_id: 'waf.fingerprint.safe', name: 'WAF fingerprint' },
];

// Same backend-generated outcome on the same asset, reported by two different checks.
const crossCheck = [
  {
    id: 'fnd_origin',
    check_id: 'origin.leak_scan.safe',
    target_id: 'tgt_a',
    target_group_id: 'tg_1',
    title: 'Finding: edge_exposed on a.acme.com',
    severity: 'high',
    status: 'open',
    created_at: '2026-09-01T00:00:00Z',
  },
  {
    id: 'fnd_waf',
    check_id: 'waf.fingerprint.safe',
    target_id: 'tgt_a',
    target_group_id: 'tg_1',
    title: 'Finding: edge_exposed on a.acme.com',
    severity: 'high',
    status: 'open',
    created_at: '2026-09-02T00:00:00Z',
  },
];

// One check with custom titles that embed the asset name.
const perAssetTitles = [
  {
    id: 'fnd_a',
    check_id: 'origin.leak_scan.safe',
    target_id: 'tgt_a',
    title: 'Origin reachable on a.acme.com',
    severity: 'high',
    status: 'open',
    created_at: '2026-09-01T00:00:00Z',
  },
  {
    id: 'fnd_b',
    check_id: 'origin.leak_scan.safe',
    target_id: 'tgt_b',
    title: 'Origin reachable on b.acme.com',
    severity: 'high',
    status: 'open',
    created_at: '2026-09-02T00:00:00Z',
  },
];

describe('grouping identity contracts (G02, ADR-0009)', () => {
  it('pins the Classic rule key: displayed outcome, checks merged', () => {
    assert.deepEqual(crossCheck.map((finding) => findingRuleKey(finding)), [
      'rule:direct server access was found',
      'rule:direct server access was found',
    ]);
  });

  it('pins the Refined alert key: check id + issue identity', () => {
    assert.deepEqual(crossCheck.map((finding) => findingGroupKey(finding, { targets, checks })), [
      'origin.leak_scan.safe|v%3Aedge_exposed',
      'waf.fingerprint.safe|v%3Aedge_exposed',
    ]);
  });

  it('counts the same two findings as one Classic rule and two Refined alerts', () => {
    const rules = groupFindingsByRule(crossCheck, { targets, checks });
    assert.equal(rules.length, 1);
    assert.equal(rules[0].members.length, 2);
    assert.deepEqual([...rules[0].checkIds].sort(), ['origin.leak_scan.safe', 'waf.fingerprint.safe']);

    const alerts = groupFindings(crossCheck, { targets, checks });
    assert.equal(alerts.length, 2);
    assert.deepEqual(alerts.map((group) => group.findingIds), [['fnd_origin'], ['fnd_waf']]);
  });

  it('drills down to different membership in each variant', () => {
    // Classic: finding-detail for the representative, with the rule-wide asset table focused.
    const [rule] = groupFindingsByRule(crossCheck, { targets, checks });
    assert.match(findingRuleDetailHash(rule), /^finding-detail\?id=fnd_[a-z]+&focus=rule-assets$/);
    const siblings = findingRuleSiblings(crossCheck[0], crossCheck, targets).map((finding) => finding.id);
    assert.deepEqual(siblings.sort(), ['fnd_origin', 'fnd_waf']);

    // Refined: each alert key resolves to a group detail containing only its own check's finding.
    const alerts = groupFindings(crossCheck, { targets, checks });
    const key = findingGroupKey(crossCheck[0], { targets, checks });
    assert.equal(findingGroupHref(key), `#finding-group-detail?key=${encodeURIComponent(key)}`);
    assert.deepEqual(findGroupByKey(alerts, key)?.findingIds, ['fnd_origin']);
  });

  it('diverges the other way for per-asset titles: two rules, one alert', () => {
    assert.deepEqual(perAssetTitles.map((finding) => findingRuleKey(finding)), [
      'rule:origin reachable on a.acme.com',
      'rule:origin reachable on b.acme.com',
    ]);
    assert.equal(groupFindingsByRule(perAssetTitles, { targets, checks }).length, 2);

    const alerts = groupFindings(perAssetTitles, { targets, checks });
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].key, 'origin.leak_scan.safe|t%3Aorigin%20reachable');
    assert.deepEqual([...alerts[0].findingIds].sort(), ['fnd_a', 'fnd_b']);
  });

  it('documents the contract instead of calling grouping presentation-only', () => {
    const variant = readFileSync(new URL('../../apps/web/react/src/lib/design-variant.ts', import.meta.url), 'utf8');
    assert.doesNotMatch(variant, /never behavior/);
    assert.match(variant, /ADR-0009/);
    const helpers = readFileSync(new URL('../../apps/web/react/src/lib/findings-helpers.ts', import.meta.url), 'utf8');
    const groups = readFileSync(new URL('../../apps/web/react/src/lib/finding-groups.mjs', import.meta.url), 'utf8');
    assert.match(helpers, /Grouping contract \(ADR-0009\)/);
    assert.match(groups, /Grouping contract \(ADR-0009\)/);
    const adr = readFileSync(new URL('../../docs/adr/0009-finding-rule-and-alert-grouping-contracts.md', import.meta.url), 'utf8');
    assert.match(adr, /findingRuleKey/);
    assert.match(adr, /findingGroupKey/);
  });
});
