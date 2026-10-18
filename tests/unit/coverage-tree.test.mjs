import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { coverageCell, openFindingChecksByTarget, rollUpCoverage, rowHasResult } from '../../apps/web/react/src/lib/coverage-tree.mjs';
import { rollUpPostureRows } from '../../apps/web/react/src/lib/dashboard-metrics.ts';
import { subdomainParentMap, topLevelAncestor } from '../../apps/web/react/src/lib/subdomain-grouping.ts';

const NOW = Date.parse('2026-10-18T00:00:00Z');

function run(id, targetId, checkId, verdict) {
  return {
    id,
    target_id: targetId,
    check_id: checkId,
    status: 'completed',
    completed_at: '2026-10-17T00:00:00Z',
    verdict: { id: `v-${id}`, test_run_id: id, target_id: targetId, check_id: checkId, verdict, evidence_ids: [`ev-${id}`] }
  };
}

describe('coverage tree cells', () => {
  it('reports untested when no evidence-backed run exists', () => {
    const cell = coverageCell({ checkIds: new Set(['a']), targetId: 't1', runs: [], evidence: [], nowMs: NOW });
    assert.equal(cell.outcome, 'untested');
    assert.equal(cell.testedHosts, 0);
  });

  it('reports passing only when every applicable check passed', () => {
    const runs = [run('r1', 't1', 'a', 'protected')];
    assert.equal(coverageCell({ checkIds: new Set(['a']), targetId: 't1', runs, evidence: [], nowMs: NOW }).outcome, 'pass');
    assert.equal(coverageCell({ checkIds: new Set(['a', 'b']), targetId: 't1', runs, evidence: [], nowMs: NOW }).outcome, 'partial');
  });

  it('treats an open finding on a covered check as a gap', () => {
    const open = openFindingChecksByTarget([{ target_id: 't1', check_id: 'a', status: 'open' }, { target_id: 't1', check_id: 'z', status: 'resolved' }]);
    assert.deepEqual([...open.get('t1')], ['a']);
    assert.equal(coverageCell({ checkIds: new Set(['a']), targetId: 't1', runs: [], evidence: [], openChecks: open.get('t1'), nowMs: NOW }).outcome, 'gap');
  });

  it('is not applicable without mapped checks', () => {
    assert.equal(coverageCell({ checkIds: new Set(), targetId: 't1', runs: [], evidence: [], nowMs: NOW }).outcome, 'na');
  });

  it('rolls subdomains up to the worst outcome and counts tested hosts', () => {
    const cells = [
      { outcome: 'pass', hosts: 1, testedHosts: 1, testedChecks: 1, applicableChecks: 1 },
      { outcome: 'gap', hosts: 1, testedHosts: 1, testedChecks: 1, applicableChecks: 1 },
      { outcome: 'untested', hosts: 1, testedHosts: 0, testedChecks: 0, applicableChecks: 1 }
    ];
    const total = rollUpCoverage(cells);
    assert.equal(total.outcome, 'gap');
    assert.equal(total.hosts, 3);
    assert.equal(total.testedHosts, 2);
    assert.equal(rowHasResult([cells[2]]), false);
    assert.equal(rowHasResult(cells), true);
  });
});

describe('subdomain hierarchy', () => {
  const targets = [
    { id: 'root', kind: 'fqdn', value: 'example.com', target_group_id: 'g' },
    { id: 'api', kind: 'fqdn', value: 'api.example.com', target_group_id: 'g' },
    { id: 'v1', kind: 'fqdn', value: 'v1.api.example.com', target_group_id: 'g' },
    { id: 'other', kind: 'fqdn', value: 'other.org', target_group_id: 'g' }
  ];

  it('maps each subdomain to its nearest declared parent', () => {
    const parents = subdomainParentMap(targets);
    assert.equal(parents.get('api'), 'root');
    assert.equal(parents.get('v1'), 'api');
    assert.equal(parents.has('root'), false);
    assert.equal(topLevelAncestor('v1', parents), 'root');
    assert.equal(topLevelAncestor('other', parents), 'other');
  });

  it('folds subdomain posture into its domain row', () => {
    const base = { kind: 'fqdn', groupId: 'g', groupName: '', tags: [], verified: true, verificationState: 'dns_verified', verdict: '', verdictBasis: 'none', verdictRunId: '', openFindings: 0, lastValidatedAt: '' };
    const rows = [
      { ...base, id: 'root', value: 'example.com', verdictStatus: 'none' },
      { ...base, id: 'api', value: 'api.example.com', verdictStatus: 'pass' },
      { ...base, id: 'v1', value: 'v1.api.example.com', verdictStatus: 'none', openFindings: 2 },
      { ...base, id: 'other', value: 'other.org', verdictStatus: 'none' }
    ];
    const parents = subdomainParentMap(targets);
    const rolled = rollUpPostureRows(rows, (id) => topLevelAncestor(id, parents));
    assert.deepEqual(rolled.map((row) => row.id), ['root', 'other']);
    assert.equal(rolled[0].verdictStatus, 'gap');
    assert.equal(rolled[0].openFindings, 2);
    assert.equal(rolled[0].hostCount, 3);
    assert.equal(rolled[0].testedHostCount, 2);
    assert.equal(rolled[1].verdictStatus, 'none');
  });
});
