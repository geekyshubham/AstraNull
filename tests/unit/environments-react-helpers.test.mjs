import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildEnvironmentReadinessRows, isActiveTargetGroup } from '../../apps/web/react/src/lib/environments.ts';

/**
 * Environment rows are built from authoritative `/v1/environments` records only.
 * Coverage counts a group only when a run in that group has a verdict backed by an
 * evidence record bound to that exact run id.
 */
describe('environments react helpers', () => {
  it('renders only authoritative environment records, never groups as environments', () => {
    const rows = buildEnvironmentReadinessRows({
      environments: [{ id: 'env_a', name: 'Env A' }],
      targetGroups: [
        { id: 'tg_active', environment_id: 'env_a', archived_at: null },
        { id: 'tg_other', environment_id: 'env_undeclared', archived_at: null }
      ],
      runs: [],
      findings: [],
      evidence: []
    });

    assert.equal(rows.length, 1);
    assert.equal(rows[0].id, 'env_a');
    assert.equal(rows[0].groups.length, 1);
    assert.equal(rows[0].state, 'needs evidence');
  });

  it('excludes archived target groups from environment rows', () => {
    const rows = buildEnvironmentReadinessRows({
      environments: [{ id: 'env_a', name: 'Env A' }, { id: 'env_b', name: 'Env B' }],
      targetGroups: [
        { id: 'tg_active', environment_id: 'env_a', archived_at: null },
        { id: 'tg_archived', environment_id: 'env_b', archived_at: '2026-07-01T00:00:00.000Z' }
      ],
      runs: [],
      findings: [],
      evidence: []
    });

    assert.equal(rows.length, 2);
    assert.equal(rows.find((row) => row.id === 'env_a')?.groupCount, 1);
    assert.equal(rows.find((row) => row.id === 'env_b')?.groupCount, 0);
    assert.equal(isActiveTargetGroup({ archived_at: null }), true);
    assert.equal(isActiveTargetGroup({ archived_at: '2026-07-01T00:00:00.000Z' }), false);
  });

  it('computes coverage only from published verdicts with bound evidence', () => {
    const rows = buildEnvironmentReadinessRows({
      environments: [{ id: 'env_demo', name: 'Demo' }],
      targetGroups: [
        { id: 'tg_one', environment_id: 'env_demo' },
        { id: 'tg_two', environment_id: 'env_demo' }
      ],
      runs: [
        { id: 'run_1', target_group_id: 'tg_one', status: 'verdicted', verdict: 'protected' },
        { id: 'run_2', target_group_id: 'tg_one', status: 'completed', verdict: { verdict: 'exposed' } },
        { id: 'run_3', target_group_id: 'tg_two', status: 'running' }
      ],
      findings: [],
      evidence: [{ test_run_id: 'run_1' }, { test_run_id: 'run_2' }]
    });

    assert.equal(rows.length, 1);
    assert.equal(rows[0].evidenceBackedRuns, 2);
    assert.equal(rows[0].groupsWithEvidence, 1);
    assert.equal(rows[0].coverage, 50);
    assert.equal(rows[0].state, 'partial evidence');
  });

  it('never credits a terminal run status without a published verdict', () => {
    const rows = buildEnvironmentReadinessRows({
      environments: [{ id: 'env_demo', name: 'Demo' }],
      targetGroups: [{ id: 'tg_one', environment_id: 'env_demo' }],
      runs: [{ id: 'run_1', target_group_id: 'tg_one', status: 'completed' }],
      findings: [],
      evidence: [{ test_run_id: 'run_1' }]
    });

    assert.equal(rows[0].evidenceBackedRuns, 0);
    assert.equal(rows[0].state, 'needs evidence');
  });

  it('does not count a published verdict without bound evidence', () => {
    const rows = buildEnvironmentReadinessRows({
      environments: [{ id: 'env_demo', name: 'Demo' }],
      targetGroups: [{ id: 'tg_one', environment_id: 'env_demo' }],
      runs: [{ id: 'run_1', target_group_id: 'tg_one', status: 'verdicted', verdict: 'protected' }],
      findings: [],
      evidence: [{ test_run_id: 'run_other' }]
    });

    assert.equal(rows[0].evidenceBackedRuns, 0);
    assert.equal(rows[0].coverage, 0);
    assert.equal(rows[0].state, 'needs evidence');
  });

  it('marks covered only when every active group has evidence and no open findings', () => {
    const input = {
      environments: [{ id: 'env_demo', name: 'Demo' }],
      targetGroups: [{ id: 'tg_one', environment_id: 'env_demo' }],
      runs: [{ id: 'run_1', target_group_id: 'tg_one', status: 'verdicted', verdict: 'protected' }],
      evidence: [{ test_run_id: 'run_1' }]
    };

    const withOpenFinding = buildEnvironmentReadinessRows({
      ...input,
      findings: [{ target_group_id: 'tg_one', state: ' Open ' }]
    });
    assert.equal(withOpenFinding[0].coverage, 100);
    assert.equal(withOpenFinding[0].openFindings, 1);
    assert.equal(withOpenFinding[0].state, 'partial evidence');

    const resolved = buildEnvironmentReadinessRows({ ...input, findings: [] });
    assert.equal(resolved[0].openFindings, 0);
    assert.equal(resolved[0].state, 'covered');
  });

  it('returns empty rows when no authoritative environment records exist', () => {
    const rows = buildEnvironmentReadinessRows({
      environments: [],
      targetGroups: [{ id: 'tg_one', environment_id: 'env_demo' }],
      runs: [],
      findings: [],
      evidence: []
    });

    assert.deepEqual(rows, []);
  });
});
