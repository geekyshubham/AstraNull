import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildEnvironmentReadinessRows, isActiveTargetGroup } from '../../apps/web/react/src/lib/environments.ts';

describe('environments react helpers', () => {
  it('excludes archived target groups from environment cards', () => {
    const rows = buildEnvironmentReadinessRows({
      targetGroups: [
        { id: 'tg_active', environment_id: 'env_a', archived_at: null },
        { id: 'tg_archived', environment_id: 'env_b', archived_at: '2026-07-01T00:00:00.000Z' }
      ],
      runs: [],
      findings: []
    });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].id, 'env_a');
    assert.equal(rows[0].groups.length, 1);
    assert.equal(isActiveTargetGroup({ archived_at: null }), true);
    assert.equal(isActiveTargetGroup({ archived_at: '2026-07-01T00:00:00.000Z' }), false);
  });

  it('computes coverage from groups with completed or verdicted runs', () => {
    const rows = buildEnvironmentReadinessRows({
      targetGroups: [
        { id: 'tg_one', environment_id: 'env_demo' },
        { id: 'tg_two', environment_id: 'env_demo' }
      ],
      runs: [
        { target_group_id: 'tg_one', status: 'verdicted' },
        { target_group_id: 'tg_one', status: 'completed' },
        { target_group_id: 'tg_two', status: 'running' }
      ],
      findings: []
    });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].completedRuns, 2);
    assert.equal(rows[0].groupsWithEvidence, 1);
    assert.equal(rows[0].coverage, 50);
    assert.equal(rows[0].state, 'partial evidence');
  });

  it('marks covered only when every active group has evidence and no open findings', () => {
    const rows = buildEnvironmentReadinessRows({
      targetGroups: [{ id: 'tg_one', environment_id: 'env_demo' }],
      runs: [{ target_group_id: 'tg_one', status: 'verdicted' }],
      findings: [{ target_group_id: 'tg_one', status: 'open' }]
    });
    assert.equal(rows[0].coverage, 100);
    assert.equal(rows[0].openFindings, 1);
    assert.equal(rows[0].state, 'partial evidence');
  });

  it('returns empty rows when no active target groups exist', () => {
    const rows = buildEnvironmentReadinessRows({
      targetGroups: [{ id: 'tg_archived', environment_id: 'env_demo', archived_at: '2026-07-01T00:00:00.000Z' }],
      runs: [],
      findings: []
    });
    assert.deepEqual(rows, []);
  });
});