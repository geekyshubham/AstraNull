import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { getTargetDetail } from '../../src/services/targetDetail.mjs';
import {
  archiveTestPolicy,
  createTestPolicy,
  patchTestPolicy,
} from '../../src/services/testPolicies.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const checkId = 'dns.authoritative_response.safe';

describe('check enable/disable lifecycle (FT-CRUD-CHK-01)', () => {
  afterEach(() => freshStore());

  it('binding, pausing, and archiving a policy is reflected in checks_applied on target detail', async () => {
    freshStore();
    const before = await getTargetDetail(ctx, 'tgt_1');
    assert.equal(before.error, undefined);
    assert.equal(before.checks_applied.some((row) => row.check_id === checkId), false);

    const policy = createTestPolicy(ctx, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: checkId,
      cadence: 'manual',
    });
    assert.equal(policy.error, undefined, JSON.stringify(policy));

    const enabled = await getTargetDetail(ctx, 'tgt_1');
    const bound = enabled.checks_applied.find((row) => row.check_id === checkId);
    assert.ok(bound);
    assert.equal(bound.policy_id, policy.id);
    assert.equal(bound.binding_scope, 'target');

    const paused = patchTestPolicy(ctx, policy.id, { enabled: false });
    assert.equal(paused.error, undefined, JSON.stringify(paused));
    const pausedDetail = await getTargetDetail(ctx, 'tgt_1');
    const pausedRow = pausedDetail.checks_applied.find((row) => row.check_id === checkId);
    assert.ok(pausedRow);
    assert.notEqual(pausedRow.policy_state, 'active');

    assert.deepEqual(archiveTestPolicy(ctx, policy.id), { archived: true, id: policy.id });
    const disabled = await getTargetDetail(ctx, 'tgt_1');
    assert.equal(disabled.checks_applied.some((row) => row.check_id === checkId), false);
  });
});
