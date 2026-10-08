import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { createHighScaleRequest, transitionHighScale } from '../../src/services/highScale.mjs';
import { computeTargetGroupScopeHash, computeScopeHashFromTargets } from '../../src/lib/scopeHash.mjs';
import { normalizeHighScaleTargetSelection, mergeRiskReviewOntoRequest } from '../../src/lib/highScalePolicy.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { validHighScaleRequestPayload } from '../helpers/highScalePayload.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'engineer', role: 'engineer' };
beforeEach(() => {
  freshStore();
  getStore().targets.push({ ...getStore().targets[0], id: 'peer', value: 'peer.test' });
});

test('a selected governed domain never expands to other domains in the retained policy', () => {
  const req = createHighScaleRequest(ctx, { ...validHighScaleRequestPayload({ target_group_id: 'tg_1' }), target_id: 'tgt_1' });
  assert.ok(req.id, JSON.stringify(req));
  assert.deepEqual(req.target_ids, ['tgt_1']);
  assert.equal(req.scope_hash, computeScopeHashFromTargets('tg_1', [getStore().targets[0]]));
  assert.notEqual(req.scope_hash, computeTargetGroupScopeHash(ctx.tenantId, 'tg_1'));
  getStore().targets.push({ ...getStore().targets[0], id: 'later', value: 'later.test' });
  assert.equal(req.scope_hash, computeTargetGroupScopeHash(ctx.tenantId, 'tg_1', req.target_ids));
  getStore().targets[0].deleted_at = new Date().toISOString();
  assert.equal(transitionHighScale({ ...ctx, userId: 'soc_a', role: 'soc' }, req.id, 'approve').error, 'target_not_found');
  assert.equal(req.adapter?.traffic_generated, undefined);
});

test('governed domain selection rejects malformed and unknown IDs and survives persistence projection', () => {
  assert.equal(normalizeHighScaleTargetSelection({ target_ids: [] }).error, 'invalid_target_selection');
  assert.equal(normalizeHighScaleTargetSelection({ target_id: 'https://untrusted.test' }).error, 'invalid_target_selection');
  const denied = createHighScaleRequest(ctx, { ...validHighScaleRequestPayload({ target_group_id: 'tg_1' }), target_ids: ['foreign'] });
  assert.equal(denied.error, 'target_not_found');
  assert.deepEqual(mergeRiskReviewOntoRequest({}, { target_ids: ['tgt_1'] }).target_ids, ['tgt_1']);
  assert.equal(getStore().highScaleRequests.length, 0);
});

test('an explicit governed domain set can span retained policies and cannot authorize an unselected peer', () => {
  const store = getStore();
  store.targetGroups.push({ ...store.targetGroups[0], id: 'secondary_policy' });
  store.targets.push({ ...store.targets[0], id: 'other_domain', value: 'other.test', target_group_id: 'secondary_policy' });
  const req = createHighScaleRequest(ctx, { ...validHighScaleRequestPayload({ target_group_id: 'tg_1' }), target_ids: ['tgt_1', 'other_domain'] });
  assert.ok(req.id, JSON.stringify(req));
  assert.deepEqual(req.target_ids, ['tgt_1', 'other_domain']);
  assert.equal(req.scope_hash, computeScopeHashFromTargets('tg_1', store.targets.filter((target) => req.target_ids.includes(target.id))));
  const oldHash = req.scope_hash;
  store.targets.find((target) => target.id === 'peer').value = 'changed-unselected.test';
  assert.equal(computeTargetGroupScopeHash(ctx.tenantId, 'tg_1', req.target_ids), oldHash);
});
