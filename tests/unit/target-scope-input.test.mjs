import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bindDeclaredTargetInput, presentTargetSelection } from '../../src/lib/targetScopeInput.mjs';

const ctx = { tenantId: 'ten_a' };
const target = { id: 'tgt_a', tenant_id: 'ten_a', target_group_id: 'private_policy_a' };
const targets = { getTarget: async (scope, id) => scope.tenantId === target.tenant_id && id === target.id ? target : null };

test('direct selection resolves the existing execution policy without mutating the request', async () => {
  const input = { target_id: 'tgt_a', check_id: 'waf.fingerprint.safe' };
  const bound = await bindDeclaredTargetInput(ctx, input, targets);
  assert.equal(bound.input.target_group_id, 'private_policy_a');
  assert.equal(bound.input.target_id, 'tgt_a');
  assert.equal(input.target_group_id, undefined);
});

test('direct selection rejects foreign, absent, malformed, archived scopes', async () => {
  assert.equal((await bindDeclaredTargetInput({ tenantId: 'foreign' }, { target_id: 'tgt_a' }, targets)).error, 'target_not_found');
  assert.equal((await bindDeclaredTargetInput(ctx, { target_id: 'https://owned.example' }, targets)).error, 'invalid_target_selection');
  assert.equal((await bindDeclaredTargetInput(ctx, { target_id: 'tgt_a' }, { getTarget: async () => ({ ...target, deleted_at: '2026-10-08' }) })).error, 'target_not_found');
  assert.equal((await bindDeclaredTargetInput(ctx, { target_id: 'tgt_a' }, {})).status, 503);
});

test('legacy scope-only inputs remain compatible and a scoped list is a supported lookup', async () => {
  const legacy = { target_group_id: 'legacy_scope', check_id: 'check' };
  assert.equal((await bindDeclaredTargetInput(ctx, legacy, {})).input, legacy);
  assert.equal((await bindDeclaredTargetInput(ctx, { target_id: 'tgt_a' }, { listTargets: async () => [target] })).input.target_group_id, 'private_policy_a');
});

test('explicit domain sets are validated in full before execution and rejected by single-target actions', async () => {
  const peer = { ...target, id: 'tgt_b', target_group_id: 'private_policy_b' };
  const lookup = { listTargets: async () => [target, peer] };
  assert.equal((await bindDeclaredTargetInput(ctx, { target_ids: ['tgt_a', 'tgt_b'] }, lookup)).error, 'target_selection_conflict');
  const selected = await bindDeclaredTargetInput(ctx, { target_ids: ['tgt_a', 'tgt_b', 'tgt_a'] }, lookup, { allowMultiple: true });
  assert.deepEqual(selected.input.target_ids, ['tgt_a', 'tgt_b']);
  assert.equal(selected.input.target_id, null);
  assert.equal((await bindDeclaredTargetInput(ctx, { target_ids: ['tgt_a', 'foreign'] }, lookup, { allowMultiple: true })).error, 'target_not_found');
  assert.equal((await bindDeclaredTargetInput(ctx, { target_ids: [] }, lookup, { allowMultiple: true })).status, 400);
});

test('direct representations remove obsolete grouping identifiers without changing stored artifacts', () => {
  const at = new Date();
  const source = { target_group_ids: ['private'], target_group_id: 'private', target: { id: 'target', target_group_name: 'Old group' }, artifacts: [{ target_group: { id: 'private' }, scope_hash: 'immutable' }], at };
  assert.deepEqual(presentTargetSelection(source), { target: { id: 'target' }, artifacts: [{ scope_hash: 'immutable' }], at });
  assert.equal(source.target_group_id, 'private');
  assert.deepEqual(source.target_group_ids, ['private']);
  assert.equal(source.artifacts[0].scope_hash, 'immutable');
});
