import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  TARGET_GROUP_FINDINGS_LIMIT,
  addTarget,
  archiveTargetGroup,
  createTargetGroup,
  deleteTarget,
  getTargetGroup,
  listTargetGroups,
  patchTarget,
  patchTargetGroup,
} from '../../src/services/targetGroups.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'engineer' };

describe('target group service CRUD', () => {
  beforeEach(() => {
    freshStore();
  });

  it('patches group settings and excludes archived groups from list/get', () => {
    const group = createTargetGroup(ctx, { name: 'Original' });
    const patched = patchTargetGroup(ctx, group.id, {
      name: 'Updated',
      description: 'New description',
      timezone: 'America/New_York',
    });
    assert.equal(patched.name, 'Updated');
    assert.equal(patched.description, 'New description');
    assert.equal(patched.timezone, 'America/New_York');

    const archived = archiveTargetGroup(ctx, group.id);
    assert.equal(archived.archived, true);
    assert.equal(getTargetGroup(ctx, group.id), null);
    assert.equal(listTargetGroups(ctx).some((g) => g.id === group.id), false);
  });

  it('blocks archive when an active run exists for the group', () => {
    const group = createTargetGroup(ctx, { name: 'Busy group' });
    const target = addTarget(ctx, group.id, { value: 'busy.example.com' });
    getStore().testRuns.push({
      id: 'run_active',
      tenant_id: ctx.tenantId,
      target_group_id: group.id,
      target_id: target.id,
      status: 'running',
      check_id: 'dns_authority_exposure',
    });

    const blocked = archiveTargetGroup(ctx, group.id);
    assert.equal(blocked.error, 'target_group_active_run');
    assert.equal(blocked.status, 409);
  });

  it('patches and deletes targets with active-run guard', () => {
    const group = createTargetGroup(ctx, { name: 'Targets' });
    const target = addTarget(ctx, group.id, { value: 'one.example.com' });

    const patched = patchTarget(ctx, group.id, target.id, {
      value: 'two.example.com',
      metadata: { source: 'manual' },
    });
    assert.equal(patched.value, 'two.example.com');
    assert.deepEqual(patched.metadata, { source: 'manual' });

    getStore().testRuns.push({
      id: 'run_target_active',
      tenant_id: ctx.tenantId,
      target_group_id: group.id,
      target_id: target.id,
      status: 'collecting',
      check_id: 'dns_authority_exposure',
    });
    const blocked = deleteTarget(ctx, group.id, target.id);
    assert.equal(blocked.error, 'target_active_run');
    assert.equal(blocked.status, 409);

    getStore().testRuns.pop();
    const deleted = deleteTarget(ctx, group.id, target.id);
    assert.equal(deleted.deleted, true);
    assert.equal(getTargetGroup(ctx, group.id).targets.length, 0);
  });

  it('persists optional onboard metadata (agent_id binding, notes) on add', () => {
    const group = createTargetGroup(ctx, { name: 'Onboard metadata' });

    // FQDN onboard form binds a target to a specific agent.
    const bound = addTarget(ctx, group.id, {
      kind: 'fqdn',
      value: 'origin.example.com',
      expected_behavior: 'block_at_edge',
      metadata: { agent_id: 'agt_edge_1' },
    });
    assert.deepEqual(bound.metadata, { agent_id: 'agt_edge_1' });

    // IP onboard form captures a free-text note.
    const noted = addTarget(ctx, group.id, {
      kind: 'ip',
      value: '203.0.113.10:443',
      expected_behavior: 'absorb_at_origin',
      metadata: { notes: 'Origin behind CDN · single-AZ' },
    });
    assert.deepEqual(noted.metadata, { notes: 'Origin behind CDN · single-AZ' });

    // A target added without metadata must not carry an empty metadata object.
    const plain = addTarget(ctx, group.id, { kind: 'fqdn', value: 'plain.example.com' });
    assert.equal(plain.metadata, undefined);

    // All three survive the round-trip through getTargetGroup.
    const reloaded = getTargetGroup(ctx, group.id).targets;
    assert.equal(reloaded.find((t) => t.value === 'origin.example.com').metadata.agent_id, 'agt_edge_1');
    assert.equal(reloaded.find((t) => t.value === '203.0.113.10:443').metadata.notes, 'Origin behind CDN · single-AZ');
  });

  it('caps findings_on_group at 50 newest-first and reports the full total', () => {
    const group = createTargetGroup(ctx, { name: 'Noisy group' });
    const total = TARGET_GROUP_FINDINGS_LIMIT + 5;
    for (let i = 0; i < total; i += 1) {
      getStore().findings.push({
        id: `fnd_cap_${String(i).padStart(3, '0')}`,
        tenant_id: ctx.tenantId,
        target_group_id: group.id,
        title: `Finding ${i}`,
        severity: 'medium',
        status: 'open',
        created_at: new Date(Date.UTC(2026, 0, 1, 0, i)).toISOString(),
      });
    }
    // A same-tenant finding on another group must not leak into either the list or the total.
    getStore().findings.push({
      id: 'fnd_cap_other_group',
      tenant_id: ctx.tenantId,
      target_group_id: 'tg_1',
      title: 'Elsewhere',
      severity: 'low',
      status: 'open',
      created_at: new Date(Date.UTC(2026, 5, 1)).toISOString(),
    });

    const detail = getTargetGroup(ctx, group.id);
    assert.equal(detail.findings_on_group.length, TARGET_GROUP_FINDINGS_LIMIT);
    assert.equal(detail.findings_on_group_total, total);
    assert.equal(detail.findings_on_group[0].id, `fnd_cap_${String(total - 1).padStart(3, '0')}`);
    assert.equal(
      detail.findings_on_group.at(-1).id,
      `fnd_cap_${String(total - TARGET_GROUP_FINDINGS_LIMIT).padStart(3, '0')}`,
    );
    assert.equal(detail.findings_on_group.some((f) => f.id === 'fnd_cap_other_group'), false);
  });
});