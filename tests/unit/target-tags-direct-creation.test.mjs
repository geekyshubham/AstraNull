import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  MAX_TARGET_TAGS,
  normalizeTargetInput,
  normalizeTargetTags,
  targetTagsFromRecord,
} from '../../src/contracts/targetManagement.mjs';
import {
  createTargetDirect,
  createTargetGroup,
  getTargetGroup,
  listTargetGroups,
  listTargets,
  patchTargetById,
} from '../../src/services/targetGroups.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };

afterEach(() => {
  freshStore();
});

describe('normalizeTargetTags', () => {
  it('trims, lowercases, and dedupes', () => {
    assert.deepEqual(normalizeTargetTags(['  Prod ', 'prod', 'Edge']), ['prod', 'edge']);
  });

  it('treats null/undefined as an empty tag list', () => {
    assert.deepEqual(normalizeTargetTags(undefined), []);
    assert.deepEqual(normalizeTargetTags(null), []);
  });

  it('accepts the ADR character set including env: namespaces', () => {
    assert.deepEqual(normalizeTargetTags(['env:production-1', 'team.payments', 'a_b']), [
      'env:production-1',
      'team.payments',
      'a_b',
    ]);
  });

  it('rejects tags that break the pattern with invalid_target_tags', () => {
    for (const bad of [['-leading'], ['has space'], ['UPPER SPACE!'], ['x'.repeat(49)]]) {
      assert.throws(() => normalizeTargetTags(bad), (err) => err.code === 'invalid_target_tags' && err.status === 400);
    }
  });

  it('rejects non-array input and non-string members', () => {
    assert.throws(() => normalizeTargetTags('prod'), (err) => err.code === 'invalid_target_tags');
    assert.throws(() => normalizeTargetTags([{ tag: 'x' }]), (err) => err.code === 'invalid_target_tags');
  });

  it('caps the number of tags at MAX_TARGET_TAGS', () => {
    const tooMany = Array.from({ length: MAX_TARGET_TAGS + 1 }, (_, i) => `tag${i}`);
    assert.throws(() => normalizeTargetTags(tooMany), (err) => err.code === 'invalid_target_tags');
  });
});

describe('normalizeTargetInput tags handling', () => {
  it('bakes tags into metadata and exposes them top-level', () => {
    const result = normalizeTargetInput({ kind: 'fqdn', value: 'a.example.com', tags: ['Prod', 'edge'] });
    assert.deepEqual(result.tags, ['prod', 'edge']);
    assert.deepEqual(result.metadata.tags, ['prod', 'edge']);
  });

  it('does not let a client metadata blob spoof tags', () => {
    const result = normalizeTargetInput({
      kind: 'fqdn',
      value: 'a.example.com',
      metadata: { tags: ['spoofed'], region: 'us' },
    });
    // The reserved `tags` key is stripped from the metadata channel.
    assert.deepEqual(result.tags, []);
    assert.equal(result.metadata.tags, undefined);
    assert.equal(result.metadata.region, 'us');
    assert.ok(result.dropped_fields.includes('tags'));
  });

  it('preserves existing tags on a metadata-only patch', () => {
    const current = { kind: 'fqdn', value: 'a.example.com', metadata: { tags: ['prod'], region: 'us' } };
    const result = normalizeTargetInput({ metadata: { region: 'eu' } }, { current });
    assert.deepEqual(result.tags, ['prod']);
    assert.deepEqual(result.metadata.tags, ['prod']);
    assert.equal(result.metadata.region, 'eu');
  });
});

describe('POST /v1/targets default-group behavior (dev store)', () => {
  it('creates a default_scope group on demand and lands the target in it', () => {
    freshStore();
    const target = createTargetDirect(ctx, { kind: 'fqdn', value: 'direct.example.com', tags: ['env:prod'] });
    assert.equal(target.error, undefined);
    assert.deepEqual(target.tags, ['env:prod']);

    const groups = listTargetGroups(ctx);
    const defaultGroup = groups.find((g) => g.settings_json?.default_scope === true);
    assert.ok(defaultGroup, 'default_scope group should exist');
    assert.equal(defaultGroup.name, 'Default');
    assert.equal(defaultGroup.validation_mode, 'external_only');
    assert.equal(defaultGroup.expected_behavior_default, 'block_at_edge');
    assert.equal(target.target_group_id, defaultGroup.id);
  });

  it('reuses the same default group for subsequent direct targets', () => {
    freshStore();
    const a = createTargetDirect(ctx, { kind: 'fqdn', value: 'one.example.com' });
    const b = createTargetDirect(ctx, { kind: 'fqdn', value: 'two.example.com' });
    assert.equal(a.target_group_id, b.target_group_id);
    const defaults = listTargetGroups(ctx).filter((g) => g.settings_json?.default_scope === true);
    assert.equal(defaults.length, 1);
  });

  it('honors an existing default_scope group instead of creating a second', () => {
    freshStore();
    const existing = createTargetGroup(ctx, { name: 'Scoped', settings_json: { default_scope: true } });
    const target = createTargetDirect(ctx, { kind: 'fqdn', value: 'scoped.example.com' });
    assert.equal(target.target_group_id, existing.id);
  });

  it('routes explicit target_group_id and surfaces tags on the inventory + detail reads', () => {
    freshStore();
    const target = createTargetDirect(ctx, {
      kind: 'fqdn',
      value: 'grouped.example.com',
      tags: ['edge'],
      target_group_id: 'tg_1',
    });
    assert.equal(target.target_group_id, 'tg_1');

    const inventory = listTargets(ctx).find((t) => t.id === target.id);
    assert.deepEqual(inventory.tags, ['edge']);

    const detail = getTargetGroup(ctx, 'tg_1');
    const detailTarget = detail.targets.find((t) => t.id === target.id);
    assert.deepEqual(detailTarget.tags, ['edge']);
  });

  it('404s an unknown explicit group', () => {
    freshStore();
    const result = createTargetDirect(ctx, { kind: 'fqdn', value: 'x.example.com', target_group_id: 'tg_missing' });
    assert.equal(result.error, 'target_group_not_found');
    assert.equal(result.status, 404);
  });

  it('rejects invalid tags with invalid_target_tags', () => {
    freshStore();
    const result = createTargetDirect(ctx, { kind: 'fqdn', value: 'y.example.com', tags: ['bad space'] });
    assert.equal(result.error, 'invalid_target_tags');
    assert.equal(result.status, 400);
  });
});

describe('PATCH /v1/targets/:id (dev store)', () => {
  it('updates tags without erasing other metadata and preserves them on later patches', () => {
    freshStore();
    const created = createTargetDirect(ctx, {
      kind: 'fqdn',
      value: 'patchme.example.com',
      tags: ['prod'],
    });
    const patched = patchTargetById(ctx, created.id, { tags: ['prod', 'edge'] });
    assert.deepEqual(patched.tags, ['prod', 'edge']);
    assert.deepEqual(targetTagsFromRecord(patched), ['prod', 'edge']);

    // A subsequent expected_behavior-only patch must not drop tags.
    const behaviorPatched = patchTargetById(ctx, created.id, { expected_behavior: 'block_at_edge' });
    assert.deepEqual(behaviorPatched.tags, ['prod', 'edge']);
    assert.equal(behaviorPatched.expected_behavior, 'block_at_edge');
  });

  it('clears tags when given an empty array', () => {
    freshStore();
    const created = createTargetDirect(ctx, { kind: 'fqdn', value: 'clear.example.com', tags: ['prod'] });
    const cleared = patchTargetById(ctx, created.id, { tags: [] });
    assert.deepEqual(cleared.tags, []);
  });

  it('404s an unknown target id', () => {
    freshStore();
    const result = patchTargetById(ctx, 'target_missing', { tags: ['x'] });
    assert.equal(result.error, 'not_found');
    assert.equal(result.status, 404);
  });
});
