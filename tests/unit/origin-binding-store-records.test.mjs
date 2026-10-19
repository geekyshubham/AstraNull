import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { bindingRecordsFromStore } from '../../src/services/originBindings.mjs';

const tenantId = 'ten_binding_records';
const target = (id, targetGroupId, extra = {}) => ({ id, tenant_id: tenantId, target_group_id: targetGroupId, ...extra });
const group = (id, extra = {}) => ({ id, tenant_id: tenantId, ...extra });

describe('origin binding store records', () => {
  it('preserves target visibility, strict group identity, order and proof-array references', () => {
    const store = {
      targets: [
        target('active', 'active'),
        target('deleted-group', 'deleted'),
        target('missing-group', 'missing'),
        target('archived-group', 'archived'),
        target('deleted-target', 'active', { deleted_at: '2026-10-20' }),
        target('archived-target', 'active', { archived_at: '2026-10-20' }),
        target('foreign-target', 'active', { tenant_id: 'ten_other' }),
        target('duplicate-group', 'duplicate'),
        target('foreign-group', 'foreign-only'),
        target('foreign-collision', 'collision'),
        target('string-id', '7'),
        target('number-id', 7),
        target('nan-id', NaN),
        target('null-id', null),
        target('undefined-id', undefined),
      ],
      targetGroups: [
        group('active'), group('deleted', { deleted_at: '2026-10-20' }),
        group('archived', { archived_at: '2026-10-20' }),
        group('duplicate'), group('duplicate', { archived_at: '2026-10-20' }),
        group('foreign-only', { tenant_id: 'ten_other', deleted_at: '2026-10-20' }),
        group('collision'), group('collision', { tenant_id: 'ten_other', archived_at: '2026-10-20' }),
        group(7, { deleted_at: '2026-10-20' }), group('7'),
        group(NaN, { archived_at: '2026-10-20' }),
        group(null, { deleted_at: '2026-10-20' }),
        group(undefined, { archived_at: '2026-10-20' }),
      ],
      targetVerifications: [{ tenant_id: tenantId }, { tenant_id: 'ten_other' }],
      wafConnectors: [{ id: 'connector' }],
      wafConnectorSnapshots: [{ id: 'snapshot' }],
    };
    const result = bindingRecordsFromStore(store, tenantId);
    assert.deepEqual(result.targets.map(({ id }) => id), [
      'active', 'missing-group', 'foreign-group', 'foreign-collision', 'string-id', 'nan-id',
    ]);
    for (const row of result.targets) assert.equal(row, store.targets.find(({ id }) => id === row.id));
    for (const key of ['targetVerifications', 'wafConnectors', 'wafConnectorSnapshots']) {
      assert.equal(result[key], store[key]);
    }
  });

  it('recomputes group visibility on each call and retains empty-store fallbacks', () => {
    assert.deepEqual(bindingRecordsFromStore({}, tenantId), {
      targets: [], targetVerifications: [], wafConnectors: [], wafConnectorSnapshots: [],
    });
    const row = target('target', 'group');
    const store = { targets: [row], targetGroups: [group('group')] };
    assert.deepEqual(bindingRecordsFromStore(store, tenantId).targets, [row]);
    store.targetGroups[0].archived_at = '2026-10-20';
    assert.deepEqual(bindingRecordsFromStore(store, tenantId).targets, []);
    delete store.targetGroups[0].archived_at;
    assert.deepEqual(bindingRecordsFromStore(store, tenantId).targets, [row]);
    store.targetGroups = null;
    assert.deepEqual(bindingRecordsFromStore(store, tenantId).targets, [row]);
  });

  it('reads group identities at most once per group rather than once per target', () => {
    let groupIdReads = 0;
    const targetGroups = Array.from({ length: 200 }, (_, index) => ({
      tenant_id: tenantId,
      archived_at: index % 2 ? '2026-10-20' : null,
      get id() { groupIdReads += 1; return `group_${index}`; },
    }));
    const targets = Array.from({ length: 120 }, (_, index) => target(`target_${index}`, `group_${index}`));
    const result = bindingRecordsFromStore({ targets, targetGroups }, tenantId);
    assert.deepEqual(result.targets, targets.filter((_, index) => index % 2 === 0));
    assert.ok(groupIdReads <= targetGroups.length, `group identity reads ${groupIdReads} must not multiply by target count`);
  });
});
