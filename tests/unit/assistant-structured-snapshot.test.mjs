import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAssistantStore, registerStructuredPurpose } from '../../src/services/assistant.mjs';

const ctx = { tenantId: 'ten_a', userId: 'usr_a', role: 'admin' };
const cfg = { assistant: { enabled: true, tenants: ['ten_a'], runnerToken: 'fixture-only', model: 'fixture' } };

function setup() {
  let clock = Date.parse('2026-10-19T12:00:00Z');
  const store = createAssistantStore({ now: () => clock });
  const audits = [];
  registerStructuredPurpose('snapshot_test', {
    parse(content, { context, validation, sources }) {
      const result = JSON.parse(content);
      return result.id === validation.ids[0] && context.target_id === 'tgt_a' && Array.isArray(sources) ? result : null;
    },
  });
  store.markRunnerSeen();
  return { store, audits, deps: { recordAudit: async (entry) => audits.push(entry) }, tick(ms) { clock += ms; } };
}
const request = (validation = { ids: ['fnd_a'] }) => ({ purpose: 'snapshot_test', prompt: 'Fixture prompt', context: { target_id: 'tgt_a' }, validation, requiredPermissions: ['target_group:read'] });

describe('private structured-job snapshots', () => {
  it('clones the binding and never publishes, audits or leases private validation', async () => {
    const { store, audits, deps } = setup();
    const validation = { ids: ['fnd_a'], private_marker: 'PRIVATE_SNAPSHOT' };
    const { job_id: id } = await store.createStructuredJob(ctx, request(validation), cfg, deps);
    assert.ok(id);
    validation.ids[0] = 'fnd_injected';
    const lease = store.leaseJob(cfg);
    for (const value of [lease, audits, store.getJob(ctx, id, cfg)]) assert.ok(!JSON.stringify(value).includes('PRIVATE_SNAPSHOT'));
    store.completeJob(id, { status: 'done', content: '{"id":"fnd_a"}' }, cfg);
    assert.deepEqual(store.getJob(ctx, id, cfg).response.snapshot_test, { id: 'fnd_a' });
    assert.equal(store._jobs.get(id).validation, undefined);
  });

  it('rejects model IDs outside the snapshot', async () => {
    const { store, deps } = setup();
    const { job_id: id } = await store.createStructuredJob(ctx, request(), cfg, deps);
    store.leaseJob(cfg);
    store.completeJob(id, { status: 'done', content: '{"id":"fnd_foreign"}' }, cfg);
    assert.equal(store.getJob(ctx, id, cfg).status, 'failed');
    assert.equal(store.getJob(ctx, id, cfg).response, undefined);
  });

  it('rechecks dataset rights and tenant/user ownership on retrieval including completed jobs', async () => {
    const { store, deps } = setup();
    const { job_id: id } = await store.createStructuredJob(ctx, request(), cfg, deps);
    store.leaseJob(cfg);
    store.completeJob(id, { status: 'done', content: '{"id":"fnd_a"}' }, cfg);
    for (const caller of [{ ...ctx, scopes: ['finding:read'] }, { ...ctx, role: 'unknown' }, { ...ctx, userId: 'usr_b' }, { ...ctx, tenantId: 'ten_b' }]) {
      assert.equal(store.getJob(caller, id, cfg), null);
      assert.equal(store.cancelJob(caller, id, cfg), null);
    }
    assert.equal(store.getJob(ctx, id, cfg).status, 'done');
    assert.equal((await store.createStructuredJob({ ...ctx, scopes: ['finding:read'] }, request(), cfg, deps)).error, 'forbidden');
  });

  it('revalidates exact source ownership before HTTP disclosure and fails closed on reader errors', async () => {
    const { store, deps } = setup();
    const access = { finding_ids: ['fnd_a'], target_ids: ['tgt_a'] };
    const { job_id: id } = await store.createStructuredJob(ctx, { ...request(), requiredAccess: access }, cfg, deps);
    access.finding_ids[0] = 'fnd_injected';
    store.leaseJob(cfg);
    store.completeJob(id, { status: 'done', content: '{"id":"fnd_a"}' }, cfg);
    const readers = { getFinding: async (_caller, sourceId) => ({ id: sourceId, tenant_id: ctx.tenantId }), getTarget: async (_caller, sourceId) => ({ id: sourceId, tenant_id: ctx.tenantId }) };
    assert.equal(await store.authorizeJobAccess(ctx, id, cfg, readers), true);
    assert.equal(await store.authorizeJobAccess(ctx, id, cfg, {}), false);
    for (const row of [null, { id: 'fnd_a', tenant_id: 'ten_b' }, { id: 'fnd_a', deleted_at: '2026-10-19' }, { id: 'fnd_other' }]) {
      assert.equal(await store.authorizeJobAccess(ctx, id, cfg, { ...readers, getFinding: async () => row }), false);
    }
    assert.equal(await store.authorizeJobAccess(ctx, id, cfg, { ...readers, getTarget: async () => { throw new Error('reader unavailable'); } }), false);
    assert.ok(!JSON.stringify(store.getJob(ctx, id, cfg)).includes('required_access'));
  });

  it('checks only actual referenced filter entity IDs after model completion', async () => {
    const { store, deps } = setup();
    registerStructuredPurpose('filters', { parse: () => ({ filters: { target_id: 'tgt_a', test_run_id: 'run_a' } }) });
    const { job_id: id } = await store.createStructuredJob(ctx, { purpose: 'filters', prompt: 'Fixture' }, cfg, deps);
    store.leaseJob(cfg); store.completeJob(id, { status: 'done', content: '{}' }, cfg);
    const readers = { getTarget: async () => ({ id: 'tgt_a' }), resolveEntity: async (_caller, type, sourceId) => type === 'run' && sourceId === 'run_a' ? { id: sourceId } : null };
    assert.equal(await store.authorizeJobAccess(ctx, id, cfg, readers), true);
    assert.equal(await store.authorizeJobAccess(ctx, id, cfg, { ...readers, resolveEntity: async () => null }), false);
    assert.equal(await store.authorizeJobAccess({ ...ctx, scopes: ['finding:read'] }, id, cfg, readers), false);
  });

  it('bounds snapshots, rejects cycles and malformed permissions before queueing', async () => {
    const { store, deps } = setup();
    const cycle = {}; cycle.self = cycle;
    for (const validation of [null, [], cycle, { text: 'x'.repeat(65536) }, { text: '界'.repeat(24000) }]) {
      assert.equal((await store.createStructuredJob(ctx, request(validation), cfg, deps)).error, 'invalid_validation_snapshot');
    }
    assert.equal((await store.createStructuredJob(ctx, { ...request(), requiredPermissions: ['*'] }, cfg, deps)).error, 'invalid_required_permissions');
    assert.equal(store._jobs.size, 0);
  });

  it('clears private snapshots on cancellation and timeout and queues nothing after audit failure', async () => {
    const { store, deps, tick } = setup();
    const first = await store.createStructuredJob(ctx, request(), cfg, deps);
    store.cancelJob(ctx, first.job_id, cfg);
    assert.equal(store._jobs.get(first.job_id).validation, undefined);
    const second = await store.createStructuredJob(ctx, request(), cfg, deps);
    store.leaseJob(cfg);
    tick(300001);
    assert.equal(store.getJob(ctx, second.job_id, cfg).status, 'failed');
    assert.equal(store._jobs.get(second.job_id).validation, undefined);
    store.markRunnerSeen();
    await assert.rejects(store.createStructuredJob(ctx, request(), cfg, { recordAudit: async () => { throw new Error('audit unavailable'); } }), /audit unavailable/);
    assert.equal(store._jobs.size, 2);
  });
});
