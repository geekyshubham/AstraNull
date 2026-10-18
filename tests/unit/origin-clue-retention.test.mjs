import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { patchCurrentTenant } from '../../src/services/tenants.mjs';
import * as retention from '../../src/services/privacyRetention.mjs';
import { createOriginClueService } from '../../src/services/originClues.mjs';
import { createDevOriginClueRepository } from '../../src/services/originClueRepository.mjs';
import { verifyAuditChain } from '../../src/audit.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const runtimeConfig = { featureFlags: { originCluesEnabledTenants: { ten_demo: true } } };
const old = '2025-01-01T00:00:00.000Z';
const now = new Date('2026-10-17T12:00:00.000Z');
const input = (records = [{ candidate_ip: '8.8.8.8', associated_hostname: 'origin.test' }]) => ({ source_kind: 'historical_dns', source_ref: 'supplied:archive', records });
const options = (key) => ({ runtimeConfig, idempotencyKey: key });
const erasure = (extra = {}) => ({ confirmation_tenant_id: ctx.tenantId, reason: 'Customer requested source metadata deletion', dry_run: false, ...extra });
function service(at, extra = {}) { return createOriginClueService({ repository: createDevOriginClueRepository(), now: () => new Date(at), ...extra }); }
beforeEach(() => freshStore());

test('0084 lifecycle migration and schema contract are exactly synchronized', () => {
  const migration = readFileSync(new URL('../../db/migrations/0084_origin_clue_retention.sql', import.meta.url), 'utf8').trim();
  const schema = readFileSync(new URL('../../db/schema.sql', import.meta.url), 'utf8');
  assert.ok(schema.includes(migration));
  assert.match(migration, /SECURITY DEFINER SET search_path = pg_catalog SET row_security = on/);
  assert.match(migration, /NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS/);
  assert.match(migration, /REVOKE ALL ON FUNCTION public.astranull_apply_origin_clue_lifecycle.*FROM PUBLIC/);
  assert.equal(/DISABLE TRIGGER|DISABLE ROW LEVEL SECURITY|NO FORCE ROW LEVEL SECURITY/.test(migration), false);
});

test('expiry removes old clues and saved copies without removing fresh children or refreshing deduplicated timestamps', async () => {
  const first = await service(old).import(ctx, 'tgt_1', input(), options('old'));
  const fresh = service(now);
  const records = [...input().records, { candidate_ip: '1.1.1.1', associated_hostname: 'origin.test' }];
  const copied = await fresh.import(ctx, 'tgt_1', input(records), options('mixed'));
  assert.equal(copied.deduplicated, 1);
  assert.equal(copied.items.find((item) => item.id === first.items[0].id).retrieved_at, old);
  const result = retention.enforceMetadataRetentionForTenant(ctx.tenantId, ctx, { now });
  assert.equal(result.deleted.originClues, 1);
  assert.equal(result.deleted.originClueBatches, 1);
  assert.equal(result.deleted.originClueResponses, 1);
  assert.equal(getStore().originClues.length, 1);
  assert.equal(getStore().originClues[0].candidate_ip, '1.1.1.1');
  assert.equal(JSON.stringify(getStore().originClueBatches).includes('8.8.8.8'), false);
  const replay = await fresh.import(ctx, 'tgt_1', input(records), options('mixed'));
  assert.equal(replay.status, 410);
  assert.equal(replay.error, 'origin_clue_response_expired');
  assert.equal((await fresh.list(ctx, 'tgt_1', {}, { runtimeConfig })).coverage.sources, undefined);
  assert.equal(verifyAuditChain(getStore().auditLog).valid, true);
});

test('current-tenant erasure is scoped, feature-independent, confirmed, audited and safely repeatable', async () => {
  await service(now).import(ctx, 'tgt_1', input(), options('erase'));
  getStore().originClues.push({ id: 'foreign', tenant_id: 'ten_other', retrieved_at: old });
  getStore().originClueBatches.push({ id: 'foreign_batch', tenant_id: 'ten_other', created_at: old, response: { items: [] } });
  const auditBefore = getStore().auditLog.length;
  const preview = retention.eraseOriginCluesForCurrentTenant(ctx, erasure({ dry_run: true }), { now });
  assert.equal(preview.would_delete.originClues, 1);
  assert.equal(preview.audit_entry_id, null);
  assert.equal(getStore().auditLog.length, auditBefore);
  assert.equal(retention.eraseOriginCluesForCurrentTenant({ ...ctx, role: 'engineer' }, erasure()).status, 403);
  assert.equal(retention.eraseOriginCluesForCurrentTenant({ ...ctx, scopes: ['tenant:read'] }, erasure()).status, 403);
  assert.equal(retention.eraseOriginCluesForCurrentTenant(ctx, erasure({ confirmation_tenant_id: 'ten_other' })).status, 400);
  assert.equal(retention.eraseOriginCluesForCurrentTenant(ctx, erasure({ force: true })).status, 400);
  const result = retention.eraseOriginCluesForCurrentTenant(ctx, erasure(), { now });
  assert.equal(result.deleted.originClues, 1);
  assert.equal(result.deleted.originClueBatches, 1);
  assert.ok(result.audit_entry_id);
  assert.deepEqual(getStore().originClues.map((item) => item.id), ['foreign']);
  assert.deepEqual(getStore().originClueBatches.map((item) => item.id), ['foreign_batch']);
  assert.equal(retention.eraseOriginCluesForCurrentTenant(ctx, erasure(), { now }).deleted.originClues, 0);
  assert.equal(verifyAuditChain(getStore().auditLog).valid, true);
});

test('legal hold blocks expiry, response scrubbing and explicit erasure but not read-only preview', async () => {
  await service(old).import(ctx, 'tgt_1', input(), options('held'));
  const store = getStore();
  store.tenants[0].privacy_settings = { evidence_retention: { legal_hold: true } };
  const before = structuredClone({ clues: store.originClues, batches: store.originClueBatches });
  assert.equal(retention.enforceMetadataRetentionForTenant(ctx.tenantId, ctx, { now }).deleted.originClues, 0);
  const preview = retention.eraseOriginCluesForCurrentTenant(ctx, erasure({ dry_run: true }), { now });
  assert.equal(preview.legal_hold, true);
  assert.equal(preview.blocked_deletions.originClues, 1);
  const erased = retention.eraseOriginCluesForCurrentTenant(ctx, erasure(), { now });
  assert.equal(erased.status, 409);
  assert.ok(erased.audit_entry_id);
  assert.deepEqual({ clues: store.originClues, batches: store.originClueBatches }, before);
});

test('expiry uses strict retrieval cutoff, not unknown/stale source timestamps, and preserves malformed ages', () => {
  const cutoff = new Date(now.getTime() - 365 * 86400000).toISOString();
  const store = getStore();
  store.originClues = [
    { id: 'old', tenant_id: ctx.tenantId, target_id: 'tgt_1', batch_id: 'old_batch', retrieved_at: old },
    { id: 'boundary', tenant_id: ctx.tenantId, target_id: 'tgt_1', batch_id: 'boundary_batch', retrieved_at: cutoff, source_observed_at: old },
    { id: 'invalid', tenant_id: ctx.tenantId, retrieved_at: 'invalid' },
    { id: 'unknown', tenant_id: ctx.tenantId, retrieved_at: null },
  ];
  store.originClueBatches = [{ id: 'old_batch', tenant_id: ctx.tenantId, target_id: 'tgt_1', created_at: old, response: {} },
    { id: 'boundary_batch', tenant_id: ctx.tenantId, target_id: 'tgt_1', created_at: cutoff, response: {} }];
  const result = retention.enforceMetadataRetentionForTenant(ctx.tenantId, ctx, { now });
  assert.equal(result.deleted.originClues, 1); assert.equal(result.deleted.originClueBatches, 1);
  assert.deepEqual(store.originClues.map((item) => item.id), ['boundary', 'invalid', 'unknown']);
});

test('dev persistence failure rolls back privacy, clues, responses, audit and erasure publication', async () => {
  await service(old).import(ctx, 'tgt_1', input(), options('rollback'));
  const store = getStore();
  const before = structuredClone(store);
  const directory = mkdtempSync(path.join(os.tmpdir(), 'astranull-origin-lifecycle-'));
  const blocked = path.join(directory, 'not-a-directory');
  writeFileSync(blocked, 'occupied');
  const oldNoPersist = process.env.ASTRANULL_NO_PERSIST;
  const oldMode = process.env.ASTRANULL_PERSISTENCE_MODE;
  const oldDirectory = process.env.ASTRANULL_DEV_DATA_DIR;
  try {
    delete process.env.ASTRANULL_NO_PERSIST;
    delete process.env.ASTRANULL_PERSISTENCE_MODE;
    process.env.ASTRANULL_DEV_DATA_DIR = blocked;
    assert.throws(() => patchCurrentTenant(ctx, { privacy_settings: { metadata_retention_days: 1 } }));
    assert.deepEqual(store, before);
    assert.throws(() => retention.eraseOriginCluesForCurrentTenant(ctx, erasure(), { now }));
    assert.deepEqual(store, before);
    process.env.ASTRANULL_DEV_DATA_DIR = directory;
    retention.eraseOriginCluesForCurrentTenant(ctx, erasure(), { now });
    const saved = JSON.parse(readFileSync(path.join(directory, 'astranull-dev.json'), 'utf8'));
    assert.equal(saved.originClues.length, 0); assert.equal(saved.originClueBatches.length, 0);
    assert.equal(saved.auditLog.at(-1).action, 'privacy.origin_clues_erased');
    assert.equal(verifyAuditChain(saved.auditLog).valid, true);
  } finally {
    for (const [key, value] of [['ASTRANULL_NO_PERSIST', oldNoPersist], ['ASTRANULL_PERSISTENCE_MODE', oldMode], ['ASTRANULL_DEV_DATA_DIR', oldDirectory]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a paused idempotency replay cannot return its staged saved response after committed erasure', async () => {
  await service(now).import(ctx, 'tgt_1', input(), options('paused-replay'));
  let entered; let release;
  const ready = new Promise((resolve) => { entered = resolve; });
  const waiting = new Promise((resolve) => { release = resolve; });
  const base = createDevOriginClueRepository();
  const repository = { ...base, withBatch: (context, targetId, fn) => base.withBatch(context, targetId, (tx) => fn({ ...tx,
    getBatch: async (key) => { const saved = await tx.getBatch(key); entered(); await waiting; return saved; },
  })) };
  const s = createOriginClueService({ repository, now: () => now, collectDns: () => { throw new Error('must not collect'); } });
  const replay = s.import(ctx, 'tgt_1', input(), options('paused-replay'));
  await ready;
  retention.eraseOriginCluesForCurrentTenant(ctx, erasure(), { now });
  release();
  assert.equal((await replay).error, 'origin_clue_lifecycle_changed');
  assert.equal(getStore().originClueBatches.length, 0);
});

test('an in-flight dev collection cannot publish after tenant erasure', async () => {
  let release; let entered;
  const started = new Promise((resolve) => { entered = resolve; });
  const waiting = new Promise((resolve) => { release = resolve; });
  const s = service(now, { collectDns: async () => { entered(); await waiting; return { records: [], sources: [], query_count: 0 }; } });
  const operation = s.collect(ctx, 'tgt_1', {}, options('in-flight'));
  await started;
  const result = retention.eraseOriginCluesForCurrentTenant(ctx, erasure(), { now });
  assert.ok(result.audit_entry_id);
  release();
  assert.equal((await operation).error, 'origin_clue_lifecycle_changed');
  assert.equal(getStore().originClueBatches.length, 0);
});
