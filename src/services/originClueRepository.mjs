import { buildAuditRecord } from '../audit.mjs';
import { commitDevStoreChanges, getStore, tenantLifecycleGeneration } from '../store.mjs';
import { getTarget } from './targetGroups.mjs';
import { OriginClueError } from '../lib/originClues.mjs';

const locks = new Map();
async function exclusive(key, fn) {
  const prior = locks.get(key) ?? Promise.resolve();
  let release;
  const next = new Promise((resolve) => { release = resolve; });
  locks.set(key, next);
  await prior;
  try { return await fn(); }
  finally { release(); if (locks.get(key) === next) locks.delete(key); }
}
/** Stage append-only rows and chained audit together; failed operations publish nothing. */
export function createDevOriginClueRepository() {
  return {
    getTarget: (ctx, id) => getTarget(ctx, id),
    latestCoverage: async (ctx, targetId) => structuredClone([...(getStore().originClueBatches ?? [])]
      .reverse().find((row) => row.tenant_id === ctx.tenantId && row.target_id === targetId)?.response.coverage ?? null),
    async list(ctx, targetId, { limit, after }) {
      return structuredClone((getStore().originClues ?? []).filter((row) => row.tenant_id === ctx.tenantId && row.target_id === targetId
        && (!after || row.retrieved_at > after.at || (row.retrieved_at === after.at && row.id > after.id)))
        .sort((a, b) => a.retrieved_at.localeCompare(b.retrieved_at) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).slice(0, limit));
    },
    withBatch: (ctx, targetId, fn) => exclusive(ctx.tenantId, async () => {
      const store = getStore();
      const generation = tenantLifecycleGeneration(ctx.tenantId);
      const pending = []; let batch; let event;
      const response = await fn({
        getTarget: async (id) => getTarget(ctx, id),
        getBatch: async (key) => structuredClone((store.originClueBatches ?? []).find((row) => row.tenant_id === ctx.tenantId && row.target_id === targetId && row.idempotency_key === key) ?? null),
        async insertClue(row) {
          const existing = [...(store.originClues ?? []), ...pending].find((item) => item.tenant_id === ctx.tenantId && item.target_id === targetId && item.fingerprint === row.fingerprint);
          if (existing) return { row: structuredClone(existing), created: false };
          pending.push(structuredClone(row));
          return { row: structuredClone(row), created: true };
        },
        async finish(row, audit) { batch = structuredClone({ ...row, tenant_id: ctx.tenantId, target_id: targetId }); event = audit; },
      });
      if (getStore() !== store || tenantLifecycleGeneration(ctx.tenantId) !== generation) {
        throw new OriginClueError('origin_clue_lifecycle_changed', 409);
      }
      if (!batch) return response;
      // Revalidate after bounded DNS collection, so an archive racing collection cannot append.
      if (!getTarget(ctx, targetId)) throw new OriginClueError('origin_clue_target_changed', 409);
      const prior = [...store.auditLog].reverse().find((row) => row.entry_hash) ?? null;
      commitDevStoreChanges({ originClues: [...(store.originClues ?? []), ...pending],
        originClueBatches: [...(store.originClueBatches ?? []), batch],
        auditLog: [...store.auditLog, buildAuditRecord(event, prior)] });
      return response;
    }),
  };
}
