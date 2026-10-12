import { getStore } from '../store.mjs';
import { encodeCursor } from '../lib/cursorPagination.mjs';
import { computeReadiness, evidenceBackedVerdictForRun } from './readiness.mjs';
import { activeTargetGroupsForTenant } from './targetGroups.mjs';
import { buildGetStatePayload } from '../lib/statePayload.mjs';
import { auditTimestampKey, normalizeAuditListQuery } from '../persistence/postgres/auditRepository.mjs';

function tenantStateRollup(store, tenantId) {
  const rollups = store.stateRollups;
  if (!rollups || typeof rollups !== 'object') return null;
  const rollup = rollups[tenantId];
  return rollup && typeof rollup === 'object' ? rollup : null;
}

/**
 * Dev-json / memory dashboard aggregate for GET /v1/state.
 * @param {{ tenantId: string }} ctx
 */
export async function getState(ctx) {
  const store = getStore();
  const tenantId = ctx.tenantId;
  const rollup = tenantStateRollup(store, tenantId);
  const tenantHighScaleRequests = Array.isArray(store.highScaleRequests)
    ? store.highScaleRequests.filter((h) => h.tenant_id === tenantId)
    : [];
  const recentRuns = store.testRuns
    .filter((run) => run.tenant_id === tenantId)
    .sort((left, right) =>
      String(left.started_at ?? left.created_at ?? '').localeCompare(
        String(right.started_at ?? right.created_at ?? ''),
      ) || String(left.id ?? '').localeCompare(String(right.id ?? '')),
    )
    .slice(-5)
    .map((run) => ({
      ...run,
      verdict: ['completed', 'verdicted'].includes(run.status)
        ? evidenceBackedVerdictForRun(store, run.id)
        : null,
    }));

  return buildGetStatePayload({
    tenantId,
    rollup,
    computed: {
      readiness: computeReadiness(tenantId),
      target_groups: activeTargetGroupsForTenant(tenantId).length,
      recent_runs: recentRuns,
      open_findings: store.findings.filter(
        (f) => f.tenant_id === tenantId && (f.status === 'open' || f.state === 'open'),
      ).length,
      high_scale_requests: tenantHighScaleRequests.length,
    },
    killSwitch: store.socKillSwitch,
    highScaleWired: Array.isArray(store.highScaleRequests),
    highScaleRequests: tenantHighScaleRequests,
  });
}

function auditStamp(entry) {
  if (typeof entry?.timestamp === 'string' && entry.timestamp) return entry.timestamp;
  if (entry?.timestamp instanceof Date) return entry.timestamp.toISOString();
  return '';
}

function auditEntryMatches(entry, query) {
  if (query.resource && entry.resource_type !== query.resource && entry.resource_id !== query.resource) return false;
  if (query.actor && entry.actor_user_id !== query.actor) return false;
  if (query.action && entry.action !== query.action) return false;
  const stamp = auditTimestampKey(auditStamp(entry));
  if (query.since && stamp < auditTimestampKey(query.since)) return false;
  if (query.until && stamp > auditTimestampKey(query.until)) return false;
  return true;
}

/**
 * Dev-store audit read. Same predicates as the Postgres query. A filter never
 * falls back to the newest 200 unfiltered rows.
 *
 * @param {{ tenantId: string }} ctx
 * @param {object} [options]
 */
export function queryAuditEntries(ctx, options = {}) {
  const query = normalizeAuditListQuery(options);
  const matched = (getStore().auditLog ?? [])
    .filter((entry) => entry.tenant_id === ctx.tenantId && auditEntryMatches(entry, query))
    .map((entry) => ({ entry, ts: auditStamp(entry) }));
  matched.sort((left, right) => {
    const leftKey = auditTimestampKey(left.ts);
    const rightKey = auditTimestampKey(right.ts);
    if (leftKey !== rightKey) return leftKey < rightKey ? 1 : -1;
    if (left.entry.id === right.entry.id) return 0;
    return left.entry.id < right.entry.id ? 1 : -1;
  });
  const cursorKey = query.cursor ? auditTimestampKey(query.cursor.ts) : null;
  const visible = query.cursor
    ? matched.filter((row) => {
      const key = auditTimestampKey(row.ts);
      return key < cursorKey || (key === cursorKey && row.entry.id < query.cursor.id);
    })
    : matched;
  const page = visible.slice(0, query.limit);
  const oldest = page[page.length - 1];
  const filters = {};
  if (query.resource) filters.resource = query.resource;
  if (query.actor) filters.actor = query.actor;
  if (query.action) filters.action = query.action;
  if (query.since) filters.since = query.since;
  if (query.until) filters.until = query.until;
  return {
    items: page.slice().reverse().map((row) => row.entry),
    count: page.length,
    total: matched.length,
    next_cursor: visible.length > query.limit && oldest
      ? encodeCursor({ v: 1, ts: oldest.ts, id: oldest.entry.id })
      : null,
    filters,
    limit: query.limit,
  };
}

/** Exact own audit event. Other tenants are not found. */
export function getAuditEntry(ctx, id) {
  if (!ctx?.tenantId || !id) return null;
  return (getStore().auditLog ?? []).find((entry) => entry.tenant_id === ctx.tenantId && entry.id === id) ?? null;
}