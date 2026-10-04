/**
 * Explicit finding to run retest lineage.
 *
 * A retest exists only when this registration records intent for the same tenant,
 * target, and check. A later routine check of that pair is `later_same_pair`.
 * Nothing here closes the finding or a sibling.
 */
import { randomBytes } from 'node:crypto';
import { roleHasPermission } from '../contracts/roles.mjs';
import { requirePermission } from '../rbac.mjs';
import { normalizeObservationTimestamp } from './targetHistory.mjs';
import { getStore, persistStore } from '../store.mjs';

const FINAL_RUN_STATUSES = new Set(['completed', 'verdicted']);

function error(code, status, extra = {}) {
  return { error: code, status, ...extra };
}

function hasPermission(ctx, permission) {
  if (!roleHasPermission(ctx?.role, permission)) return false;
  if (Array.isArray(ctx?.scopes)) return ctx.scopes.includes('*') || ctx.scopes.includes(permission);
  return true;
}

function gate(ctx, permission) {
  if (hasPermission(ctx, permission)) return { ok: true };
  return requirePermission(ctx, permission, { resource_type: 'finding_retest_lineage' });
}

function lineageOf(store) {
  if (!Array.isArray(store.findingRetestLineage)) store.findingRetestLineage = [];
  return store.findingRetestLineage;
}

export function planRetestRegistration({ finding, run, intent, existing = null }) {
  if (!finding) return error('unknown_finding', 404);
  if (!run) return error('unknown_run', 404);
  if (finding.tenant_id !== run.tenant_id || finding.target_id !== run.target_id || finding.check_id !== run.check_id) {
    return error('pair_mismatch', 409);
  }
  if (intent !== 'retest') return error('intent_required', 400);
  if (existing) return { replayed: true, record: existing };
  return { replayed: false };
}

export function labelRunRelation({ finding, run, lineage = [] }) {
  if (!finding || !run) return { relation: 'not_comparable', reason: 'missing_record', can_advance_remediation: false };
  if (finding.tenant_id !== run.tenant_id || finding.target_id !== run.target_id || finding.check_id !== run.check_id) {
    return { relation: 'not_comparable', reason: 'different_pair', can_advance_remediation: false };
  }
  if (lineage.some((row) => row.finding_id === finding.id && row.test_run_id === run.id && row.intent === 'retest')) {
    return { relation: 'retest', reason: null, can_advance_remediation: false, finalized: FINAL_RUN_STATUSES.has(run.status) };
  }
  if (run.id === finding.test_run_id) {
    return { relation: 'originating', reason: null, can_advance_remediation: false };
  }
  return {
    relation: 'later_same_pair',
    reason: 'no_explicit_retest_intent',
    can_advance_remediation: false,
    finalized: FINAL_RUN_STATUSES.has(run.status),
  };
}

export function presentFindingLineage({ finding, runs = [], lineage = [], siblings = [] }) {
  const explicit = new Set(lineage.map((row) => row.test_run_id));
  const related = runs.filter((run) => run.tenant_id === finding.tenant_id
    && run.target_id === finding.target_id
    && run.check_id === finding.check_id
    && run.id !== finding.test_run_id);
  const runsById = new Map(runs
    .filter((run) => run.tenant_id === finding.tenant_id)
    .map((run) => [run.id, run]));
  const newestLineageRow = [...lineage]
    .sort((left, right) => String(right.created_at ?? '').localeCompare(String(left.created_at ?? '')))[0] ?? null;
  const latestRunId = newestLineageRow ? newestLineageRow.test_run_id : (finding.test_run_id ?? null);
  const latestRun = latestRunId ? runsById.get(latestRunId) ?? null : null;
  const latestFinalized = Boolean(latestRun && FINAL_RUN_STATUSES.has(latestRun.status));
  return {
    finding_id: finding.id,
    tenant_id: finding.tenant_id,
    target_id: finding.target_id,
    check_id: finding.check_id,
    closed_at: finding.closed_at ?? null,
    sibling_closure: false,
    siblings: siblings.map((sibling) => ({
      id: sibling.id,
      target_id: sibling.target_id,
      status: sibling.status,
      closed_at: sibling.closed_at ?? null,
    })),
    retests: lineage.map((row) => ({
      id: row.id,
      test_run_id: row.test_run_id,
      target_id: row.target_id,
      check_id: row.check_id,
      intent: 'retest',
      relation: 'retest',
      created_at: row.created_at,
    })),
    later_same_pair: related
      .filter((run) => !explicit.has(run.id))
      .map((run) => ({
        test_run_id: run.id,
        ...labelRunRelation({ finding, run, lineage }),
      })),
    originating: finding.test_run_id
      ? {
          test_run_id: finding.test_run_id,
          relation: 'originating',
          status: runsById.get(finding.test_run_id)?.status ?? null,
        }
      : null,
    latest: latestRunId
      ? {
          test_run_id: latestRunId,
          relation: newestLineageRow ? 'retest' : 'originating',
          status: latestRun?.status ?? null,
          finalized: latestFinalized,
          // A not-yet-finalized attempt is explicitly pending. It never claims a
          // later passing result, never replaces the original evidence, and
          // never advances remediation on its own.
          completed_at: latestRun?.completed_at ?? null,
          pending: Boolean(latestRun) && !latestFinalized,
          can_advance_remediation: false,
        }
      : null,
  };
}

export function registerRetestLineage(ctx, input = {}, options = {}) {
  const allowed = gate(ctx, 'finding:write');
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  const store = getStore();
  const finding = (store.findings ?? []).find((row) => row.tenant_id === ctx.tenantId && row.id === input.finding_id) ?? null;
  const run = (store.testRuns ?? []).find((row) => row.tenant_id === ctx.tenantId && row.id === input.test_run_id) ?? null;
  const existing = lineageOf(store).find((row) => row.tenant_id === ctx.tenantId
    && row.finding_id === input.finding_id
    && row.test_run_id === input.test_run_id) ?? null;
  const planned = planRetestRegistration({ finding, run, intent: input.intent, existing });
  if (planned.error) return planned;
  if (planned.replayed) return { ...planned.record, replayed: true, sibling_closure: false };
  const record = {
    id: `rtln_${randomBytes(8).toString('hex')}`,
    tenant_id: ctx.tenantId,
    finding_id: finding.id,
    test_run_id: run.id,
    target_id: finding.target_id,
    check_id: finding.check_id,
    intent: 'retest',
    relation: 'retest',
    created_by: ctx.userId ?? null,
    created_at: normalizeObservationTimestamp(options.now ?? new Date()),
  };
  lineageOf(store).push(record);
  persistStore();
  return { ...record, replayed: false, sibling_closure: false };
}

export function listFindingLineage(ctx, findingId) {
  const allowed = gate(ctx, 'finding:read');
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  const store = getStore();
  const finding = (store.findings ?? []).find((row) => row.tenant_id === ctx.tenantId && row.id === findingId) ?? null;
  if (!finding) return error('unknown_finding', 404);
  const lineage = lineageOf(store).filter((row) => row.tenant_id === ctx.tenantId && row.finding_id === finding.id);
  const runs = (store.testRuns ?? []).filter((row) => row.tenant_id === ctx.tenantId);
  const siblings = (store.findings ?? []).filter((row) => row.tenant_id === ctx.tenantId
    && row.id !== finding.id
    && row.check_id === finding.check_id);
  return presentFindingLineage({ finding, runs, lineage, siblings });
}
