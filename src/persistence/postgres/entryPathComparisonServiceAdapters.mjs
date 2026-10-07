// Postgres backend for the shared entry-path comparison lifecycle; Postgres mode never falls back to the dev store.
import { deferredStepEligibleAt, isHourlyCapDenial } from '../../contracts/validationScanManagement.mjs';
import { incMetric } from '../../lib/metrics.mjs';
import { normalizeSafetyPolicy } from '../../lib/safeTestGuards.mjs';
import {
  buildComparisonAttempt,
  comparisonDeclarationDigests,
  createEntryPathComparisonService,
  entryPathComparisonEvaluationRecord,
} from '../../services/entryPathComparisons.mjs';
import { currentOriginProof } from '../../services/originBindings.mjs';
import { LEAN_GROUP_LOOKUP } from './coreCatalogRepository.mjs';
import { ENTRY_PATH_COMPARISON_REPOSITORY_METHODS } from './entryPathComparisonRepository.mjs';

export const POSTGRES_ENTRY_PATH_COMPARISON_SERVICE_METHODS = Object.freeze([
  'planOrStartEntryPathComparison',
  'listEntryPathComparisons',
  'getEntryPathComparison',
  'cancelEntryPathComparison',
  'advanceEntryPathComparison',
  'advanceDueEntryPathComparisons',
  'onRunTerminal',
  'configureEntryPathComparisonRuntime',
  'setEvaluationRecorder',
]);

const DUE_LIMIT_DEFAULT = 25;
const DUE_LIMIT_MAX = 100;
const RECORD_RETRY_LIMIT = 10;

const DEPENDENCY_METHODS = Object.freeze({
  repository: ENTRY_PATH_COMPARISON_REPOSITORY_METHODS,
  protectionValidation: ['getEntryPaths', 'loadTargetContext', 'getOriginBindings'],
  coreCatalog: ['getTargetGroup'],
  validationEvidence: ['getTestRun', 'getVerdictForRun', 'listRunEvents', 'listTestRuns'],
  probeJobs: ['getProbeJobByTestRun'],
  killSwitch: ['isKillSwitchActiveForTenant'],
  testRuns: ['startTestRun', 'cancelTestRun'],
});

/** Missing dependency methods as `label.method`; an incomplete runtime keeps the routes unwired. */
export function missingEntryPathComparisonDependencies(deps = {}) {
  return Object.entries(DEPENDENCY_METHODS)
    .flatMap(([label, methods]) => methods.filter((name) => typeof deps[label]?.[name] !== 'function').map((name) => `${label}.${name}`));
}

function boundedLimit(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 1 ? Math.min(parsed, DUE_LIMIT_MAX) : DUE_LIMIT_DEFAULT;
}

function presentTarget(row) {
  const { metadata_json: metadata, declaration_json: declaration, ...rest } = row;
  return { ...rest, metadata: metadata ?? {}, declaration: declaration ?? null };
}

/**
 * @param {{
 *   repository: Record<string, Function>,
 *   protectionValidation: { getEntryPaths: Function, loadTargetContext: Function, getOriginBindings: Function },
 *   coreCatalog: { getTargetGroup: Function },
 *   validationEvidence: { getTestRun: Function, getVerdictForRun: Function, listRunEvents: Function, listTestRuns: Function },
 *   probeJobs: { getProbeJobByTestRun: Function },
 *   killSwitch: { isKillSwitchActiveForTenant: Function },
 *   testRuns: { startTestRun: Function, cancelTestRun: Function },
 *   resolveSourcePerspective?: (workerId: string | null) => string | null,
 *   runtimeConfig?: object | null,
 * }} deps
 */
export function createPostgresEntryPathComparisonBackend(deps) {
  const { repository, protectionValidation, coreCatalog, validationEvidence, probeJobs, killSwitch, testRuns } = deps;
  const missing = missingEntryPathComparisonDependencies(deps);
  if (missing.length) throw new Error(`entry-path comparison services require: ${missing.join(', ')}`);
  const resolveSource = typeof deps.resolveSourcePerspective === 'function' ? deps.resolveSourcePerspective : () => null;
  let runtimeConfig = deps.runtimeConfig ?? null;
  let recordEvaluation = null;

  async function loadRecords(ctx, selection = {}) {
    const entryPathIds = [...new Set((selection.entryPathIds ?? []).filter(Boolean))];
    const relations = (entryPathIds.length ? await protectionValidation.getEntryPaths(ctx, entryPathIds) : [])
      .filter((row) => row.tenant_id === ctx.tenantId);
    const targetIds = [...new Set([
      selection.anchorTargetId,
      ...(selection.targetIds ?? []),
      ...relations.flatMap((row) => [row.anchor_target_id, row.entry_target_id]),
    ].filter(Boolean))];
    const context = targetIds.length
      ? await protectionValidation.loadTargetContext(ctx, targetIds)
      : { targets: [], records: { targets: [], targetVerifications: [], wafConnectors: [], wafConnectorSnapshots: [] } };
    const targets = context.targets.filter((row) => row.tenant_id === ctx.tenantId).map(presentTarget);
    const bindingIds = [...new Set(relations.map((row) => row.origin_binding_id).filter(Boolean))];
    const originBindings = (bindingIds.length ? await protectionValidation.getOriginBindings(ctx, bindingIds) : [])
      .filter((row) => row.tenant_id === ctx.tenantId);
    const groupIds = [...new Set(targets.map((row) => row.target_group_id).filter(Boolean))];
    const targetGroups = [];
    for (const groupId of groupIds) {
      const group = await coreCatalog.getTargetGroup(ctx, groupId, LEAN_GROUP_LOOKUP);
      if (group && group.tenant_id === ctx.tenantId) targetGroups.push(group);
    }
    const proof = (targetId) => currentOriginProof(context.records, ctx.tenantId, targetId);
    return { relations, targets, originBindings, targetGroups, originProof: proof, targetProof: (_group, targetId) => proof(targetId) };
  }

  async function deferUntil(comparison, scopeItem, result, at) {
    const execCtx = { tenantId: comparison.tenant_id, userId: 'system', role: 'system' };
    const code = result?.error ?? 'safe_min_interval_active';
    const group = await coreCatalog.getTargetGroup(execCtx, scopeItem.target_group_id, LEAN_GROUP_LOOKUP);
    const runs = await validationEvidence.listTestRuns(
      execCtx,
      isHourlyCapDenial(code) ? { limit: 500 } : { targetGroupId: scopeItem.target_group_id, limit: 5 },
    );
    return deferredStepEligibleAt({
      code,
      runs,
      tenantId: comparison.tenant_id,
      targetGroupId: scopeItem.target_group_id,
      minSecondsBetweenRuns: normalizeSafetyPolicy(group?.safety_policy).min_seconds_between_runs,
      now: new Date(at),
    });
  }

  async function attempt(comparison, item) {
    const ctx = { tenantId: comparison.tenant_id };
    const run = await validationEvidence.getTestRun(ctx, item.test_run_id);
    if (!run || run.tenant_id !== comparison.tenant_id) return null;
    const [verdict, events, job] = await Promise.all([
      validationEvidence.getVerdictForRun(ctx, run.id),
      validationEvidence.listRunEvents(ctx, run.id, { signalType: 'probe_result' }),
      probeJobs.getProbeJobByTestRun(ctx, run.id).catch(() => null),
    ]);
    return buildComparisonAttempt({ run, verdict, events: events ?? [], job }, resolveSource);
  }

  async function finalized(comparison) {
    if (typeof recordEvaluation !== 'function') return;
    try {
      const stored = await recordEvaluation(comparison, entryPathComparisonEvaluationRecord(comparison));
      if (stored?.id) await repository.linkEvaluation(comparison.tenant_id, comparison.id, stored.id);
      else incMetric('entry_path_comparison_record_failed');
    } catch {
      incMetric('entry_path_comparison_finalized_hook_failed');
    }
  }

  return {
    runtimeConfig: () => runtimeConfig,
    setRuntimeConfig: (value) => {
      runtimeConfig = value ?? null;
    },
    setEvaluationRecorder: (fn) => {
      recordEvaluation = typeof fn === 'function' ? fn : null;
    },
    loadRecords: (ctx, selection) => loadRecords(ctx, selection),
    killSwitchActive: (tenantId) => killSwitch.isKillSwitchActiveForTenant({ tenantId }),
    startRun: async (execCtx, body, config, extra = {}) => {
      await repository.claimItem(extra.comparison, extra.item);
      return testRuns.startTestRun(execCtx, body, config);
    },
    checkpoint: (comparison) => repository.saveComparison(comparison),
    getRun: async (tenantId, runId) => {
      const run = await validationEvidence.getTestRun({ tenantId }, runId);
      return run && run.tenant_id === tenantId ? run : null;
    },
    cancelRun: (ctx, runId, options) => testRuns.cancelTestRun(ctx, runId, options),
    deferUntil,
    attempt,
    declarationDigests: async (comparison) => {
      const ids = [...new Set(comparison.approved_scope.items.map((item) => item.entry_path_id))];
      const relations = await protectionValidation.getEntryPaths({ tenantId: comparison.tenant_id }, ids);
      return comparisonDeclarationDigests(comparison, relations.filter((row) => row.tenant_id === comparison.tenant_id));
    },
    findByIdempotencyKey: (ctx, key) => repository.findByIdempotencyKey(ctx, key),
    findRunningByPlanDigest: (ctx, digest) => repository.findRunningByPlanDigest(ctx, digest),
    insert: (ctx, comparison) => repository.insertComparison(ctx, comparison),
    save: (comparison) => repository.saveComparison(comparison),
    appendAudits: (ctx, entries) => repository.appendAuditEntries(ctx, entries),
    get: (tenantId, id) => (tenantId ? repository.getComparison(tenantId, id) : null),
    list: (ctx, filter) => repository.listComparisons(ctx, filter),
    listDue: (ctx, at, options = {}) => repository.listDueComparisonIds(ctx, at, boundedLimit(options.limit)),
    lock: (tenantId, id, options) => repository.acquireLock(tenantId, id, options),
    unlock: (handle) => repository.releaseLock(handle),
    reconcileRequested: (tenantId, id) => repository.reconcileRequested(tenantId, id),
    requestReconcile: (candidate) => repository.requestReconcile(candidate.tenant_id, candidate.id),
    findByRun: (run) => repository.findRunningByRun(run.tenant_id, run.id),
    finalized,
    retryUnlinked: async (ctx, limit = RECORD_RETRY_LIMIT) => {
      const rows = await repository.listUnlinkedFinished(ctx, Math.min(boundedLimit(limit), RECORD_RETRY_LIMIT));
      for (const comparison of rows) await finalized(comparison);
      return rows.length;
    },
  };
}

/** Same service as the dev store over the Postgres backend; every method is async and tenant scoped. */
export function createPostgresEntryPathComparisonServices(deps) {
  const backend = createPostgresEntryPathComparisonBackend(deps);
  const service = createEntryPathComparisonService({ backend, async: true });
  return {
    planOrStartEntryPathComparison: service.planOrStartEntryPathComparison,
    listEntryPathComparisons: service.listEntryPathComparisons,
    getEntryPathComparison: service.getEntryPathComparison,
    cancelEntryPathComparison: service.cancelEntryPathComparison,
    advanceEntryPathComparison: service.advanceEntryPathComparison,
    /** Runner tick for one tenant: resume due comparisons, then retry evaluation records that did not land. */
    async advanceDueEntryPathComparisons(ctx, options = {}) {
      if (!ctx?.tenantId) throw new Error('advanceDueEntryPathComparisons requires a tenant context.');
      const results = await service.advanceDueEntryPathComparisons(ctx, options);
      await backend.retryUnlinked(ctx);
      return results;
    },
    onRunTerminal: (run, context = {}) => service.onRunTerminal(run, context).catch(() => {
      incMetric('entry_path_comparison_run_hook_failed');
    }),
    configureEntryPathComparisonRuntime: (runtimeConfig) => backend.setRuntimeConfig(runtimeConfig),
    setEvaluationRecorder: (fn) => backend.setEvaluationRecorder(fn),
  };
}
