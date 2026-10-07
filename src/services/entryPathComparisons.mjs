// PV-04 one comparison lifecycle over two backends: plan is passive; start runs only through startTestRun and its signed-job gates.
import { randomBytes } from 'node:crypto';
import { audit } from '../audit.mjs';
import { CHECK_CATALOG } from '../contracts/checks.mjs';
import {
  PROTECTION_VALIDATION_AUDIT_ACTIONS,
  PROTECTION_VALIDATION_PAGE_LIMIT,
  PROTECTION_VALIDATION_PERMISSIONS,
  ProtectionValidationError,
  REQUIRED_LIMITATIONS,
  normalizeEntryPathComparisonRequest,
} from '../contracts/protectionValidation.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { classifyStartDenial, deferredStepEligibleAt } from '../contracts/validationScanManagement.mjs';
import {
  buildApprovedScope,
  evaluateEntryPathComparison,
  planEntryPathComparison,
  reviewedPlanMatches,
  revalidateScopeItem,
  runStartBodyForScopeItem,
  verifyApprovedScope,
} from '../lib/entryPathComparison.mjs';
import { probeSourceResolverFromEnv } from '../lib/probeSourcePerspective.mjs';
import { isTrustedProducerEvent } from '../lib/trustedEventProvenance.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { requirePermission } from '../rbac.mjs';
import { getStore, persistStore } from '../store.mjs';
import { isKillSwitchActiveForTenant } from './killSwitchState.mjs';
import { isProtectionValidationEnabled } from './tenantDeploymentFeatures.mjs';
import { bindingRecordsFromStore, currentOriginProof } from './originBindings.mjs';
import { targetOwnershipProof } from './ownershipVerification.mjs';
import { registerRunTerminalHook } from './runTerminalHooks.mjs';
import { normalizeSafetyPolicy } from './safeTestPolicy.mjs';
import { isArchivedTargetGroup } from './targetGroups.mjs';
import { cancelTestRun, maybeFinalizeCollectingRun, startTestRun } from './testRuns.mjs';

export const ENTRY_PATH_COMPARISON_AUDIT_ACTIONS = Object.freeze({
  started: PROTECTION_VALIDATION_AUDIT_ACTIONS.entry_path_comparison_started,
  startDenied: 'entry_path_comparison.start_denied',
  itemSkipped: 'entry_path_comparison.item_skipped',
  scopeRejected: 'entry_path_comparison.scope_rejected',
  completed: 'entry_path_comparison.completed',
  cancelled: 'entry_path_comparison.cancelled',
});

/** Comparison backend contract shared by the dev store and Postgres. */
export const ENTRY_PATH_COMPARISON_BACKEND_METHODS = Object.freeze([
  'runtimeConfig', 'loadRecords', 'killSwitchActive', 'startRun', 'checkpoint', 'getRun', 'cancelRun', 'deferUntil',
  'attempt', 'declarationDigests', 'findByIdempotencyKey', 'findRunningByPlanDigest', 'insert', 'save', 'appendAudits',
  'get', 'list', 'listDue', 'lock', 'unlock', 'reconcileRequested', 'requestReconcile', 'findByRun', 'finalized',
]);

export const ACTIVE_RUN_STATUSES = new Set(['planned', 'running', 'collecting']);
export const FINALIZED_RUN_STATUSES = new Set(['verdicted', 'completed']);
const TENANT_WIDE_ABORTS = new Set(['kill_switch_active', 'tenant_suspended']);
const MAX_START_ATTEMPTS = 2;
const MAX_RECONCILE_PASSES = 3;
export const ENTRY_PATH_DEFERRAL_WINDOW_MS = 24 * 60 * 60 * 1000;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const PENDING_AUDITS = Symbol('entryPathComparisonPendingAudits');
const advancing = new Set();
const finalizedHooks = new Set();
let defaultRuntimeConfig = null;
let resolveSourcePerspective = probeSourceResolverFromEnv();

/** Raised when a stored comparison changed underneath a locked writer; the write is rolled back. */
export class EntryPathComparisonConflictError extends Error {
  constructor(comparisonId) {
    super('entry-path comparison changed concurrently');
    this.name = 'EntryPathComparisonConflictError';
    this.comparisonId = comparisonId;
  }
}

export function configureEntryPathComparisonRuntime(runtimeConfig, options = {}) {
  defaultRuntimeConfig = runtimeConfig ?? null;
  if (typeof options.resolveSourcePerspective === 'function') resolveSourcePerspective = options.resolveSourcePerspective;
}

/** Called once per comparison after its evaluation is frozen; hooks record it and derive findings. */
export function registerEntryPathComparisonFinalizedHook(hook) {
  if (typeof hook !== 'function') throw new TypeError('registerEntryPathComparisonFinalizedHook requires a function.');
  finalizedHooks.add(hook);
  return () => finalizedHooks.delete(hook);
}

function notifyFinalized(comparison) {
  for (const hook of finalizedHooks) {
    try {
      Promise.resolve(hook(structuredClone(comparison))).catch(() => incMetric('entry_path_comparison_finalized_hook_failed'));
    } catch {
      incMetric('entry_path_comparison_finalized_hook_failed');
    }
  }
}

/** Links the recorded PV-03 evaluation back to its comparison (dev store). */
export function linkEntryPathComparisonEvaluation(tenantId, comparisonId, evaluationId) {
  const comparison = comparisonsOf(getStore()).find((row) => row.id === comparisonId && row.tenant_id === tenantId);
  if (!comparison || !evaluationId) return false;
  comparison.evaluation_id = evaluationId;
  persistStore();
  return true;
}

function comparisonsOf(store) {
  if (!Array.isArray(store.entryPathComparisons)) store.entryPathComparisons = [];
  return store.entryPathComparisons;
}

function newComparisonId(prefix) {
  return `${prefix}_${randomBytes(8).toString('hex')}`;
}

function nowIso(options) {
  const value = options?.now ? new Date(options.now) : new Date();
  return Number.isNaN(value.getTime()) ? new Date().toISOString() : value.toISOString();
}

function gate(ctx, permission) {
  if (!roleHasPermission(ctx?.role, permission)) return requirePermission(ctx, permission, { resource_type: 'entry_path_comparison' });
  if (Array.isArray(ctx?.scopes) && !ctx.scopes.includes('*') && !ctx.scopes.includes(permission)) {
    return requirePermission(ctx, permission, { resource_type: 'entry_path_comparison' });
  }
  return { ok: true };
}

function denied(result) {
  return { error: result.body?.error ?? 'forbidden', status: result.status ?? 403, permission: result.body?.permission ?? null };
}

function auditEntry(ctx, comparison, action, metadata = {}) {
  return {
    tenant_id: comparison?.tenant_id ?? ctx.tenantId,
    actor_user_id: ctx.userId ?? 'system',
    actor_role: ctx.role ?? 'system',
    action,
    resource_type: 'entry_path_comparison',
    resource_id: comparison?.id ?? null,
    metadata: {
      anchor_target_id: comparison?.anchor_target_id ?? metadata.anchor_target_id ?? null,
      ...metadata,
    },
  };
}

/** Audits ride with the comparison until the backend commits them alongside the state change. */
function comparisonAudit(ctx, comparison, action, metadata = {}) {
  if (!comparison[PENDING_AUDITS]) comparison[PENDING_AUDITS] = [];
  comparison[PENDING_AUDITS].push(auditEntry(ctx, comparison, action, metadata));
}

export function takePendingComparisonAudits(comparison) {
  const pending = comparison?.[PENDING_AUDITS] ?? [];
  if (comparison) comparison[PENDING_AUDITS] = [];
  return pending;
}

function probeLeavesHost(runtimeConfig) {
  return (runtimeConfig?.probeMode ?? 'simulation') === 'signed-worker';
}

/** Execution-time gates beyond the declaration: active group and current ownership proofs. */
function executionGate(records, runtimeConfig) {
  return (relation, entryTarget) => {
    const group = records.targetGroups.find((row) => row.id === entryTarget.target_group_id);
    if (!group || isArchivedTargetGroup(group)) return { ok: false, error: 'target_group_not_found' };
    if (!probeLeavesHost(runtimeConfig)) return { ok: true };
    if (relation.relation_kind === 'origin') {
      if (!records.originProof(entryTarget.id).verified) return { ok: false, error: 'ownership_not_verified' };
      if (!records.originProof(relation.anchor_target_id).verified) return { ok: false, error: 'ownership_not_verified' };
      return { ok: true };
    }
    return records.targetProof(group, entryTarget.id).verified ? { ok: true } : { ok: false, error: 'ownership_not_verified' };
  };
}

function normalizeRequest(body) {
  try {
    return { request: normalizeEntryPathComparisonRequest(body) };
  } catch (error) {
    if (error instanceof ProtectionValidationError) return { error: error.toResponse() };
    throw error;
  }
}

function normalizeIdempotencyKey(value) {
  if (value == null || value === '') return { key: null };
  const key = String(value).trim();
  if (!IDEMPOTENCY_KEY_PATTERN.test(key)) return { error: { error: 'invalid_idempotency_key', status: 400, field: 'Idempotency-Key' } };
  return { key };
}

function scopeSelection(comparison) {
  const items = comparison.approved_scope?.items ?? [];
  return {
    anchorTargetId: comparison.anchor_target_id,
    entryPathIds: [...new Set(items.map((item) => item.entry_path_id).filter(Boolean))],
    targetIds: [...new Set(items.map((item) => item.target_id).filter(Boolean))],
  };
}

function* computePlan(b, ctx, request, runtimeConfig, options) {
  const records = yield b.loadRecords(ctx, {
    anchorTargetId: request.anchor_target_id,
    entryPathIds: request.entry_path_ids,
    targetIds: [],
  }, options);
  const anchorTarget = records.targets.find((row) => row.id === request.anchor_target_id) ?? null;
  if (!anchorTarget) return { error: { error: 'unknown_target', status: 404, field: 'anchor_target_id' } };
  try {
    const plan = planEntryPathComparison({
      tenantId: ctx.tenantId,
      request,
      anchorTarget,
      relations: records.relations,
      targets: records.targets,
      originBindings: records.originBindings,
      catalog: options.catalog ?? CHECK_CATALOG,
      authorize: executionGate(records, runtimeConfig),
    });
    return { plan, records, anchorTarget };
  } catch (error) {
    if (error instanceof ProtectionValidationError) return { error: error.toResponse() };
    throw error;
  }
}

function presentPlan(plan) {
  return {
    mode: 'plan',
    contract_version: plan.contract_version,
    plan_digest: plan.plan_digest,
    anchor_target_id: plan.anchor_target_id,
    primary_entry_path_id: plan.primary_entry_path_id,
    expectation: {
      id: null,
      scenario: plan.expectation.scenario,
      layer_outcomes: plan.expectation.layer_outcomes,
      expectation_version: plan.expectation.expectation_version,
      digest: plan.expectation.digest,
    },
    items: plan.items.map((item) => ({
      entry_path_id: item.entry_path_id,
      is_primary: item.is_primary,
      relation_kind: item.relation_kind,
      expected_behavior: item.expected_behavior,
      target_id: item.target_id,
      target: item.target,
      declaration_digest: item.declaration_digest,
      check_id: item.check_id,
      check_version: item.check_version,
      scenario_version: item.scenario_version,
      origin_binding_id: item.origin_binding_id,
      eligible: item.eligible,
      ineligible_reason: item.ineligible_reason,
    })),
    eligible_count: plan.eligible_count,
    primary_eligible: plan.primary_eligible,
    expectation_conflicts: plan.expectation_conflicts,
    limitations: plan.limitations,
  };
}

function* createCore(b, ctx, body, runtimeConfig, options) {
  const allowed = gate(ctx, PROTECTION_VALIDATION_PERMISSIONS.run_start);
  if (!allowed.ok) return denied(allowed);
  const normalized = normalizeRequest(body);
  if (normalized.error) return normalized.error;
  const idempotency = normalizeIdempotencyKey(options.idempotencyKey);
  if (idempotency.error) return idempotency.error;
  const config = runtimeConfig ?? (yield b.runtimeConfig()) ?? { probeMode: 'simulation' };
  if (normalized.request.mode === 'plan') {
    const computed = yield* computePlan(b, ctx, normalized.request, config, options);
    if (computed.error) return computed.error;
    return { status: 200, plan: presentPlan(computed.plan) };
  }
  return yield* startComparison(b, ctx, normalized.request, config, { ...options, idempotencyKey: idempotency.key });
}

function* denyStart(b, ctx, request, code, status, extra = {}) {
  yield b.appendAudits(ctx, [auditEntry(ctx, null, ENTRY_PATH_COMPARISON_AUDIT_ACTIONS.startDenied, {
    anchor_target_id: request.anchor_target_id,
    reason: code,
    ...extra,
  })]);
  return { error: code, status, ...extra };
}

/** A replayed start also nudges a still-running comparison, so a start that failed mid-advance is not left idle. */
function* replayStart(b, ctx, comparison, options) {
  if (comparison.status !== 'running') return { status: 200, replayed: true, comparison: presentStart(comparison) };
  try {
    yield* advanceComparison(b, ctx, comparison.id, options);
  } catch (error) {
    if (error instanceof EntryPathComparisonConflictError) incMetric('entry_path_comparison_conflict');
    else incMetric('entry_path_comparison_advance_failed');
  }
  const latest = (yield b.get(ctx.tenantId, comparison.id)) ?? comparison;
  return { status: 200, replayed: true, comparison: presentStart(latest) };
}

function* existingStart(b, ctx, plan, idempotencyKey, options = {}) {
  if (idempotencyKey) {
    const keyed = yield b.findByIdempotencyKey(ctx, idempotencyKey);
    if (keyed) {
      if (keyed.plan_digest !== plan.plan_digest) return { error: 'idempotency_conflict', status: 409, existing_id: keyed.id };
      return yield* replayStart(b, ctx, keyed, options);
    }
  }
  const running = yield b.findRunningByPlanDigest(ctx, plan.plan_digest);
  if (running) return yield* replayStart(b, ctx, running, options);
  return null;
}

function* startComparison(b, ctx, request, runtimeConfig, options) {
  if (yield b.killSwitchActive(ctx.tenantId)) return yield* denyStart(b, ctx, request, 'kill_switch_active', 423);
  const computed = yield* computePlan(b, ctx, request, runtimeConfig, options);
  if (computed.error) return computed.error;
  const { plan } = computed;
  if (!reviewedPlanMatches(plan, request.reviewed_plan_digest)) {
    return yield* denyStart(b, ctx, request, 'reviewed_plan_mismatch', 409, { plan_digest: plan.plan_digest });
  }
  if (plan.eligible_count === 0) return yield* denyStart(b, ctx, request, 'no_eligible_entry_paths', 409);

  const idempotencyKey = options.idempotencyKey ?? null;
  const existing = yield* existingStart(b, ctx, plan, idempotencyKey, { ...options, runtimeConfig });
  if (existing) return existing;

  const at = nowIso(options);
  const id = newComparisonId('epc');
  const expectation = { id: newComparisonId('pvx'), ...plan.expectation };
  const scope = buildApprovedScope(plan, { comparisonId: id, approvedAt: at, approvedBy: ctx.userId ?? null });
  const comparison = {
    id,
    tenant_id: ctx.tenantId,
    anchor_target_id: plan.anchor_target_id,
    primary_entry_path_id: plan.primary_entry_path_id,
    status: 'running',
    plan_digest: plan.plan_digest,
    expectation,
    approved_scope: scope,
    probe_mode: runtimeConfig?.probeMode ?? 'simulation',
    execution_ctx: { tenantId: ctx.tenantId, userId: ctx.userId ?? null, role: ctx.role ?? null },
    items: scope.items.map((item) => ({
      entry_path_id: item.entry_path_id,
      state: item.eligible ? 'pending' : 'skipped',
      skip_reason: item.eligible ? null : item.ineligible_reason,
      test_run_id: null,
      attempts: 0,
      deferred_until: null,
      last_start_error: null,
      updated_at: at,
    })),
    cancel_reason: null,
    idempotency_key: idempotencyKey,
    created_by: ctx.userId ?? null,
    created_at: at,
    started_at: at,
    completed_at: null,
    evaluation: null,
  };
  comparisonAudit(ctx, comparison, ENTRY_PATH_COMPARISON_AUDIT_ACTIONS.started, {
    plan_digest: plan.plan_digest,
    scope_digest: scope.scope_digest,
    expectation_digest: expectation.digest,
    item_count: scope.items.length,
    eligible_count: plan.eligible_count,
  });
  const stored = yield b.insert(ctx, comparison);
  if (stored?.conflict) {
    const replay = yield* existingStart(b, ctx, plan, idempotencyKey, { ...options, runtimeConfig });
    return replay ?? { error: 'comparison_conflict', status: 409 };
  }
  yield* advanceComparison(b, ctx, id, { ...options, runtimeConfig });
  const latest = yield b.get(ctx.tenantId, id);
  return { status: 202, comparison: presentStart(latest ?? comparison) };
}

function presentStart(comparison) {
  return {
    id: comparison.id,
    status: comparison.status,
    plan_digest: comparison.plan_digest,
    scope_digest: comparison.approved_scope?.scope_digest ?? null,
    items: comparison.items.map((item) => ({
      entry_path_id: item.entry_path_id,
      test_run_id: item.test_run_id,
      execution_state: item.state,
      skip_reason: item.skip_reason,
      deferred_until: item.deferred_until,
      outcome: item.state === 'skipped' ? 'skipped' : 'not_tested',
    })),
  };
}

function itemScope(comparison, entryPathId) {
  return comparison.approved_scope.items.find((row) => row.entry_path_id === entryPathId) ?? null;
}

function skipItem(ctx, comparison, item, reason, at) {
  item.state = 'skipped';
  item.skip_reason = reason;
  item.deferred_until = null;
  item.updated_at = at;
  comparisonAudit(ctx, comparison, ENTRY_PATH_COMPARISON_AUDIT_ACTIONS.itemSkipped, {
    entry_path_id: item.entry_path_id,
    reason,
  });
}

function skipOutstanding(ctx, comparison, reason, at) {
  for (const item of comparison.items) {
    if (item.state === 'pending' || item.state === 'deferred') skipItem(ctx, comparison, item, reason, at);
  }
}

function runCancelledByKillSwitch(run, context = {}) {
  return run?.cancelled_by_kill_switch === true || run?.summary?.cancelled_by_kill_switch === true || context.reason === 'kill_switch';
}

/** One terminal run settles its attempt; a kill-switch cancel also stops everything still queued. */
function applyRunTerminal(ctx, comparison, item, run, context, at) {
  const killed = runCancelledByKillSwitch(run, context);
  if (FINALIZED_RUN_STATUSES.has(run.status)) {
    item.state = 'finalized';
    item.updated_at = at;
  } else {
    skipItem(ctx, comparison, item, killed ? 'kill_switch_active' : (comparison.cancel_reason ? 'comparison_cancelled' : 'run_cancelled'), at);
  }
  if (killed) {
    comparison.cancel_reason = 'kill_switch_active';
    skipOutstanding(ctx, comparison, 'kill_switch_active', at);
  }
  return killed;
}

/** Settles started attempts whose run already ended but whose terminal hook could not take the lock. */
function* reconcileStarted(b, ctx, comparison, at) {
  for (const item of comparison.items) {
    if (item.state !== 'started') continue;
    if (!item.test_run_id) {
      skipItem(ctx, comparison, item, 'start_interrupted', at);
      continue;
    }
    const run = yield b.getRun(comparison.tenant_id, item.test_run_id);
    if (!run || ACTIVE_RUN_STATUSES.has(run.status)) continue;
    applyRunTerminal(ctx, comparison, item, run, {}, at);
  }
}

function* cancelStartedRuns(b, ctx, comparison, reason) {
  for (const item of comparison.items) {
    if (item.state !== 'started' || !item.test_run_id) continue;
    const run = yield b.getRun(comparison.tenant_id, item.test_run_id);
    if (run && ACTIVE_RUN_STATUSES.has(run.status)) {
      yield b.cancelRun(ctx, run.id, { reason, source: 'entry_path_comparison' });
    }
  }
}

function orderedItems(comparison) {
  const primary = comparison.items.filter((item) => item.entry_path_id === comparison.primary_entry_path_id);
  return [...primary, ...comparison.items.filter((item) => item.entry_path_id !== comparison.primary_entry_path_id)];
}

function revalidate(comparison, scopeItem, records, authorize) {
  const relation = records.relations.find((row) => row.id === scopeItem.entry_path_id) ?? null;
  const entryTarget = records.targets.find((row) => row.id === scopeItem.target_id) ?? null;
  const anchorTarget = records.targets.find((row) => row.id === comparison.anchor_target_id) ?? null;
  const originBinding = scopeItem.origin_binding_id
    ? records.originBindings.find((row) => row.id === scopeItem.origin_binding_id) ?? null
    : null;
  const result = revalidateScopeItem(scopeItem, { relation, anchorTarget, entryTarget, originBinding, tenantId: comparison.tenant_id });
  if (!result.ok) return result;
  return authorize(relation, entryTarget);
}

function outstanding(comparison) {
  return comparison.items.some((item) => ['pending', 'deferred', 'started'].includes(item.state));
}

function* lockedOperation(b, tenantId, id, options, operation) {
  const handle = yield b.lock(tenantId, id, options);
  if (!handle) return { locked: false };
  try {
    return { locked: true, result: yield* operation() };
  } finally {
    yield b.unlock(handle);
  }
}

/** Start approved items via startTestRun after rechecking scope digest, declaration, target hash, and ownership. */
function* advanceComparison(b, ctx, id, options = {}) {
  let result = null;
  for (let pass = 0; pass < MAX_RECONCILE_PASSES; pass += 1) {
    const preview = yield b.get(ctx?.tenantId ?? null, id);
    if (!preview) return pass ? result : null;
    if (preview.status !== 'running') return pass ? result : { id, advanced: false, reason: 'inactive', status: preview.status };
    const outcome = yield* lockedOperation(b, preview.tenant_id, id, {}, function* advance() {
      const comparison = yield b.get(preview.tenant_id, id);
      return comparison ? yield* advanceLocked(b, ctx, comparison, options) : null;
    });
    if (!outcome.locked) return pass ? result : { id, advanced: false, reason: 'reentrant' };
    result = outcome.result;
    if (!(yield b.reconcileRequested(preview.tenant_id, id))) return result;
  }
  return result;
}

function* advanceLocked(b, ctx, comparison, options) {
  const { id } = comparison;
  if (comparison.status !== 'running') return { id, advanced: false, reason: 'inactive', status: comparison.status };
  const runtimeConfig = options.runtimeConfig ?? (yield b.runtimeConfig()) ?? null;
  const execCtx = comparison.execution_ctx ?? { tenantId: comparison.tenant_id, userId: 'system', role: 'system' };
  const actor = ctx?.userId ? ctx : execCtx;
  const at = nowIso(options);
  yield* reconcileStarted(b, actor, comparison, at);
  if (!verifyApprovedScope(comparison.approved_scope)) {
    comparison.cancel_reason = 'approved_scope_invalid';
    comparisonAudit(actor, comparison, ENTRY_PATH_COMPARISON_AUDIT_ACTIONS.scopeRejected, { reason: 'approved_scope_invalid' });
    skipOutstanding(actor, comparison, 'approved_scope_invalid', at);
    yield* cancelStartedRuns(b, actor, comparison, 'approved_scope_invalid');
    yield* reconcileStarted(b, actor, comparison, at);
    return yield* finishComparison(b, actor, comparison, options);
  }
  if (yield b.killSwitchActive(comparison.tenant_id)) {
    comparison.cancel_reason = 'kill_switch_active';
    skipOutstanding(actor, comparison, 'kill_switch_active', at);
    if (!outstanding(comparison)) return yield* finishComparison(b, actor, comparison, options);
    yield b.save(comparison);
    return { id, advanced: false, reason: 'kill_switch_active', status: comparison.status };
  }
  if (runtimeConfig && !isProtectionValidationEnabled({ tenantId: comparison.tenant_id }, runtimeConfig)) {
    if (options.pauseWhenGateOff === true) {
      yield b.save(comparison);
      return { id, advanced: false, reason: 'protection_validation_disabled', paused: true, status: comparison.status };
    }
    comparison.cancel_reason = 'protection_validation_disabled';
    skipOutstanding(actor, comparison, 'protection_validation_disabled', at);
    if (!outstanding(comparison)) return yield* finishComparison(b, actor, comparison, options);
    yield b.save(comparison);
    return { id, advanced: false, reason: 'protection_validation_disabled', status: comparison.status };
  }
  if (!runtimeConfig || (runtimeConfig.probeMode ?? 'simulation') !== comparison.probe_mode) {
    yield b.save(comparison);
    return { id, advanced: false, reason: 'runtime_not_configured', status: comparison.status };
  }
  const maxStarts = Math.max(1, Number(options.maxStartsPerTick) || 8);
  const records = yield b.loadRecords(execCtx, scopeSelection(comparison), options);
  const authorize = executionGate(records, runtimeConfig);
  let starts = 0;
  let waiting = false;
  for (const item of orderedItems(comparison)) {
    if (item.state !== 'pending' && item.state !== 'deferred') continue;
    if (item.state === 'deferred' && item.deferred_until && Date.parse(item.deferred_until) > Date.parse(at)) continue;
    if (starts >= maxStarts) {
      waiting = true;
      break;
    }
    const scopeItem = itemScope(comparison, item.entry_path_id);
    const check = scopeItem ? revalidate(comparison, scopeItem, records, authorize) : { ok: false, error: 'approved_scope_invalid' };
    if (!check.ok) {
      skipItem(actor, comparison, item, check.error, at);
      continue;
    }
    item.attempts += 1;
    starts += 1;
    let result;
    try {
      result = yield b.startRun(execCtx, runStartBodyForScopeItem(scopeItem), runtimeConfig, { comparison, item, startRun: options.startRun });
    } catch (error) {
      if (error instanceof EntryPathComparisonConflictError) throw error;
      result = { error: 'start_test_run_failed', status: 500 };
    }
    if (result?.run) {
      const run = (yield b.getRun(comparison.tenant_id, result.run.id)) ?? result.run;
      if (run.target_id !== scopeItem.target_id || run.check_id !== scopeItem.check_id
        || (run.origin_binding_id ?? null) !== (scopeItem.origin_binding_id ?? null)) {
        if (ACTIVE_RUN_STATUSES.has(run.status)) {
          yield b.cancelRun(execCtx, run.id, { reason: 'attempt_scope_mismatch', source: 'entry_path_comparison' });
        }
        skipItem(actor, comparison, item, 'attempt_scope_mismatch', at);
        continue;
      }
      item.test_run_id = run.id;
      item.state = FINALIZED_RUN_STATUSES.has(run.status) ? 'finalized' : run.status === 'cancelled' ? 'skipped' : 'started';
      if (item.state === 'skipped') item.skip_reason = 'run_cancelled';
      item.deferred_until = null;
      item.last_start_error = null;
      item.updated_at = at;
      yield b.checkpoint(comparison);
      continue;
    }
    item.last_start_error = result?.error ?? 'start_test_run_failed';
    const classification = classifyStartDenial(result);
    if (classification === 'defer') {
      item.attempts -= 1;
      if (deferralWindowElapsed(comparison, at)) {
        skipItem(actor, comparison, item, 'deferral_limit_reached', at);
        continue;
      }
      item.state = 'deferred';
      item.deferred_until = yield b.deferUntil(comparison, scopeItem, result, at);
      item.updated_at = at;
      continue;
    }
    if (classification === 'abort') {
      if (result.error === 'concurrent_run_blocked') {
        item.attempts -= 1;
        waiting = true;
        continue;
      }
      if (TENANT_WIDE_ABORTS.has(result.error)) {
        comparison.cancel_reason = result.error;
        skipOutstanding(actor, comparison, result.error, at);
        break;
      }
      skipItem(actor, comparison, item, result.error, at);
      continue;
    }
    if (classification === 'step' || item.attempts >= MAX_START_ATTEMPTS) {
      skipItem(actor, comparison, item, classification === 'step' ? result.error : 'start_test_run_failed', at);
      continue;
    }
    waiting = true;
  }
  if (!outstanding(comparison)) return yield* finishComparison(b, actor, comparison, options);
  yield b.save(comparison);
  return { id, advanced: true, waiting, status: comparison.status };
}

/** Deferrals stop being retried once the comparison has waited a full window since it started. */
function deferralWindowElapsed(comparison, at) {
  const started = Date.parse(comparison.started_at ?? comparison.created_at ?? '');
  return Number.isFinite(started) && Date.parse(at) - started >= ENTRY_PATH_DEFERRAL_WINDOW_MS;
}

/** One failing comparison is recorded and skipped; it never starves the rest of the tick. */
function* advanceDueCore(b, ctx, options = {}) {
  const at = nowIso(options);
  const due = yield b.listDue(ctx, at, options);
  const results = [];
  for (const comparison of due) {
    try {
      results.push(yield* advanceComparison(b, { tenantId: comparison.tenant_id }, comparison.id, options));
    } catch (error) {
      const conflict = error instanceof EntryPathComparisonConflictError;
      incMetric(conflict ? 'entry_path_comparison_conflict' : 'entry_path_comparison_advance_failed');
      results.push({ id: comparison.id, advanced: false, reason: conflict ? 'conflict' : 'advance_failed' });
    }
  }
  return results;
}

/** Pure attempt projection from one run's stored evidence; identical for both backends. */
export function buildComparisonAttempt({ run, verdict = null, events = [], job = null }, resolveSource = resolveSourcePerspective) {
  if (!run) return null;
  const probeEvent = events.find((row) => row.test_run_id === run.id
    && row.signal_type === 'probe_result'
    && isTrustedProducerEvent(row)
    && row.nonce_hash === run.correlation?.nonce_hash) ?? null;
  const metadata = probeEvent?.metadata ?? null;
  const workerId = probeEvent?.producer_kind === 'signed_probe' ? (metadata?.probe_worker_id ?? null) : null;
  return {
    test_run_id: run.id,
    run_status: run.status,
    check_id: run.check_id,
    check_version: run.check_version ?? null,
    scenario_version: run.scenario_version ?? null,
    target_id: run.target_id,
    origin_binding_id: run.origin_binding_id ?? null,
    verdict_id: verdict?.id ?? null,
    evidence_ids: verdict?.evidence_ids ?? (probeEvent ? [probeEvent.id] : []),
    observed_at: probeEvent?.timestamp ?? run.completed_at ?? run.created_at,
    worker_id: workerId,
    source_perspective: resolveSource(workerId),
    signed_target: job?.target ?? null,
    external_result: run.probe_external_result ?? metadata?.external_result ?? null,
    probe_metadata: probeEvent?.producer_kind === 'signed_probe' ? metadata : null,
  };
}

/** Current declaration digest per approved path; archived relations read as 'archived'. */
export function comparisonDeclarationDigests(comparison, relations) {
  const out = {};
  for (const item of comparison.approved_scope.items) {
    const relation = relations.find((row) => row.id === item.entry_path_id);
    if (!relation) continue;
    out[item.entry_path_id] = relation.status === 'active' ? relation.declaration_digest : 'archived';
  }
  return out;
}

function* finishComparison(b, ctx, comparison, options = {}) {
  const at = nowIso(options);
  const attempts = {};
  const execution = {};
  for (const item of comparison.items) {
    attempts[item.entry_path_id] = item.test_run_id ? yield b.attempt(comparison, item) : null;
    execution[item.entry_path_id] = { state: item.state, skip_reason: item.skip_reason };
  }
  const result = evaluateEntryPathComparison({
    scope: comparison.approved_scope,
    expectation: comparison.expectation,
    attempts,
    execution,
    currentDeclarationDigests: yield b.declarationDigests(comparison, options),
    evaluatedAt: at,
  });
  comparison.evaluation = {
    ...result.evaluation,
    anchor_target_id: comparison.anchor_target_id,
    primary_entry_path_id: comparison.primary_entry_path_id,
    reviewed_plan_digest: comparison.plan_digest,
    attempts: result.attempts,
    primary_evidence_set: result.primary_evidence_set,
  };
  comparison.status = comparison.cancel_reason ? 'cancelled' : 'completed';
  comparison.completed_at = at;
  comparisonAudit(ctx, comparison, comparison.status === 'cancelled'
    ? ENTRY_PATH_COMPARISON_AUDIT_ACTIONS.cancelled
    : ENTRY_PATH_COMPARISON_AUDIT_ACTIONS.completed, {
    reason: comparison.cancel_reason,
    evaluation_digest: result.evaluation.evaluation_digest,
    accepted: result.evaluation.summary.accepted,
    total: result.evaluation.summary.total,
    evaluated: result.evaluation.summary.evaluated,
  });
  yield b.save(comparison);
  yield b.finalized(comparison);
  return { id: comparison.id, advanced: true, waiting: false, status: comparison.status };
}

function cancelReason(options) {
  return typeof options.reason === 'string' && options.reason.trim() ? options.reason.trim().slice(0, 200) : 'comparison_cancelled';
}

/** Stop: cancel started runs through the existing cancel path and skip everything outstanding. */
function* cancelCore(b, ctx, id, options = {}) {
  const allowed = gate(ctx, PROTECTION_VALIDATION_PERMISSIONS.run_start);
  if (!allowed.ok) return denied(allowed);
  const preview = yield b.get(ctx.tenantId, id);
  if (!preview || preview.tenant_id !== ctx.tenantId) return { error: 'not_found', status: 404 };
  if (preview.status !== 'running') return { error: 'not_cancellable', status: 409 };
  const outcome = yield* lockedOperation(b, ctx.tenantId, id, { wait: true }, function* cancel() {
    const comparison = yield b.get(ctx.tenantId, id);
    if (!comparison || comparison.status !== 'running') return { error: 'not_cancellable', status: 409 };
    const at = nowIso(options);
    const reason = cancelReason(options);
    comparison.cancel_reason = reason;
    skipOutstanding(ctx, comparison, 'comparison_cancelled', at);
    yield* cancelStartedRuns(b, ctx, comparison, reason);
    for (const item of comparison.items) {
      if (item.state !== 'started') continue;
      const run = item.test_run_id ? yield b.getRun(comparison.tenant_id, item.test_run_id) : null;
      if (run && FINALIZED_RUN_STATUSES.has(run.status)) item.state = 'finalized';
      else skipItem(ctx, comparison, item, 'comparison_cancelled', at);
    }
    yield* finishComparison(b, ctx, comparison, options);
    return { comparison: presentComparison(comparison) };
  });
  if (!outcome.locked) return { error: 'comparison_busy', status: 409 };
  return outcome.result;
}

export function presentComparison(comparison) {
  const evaluation = comparison.evaluation;
  const runByPath = new Map(comparison.items.map((item) => [item.entry_path_id, item.test_run_id ?? null]));
  return {
    id: comparison.id,
    status: comparison.status,
    plan_digest: comparison.plan_digest,
    scope_digest: comparison.approved_scope?.scope_digest ?? null,
    anchor_target_id: comparison.anchor_target_id,
    primary_entry_path_id: comparison.primary_entry_path_id,
    expectation: {
      id: comparison.expectation.id,
      scenario: comparison.expectation.scenario,
      layer_outcomes: comparison.expectation.layer_outcomes,
      expectation_version: comparison.expectation.expectation_version,
      digest: comparison.expectation.digest,
    },
    baseline: evaluation?.primary_evidence_set ?? null,
    execution: comparison.items.map((item) => ({
      entry_path_id: item.entry_path_id,
      test_run_id: item.test_run_id,
      execution_state: item.state,
      skip_reason: item.skip_reason,
      deferred_until: item.deferred_until,
    })),
    evaluation_id: comparison.evaluation_id ?? null,
    items: evaluation?.items?.map((item) => ({ ...item, test_run_id: runByPath.get(item.entry_path_id) ?? null })) ?? comparison.items.map((item) => ({
      entry_path_id: item.entry_path_id,
      test_run_id: item.test_run_id ?? null,
      scenario: comparison.expectation.scenario,
      outcome: item.state === 'skipped' ? 'skipped' : 'not_tested',
      attribution: 'unattributed',
      reasons: item.skip_reason ? [item.skip_reason] : [],
      compatibility_reasons: [],
      evidence_refs: [],
      limitations: [...REQUIRED_LIMITATIONS.path_validation],
    })),
    attempts: evaluation?.attempts ?? [],
    compatibility: evaluation?.compatibility ?? null,
    summary: evaluation?.summary ?? null,
    limitations: evaluation?.limitations ?? null,
    evaluation_digest: evaluation?.evaluation_digest ?? null,
    evaluated_at: evaluation?.evaluated_at ?? null,
    cancel_reason: comparison.cancel_reason,
    created_at: comparison.created_at,
    completed_at: comparison.completed_at,
  };
}

/** Passive read: never advances, starts, or finalizes anything. */
function* getCore(b, ctx, idOrInput) {
  const id = typeof idOrInput === 'object' && idOrInput ? idOrInput.comparisonId : idOrInput;
  const allowed = gate(ctx, PROTECTION_VALIDATION_PERMISSIONS.evidence_read);
  if (!allowed.ok) return denied(allowed);
  if (typeof id !== 'string' || !id) return null;
  const comparison = yield b.get(ctx.tenantId, id);
  if (!comparison || comparison.tenant_id !== ctx.tenantId) return null;
  return presentComparison(comparison);
}

export function comparisonPageLimit(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 1
    ? Math.min(parsed, PROTECTION_VALIDATION_PAGE_LIMIT.max)
    : PROTECTION_VALIDATION_PAGE_LIMIT.default;
}

/** Passive list with bounded cursor pagination (newest first). */
function* listCore(b, ctx, query = {}) {
  const allowed = gate(ctx, PROTECTION_VALIDATION_PERMISSIONS.evidence_read);
  if (!allowed.ok) return denied(allowed);
  const page = yield b.list(ctx, {
    anchor_target_id: typeof query.anchor_target_id === 'string' && query.anchor_target_id ? query.anchor_target_id : null,
    cursor: typeof query.cursor === 'string' && query.cursor ? query.cursor : null,
    limit: comparisonPageLimit(query.limit),
  });
  return { items: page.rows.map(presentComparison), count: page.rows.length, next_cursor: page.next_cursor };
}

function* onRunTerminalCore(b, run, context = {}) {
  if (!run?.id || !run.tenant_id) return;
  const found = yield b.findByRun(run);
  for (const candidate of found) {
    const ctx = { tenantId: candidate.tenant_id, userId: 'system', role: 'system' };
    const at = new Date().toISOString();
    const outcome = yield* lockedOperation(b, candidate.tenant_id, candidate.id, {}, function* settle() {
      const comparison = yield b.get(candidate.tenant_id, candidate.id);
      if (!comparison || comparison.status !== 'running') return;
      const item = comparison.items.find((row) => row.test_run_id === run.id);
      if (!item || item.state !== 'started') return;
      const killed = applyRunTerminal(ctx, comparison, item, run, context, at);
      if (!outstanding(comparison)) {
        yield* finishComparison(b, ctx, comparison);
        return;
      }
      if (!killed) yield* advanceLocked(b, ctx, comparison, {});
      else yield b.save(comparison);
    });
    if (!outcome.locked) {
      yield b.requestReconcile(candidate, run, context, at);
      continue;
    }
    if (yield b.reconcileRequested(candidate.tenant_id, candidate.id)) yield* advanceComparison(b, ctx, candidate.id, {});
  }
}

/** Evaluation in the shape of protection_comparison_evaluations for the PV-03 repository. */
export function entryPathComparisonEvaluationRecord(comparison) {
  if (!comparison?.evaluation) return null;
  const { attempts: _attempts, primary_evidence_set: _primary, ...evaluation } = comparison.evaluation;
  return evaluation;
}

function isThenable(value) {
  return value != null && typeof value.then === 'function';
}

function runSync(generator) {
  let step = generator.next();
  while (!step.done) {
    if (isThenable(step.value)) throw new TypeError('A synchronous comparison backend returned a promise.');
    step = generator.next(step.value);
  }
  return step.value;
}

async function runAsync(generator) {
  let step = generator.next();
  while (!step.done) {
    let value;
    try {
      value = await step.value;
    } catch (error) {
      step = generator.throw(error);
      continue;
    }
    step = generator.next(value);
  }
  return step.value;
}

/** The same lifecycle over any backend: synchronous for the dev store, asynchronous for Postgres. */
export function createEntryPathComparisonService({ backend, async: isAsync = false } = {}) {
  const missing = ENTRY_PATH_COMPARISON_BACKEND_METHODS.filter((name) => typeof backend?.[name] !== 'function');
  if (missing.length) throw new Error(`entry-path comparison backend is missing: ${missing.join(', ')}`);
  const drive = isAsync ? runAsync : runSync;
  const settle = (generator, fallback) => (isAsync
    ? runAsync(generator).catch((error) => {
      if (!(error instanceof EntryPathComparisonConflictError)) throw error;
      incMetric('entry_path_comparison_conflict');
      return fallback;
    })
    : runSync(generator));

  function createEntryPathComparison(ctx, body = {}, runtimeConfig = undefined, options = {}) {
    return settle(createCore(backend, ctx, body, runtimeConfig, options), { error: 'comparison_conflict', status: 409 });
  }

  function planOrStartEntryPathComparison(ctx, input = {}, options = {}) {
    const shape = (result) => {
      if (result?.error) return result;
      if (result.plan) return result.plan;
      return { mode: 'start', ...(result.replayed ? { replayed: true } : {}), ...result.comparison };
    };
    const result = createEntryPathComparison(ctx, input, options.runtimeConfig, options);
    return isAsync ? result.then(shape) : shape(result);
  }

  return {
    createEntryPathComparison,
    planOrStartEntryPathComparison,
    advanceEntryPathComparison: (ctx, id, options = {}) => settle(advanceComparison(backend, ctx, id, options), { id, advanced: false, reason: 'conflict' }),
    advanceDueEntryPathComparisons: (ctx, options = {}) => settle(advanceDueCore(backend, ctx, options), []),
    cancelEntryPathComparison: (ctx, id, options = {}) => settle(cancelCore(backend, ctx, id, options), { error: 'comparison_busy', status: 409 }),
    getEntryPathComparison: (ctx, idOrInput) => drive(getCore(backend, ctx, idOrInput)),
    listEntryPathComparisons: (ctx, query = {}) => drive(listCore(backend, ctx, query)),
    onRunTerminal: (run, context = {}) => settle(onRunTerminalCore(backend, run, context), undefined),
  };
}

/** Declared relations come from the PV-03 store (or an injected loader); never inferred. */
function loadDevRecords(ctx, options = {}) {
  const store = getStore();
  const relations = typeof options.loadEntryPaths === 'function'
    ? options.loadEntryPaths(ctx)
    : (store.applicationEntryPaths ?? []);
  const bindingRecords = bindingRecordsFromStore(store, ctx.tenantId);
  return {
    relations: (relations ?? []).filter((row) => row?.tenant_id === ctx.tenantId),
    targets: (store.targets ?? []).filter((row) => row.tenant_id === ctx.tenantId),
    originBindings: (store.originBindings ?? []).filter((row) => row.tenant_id === ctx.tenantId),
    targetGroups: (store.targetGroups ?? []).filter((row) => row.tenant_id === ctx.tenantId),
    originProof: (targetId) => currentOriginProof(bindingRecords, ctx.tenantId, targetId),
    targetProof: (group, targetId) => targetOwnershipProof(ctx, group, targetId),
  };
}

function devAttempt(comparison, item) {
  const store = getStore();
  const run = store.testRuns.find((row) => row.id === item.test_run_id && row.tenant_id === comparison.tenant_id);
  if (!run) return null;
  return buildComparisonAttempt({
    run,
    verdict: (store.verdicts ?? []).find((row) => row.test_run_id === run.id && row.tenant_id === comparison.tenant_id) ?? null,
    events: (store.events ?? []).filter((row) => row.test_run_id === run.id && row.tenant_id === comparison.tenant_id),
    job: (store.probeJobs ?? []).find((row) => row.test_run_id === run.id && row.tenant_id === comparison.tenant_id) ?? null,
  });
}

function flushDevAudits(entries) {
  for (const entry of entries) audit(entry);
}

function createDevComparisonBackend() {
  const find = (tenantId, id) => comparisonsOf(getStore()).find((row) => row.id === id && (!tenantId || row.tenant_id === tenantId)) ?? null;
  return {
    runtimeConfig: () => defaultRuntimeConfig,
    loadRecords: (ctx, _selection, options) => loadDevRecords(ctx, options),
    killSwitchActive: (tenantId) => isKillSwitchActiveForTenant(tenantId),
    startRun: (execCtx, body, runtimeConfig, extra = {}) => (extra.startRun ?? startTestRun)(execCtx, body, runtimeConfig),
    checkpoint: () => undefined,
    getRun: (tenantId, runId) => getStore().testRuns.find((row) => row.id === runId && row.tenant_id === tenantId) ?? null,
    cancelRun: (ctx, runId, options) => cancelTestRun(ctx, runId, options),
    deferUntil: (comparison, scopeItem, result, at) => {
      const store = getStore();
      const group = store.targetGroups.find((row) => row.id === scopeItem.target_group_id && row.tenant_id === comparison.tenant_id);
      return deferredStepEligibleAt({
        code: result.error,
        runs: store.testRuns,
        tenantId: comparison.tenant_id,
        targetGroupId: scopeItem.target_group_id,
        minSecondsBetweenRuns: normalizeSafetyPolicy(group?.safety_policy).min_seconds_between_runs,
        now: new Date(at),
      });
    },
    attempt: devAttempt,
    declarationDigests: (comparison, options) => comparisonDeclarationDigests(
      comparison,
      loadDevRecords({ tenantId: comparison.tenant_id }, options).relations,
    ),
    findByIdempotencyKey: (ctx, key) => comparisonsOf(getStore()).find((row) => row.tenant_id === ctx.tenantId && row.idempotency_key === key) ?? null,
    findRunningByPlanDigest: (ctx, digest) => comparisonsOf(getStore()).find((row) => row.tenant_id === ctx.tenantId
      && row.plan_digest === digest
      && row.status === 'running') ?? null,
    insert: (_ctx, comparison) => {
      comparisonsOf(getStore()).push(comparison);
      flushDevAudits(takePendingComparisonAudits(comparison));
      persistStore();
      return { comparison };
    },
    save: (comparison) => {
      flushDevAudits(takePendingComparisonAudits(comparison));
      persistStore();
    },
    appendAudits: (_ctx, entries) => {
      flushDevAudits(entries);
      persistStore();
    },
    get: find,
    list: (ctx, filter) => {
      const rows = comparisonsOf(getStore())
        .filter((row) => row.tenant_id === ctx.tenantId)
        .filter((row) => !filter.anchor_target_id || row.anchor_target_id === filter.anchor_target_id)
        .sort((a, b) => (b.created_at.localeCompare(a.created_at)) || b.id.localeCompare(a.id));
      const start = filter.cursor ? rows.findIndex((row) => row.id === filter.cursor) + 1 : 0;
      const page = rows.slice(Math.max(0, start), Math.max(0, start) + filter.limit);
      const nextCursor = Math.max(0, start) + filter.limit < rows.length ? page.at(-1)?.id ?? null : null;
      return { rows: page, next_cursor: nextCursor };
    },
    listDue: (_ctx, at) => comparisonsOf(getStore()).filter((comparison) => comparison.status === 'running'
      && comparison.items.some((item) => item.state === 'pending'
        || (item.state === 'deferred' && (!item.deferred_until || Date.parse(item.deferred_until) <= Date.parse(at))))),
    lock: (_tenantId, id, options = {}) => {
      if (advancing.has(id) && options.wait !== true) return null;
      advancing.add(id);
      return id;
    },
    unlock: (id) => {
      advancing.delete(id);
    },
    reconcileRequested: () => false,
    requestReconcile: (candidate, run, context, at) => {
      const ctx = { tenantId: candidate.tenant_id, userId: 'system', role: 'system' };
      const comparison = find(candidate.tenant_id, candidate.id);
      const item = comparison?.status === 'running' ? comparison.items.find((row) => row.test_run_id === run.id) : null;
      if (item?.state === 'started') applyRunTerminal(ctx, comparison, item, run, context, at);
    },
    findByRun: (run) => comparisonsOf(getStore()).filter((comparison) => comparison.tenant_id === run.tenant_id
      && comparison.status === 'running'
      && comparison.items.some((item) => item.test_run_id === run.id && item.state === 'started')),
    finalized: (comparison) => notifyFinalized(comparison),
  };
}

const devService = createEntryPathComparisonService({ backend: createDevComparisonBackend() });

/** POST /v1/entry-path-comparisons: `plan` is passive; `start` is the only traffic-dispatching mode. */
export function createEntryPathComparison(ctx, body = {}, runtimeConfig = undefined, options = {}) {
  return devService.createEntryPathComparison(ctx, body, runtimeConfig, options);
}

export function planEntryPathComparisonForTarget(ctx, body = {}, runtimeConfig = undefined, options = {}) {
  return createEntryPathComparison(ctx, { ...body, mode: 'plan' }, runtimeConfig, options);
}

export function advanceEntryPathComparison(ctx, id, options = {}) {
  return devService.advanceEntryPathComparison(ctx, id, options);
}

/** Dev store has no collection sweeper: finalize started runs whose window expired so their hooks settle the comparison. */
export function finalizeExpiredComparisonRuns() {
  const store = getStore();
  let finalized = 0;
  for (const comparison of comparisonsOf(store)) {
    if (comparison.status !== 'running') continue;
    for (const item of comparison.items) {
      if (item.state !== 'started' || !item.test_run_id) continue;
      const run = store.testRuns.find((row) => row.id === item.test_run_id && row.tenant_id === comparison.tenant_id);
      if (run && maybeFinalizeCollectingRun(run)) finalized += 1;
    }
  }
  if (finalized > 0) persistStore();
  return finalized;
}

/** Scheduler tick: resume running comparisons whose deferred items are now eligible. */
export function advanceDueEntryPathComparisons(options = {}) {
  return devService.advanceDueEntryPathComparisons({}, options);
}

export function cancelEntryPathComparison(ctx, id, options = {}) {
  return devService.cancelEntryPathComparison(ctx, id, options);
}

export function getEntryPathComparison(ctx, idOrInput) {
  return devService.getEntryPathComparison(ctx, idOrInput);
}

export function listEntryPathComparisons(ctx, query = {}) {
  return devService.listEntryPathComparisons(ctx, query);
}

registerRunTerminalHook((run, context) => devService.onRunTerminal(run, context));

/** Delegated route shape: flattened body with `mode`, or `{ error, status }`. */
export function planOrStartEntryPathComparison(ctx, input = {}, options = {}) {
  return devService.planOrStartEntryPathComparison(ctx, input, options);
}

export const ENTRY_PATH_COMPARISON_SERVICE_METHODS = Object.freeze({
  planOrStartEntryPathComparison,
  listEntryPathComparisons,
  getEntryPathComparison,
  cancelEntryPathComparison,
});
