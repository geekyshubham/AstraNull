import { randomUUID } from 'node:crypto';
import { CHECK_CATALOG, customerSelectableChecks, getCheckById, isCustomerRunnable } from '../../contracts/checks.mjs';
import {
  ACTIVE_SCAN_STATUSES,
  ACTIVE_STEP_STATUSES,
  CANCELLABLE_SCAN_STATUSES,
  MAX_STEP_START_ATTEMPTS,
  SCAN_AUDIT_ACTIONS,
  SCAN_LEASE_MS,
  buildActivityItems,
  classifyStartDenial,
  computeScanSummary,
  deferredStepEligibleAt,
  deriveScanStatus,
  isHourlyCapDenial,
  nextScanOccurrenceAt,
  nextScanOccurrenceAfter,
  normalizeCancelReason,
  normalizeScanInput,
  paginateActivity,
  planScanSteps,
  projectScanStep,
  scanExecutionContext,
  scanOccurrenceKey,
  scanValidationResponse,
} from '../../contracts/validationScanManagement.mjs';
import { roleHasPermission } from '../../contracts/roles.mjs';
import { probeDispatchReady } from '../../config.mjs';
import { newId } from '../../lib/ids.mjs';
import { incMetric } from '../../lib/metrics.mjs';
import { isWithinSafeTestWindow, normalizeSafetyPolicy } from '../../lib/safeTestGuards.mjs';
import { LEAN_GROUP_LOOKUP } from './coreCatalogRepository.mjs';

const ACTIVE_RUN_STATUSES = Object.freeze(['planned', 'running', 'collecting']);
// Matches the 500-id cap of the evidence and probe-job batch reads.
const RUN_ID_BATCH_SIZE = 500;

function chunkRunIds(runIds) {
  const chunks = [];
  for (let index = 0; index < runIds.length; index += RUN_ID_BATCH_SIZE) {
    chunks.push(runIds.slice(index, index + RUN_ID_BATCH_SIZE));
  }
  return chunks;
}

/** @type {readonly string[]} */
export const POSTGRES_VALIDATION_SCAN_SERVICE_METHODS = Object.freeze([
  'createValidationScan',
  'listValidationScans',
  'getValidationScan',
  'patchValidationScan',
  'cancelValidationScan',
  'getValidationScanActivity',
  'advanceScan',
  'advanceScanForRun',
  'listDueValidationScans',
  'listRunnableScans',
  'dispatchDueValidationScans',
  'configureValidationScanRuntime',
]);

/** @type {readonly string[]} */
export const VALIDATION_SCAN_REPOSITORY_REQUIRED_METHODS = Object.freeze([
  'createScan',
  'getScan',
  'getStep',
  'listScans',
  'listSteps',
  'updateScan',
  'updateScanWithSteps',
  'updateStep',
  'replaceSteps',
  'findScanByOccurrenceKey',
  'listDueScans',
  'leaseDueScans',
  'listRunnableScans',
  'withScanLock',
  'createNextOccurrence',
  'appendScanAudit',
  'listAuditEntriesForScan',
]);

/** @type {readonly string[]} */
export const VALIDATION_SCAN_TEST_RUN_SERVICE_METHODS = Object.freeze([
  'startTestRun',
  'cancelTestRun',
  'getTestRun',
  'registerRunTerminalHook',
]);

function assertMethods(target, label, methods, prefix) {
  if (!target || typeof target !== 'object') {
    throw new Error(`${prefix} requires ${label}.`);
  }
  for (const method of methods) {
    if (typeof target[method] !== 'function') {
      throw new Error(`${prefix} requires ${label}.${method}().`);
    }
  }
}

function toDate(value) {
  const date = value instanceof Date ? value : new Date(value ?? Date.now());
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function systemCtx(tenantId) {
  return { tenantId, userId: 'system', role: 'system' };
}

function execCtxFor(scan) {
  return scanExecutionContext(scan);
}

class ScanInactiveError extends Error {
  constructor(scanId) {
    super('validation scan is no longer in the expected state');
    this.name = 'ScanInactiveError';
    this.scanId = scanId;
  }
}

function canAdvanceOnRead(ctx) {
  return roleHasPermission(ctx?.role, 'test_run:start');
}

function advanceEnabled(options) {
  return options?.advance !== false && options?.advance !== 'false';
}

function leaseHeldByOther(scan, now) {
  return Boolean(scan.lease_token && scan.lease_expires_at && new Date(scan.lease_expires_at) > now);
}

function stepAuditMetadata(step, extra = {}) {
  return {
    step_id: step.id,
    check_id: step.check_id,
    target_id: step.target_id,
    test_run_id: step.test_run_id ?? null,
    ...extra,
  };
}

function resolveChecks(checkIds) {
  const selectable = new Set(customerSelectableChecks(CHECK_CATALOG).map((check) => check.check_id));
  const checks = [];
  for (const checkId of checkIds) {
    const check = getCheckById(checkId);
    if (!check) return { error: 'unknown_check', status: 400, check_id: checkId };
    if (!isCustomerRunnable(check)) {
      return { error: 'soc_gated_check', status: 403, check_id: checkId, message: 'This check requires SOC governance.' };
    }
    if (!selectable.has(checkId)) {
      return { error: 'check_requires_additional_input', status: 400, check_id: checkId };
    }
    checks.push(check);
  }
  return { checks };
}

function materializeSteps(steps, checks, now) {
  const checkById = new Map(checks.map((check) => [check.check_id, check]));
  return steps.map((step) => ({
    id: newId('step'),
    position: step.position,
    check_id: step.check_id,
    check_name: checkById.get(step.check_id)?.name ?? step.check_id,
    target_id: step.target_id,
    status: 'pending',
    test_run_id: null,
    error_code: null,
    skip_reason: null,
    eligible_at: null,
    attempts: 0,
    request_snapshot: step.request_snapshot,
    started_at: null,
    completed_at: null,
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
  }));
}

function planSnapshot(plan) {
  const checks = {};
  for (const check of plan.checks) {
    checks[check.check_id] = {
      name: check.name,
      vector_family: check.vector_family,
      evidence_tier: check.evidence_tier ?? null,
      probe_profile_kind: check.probe_profile?.kind ?? null,
      safety_constraints: check.safety_constraints ?? null,
    };
  }
  return {
    checks,
    group_safety_policy: normalizeSafetyPolicy(plan.group.safety_policy),
    target_ids: plan.targets.map((target) => target.id),
    target_policy_bindings: Object.fromEntries(plan.targets.map((target) => [target.id, target.target_group_id ?? plan.group.id])),
    excluded: plan.excluded,
  };
}

/**
 * @param {{
 *   validationScans: Record<string, Function>,
 *   validationEvidence: Record<string, Function>,
 *   coreCatalog: { getTargetGroup: Function },
 *   audit?: Record<string, Function>,
 *   killSwitch: { isKillSwitchActiveForTenant: Function },
 *   internalManagement?: { getTenantDetail?: Function },
 *   subscriptions?: Record<string, Function>,
 * }} repositories
 * @param {{
 *   testRuns: { startTestRun: Function, cancelTestRun: Function, getTestRun: Function, registerRunTerminalHook: Function },
 *   now?: () => Date,
 *   runtimeConfig?: Record<string, unknown>,
 * }} options
 */
export function createPostgresValidationScanServices(repositories, options = {}) {
  const prefix = 'Postgres validation scan service adapter';
  assertMethods(repositories?.validationScans, 'repositories.validationScans', VALIDATION_SCAN_REPOSITORY_REQUIRED_METHODS, prefix);
  assertMethods(repositories?.validationEvidence, 'repositories.validationEvidence', ['listTestRuns', 'getTestRun', 'getVerdictForRun', 'listRunEvents'], prefix);
  assertMethods(repositories?.coreCatalog, 'repositories.coreCatalog', ['getTargetGroup'], prefix);
  assertMethods(repositories?.killSwitch, 'repositories.killSwitch', ['isKillSwitchActiveForTenant'], prefix);
  assertMethods(options?.testRuns, 'options.testRuns', VALIDATION_SCAN_TEST_RUN_SERVICE_METHODS, prefix);

  const repo = repositories.validationScans;
  const validationEvidence = repositories.validationEvidence;
  const coreCatalog = repositories.coreCatalog;
  const killSwitch = repositories.killSwitch;
  const internalManagement = repositories.internalManagement ?? null;
  const testRuns = options.testRuns;
  const nowFn = options.now ?? (() => new Date());
  let defaultRuntimeConfig = options.runtimeConfig ?? null;

  function runtimeConfigFor(callOptions = {}) {
    return callOptions.runtimeConfig ?? defaultRuntimeConfig ?? { probeMode: 'simulation' };
  }

  async function scanAudit(ctx, scan, action, metadata = {}) {
    await repo.appendScanAudit(ctx, {
      action,
      resource_type: 'validation_scan',
      resource_id: scan.id,
      metadata: {
        target_group_id: scan.target_group_id,
        target_id: scan.target_id ?? null,
        ...metadata,
      },
    }, { now: nowFn() });
  }

  async function loadGroup(ctx, groupId) {
    return coreCatalog.getTargetGroup(ctx, groupId, LEAN_GROUP_LOOKUP);
  }

  async function activeRunForGroup(ctx, targetGroupId) {
    const runs = await validationEvidence.listTestRuns(ctx, {
      targetGroupId,
      statuses: [...ACTIVE_RUN_STATUSES],
      limit: 1,
    });
    return runs[0] ?? null;
  }

  async function activeScanForGroup(ctx, targetGroupId, excludeId = null) {
    const scans = await repo.listScans(ctx, {
      targetGroupId,
      status: [...ACTIVE_SCAN_STATUSES],
      excludeId,
      limit: 1,
    });
    return scans[0] ?? null;
  }

  async function tenantSuspended(tenantId) {
    if (typeof internalManagement?.getTenantDetail !== 'function') return false;
    const detail = await internalManagement.getTenantDetail(tenantId);
    return detail?.account?.lifecycle_state === 'suspended';
  }

  async function buildPlan(ctx, input) {
    let policyId = input.target_group_id;
    if (!policyId) {
      if (typeof coreCatalog.getTarget !== 'function') return { error: 'target_selection_unavailable', status: 503 };
      const selected = await coreCatalog.getTarget(ctx, input.target_id ?? input.target_ids?.[0]);
      if (!selected || selected.tenant_id !== ctx.tenantId) return { error: 'target_not_found', status: 404 };
      policyId = selected.target_group_id;
    }
    const group = await loadGroup(ctx, policyId);
    if (!group) return { error: 'target_group_not_found', status: 404 };
    const resolved = resolveChecks(input.check_ids);
    if (resolved.error) return resolved;
    let targets = (group.targets ?? []).filter((target) => !target.deleted_at);
    if (input.target_ids) {
      const scopes = new Map([[group.id, group]]);
      const selected = [];
      for (const id of input.target_ids) {
        let target = targets.find((candidate) => candidate.id === id);
        if (!target) {
          if (typeof coreCatalog.getTarget !== 'function') return { error: 'target_selection_unavailable', status: 503 };
          const binding = await coreCatalog.getTarget(ctx, id);
          if (!binding || binding.tenant_id !== ctx.tenantId) return { error: 'target_not_found', status: 404 };
          if (!scopes.has(binding.target_group_id)) scopes.set(binding.target_group_id, await loadGroup(ctx, binding.target_group_id));
          target = scopes.get(binding.target_group_id)?.targets?.find((candidate) => candidate.id === id && !candidate.deleted_at);
        }
        if (!target) return { error: 'target_not_found', status: 404 };
        selected.push(target);
      }
      targets = selected;
      if ((targets[0].target_group_id ?? group.id) !== group.id) return { error: 'target_selection_conflict', status: 400 };
    }
    if (input.target_id && !targets.some((target) => target.id === input.target_id)) {
      return { error: 'target_not_found', status: 404 };
    }
    let plan;
    try {
      plan = planScanSteps({ checks: resolved.checks, targets, targetId: input.target_id });
    } catch (err) {
      return scanValidationResponse(err);
    }
    if (input.target_id && plan.excluded.length) {
      const first = plan.excluded[0];
      return {
        error: 'target_kind_not_supported',
        status: 400,
        check_id: first.check_id,
        target_kind: first.target_kind,
        supported_targets: first.supported_targets,
      };
    }
    if (!plan.steps.length) return { error: 'scan_has_no_runnable_steps', status: 400, excluded: plan.excluded };
    return { group, targets: input.target_id ? targets.filter((target) => target.id === input.target_id) : targets, checks: resolved.checks, steps: plan.steps, excluded: plan.excluded };
  }

  class ScanState {
    constructor(ctx, scan, steps, guard = { expectedStatuses: [...ACTIVE_SCAN_STATUSES] }) {
      this.ctx = ctx;
      this.scan = scan;
      this.steps = steps;
      this.guard = guard;
    }

    async patchScan(patch, now) {
      const updated = await repo.updateScan(this.ctx, this.scan.id, { ...patch, updated_at: now.toISOString() }, this.guard);
      if (updated?.error) throw Object.assign(new Error(updated.error), { scanUpdate: updated });
      if (!updated) throw new ScanInactiveError(this.scan.id);
      this.scan = updated;
      return this.scan;
    }

    async patchStep(step, patch, now, options = {}) {
      const updated = await repo.updateStep(this.ctx, step.id, { ...patch, updated_at: now.toISOString() }, options);
      if (updated) {
        Object.assign(step, updated);
        return step;
      }
      if (options.expectedStatuses) return null;
      Object.assign(step, patch, { updated_at: now.toISOString() });
      return step;
    }

    async refreshSummary(now, extra = {}) {
      return this.patchScan({ summary: computeScanSummary(this.steps), ...extra }, now);
    }

    async releaseLease(now, extra = {}) {
      return this.patchScan({ lease_token: null, lease_owner: null, lease_expires_at: null, ...extra }, now);
    }

    async claimLease(owner, now) {
      const token = randomUUID();
      await this.patchScan({
        lease_token: token,
        lease_owner: owner,
        lease_expires_at: new Date(now.getTime() + SCAN_LEASE_MS).toISOString(),
      }, now);
      return token;
    }
  }

  async function loadState(ctx, scanId) {
    const scan = await repo.getScan(ctx, scanId);
    if (!scan) return null;
    const steps = await repo.listSteps(ctx, scan.id);
    return new ScanState(ctx, scan, steps);
  }

  async function skipRemainingSteps(state, reason, now) {
    const skipped = [];
    for (const step of state.steps) {
      if (!['pending', 'deferred', 'starting'].includes(step.status)) continue;
      await state.patchStep(step, {
        status: 'skipped',
        skip_reason: reason,
        completed_at: now.toISOString(),
      }, now);
      skipped.push(step.id);
    }
    return skipped;
  }

  async function finishScan(actor, state, now) {
    const derived = deriveScanStatus(state.steps);
    const status = derived === 'running' ? 'completed' : derived;
    await state.patchScan({
      status,
      completed_at: now.toISOString(),
      next_eligible_at: null,
      lease_token: null,
      lease_owner: null,
      lease_expires_at: null,
      summary: computeScanSummary(state.steps),
    }, now);
    await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.completed, {
      status: state.scan.status,
      summary: state.scan.summary,
      abort_reason: state.scan.abort_reason ?? null,
    }, now);
  }

  async function completeStep(actor, state, step, run, now) {
    const verdict = await validationEvidence.getVerdictForRun(state.ctx, run.id);
    const dispatchFailed = run.status === 'cancelled' && run.summary?.dispatch_failed === true;
    await state.patchStep(step, {
      status: run.status === 'verdicted' ? 'verdicted' : dispatchFailed ? 'denied' : 'cancelled',
      error_code: dispatchFailed ? 'probe_dispatch_failed' : step.error_code ?? null,
      completed_at: run.completed_at ?? now.toISOString(),
    }, now);
    await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.stepCompleted, stepAuditMetadata(step, {
      run_status: run.status,
      verdict: verdict?.verdict ?? null,
      confidence: verdict?.confidence ?? null,
    }), now);
  }

  async function reconcileActiveStep(actor, state, now) {
    const active = state.steps.find((step) => ACTIVE_STEP_STATUSES.includes(step.status));
    if (!active) return { waiting: false };
    let run = null;
    if (active.test_run_id) {
      run = await validationEvidence.getTestRun(state.ctx, active.test_run_id);
    } else if (typeof validationEvidence.getTestRunByScanStepId === 'function') {
      run = await validationEvidence.getTestRunByScanStepId(state.ctx, active.id);
    }
    if (run && !active.test_run_id) await state.patchStep(active, { test_run_id: run.id }, now);
    if (!run) {
      if (active.attempts >= MAX_STEP_START_ATTEMPTS) {
        await state.patchStep(active, {
          status: 'denied',
          error_code: 'start_test_run_failed',
          completed_at: now.toISOString(),
        }, now);
        await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.advanceFailed, stepAuditMetadata(active, {
          error_code: active.error_code,
        }), now);
      } else {
        await state.patchStep(active, { status: 'pending' }, now);
      }
      return { waiting: false };
    }
    if (run.status === 'verdicted' || run.status === 'cancelled') {
      await completeStep(actor, state, active, run, now);
      return { waiting: false };
    }
    await state.patchStep(active, { status: run.status === 'collecting' ? 'collecting' : 'running' }, now);
    if (state.scan.status === 'pending') await state.patchScan({ status: 'running' }, now);
    return { waiting: true };
  }

  function nextStartableStep(state, now) {
    const pending = state.steps.find((step) => step.status === 'pending');
    if (pending) return pending;
    return state.steps.find(
      (step) => step.status === 'deferred' && step.eligible_at && new Date(step.eligible_at) <= now,
    ) ?? null;
  }

  async function deferStep(actor, state, step, result, now) {
    const execCtx = execCtxFor(state.scan);
    const code = result?.error ?? 'safe_min_interval_active';
    const policyId = state.scan.plan_snapshot?.target_policy_bindings?.[step.target_id] ?? state.scan.target_group_id;
    const group = await loadGroup(execCtx, policyId);
    const policy = normalizeSafetyPolicy(group?.safety_policy);
    const recentRuns = await validationEvidence.listTestRuns(
      execCtx,
      isHourlyCapDenial(code) ? { limit: 500 } : { targetGroupId: policyId, limit: 5 },
    );
    const eligibleAt = deferredStepEligibleAt({
      code,
      runs: recentRuns,
      tenantId: state.scan.tenant_id,
      targetGroupId: policyId,
      minSecondsBetweenRuns: policy.min_seconds_between_runs,
      now,
    });
    await state.patchStep(step, { status: 'deferred', eligible_at: eligibleAt }, now);
    await state.patchScan({ next_eligible_at: eligibleAt }, now);
    await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.stepDeferred, stepAuditMetadata(step, {
      eligible_at: eligibleAt,
      error_code: code,
    }), now);
  }

  async function denyStep(actor, state, step, result, now) {
    await state.patchStep(step, {
      status: 'denied',
      error_code: result.error ?? 'start_test_run_failed',
      completed_at: now.toISOString(),
    }, now);
    await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.stepDenied, stepAuditMetadata(step, {
      error_code: step.error_code,
    }), now);
  }

  async function abortScan(actor, state, step, result, now) {
    await denyStep(actor, state, step, result, now);
    await state.patchScan({ abort_reason: result.error }, now);
    const reason = `scan_aborted:${result.error}`;
    const skipped = await skipRemainingSteps(state, reason, now);
    if (skipped.length) {
      await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.stepSkipped, {
        step_ids: skipped,
        skipped_steps: skipped.length,
        reason,
      }, now);
    }
  }

  async function cancelOrphanedRun(state, step, run, now) {
    const ctx = systemCtx(state.scan.tenant_id);
    const current = await repo.getScan(ctx, state.scan.id);
    const reason = current?.cancel_reason ?? 'scan_no_longer_active';
    let cancelled = false;
    if (run?.id && ACTIVE_RUN_STATUSES.includes(run.status)) {
      const result = await testRuns.cancelTestRun(ctx, run.id, { reason, source: 'scan', scan_id: state.scan.id });
      cancelled = Boolean(result && !result.error);
    }
    await state.patchStep(step, {
      status: 'cancelled',
      test_run_id: run?.id ?? step.test_run_id ?? null,
      completed_at: now.toISOString(),
    }, now);
    if (run?.id) {
      await scanAudit(ctx, current ?? state.scan, SCAN_AUDIT_ACTIONS.orphanRunCancelled, stepAuditMetadata(step, {
        test_run_id: run.id,
        run_cancelled: cancelled,
        status: current?.status ?? null,
      }), now);
    }
  }

  async function startStep(state, step, runtimeConfig, now) {
    await state.patchStep(step, {
      status: 'starting',
      attempts: (step.attempts ?? 0) + 1,
      started_at: step.started_at ?? now.toISOString(),
    }, now);
    const leaseToken = await state.claimLease('validation-scan-executor', now);
    let result;
    try {
      result = await testRuns.startTestRun(
        execCtxFor(state.scan),
        { check_id: step.check_id, target_group_id: state.scan.plan_snapshot?.target_policy_bindings?.[step.target_id] ?? state.scan.target_group_id, target_id: step.target_id },
        runtimeConfig,
        { scanDispatch: { scan_id: state.scan.id, step_id: step.id, lease_token: leaseToken } },
      );
    } catch {
      result = { error: 'start_test_run_failed', status: 500 };
    }
    try {
      await state.releaseLease(now);
    } catch (err) {
      if (err instanceof ScanInactiveError) await cancelOrphanedRun(state, step, result?.run ?? null, now);
      throw err;
    }
    return result;
  }

  async function blockAdvance(actor, state, runtimeConfig, now) {
    await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.advanceBlocked, {
      reason: 'probe_signing_unavailable',
      error_code: runtimeConfig?.probeConfigError ?? 'probe_worker_secret_invalid',
    }, now);
    await state.refreshSummary(now);
    return {
      scan_id: state.scan.id,
      acquired: true,
      waiting: true,
      status: state.scan.status,
      reason: 'probe_signing_unavailable',
    };
  }

  async function executeScan(actor, state, callOptions, now) {
    const runtimeConfig = runtimeConfigFor(callOptions);
    const maxStarts = Math.max(1, Number(callOptions.maxStartsPerTick) || 5);
    const scanId = state.scan.id;
    let starts = 0;
    for (;;) {
      const reconciled = await reconcileActiveStep(actor, state, now);
      if (reconciled.waiting) {
        await state.refreshSummary(now);
        return { scan_id: scanId, acquired: true, waiting: true, status: state.scan.status };
      }
      const step = nextStartableStep(state, now);
      if (!step) {
        const deferred = state.steps.filter((row) => row.status === 'deferred');
        if (deferred.length) {
          const nextEligible = deferred.map((row) => row.eligible_at).sort()[0];
          await state.refreshSummary(now, { status: 'running', next_eligible_at: nextEligible });
          return { scan_id: scanId, acquired: true, waiting: true, deferred_until: nextEligible, status: state.scan.status };
        }
        await finishScan(actor, state, now);
        return { scan_id: scanId, acquired: true, waiting: false, status: state.scan.status };
      }
      if (starts >= maxStarts) {
        await state.refreshSummary(now);
        return { scan_id: scanId, acquired: true, waiting: true, status: state.scan.status, reason: 'max_starts_per_tick' };
      }
      if (!probeDispatchReady(runtimeConfig)) return blockAdvance(actor, state, runtimeConfig, now);
      starts += 1;
      await state.patchScan({
        status: 'running',
        started_at: state.scan.started_at ?? now.toISOString(),
        next_eligible_at: null,
      }, now);
      const result = await startStep(state, step, runtimeConfig, now);
      if (!result?.error) {
        const run = result.run ?? null;
        const linked = await state.patchStep(step, {
          test_run_id: run?.id ?? null,
          status: run?.status === 'verdicted' ? 'verdicted' : run?.status === 'collecting' ? 'collecting' : 'running',
          eligible_at: null,
        }, now, { expectedStatuses: ['starting'] });
        if (!linked) {
          await cancelOrphanedRun(state, step, run, now);
          throw new ScanInactiveError(scanId);
        }
        await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.stepStarted, stepAuditMetadata(step, {
          run_status: run?.status ?? null,
        }), now);
        if (step.status === 'verdicted' && run) await completeStep(actor, state, step, run, now);
        await state.refreshSummary(now);
        continue;
      }
      const classification = classifyStartDenial(result);
      if (classification === 'defer') {
        await deferStep(actor, state, step, result, now);
        await state.refreshSummary(now);
        return { scan_id: scanId, acquired: true, waiting: true, deferred_until: state.scan.next_eligible_at, status: state.scan.status };
      }
      if (classification === 'abort') {
        if (result.error === 'concurrent_run_blocked') {
          const blocking = await activeRunForGroup(execCtxFor(state.scan), state.scan.target_group_id);
          const ownStepId = blocking?.scan_id === scanId ? blocking.scan_step_id : null;
          if (ownStepId) {
            const ownStep = state.steps.find((row) => row.id === ownStepId);
            if (ownStep) {
              await state.patchStep(ownStep, {
                test_run_id: blocking.id,
                status: blocking.status === 'collecting' ? 'collecting' : 'running',
              }, now);
            }
            await state.patchStep(step, { status: 'pending', attempts: Math.max(0, step.attempts - 1) }, now);
            await state.refreshSummary(now);
            return { scan_id: scanId, acquired: true, waiting: true, status: state.scan.status };
          }
        }
        await abortScan(actor, state, step, result, now);
        await finishScan(actor, state, now);
        return { scan_id: scanId, acquired: true, waiting: false, status: state.scan.status, abort_reason: state.scan.abort_reason };
      }
      if (classification === 'step') {
        await denyStep(actor, state, step, result, now);
        await state.refreshSummary(now);
        continue;
      }
      if (step.attempts >= MAX_STEP_START_ATTEMPTS) {
        await denyStep(actor, state, step, { error: 'start_test_run_failed' }, now);
        await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.advanceFailed, stepAuditMetadata(step, {
          error_code: result.error ?? null,
        }), now);
        await state.refreshSummary(now);
        continue;
      }
      await state.patchStep(step, { status: 'pending' }, now);
      await state.refreshSummary(now);
      return { scan_id: scanId, acquired: true, waiting: true, status: state.scan.status, reason: 'retry_scheduled' };
    }
  }

  async function advanceScan(ctx, id, callOptions = {}) {
    if (!advanceEnabled(callOptions)) {
      return { scan_id: id, acquired: false, reason: 'advance_disabled', dispatched: false };
    }
    if (!ctx?.tenantId) return null;
    const preview = await repo.getScan(ctx, id);
    if (!preview) return null;
    const now = toDate(callOptions.now);
    if (!ACTIVE_SCAN_STATUSES.includes(preview.status)) {
      return { scan_id: preview.id, acquired: false, reason: 'inactive', status: preview.status };
    }
    if (leaseHeldByOther(preview, now)) return { scan_id: preview.id, acquired: false, reason: 'leased' };
    const actor = ctx?.userId ? ctx : systemCtx(preview.tenant_id);
    const lock = await repo.withScanLock(ctx, preview.id, async () => {
      const state = await loadState(ctx, preview.id);
      if (!state) return null;
      if (!ACTIVE_SCAN_STATUSES.includes(state.scan.status)) {
        return { scan_id: state.scan.id, acquired: false, reason: 'inactive', status: state.scan.status };
      }
      if (leaseHeldByOther(state.scan, now)) return { scan_id: state.scan.id, acquired: false, reason: 'leased' };
      try {
        return await executeScan(actor, state, callOptions, now);
      } catch (err) {
        if (!(err instanceof ScanInactiveError)) throw err;
        const current = await repo.getScan(ctx, preview.id);
        return { scan_id: preview.id, acquired: true, waiting: false, reason: 'inactive', status: current?.status ?? null };
      }
    });
    if (!lock.acquired) return { scan_id: preview.id, acquired: false, reason: 'locked' };
    return lock.result;
  }

  async function scheduleDenied(actor, state, code, now, extra = {}) {
    const skipped = state.steps
      .filter((step) => ['pending', 'deferred', 'starting'].includes(step.status))
      .map((step) => ({ ...step, status: 'skipped', skip_reason: `schedule_denied:${code}`, completed_at: now.toISOString() }));
    const denied = await repo.updateScan(state.ctx, state.scan.id, {
      status: 'denied',
      abort_reason: code,
      completed_at: now.toISOString(),
      lease_token: null,
      lease_owner: null,
      lease_expires_at: null,
      summary: computeScanSummary(state.steps.map((step) => skipped.find((row) => row.id === step.id) ?? step)),
      updated_at: now.toISOString(),
    }, state.guard);
    if (!denied || denied.error) return { scan_id: state.scan.id, dispatched: false, reason: 'lease_lost' };
    state.scan = denied;
    state.guard = { expectedStatuses: ['denied'] };
    await skipRemainingSteps(state, `schedule_denied:${code}`, now);
    await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.scheduleDenied, {
      code,
      scheduled_for: state.scan.scheduled_for,
      ...extra,
    }, now);
    return { scan_id: state.scan.id, dispatched: false, denied: code };
  }

  async function createNextOccurrence(actor, state, now) {
    const scan = state.scan;
    if (!scan.recurrence || scan.next_scan_id) return null;
    const seriesId = scan.recurrence_series_id ?? scan.id;
    const nextAt = nextScanOccurrenceAfter(scan.recurrence, scan.scheduled_for ?? now, now);
    if (!nextAt) return null;
    const occurrenceKey = scanOccurrenceKey(scan.tenant_id, seriesId, nextAt);
    let next = await repo.findScanByOccurrenceKey(state.ctx, occurrenceKey);
    let created = false;
    if (!next) {
      const checks = scan.check_ids.map((checkId) => getCheckById(checkId)).filter(Boolean);
      const steps = materializeSteps(
        state.steps.map((step, position) => ({
          position,
          check_id: step.check_id,
          target_id: step.target_id,
          request_snapshot: step.request_snapshot,
        })),
        checks,
        now,
      );
      const record = {
        ...scan,
        id: newId('scan'),
        status: 'scheduled',
        scheduled_for: nextAt,
        recurrence_series_id: seriesId,
        occurrence_key: occurrenceKey,
        occurrence_index: (scan.occurrence_index ?? 0) + 1,
        previous_scan_id: scan.id,
        next_scan_id: null,
        dispatched_at: null,
        started_at: null,
        completed_at: null,
        abort_reason: null,
        cancel_reason: null,
        cancelled_by: null,
        cancelled_by_role: null,
        cancelled_at: null,
        lease_token: null,
        lease_owner: null,
        lease_expires_at: null,
        next_eligible_at: null,
        revision: 1,
        summary: computeScanSummary(steps),
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      };
      const inserted = await repo.createNextOccurrence(state.ctx, record, steps);
      next = inserted?.scan ?? null;
      created = Boolean(inserted?.created && next);
      if (created) {
        await scanAudit(actor, next, SCAN_AUDIT_ACTIONS.scheduled, {
          series_id: seriesId,
          occurrence_index: next.occurrence_index,
          scheduled_for: next.scheduled_for,
          previous_scan_id: scan.id,
        }, now);
      }
    }
    if (!next) return null;
    try {
      await state.patchScan({ next_scan_id: next.id }, now);
    } catch (err) {
      if (!(err instanceof ScanInactiveError)) throw err;
      const current = await repo.getScan(state.ctx, scan.id);
      if (current && !current.recurrence && next.status === 'scheduled') {
        await services.cancelValidationScan(actor, next.id, { reason: current.cancel_reason ?? 'series_stopped', now });
      }
      throw err;
    }
    return next;
  }

  // Continue a recurring series after a single occurrence is cancelled without cancel_series.
  // The successor is otherwise only created at dispatch, so cancelling a scheduled run that never
  // dispatched would silently end the whole series. The new occurrence is anchored from now and is
  // not linked via the cancelled scan's next_scan_id (that scan is terminal).
  async function continueSeriesAfterCancel(actor, ctx, scan, steps, now) {
    if (!scan.recurrence) return null;
    const seriesId = scan.recurrence_series_id ?? scan.id;
    const nextAt = nextScanOccurrenceAfter(scan.recurrence, scan.scheduled_for ?? now, now);
    if (!nextAt) return null;
    const occurrenceKey = scanOccurrenceKey(scan.tenant_id, seriesId, nextAt);
    const existing = await repo.findScanByOccurrenceKey(ctx, occurrenceKey);
    if (existing) return existing;
    const checks = scan.check_ids.map((checkId) => getCheckById(checkId)).filter(Boolean);
    const nextSteps = materializeSteps(
      steps.map((step, position) => ({
        position,
        check_id: step.check_id,
        target_id: step.target_id,
        request_snapshot: step.request_snapshot,
      })),
      checks,
      now,
    );
    const record = {
      ...scan,
      id: newId('scan'),
      status: 'scheduled',
      scheduled_for: nextAt,
      recurrence_series_id: seriesId,
      occurrence_key: occurrenceKey,
      occurrence_index: (scan.occurrence_index ?? 0) + 1,
      previous_scan_id: scan.id,
      next_scan_id: null,
      dispatched_at: null,
      started_at: null,
      completed_at: null,
      abort_reason: null,
      cancel_reason: null,
      cancelled_by: null,
      cancelled_by_role: null,
      cancelled_at: null,
      lease_token: null,
      lease_owner: null,
      lease_expires_at: null,
      next_eligible_at: null,
      revision: 1,
      summary: computeScanSummary(nextSteps),
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
    };
    const inserted = await repo.createNextOccurrence(ctx, record, nextSteps);
    const next = inserted?.scan ?? null;
    if (inserted?.created && next) {
      await scanAudit(actor, next, SCAN_AUDIT_ACTIONS.scheduled, {
        series_id: seriesId,
        occurrence_index: next.occurrence_index,
        scheduled_for: next.scheduled_for,
        previous_scan_id: scan.id,
        continued_after_cancel: true,
      }, now);
    }
    return next;
  }

  async function dispatchLeasedScan(actor, leasedScan, callOptions = {}) {
    const now = toDate(callOptions.now);
    const ctx = { tenantId: leasedScan.tenant_id, userId: actor.userId, role: actor.role };
    const guard = { expectedStatuses: ['scheduled'], leaseToken: leasedScan.lease_token };
    const state = new ScanState(ctx, leasedScan, await repo.listSteps(ctx, leasedScan.id), guard);
    if (state.scan.status !== 'scheduled') return { scan_id: state.scan.id, dispatched: false, reason: 'not_scheduled' };
    try {
      await createNextOccurrence(actor, state, now);
    } catch (err) {
      if (err instanceof ScanInactiveError) return { scan_id: state.scan.id, dispatched: false, reason: 'lease_lost' };
      throw err;
    }
    const execCtx = execCtxFor(state.scan);

    if (await killSwitch.isKillSwitchActiveForTenant(execCtx)) return scheduleDenied(actor, state, 'kill_switch_active', now);
    if (await tenantSuspended(state.scan.tenant_id)) return scheduleDenied(actor, state, 'tenant_suspended', now);
    const group = await loadGroup(execCtx, state.scan.target_group_id);
    if (!group) return scheduleDenied(actor, state, 'target_group_not_found', now);
    const policyIds = [...new Set([state.scan.target_group_id, ...Object.values(state.scan.plan_snapshot?.target_policy_bindings ?? {})])];
    for (const policyId of policyIds) {
      const policy = await loadGroup(execCtx, policyId);
      if (!policy) return scheduleDenied(actor, state, 'target_execution_policy_unavailable', now);
      if ((policy.safe_test_windows ?? []).length && !isWithinSafeTestWindow(policy, now.getTime())) return scheduleDenied(actor, state, 'safe_window_closed', now);
      if (await activeRunForGroup(execCtx, policy.id) || await activeScanForGroup(execCtx, policy.id, state.scan.id)) return scheduleDenied(actor, state, 'concurrent_run_blocked', now);
    }
    const plan = await buildPlan(execCtx, {
      target_group_id: state.scan.target_group_id,
      target_id: state.scan.target_id,
      target_ids: state.scan.plan_snapshot?.target_ids ?? [...new Set(state.steps.map((step) => step.target_id))],
      check_ids: state.scan.check_ids,
    });
    if (plan.error) return scheduleDenied(actor, state, plan.error, now, { check_id: plan.check_id ?? null });
    const replannedSteps = state.scan.target_id ? null : materializeSteps(plan.steps, plan.checks, now);
    const activation = {
      status: 'running',
      dispatched_at: now.toISOString(),
      started_at: now.toISOString(),
      lease_token: null,
      lease_owner: null,
      lease_expires_at: null,
      summary: computeScanSummary(replannedSteps ?? state.steps),
      updated_at: now.toISOString(),
      ...(replannedSteps ? { plan_snapshot: planSnapshot(plan) } : {}),
    };
    const activated = replannedSteps
      ? await repo.updateScanWithSteps(ctx, state.scan.id, activation, replannedSteps, guard)
      : await repo.updateScan(ctx, state.scan.id, activation, guard);
    if (!activated) return { scan_id: state.scan.id, dispatched: false, reason: 'lease_lost' };
    if (activated.error === 'concurrent_scan_blocked') return scheduleDenied(actor, state, 'concurrent_run_blocked', now);
    if (activated.error) return scheduleDenied(actor, state, activated.error, now);
    const { steps: activatedSteps, ...activatedScan } = activated;
    state.scan = activatedScan;
    if (activatedSteps) state.steps = activatedSteps;
    await scanAudit(actor, state.scan, SCAN_AUDIT_ACTIONS.dispatched, {
      scheduled_for: state.scan.scheduled_for,
      step_count: state.steps.length,
    }, now);
    const advanced = await advanceScan(ctx, state.scan.id, { ...callOptions, now });
    return { scan_id: state.scan.id, dispatched: true, advanced };
  }

  async function dispatchDueValidationScans(ctx, callOptions = {}) {
    if (!advanceEnabled(callOptions)) return [];
    const now = toDate(callOptions.now);
    const actor = ctx?.userId ? ctx : systemCtx(ctx.tenantId);
    const leased = await repo.leaseDueScans(ctx, {
      now,
      workerId: callOptions.workerId ?? 'validation-scan-dispatcher',
      leaseMs: SCAN_LEASE_MS,
      limit: callOptions.limit,
      scanId: callOptions.scanId,
    });
    if (!Array.isArray(leased)) return leased;
    const results = [];
    for (const scan of leased) {
      try {
        results.push(await dispatchLeasedScan(actor, scan, { ...callOptions, now }));
      } catch {
        incMetric('validation_scan_dispatch_failed');
        await scanAudit(actor, scan, SCAN_AUDIT_ACTIONS.dispatchFailed, {
          scheduled_for: scan.scheduled_for,
          reason: 'dispatch_exception',
        }, now).catch(() => {});
        results.push({ scan_id: scan.id, dispatched: false, reason: 'dispatch_failed' });
      }
    }
    return results;
  }

  async function readPathAdvance(ctx, scan, callOptions = {}) {
    if (!advanceEnabled(callOptions) || !canAdvanceOnRead(ctx)) return;
    const now = toDate(callOptions.now);
    const system = systemCtx(scan.tenant_id);
    if (scan.status === 'scheduled' && scan.scheduled_for && new Date(scan.scheduled_for) <= now) {
      await dispatchDueValidationScans(system, { ...callOptions, now, scanId: scan.id, limit: 1 });
      return;
    }
    if (ACTIVE_SCAN_STATUSES.includes(scan.status)) await advanceScan(system, scan.id, { ...callOptions, now });
  }

  async function projectScans(ctx, scans) {
    if (!scans.length) return [];
    const stepsByScan = new Map(scans.map((scan) => [scan.id, []]));
    const allSteps = typeof repo.listStepsForScans === 'function'
      ? await repo.listStepsForScans(ctx, scans.map((scan) => scan.id))
      : (await Promise.all(scans.map((scan) => repo.listSteps(ctx, scan.id)))).flat();
    for (const step of allSteps) stepsByScan.get(step.scan_id)?.push(step);
    const runIds = [...new Set(allSteps.map((step) => step.test_run_id).filter(Boolean))];
    // A listed page of scans can hold more child runs than one evidence batch accepts, so read in
    // batch-sized chunks instead of failing the whole list.
    const runIdChunks = chunkRunIds(runIds);
    const runs = runIds.length && typeof validationEvidence.listTestRunsByIds === 'function'
      ? (await Promise.all(runIdChunks.map((chunk) => validationEvidence.listTestRunsByIds(ctx, chunk)))).flat()
      : await Promise.all(runIds.map((runId) => validationEvidence.getTestRun(ctx, runId)));
    const runById = new Map(runs.filter(Boolean).map((run) => [run.id, run]));
    let verdicts = [];
    let events = [];
    if (runIds.length && typeof validationEvidence.loadRunEvidenceBatch === 'function') {
      for (const chunk of runIdChunks) {
        const batch = await validationEvidence.loadRunEvidenceBatch(ctx, { runIds: chunk, eventRunIds: chunk, eventLimitPerRun: 200 });
        verdicts.push(...(batch.verdicts ?? []));
        events.push(...(batch.events ?? []));
      }
    } else if (runIds.length) {
      for (const runId of runIds) {
        const verdict = await validationEvidence.getVerdictForRun(ctx, runId);
        if (verdict) verdicts.push(verdict);
        events.push(...(await validationEvidence.listRunEvents(ctx, runId, { limit: 200 })));
      }
    }
    const verdictByRun = new Map(verdicts.map((verdict) => [verdict.test_run_id, verdict]));
    const eventsByRun = new Map();
    for (const event of events) {
      if (!eventsByRun.has(event.test_run_id)) eventsByRun.set(event.test_run_id, []);
      eventsByRun.get(event.test_run_id).push(event);
    }
    const probeJobs = runIds.length && typeof repo.listProbeJobsForRuns === 'function'
      ? (await Promise.all(runIdChunks.map((chunk) => repo.listProbeJobsForRuns(ctx, chunk)))).flat()
      : [];
    const probeJobByRun = new Map();
    for (const job of probeJobs) if (!probeJobByRun.has(job.test_run_id)) probeJobByRun.set(job.test_run_id, job);

    const groupCache = new Map();
    const projected = [];
    for (const scan of scans) {
      if (!groupCache.has(scan.target_group_id)) {
        groupCache.set(scan.target_group_id, await loadGroup(ctx, scan.target_group_id));
      }
      const group = groupCache.get(scan.target_group_id);
      const targetById = new Map((group?.targets ?? []).map((target) => [target.id, target]));
      for (const policyId of new Set(Object.values(scan.plan_snapshot?.target_policy_bindings ?? {}))) {
        if (!groupCache.has(policyId)) groupCache.set(policyId, await loadGroup(ctx, policyId));
        for (const target of groupCache.get(policyId)?.targets ?? []) targetById.set(target.id, target);
      }
      const steps = stepsByScan.get(scan.id) ?? [];
      const target = scan.target_id ? targetById.get(scan.target_id) ?? null : null;
      projected.push({
        id: scan.id,
        tenant_id: scan.tenant_id,
        status: scan.status,
        name: scan.name ?? null,
        target_group_id: scan.target_group_id,
        target_group: group ? { id: group.id, name: group.name, environment_id: group.environment_id ?? null } : null,
        target_id: scan.target_id ?? null,
        target_ids: scan.plan_snapshot?.target_ids ?? [...new Set(steps.map((step) => step.target_id))],
        target: target ? { id: target.id, kind: target.kind, value: target.value } : null,
        check_ids: [...scan.check_ids],
        scheduled_for: scan.scheduled_for ?? null,
        recurrence: scan.recurrence ?? null,
        recurrence_series_id: scan.recurrence_series_id ?? scan.id,
        occurrence_index: scan.occurrence_index ?? 0,
        previous_scan_id: scan.previous_scan_id ?? null,
        next_scan_id: scan.next_scan_id ?? null,
        next_occurrence_at: scan.recurrence && scan.scheduled_for ? nextScanOccurrenceAt(scan.recurrence, scan.scheduled_for) : null,
        created_by: scan.created_by,
        created_by_role: scan.created_by_role ?? null,
        created_at: scan.created_at,
        updated_at: scan.updated_at,
        dispatched_at: scan.dispatched_at ?? null,
        started_at: scan.started_at ?? null,
        completed_at: scan.completed_at ?? null,
        abort_reason: scan.abort_reason ?? null,
        cancel_reason: scan.cancel_reason ?? null,
        cancelled_by: scan.cancelled_by ?? null,
        cancelled_at: scan.cancelled_at ?? null,
        next_eligible_at: scan.next_eligible_at ?? null,
        revision: scan.revision ?? 1,
        summary: computeScanSummary(steps),
        excluded: scan.plan_snapshot?.excluded ?? [],
        steps: steps.map((step) => {
          const run = step.test_run_id ? runById.get(step.test_run_id) ?? null : null;
          return projectScanStep({
            step,
            check: getCheckById(step.check_id),
            target: targetById.get(step.target_id) ?? null,
            run,
            verdict: run ? verdictByRun.get(run.id) ?? null : null,
            events: run ? eventsByRun.get(run.id) ?? [] : [],
            probeJob: run ? probeJobByRun.get(run.id) ?? null : null,
          });
        }),
      });
    }
    return projected;
  }

  async function projectScan(ctx, scan) {
    const [projected] = await projectScans(ctx, [scan]);
    return projected ?? null;
  }

  const services = {
    configureValidationScanRuntime(runtimeConfig) {
      defaultRuntimeConfig = runtimeConfig ?? null;
    },

    async createValidationScan(ctx, body = {}, runtimeConfig = undefined, callOptions = {}) {
      const now = toDate(callOptions.now);
      let input;
      try {
        input = normalizeScanInput(body, { now });
      } catch (err) {
        return scanValidationResponse(err);
      }
      const plan = await buildPlan(ctx, input);
      if (plan.error) {
        if (plan.error === 'soc_gated_check' || plan.error === 'unknown_check') {
          await repo.appendScanAudit(ctx, {
            action: SCAN_AUDIT_ACTIONS.createDenied,
            resource_type: 'validation_scan',
            resource_id: input.target_group_id,
            metadata: { error_code: plan.error, check_id: plan.check_id ?? null, target_group_id: input.target_group_id },
          }, { now });
        }
        return plan;
      }
      if (!input.scheduled_for) {
        for (const policyId of new Set(plan.targets.map((target) => target.target_group_id ?? plan.group.id))) {
          if (await activeScanForGroup(ctx, policyId) || await activeRunForGroup(ctx, policyId)) return { error: 'concurrent_scan_blocked', status: 409 };
        }
      }
      const id = newId('scan');
      const steps = materializeSteps(plan.steps, plan.checks, now);
      const record = {
        id,
        tenant_id: ctx.tenantId,
        target_group_id: plan.group.id,
        target_id: input.target_id ?? null,
        name: input.name ?? null,
        status: input.scheduled_for ? 'scheduled' : 'pending',
        check_ids: input.check_ids,
        plan_snapshot: planSnapshot(plan),
        scheduled_for: input.scheduled_for ?? null,
        recurrence: input.recurrence ?? null,
        recurrence_series_id: id,
        occurrence_key: input.scheduled_for ? scanOccurrenceKey(ctx.tenantId, id, input.scheduled_for) : null,
        occurrence_index: 0,
        previous_scan_id: null,
        next_scan_id: null,
        created_by: ctx.userId,
        created_by_role: ctx.role,
        revision: 1,
        summary: computeScanSummary(steps),
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      };
      const created = await repo.createScan(ctx, record, steps);
      if (created?.error) return created;
      const scan = created.scan;
      await scanAudit(ctx, scan, scan.status === 'scheduled' ? SCAN_AUDIT_ACTIONS.scheduled : SCAN_AUDIT_ACTIONS.created, {
        check_ids: scan.check_ids,
        step_count: steps.length,
        excluded_count: plan.excluded.length,
        scheduled_for: scan.scheduled_for,
        recurrence: scan.recurrence?.cadence ?? null,
      }, now);
      if (scan.status === 'pending') await advanceScan(ctx, scan.id, { runtimeConfig, now });
      const fresh = await repo.getScan(ctx, scan.id);
      return projectScan(ctx, fresh ?? scan);
    },

    async listValidationScans(ctx, callOptions = {}) {
      const statuses = callOptions.status
        ? String(callOptions.status).split(',').map((value) => value.trim()).filter(Boolean)
        : [];
      const limit = Math.max(1, Math.min(200, Number(callOptions.limit) || 50));
      const scans = await repo.listScans(ctx, {
        targetGroupId: callOptions.target_group_id || null,
        targetId: callOptions.target_id || null,
        status: statuses,
        limit,
      });
      const items = await projectScans(ctx, scans);
      return {
        items,
        count: items.length,
        meta: {
          empty_reason: items.length
            ? null
            : callOptions.target_group_id
              ? 'No validation scans match this target group filter.'
              : callOptions.status
                ? 'No validation scans match this status filter.'
                : 'No validation scans have been created for this tenant yet.',
        },
      };
    },

    async getValidationScan(ctx, id, callOptions = {}) {
      const scan = await repo.getScan(ctx, id);
      if (!scan) return null;
      await readPathAdvance(ctx, scan, callOptions);
      const fresh = await repo.getScan(ctx, id);
      return projectScan(ctx, fresh ?? scan);
    },

    async patchValidationScan(ctx, id, body = {}, callOptions = {}) {
      const scan = await repo.getScan(ctx, id);
      if (!scan) return null;
      const now = toDate(callOptions.now);
      if (scan.status !== 'scheduled' || leaseHeldByOther(scan, now)) return { error: 'scan_not_editable', status: 409 };
      let input;
      try {
        input = normalizeScanInput(body, { now, partial: true });
      } catch (err) {
        return scanValidationResponse(err);
      }
      const merged = {
        target_group_id: input.target_group_id ?? scan.target_group_id,
        target_id: input.target_ids ? (input.target_id ?? null) : input.target_id !== undefined ? input.target_id : scan.target_id,
        target_ids: input.target_ids ?? (input.target_id !== undefined ? (input.target_id ? [input.target_id] : undefined) : scan.plan_snapshot?.target_ids ?? [...new Set((await repo.listSteps(ctx, scan.id)).map((step) => step.target_id))]),
        check_ids: input.check_ids ?? scan.check_ids,
        name: input.name !== undefined ? input.name : scan.name,
        scheduled_for: input.scheduled_for !== undefined ? input.scheduled_for : scan.scheduled_for,
        recurrence: input.recurrence !== undefined ? input.recurrence : scan.recurrence,
      };
      if (!merged.scheduled_for) {
        return { error: 'invalid_validation_scan', status: 400, field: 'scheduled_for', message: 'A scheduled scan must keep a future scheduled_for time.' };
      }
      const plan = await buildPlan(ctx, merged);
      if (plan.error) return plan;
      const changedFields = Object.keys(input).filter((key) => JSON.stringify(input[key]) !== JSON.stringify(scan[key]));
      const steps = materializeSteps(plan.steps, plan.checks, now);
      const updated = await repo.updateScanWithSteps(ctx, scan.id, {
        target_group_id: plan.group.id,
        target_id: merged.target_id ?? null,
        check_ids: merged.check_ids,
        name: merged.name ?? null,
        scheduled_for: merged.scheduled_for,
        recurrence: merged.recurrence ?? null,
        plan_snapshot: planSnapshot(plan),
        occurrence_key: scanOccurrenceKey(scan.tenant_id, scan.recurrence_series_id ?? scan.id, merged.scheduled_for),
        revision: (scan.revision ?? 1) + 1,
        summary: computeScanSummary(steps),
        updated_at: now.toISOString(),
      }, steps, { expectedStatuses: ['scheduled'], requireUnleasedAt: now.toISOString() });
      if (!updated) return { error: 'scan_not_editable', status: 409 };
      if (updated.error) return updated;
      const { steps: _replacedSteps, ...updatedScan } = updated;
      await scanAudit(ctx, updatedScan, SCAN_AUDIT_ACTIONS.updated, {
        changed_fields: changedFields,
        scheduled_for: updatedScan.scheduled_for,
      }, now);
      return projectScan(ctx, updatedScan);
    },

    async cancelValidationScan(ctx, id, callOptions = {}) {
      const scan = await repo.getScan(ctx, id);
      if (!scan) return null;
      const now = toDate(callOptions.now);
      if (!CANCELLABLE_SCAN_STATUSES.includes(scan.status)) {
        await scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.cancelDenied, { status: scan.status }, now);
        return { error: 'not_cancellable', status: 409 };
      }
      const reason = normalizeCancelReason(callOptions.reason);
      const cancelled = await repo.updateScan(ctx, scan.id, {
        status: 'cancelled',
        cancel_reason: reason,
        cancelled_by: ctx.userId,
        cancelled_by_role: ctx.role,
        cancelled_at: now.toISOString(),
        completed_at: now.toISOString(),
        next_eligible_at: null,
        lease_token: null,
        lease_owner: null,
        lease_expires_at: null,
        ...(callOptions.cancel_series ? { recurrence: null } : {}),
        updated_at: now.toISOString(),
      }, { expectedStatuses: [...CANCELLABLE_SCAN_STATUSES] });
      if (!cancelled) return { error: 'not_cancellable', status: 409 };
      if (cancelled.error) return cancelled;
      const state = new ScanState(ctx, cancelled, await repo.listSteps(ctx, scan.id), { expectedStatuses: ['cancelled'] });
      const cancelledSteps = [];
      const cancelledRunIds = new Set();
      const cancelRun = async (runId) => {
        if (!runId || cancelledRunIds.has(runId)) return;
        const run = await validationEvidence.getTestRun(ctx, runId);
        if (run && ACTIVE_RUN_STATUSES.includes(run.status)) {
          await testRuns.cancelTestRun(ctx, runId, { reason, source: 'scan', scan_id: scan.id });
        }
        cancelledRunIds.add(runId);
      };
      for (const step of state.steps) {
        if (!ACTIVE_STEP_STATUSES.includes(step.status)) continue;
        await cancelRun(step.test_run_id);
        await state.patchStep(step, { status: 'cancelled', completed_at: now.toISOString() }, now);
        cancelledSteps.push(step.id);
      }
      const orphan = await activeRunForGroup(ctx, scan.target_group_id);
      if (orphan?.scan_id === scan.id && !cancelledRunIds.has(orphan.id)) {
        await cancelRun(orphan.id);
        const orphanStep = state.steps.find((step) => step.id === orphan.scan_step_id);
        if (orphanStep && orphanStep.status !== 'cancelled') {
          await state.patchStep(orphanStep, {
            status: 'cancelled',
            test_run_id: orphan.id,
            completed_at: now.toISOString(),
          }, now);
          cancelledSteps.push(orphanStep.id);
        }
      }
      const skipped = await skipRemainingSteps(state, 'scan_cancelled', now);
      const activeRunId = [...cancelledRunIds].at(-1) ?? null;
      let continued = null;
      if (callOptions.cancel_series && scan.recurrence) {
        await scanAudit(ctx, state.scan, SCAN_AUDIT_ACTIONS.seriesStopped, { reason }, now);
        const seriesId = scan.recurrence_series_id ?? scan.id;
        const upcoming = await repo.listScans(ctx, { seriesId, status: ['scheduled'], limit: 200 });
        const nextId = state.scan.next_scan_id;
        const extra = nextId && !upcoming.some((row) => row.id === nextId) ? [await repo.getScan(ctx, nextId)] : [];
        for (const next of [...upcoming, ...extra]) {
          if (next?.status !== 'scheduled' || next.id === scan.id) continue;
          await services.cancelValidationScan(ctx, next.id, { reason, cancel_series: true, now });
        }
      } else if (scan.recurrence && !state.scan.next_scan_id) {
        // Single-occurrence cancel: keep the series alive. Without this the successor is only ever
        // created at dispatch, so cancelling a scheduled run that never dispatched silently ends
        // every future run of the recurring scan.
        continued = await continueSeriesAfterCancel(ctx, ctx, scan, state.steps, now);
      }
      await state.refreshSummary(now);
      await scanAudit(ctx, state.scan, SCAN_AUDIT_ACTIONS.cancelled, {
        reason,
        cancelled_by: ctx.userId,
        cancelled_by_role: ctx.role,
        cancelled_steps: cancelledSteps.length,
        skipped_steps: skipped.length,
        active_test_run_id: activeRunId,
        ...(continued ? { series_continued_scan_id: continued.id, next_scheduled_for: continued.scheduled_for } : {}),
      }, now);
      return projectScan(ctx, state.scan);
    },

    async getValidationScanActivity(ctx, id, callOptions = {}) {
      const initial = await repo.getScan(ctx, id);
      if (!initial) return null;
      await readPathAdvance(ctx, initial, callOptions);
      const scan = (await repo.getScan(ctx, id)) ?? initial;
      const steps = await repo.listSteps(ctx, scan.id);
      const childRunIds = steps.map((step) => step.test_run_id).filter(Boolean);
      const limit = Math.max(1, Math.min(500, Number(callOptions.limit) || 200));
      const auditEntries = await repo.listAuditEntriesForScan(ctx, { scanId: scan.id, runIds: childRunIds, limit: 500 });
      let runEvents = [];
      if (childRunIds.length && typeof validationEvidence.loadRunEvidenceBatch === 'function') {
        const batch = await validationEvidence.loadRunEvidenceBatch(ctx, {
          runIds: [],
          eventRunIds: childRunIds,
          eventLimitPerRun: 200,
        });
        runEvents = batch.events ?? [];
      } else {
        for (const runId of childRunIds) {
          runEvents.push(...(await validationEvidence.listRunEvents(ctx, runId, { limit: 200 })));
        }
      }
      const page = paginateActivity(buildActivityItems({ scan, steps, auditEntries, runEvents }), {
        after: callOptions.after ?? null,
        limit,
      });
      return {
        scan_id: scan.id,
        status: scan.status,
        items: page.items,
        count: page.items.length,
        cursor: page.cursor,
      };
    },

    advanceScan,

    async advanceScanForRun(run, callOptions = {}) {
      if (!run?.scan_id || !run?.tenant_id) return null;
      return advanceScan(systemCtx(run.tenant_id), run.scan_id, callOptions);
    },

    async listDueValidationScans(ctx, callOptions = {}) {
      return repo.listDueScans(ctx, { now: toDate(callOptions.now), limit: callOptions.limit });
    },

    async listRunnableScans(ctx, callOptions = {}) {
      return repo.listRunnableScans(ctx, { now: toDate(callOptions.now), limit: callOptions.limit });
    },

    dispatchDueValidationScans,
  };

  testRuns.registerRunTerminalHook(async (run) => {
    await services.advanceScanForRun(run);
  });

  return services;
}
