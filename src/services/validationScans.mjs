import { randomUUID } from 'node:crypto';
import { audit } from '../audit.mjs';
import { customerSelectableChecks, getCheckById, isCustomerRunnable } from '../contracts/checks.mjs';
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
} from '../contracts/validationScanManagement.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { probeDispatchReady } from '../config.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { isKillSwitchActiveForTenant } from './killSwitchState.mjs';
import { registerRunTerminalHook } from './runTerminalHooks.mjs';
import { isWithinSafeTestWindow, normalizeSafetyPolicy } from './safeTestPolicy.mjs';
import { getTenantAccount } from './subscriptions.mjs';
import { activeTargetGroupsForTenant, isArchivedTarget } from './targetGroups.mjs';
import { cancelTestRun, getTestRun, startTestRun } from './testRuns.mjs';

const ACTIVE_RUN_STATUSES = new Set(['planned', 'running', 'collecting']);
const advancing = new Set();
let defaultRuntimeConfig = null;

export function configureValidationScanRuntime(runtimeConfig) {
  defaultRuntimeConfig = runtimeConfig ?? null;
}

function ensureStoreShape() {
  const store = getStore();
  if (!Array.isArray(store.validationScans)) store.validationScans = [];
  return store;
}

function toDate(value) {
  const date = value instanceof Date ? value : new Date(value ?? Date.now());
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function activeGroup(ctx, id) {
  return activeTargetGroupsForTenant(ctx.tenantId).find((group) => group.id === id) ?? null;
}

function targetsForGroup(tenantId, targetGroupId) {
  return getStore().targets.filter(
    (target) => target.tenant_id === tenantId
      && target.target_group_id === targetGroupId
      && !isArchivedTarget(target),
  );
}

function scanForTenant(ctx, id) {
  ensureStoreShape();
  return getStore().validationScans.find((scan) => scan.id === id && scan.tenant_id === ctx.tenantId) ?? null;
}

function activeScanForGroup(tenantId, targetGroupId, excludeId = null) {
  ensureStoreShape();
  return getStore().validationScans.find(
    (scan) => scan.tenant_id === tenantId
      && scan.target_group_id === targetGroupId
      && scan.id !== excludeId
      && ACTIVE_SCAN_STATUSES.includes(scan.status),
  ) ?? null;
}

function activeRunForGroup(tenantId, targetGroupId) {
  return getStore().testRuns.find(
    (run) => run.tenant_id === tenantId
      && run.target_group_id === targetGroupId
      && ACTIVE_RUN_STATUSES.has(run.status),
  ) ?? null;
}

function execCtxFor(scan) {
  return scanExecutionContext(scan);
}

function canAdvanceOnRead(ctx) {
  return roleHasPermission(ctx?.role, 'test_run:start');
}

function systemCtx(tenantId) {
  return { tenantId, userId: 'system', role: 'system' };
}

function scanAudit(ctx, scan, action, metadata = {}) {
  return audit({
    tenant_id: scan.tenant_id,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action,
    resource_type: 'validation_scan',
    resource_id: scan.id,
    metadata: {
      target_group_id: scan.target_group_id,
      target_id: scan.target_id ?? null,
      ...metadata,
    },
  });
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
  const selectable = new Set(customerSelectableChecks(getStore().checkCatalog ?? []).map((check) => check.check_id));
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

function buildPlan(ctx, input) {
  const group = activeGroup(ctx, input.target_group_id);
  if (!group) return { error: 'target_group_not_found', status: 404 };
  const resolved = resolveChecks(input.check_ids);
  if (resolved.error) return resolved;
  const targets = targetsForGroup(ctx.tenantId, group.id);
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
  return { group, targets, checks: resolved.checks, steps: plan.steps, excluded: plan.excluded };
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
    excluded: plan.excluded,
  };
}

function refreshSummary(scan, now) {
  scan.summary = computeScanSummary(scan.steps);
  scan.updated_at = now.toISOString();
  return scan.summary;
}

function releaseLease(scan) {
  scan.lease_token = null;
  scan.lease_owner = null;
  scan.lease_expires_at = null;
}

function claimLease(scan, owner, now) {
  scan.lease_token = randomUUID();
  scan.lease_owner = owner;
  scan.lease_expires_at = new Date(now.getTime() + SCAN_LEASE_MS).toISOString();
  return scan.lease_token;
}

function leaseHeldByOther(scan, now) {
  return Boolean(scan.lease_token && scan.lease_expires_at && new Date(scan.lease_expires_at) > now);
}

function skipRemainingSteps(scan, reason, now) {
  const skipped = [];
  for (const step of scan.steps) {
    if (!['pending', 'deferred', 'starting'].includes(step.status)) continue;
    step.status = 'skipped';
    step.skip_reason = reason;
    step.completed_at = now.toISOString();
    step.updated_at = now.toISOString();
    skipped.push(step.id);
  }
  return skipped;
}

function finishScan(ctx, scan, now) {
  const derived = deriveScanStatus(scan.steps);
  scan.status = derived === 'running' ? 'completed' : derived;
  scan.completed_at = now.toISOString();
  scan.next_eligible_at = null;
  releaseLease(scan);
  refreshSummary(scan, now);
  scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.completed, {
    status: scan.status,
    summary: scan.summary,
    abort_reason: scan.abort_reason ?? null,
  });
  persistStore();
}

function completeStep(ctx, scan, step, run, now) {
  const dispatchFailed = run.status === 'cancelled' && run.summary?.dispatch_failed === true;
  step.status = run.status === 'verdicted' ? 'verdicted' : dispatchFailed ? 'denied' : 'cancelled';
  if (dispatchFailed) step.error_code = 'probe_dispatch_failed';
  step.completed_at = run.completed_at ?? now.toISOString();
  step.updated_at = now.toISOString();
  const verdict = getStore().verdicts.find((row) => row.test_run_id === run.id) ?? null;
  scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.stepCompleted, stepAuditMetadata(step, {
    run_status: run.status,
    verdict: verdict?.verdict ?? null,
    confidence: verdict?.confidence ?? null,
  }));
}

function reconcileActiveStep(ctx, scan, now) {
  const active = scan.steps.find((step) => ACTIVE_STEP_STATUSES.includes(step.status));
  if (!active) return { waiting: false };
  const store = getStore();
  let run = active.test_run_id
    ? store.testRuns.find((row) => row.id === active.test_run_id && row.tenant_id === scan.tenant_id)
    : store.testRuns.find((row) => row.scan_step_id === active.id && row.tenant_id === scan.tenant_id);
  if (run && !active.test_run_id) active.test_run_id = run.id;
  if (!run) {
    if (active.attempts >= MAX_STEP_START_ATTEMPTS) {
      active.status = 'denied';
      active.error_code = 'start_test_run_failed';
      active.completed_at = now.toISOString();
      scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.advanceFailed, stepAuditMetadata(active, { error_code: active.error_code }));
    } else {
      active.status = 'pending';
    }
    active.updated_at = now.toISOString();
    return { waiting: false };
  }
  getTestRun(execCtxFor(scan), run.id);
  run = store.testRuns.find((row) => row.id === run.id);
  if (run.status === 'verdicted' || run.status === 'cancelled') {
    completeStep(ctx, scan, active, run, now);
    return { waiting: false };
  }
  active.status = run.status === 'collecting' ? 'collecting' : 'running';
  active.updated_at = now.toISOString();
  if (scan.status === 'pending') scan.status = 'running';
  return { waiting: true };
}

function nextStartableStep(scan, now) {
  const pending = scan.steps.find((step) => step.status === 'pending');
  if (pending) return pending;
  return scan.steps.find(
    (step) => step.status === 'deferred' && step.eligible_at && new Date(step.eligible_at) <= now,
  ) ?? null;
}

function deferStep(ctx, scan, step, result, now) {
  const code = result?.error ?? 'safe_min_interval_active';
  const policy = normalizeSafetyPolicy(activeGroup(execCtxFor(scan), scan.target_group_id)?.safety_policy);
  const eligibleAt = deferredStepEligibleAt({
    code,
    runs: getStore().testRuns,
    tenantId: scan.tenant_id,
    targetGroupId: scan.target_group_id,
    minSecondsBetweenRuns: policy.min_seconds_between_runs,
    now,
  });
  step.status = 'deferred';
  step.eligible_at = eligibleAt;
  step.updated_at = now.toISOString();
  scan.next_eligible_at = eligibleAt;
  scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.stepDeferred, stepAuditMetadata(step, {
    eligible_at: step.eligible_at,
    error_code: code,
  }));
}

function denyStep(ctx, scan, step, result, now) {
  step.status = 'denied';
  step.error_code = result.error ?? 'start_test_run_failed';
  step.completed_at = now.toISOString();
  step.updated_at = now.toISOString();
  scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.stepDenied, stepAuditMetadata(step, { error_code: step.error_code }));
}

function abortScan(ctx, scan, step, result, now) {
  denyStep(ctx, scan, step, result, now);
  scan.abort_reason = result.error;
  const skipped = skipRemainingSteps(scan, `scan_aborted:${result.error}`, now);
  if (skipped.length) {
    scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.stepSkipped, {
      step_ids: skipped,
      skipped_steps: skipped.length,
      reason: `scan_aborted:${result.error}`,
    });
  }
}

function cancelOrphanedRun(scan, step, run, now) {
  const ctx = systemCtx(scan.tenant_id);
  let cancelled = false;
  if (run?.id && ACTIVE_RUN_STATUSES.has(run.status)) {
    const result = cancelTestRun(ctx, run.id, { reason: scan.cancel_reason ?? 'scan_no_longer_active', source: 'scan', scan_id: scan.id });
    cancelled = Boolean(result && !result.error);
  }
  step.status = 'cancelled';
  step.test_run_id = run?.id ?? step.test_run_id ?? null;
  step.completed_at = now.toISOString();
  step.updated_at = now.toISOString();
  if (run?.id) {
    scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.orphanRunCancelled, stepAuditMetadata(step, {
      run_cancelled: cancelled,
      status: scan.status,
    }));
  }
}

function startStep(ctx, scan, step, runtimeConfig, now) {
  step.status = 'starting';
  step.attempts = (step.attempts ?? 0) + 1;
  step.started_at = step.started_at ?? now.toISOString();
  step.updated_at = now.toISOString();
  const leaseToken = claimLease(scan, 'validation-scan-executor', now);
  let result;
  try {
    result = startTestRun(
      execCtxFor(scan),
      { check_id: step.check_id, target_group_id: scan.target_group_id, target_id: step.target_id },
      runtimeConfig,
      { scanDispatch: { scan_id: scan.id, step_id: step.id, lease_token: leaseToken, now: now.toISOString() } },
    );
  } catch {
    result = { error: 'start_test_run_failed', status: 500 };
  }
  if (!ACTIVE_SCAN_STATUSES.includes(scan.status) || step.status !== 'starting') {
    cancelOrphanedRun(scan, step, result?.run ? getStore().testRuns.find((row) => row.id === result.run.id) : null, now);
    return { inactive: true };
  }
  releaseLease(scan);
  return result;
}

function pendingRunStepId(scan, run) {
  return run?.scan_id === scan.id ? run.scan_step_id : null;
}

export function advanceScan(ctx, id, options = {}) {
  const store = ensureStoreShape();
  const scan = store.validationScans.find((row) => row.id === id && (!ctx?.tenantId || row.tenant_id === ctx.tenantId));
  if (!scan) return null;
  if (advancing.has(scan.id)) return { scan_id: scan.id, acquired: false, reason: 'reentrant' };
  const now = toDate(options.now);
  if (!ACTIVE_SCAN_STATUSES.includes(scan.status)) return { scan_id: scan.id, acquired: false, reason: 'inactive', status: scan.status };
  if (leaseHeldByOther(scan, now)) return { scan_id: scan.id, acquired: false, reason: 'leased' };
  const runtimeConfig = options.runtimeConfig ?? defaultRuntimeConfig ?? { probeMode: 'simulation' };
  const actor = ctx?.userId ? ctx : systemCtx(scan.tenant_id);
  const maxStarts = Math.max(1, Number(options.maxStartsPerTick) || 5);
  advancing.add(scan.id);
  try {
    let starts = 0;
    for (;;) {
      const reconciled = reconcileActiveStep(actor, scan, now);
      if (reconciled.waiting) {
        refreshSummary(scan, now);
        persistStore();
        return { scan_id: scan.id, acquired: true, waiting: true, status: scan.status };
      }
      const step = nextStartableStep(scan, now);
      if (!step) {
        const deferred = scan.steps.filter((row) => row.status === 'deferred');
        if (deferred.length) {
          scan.next_eligible_at = deferred
            .map((row) => row.eligible_at)
            .sort()[0];
          scan.status = 'running';
          refreshSummary(scan, now);
          persistStore();
          return { scan_id: scan.id, acquired: true, waiting: true, deferred_until: scan.next_eligible_at, status: scan.status };
        }
        finishScan(actor, scan, now);
        return { scan_id: scan.id, acquired: true, waiting: false, status: scan.status };
      }
      if (starts >= maxStarts) {
        refreshSummary(scan, now);
        persistStore();
        return { scan_id: scan.id, acquired: true, waiting: true, status: scan.status, reason: 'max_starts_per_tick' };
      }
      if (!probeDispatchReady(runtimeConfig)) {
        scanAudit(actor, scan, SCAN_AUDIT_ACTIONS.advanceBlocked, {
          reason: 'probe_signing_unavailable',
          error_code: runtimeConfig?.probeConfigError ?? 'probe_worker_secret_invalid',
        });
        refreshSummary(scan, now);
        persistStore();
        return { scan_id: scan.id, acquired: true, waiting: true, status: scan.status, reason: 'probe_signing_unavailable' };
      }
      starts += 1;
      scan.status = 'running';
      scan.started_at = scan.started_at ?? now.toISOString();
      scan.next_eligible_at = null;
      const result = startStep(actor, scan, step, runtimeConfig, now);
      if (result?.inactive) {
        refreshSummary(scan, now);
        persistStore();
        return { scan_id: scan.id, acquired: true, waiting: false, reason: 'inactive', status: scan.status };
      }
      if (!result?.error) {
        const run = result.run ?? null;
        step.test_run_id = run?.id ?? null;
        step.status = run?.status === 'verdicted' ? 'verdicted' : run?.status === 'collecting' ? 'collecting' : 'running';
        step.eligible_at = null;
        step.updated_at = now.toISOString();
        scanAudit(actor, scan, SCAN_AUDIT_ACTIONS.stepStarted, stepAuditMetadata(step, { run_status: run?.status ?? null }));
        if (step.status === 'verdicted') {
          const stored = store.testRuns.find((row) => row.id === run.id);
          if (stored) completeStep(actor, scan, step, stored, now);
        }
        refreshSummary(scan, now);
        persistStore();
        continue;
      }
      const classification = classifyStartDenial(result);
      if (classification === 'defer') {
        deferStep(actor, scan, step, result, now);
        refreshSummary(scan, now);
        persistStore();
        return { scan_id: scan.id, acquired: true, waiting: true, deferred_until: scan.next_eligible_at, status: scan.status };
      }
      if (classification === 'abort') {
        if (result.error === 'concurrent_run_blocked') {
          const blocking = activeRunForGroup(scan.tenant_id, scan.target_group_id);
          const ownStepId = pendingRunStepId(scan, blocking);
          if (ownStepId) {
            const ownStep = scan.steps.find((row) => row.id === ownStepId);
            if (ownStep) {
              ownStep.test_run_id = blocking.id;
              ownStep.status = blocking.status === 'collecting' ? 'collecting' : 'running';
            }
            step.status = 'pending';
            step.attempts -= 1;
            refreshSummary(scan, now);
            persistStore();
            return { scan_id: scan.id, acquired: true, waiting: true, status: scan.status };
          }
        }
        abortScan(actor, scan, step, result, now);
        finishScan(actor, scan, now);
        return { scan_id: scan.id, acquired: true, waiting: false, status: scan.status, abort_reason: scan.abort_reason };
      }
      if (classification === 'step') {
        denyStep(actor, scan, step, result, now);
        refreshSummary(scan, now);
        persistStore();
        continue;
      }
      if (step.attempts >= MAX_STEP_START_ATTEMPTS) {
        denyStep(actor, scan, step, { error: 'start_test_run_failed' }, now);
        scanAudit(actor, scan, SCAN_AUDIT_ACTIONS.advanceFailed, stepAuditMetadata(step, { error_code: result.error ?? null }));
        refreshSummary(scan, now);
        persistStore();
        continue;
      }
      step.status = 'pending';
      refreshSummary(scan, now);
      persistStore();
      return { scan_id: scan.id, acquired: true, waiting: true, status: scan.status, reason: 'retry_scheduled' };
    }
  } finally {
    advancing.delete(scan.id);
  }
}

export function advanceScanForRun(run, options = {}) {
  if (!run?.scan_id) return null;
  return advanceScan(systemCtx(run.tenant_id), run.scan_id, options);
}

function scheduleDenied(ctx, scan, code, now, extra = {}) {
  scan.status = 'denied';
  scan.abort_reason = code;
  scan.completed_at = now.toISOString();
  releaseLease(scan);
  skipRemainingSteps(scan, `schedule_denied:${code}`, now);
  refreshSummary(scan, now);
  scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.scheduleDenied, { code, scheduled_for: scan.scheduled_for, ...extra });
  persistStore();
  return { scan_id: scan.id, dispatched: false, denied: code };
}

function createNextOccurrence(ctx, scan, now) {
  if (!scan.recurrence || scan.next_scan_id) return null;
  // Advance past now while preserving cadence alignment: on-time runs keep their wall-clock slot,
  // but a catch-up after downtime collapses the missed backlog into one future run.
  const nextAt = nextScanOccurrenceAfter(scan.recurrence, scan.scheduled_for ?? now, now);
  if (!nextAt) return null;
  const seriesId = scan.recurrence_series_id ?? scan.id;
  const occurrenceKey = scanOccurrenceKey(scan.tenant_id, seriesId, nextAt);
  const store = ensureStoreShape();
  let next = store.validationScans.find((row) => row.tenant_id === scan.tenant_id && row.occurrence_key === occurrenceKey);
  if (!next) {
    const checks = scan.check_ids.map((checkId) => getCheckById(checkId)).filter(Boolean);
    next = {
      ...scan,
      id: newId('scan'),
      status: 'scheduled',
      steps: materializeSteps(
        scan.steps.map((step, position) => ({
          position,
          check_id: step.check_id,
          target_id: step.target_id,
          request_snapshot: step.request_snapshot,
        })),
        checks,
        now,
      ),
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
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
    };
    next.summary = computeScanSummary(next.steps);
    store.validationScans.push(next);
    scanAudit(ctx, next, SCAN_AUDIT_ACTIONS.scheduled, {
      series_id: seriesId,
      occurrence_index: next.occurrence_index,
      scheduled_for: next.scheduled_for,
      previous_scan_id: scan.id,
    });
  }
  scan.next_scan_id = next.id;
  return next;
}

function dispatchScheduledScan(ctx, scan, options = {}) {
  const now = toDate(options.now);
  if (scan.status !== 'scheduled') return { scan_id: scan.id, dispatched: false, reason: 'not_scheduled' };
  if (leaseHeldByOther(scan, now)) return { scan_id: scan.id, dispatched: false, reason: 'leased' };
  claimLease(scan, options.workerId ?? 'validation-scan-dispatcher', now);
  createNextOccurrence(ctx, scan, now);
  const execCtx = execCtxFor(scan);

  if (isKillSwitchActiveForTenant(scan.tenant_id)) return scheduleDenied(ctx, scan, 'kill_switch_active', now);
  if (getTenantAccount(scan.tenant_id)?.lifecycle_state === 'suspended') return scheduleDenied(ctx, scan, 'tenant_suspended', now);
  const group = activeGroup(execCtx, scan.target_group_id);
  if (!group) return scheduleDenied(ctx, scan, 'target_group_not_found', now);
  if ((group.safe_test_windows ?? []).length > 0 && !isWithinSafeTestWindow(group, now.getTime())) {
    return scheduleDenied(ctx, scan, 'safe_window_closed', now);
  }
  if (activeRunForGroup(scan.tenant_id, group.id) || activeScanForGroup(scan.tenant_id, group.id, scan.id)) {
    return scheduleDenied(ctx, scan, 'concurrent_run_blocked', now);
  }
  const plan = buildPlan(execCtx, {
    target_group_id: scan.target_group_id,
    target_id: scan.target_id,
    check_ids: scan.check_ids,
  });
  if (plan.error) return scheduleDenied(ctx, scan, plan.error, now, { check_id: plan.check_id ?? null });
  if (!scan.target_id) {
    scan.steps = materializeSteps(plan.steps, plan.checks, now);
    scan.plan_snapshot = planSnapshot(plan);
  }
  scan.status = 'running';
  scan.dispatched_at = now.toISOString();
  scan.started_at = now.toISOString();
  releaseLease(scan);
  refreshSummary(scan, now);
  scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.dispatched, { scheduled_for: scan.scheduled_for, step_count: scan.steps.length });
  persistStore();
  const advanced = advanceScan(ctx, scan.id, { ...options, now });
  return { scan_id: scan.id, dispatched: true, advanced };
}

export function listDueValidationScans(ctx, options = {}) {
  const store = ensureStoreShape();
  const now = toDate(options.now);
  const limit = Math.max(1, Math.min(100, Number(options.limit) || 25));
  return store.validationScans
    .filter((scan) => scan.tenant_id === ctx.tenantId
      && scan.status === 'scheduled'
      && scan.scheduled_for
      && new Date(scan.scheduled_for) <= now
      && !leaseHeldByOther(scan, now))
    .sort((left, right) => String(left.scheduled_for).localeCompare(String(right.scheduled_for)) || left.id.localeCompare(right.id))
    .slice(0, limit);
}

export function dispatchDueValidationScans(ctx, options = {}) {
  const now = toDate(options.now);
  const actor = ctx?.userId ? ctx : systemCtx(ctx.tenantId);
  const results = [];
  for (const scan of listDueValidationScans(ctx, { now, limit: options.limit })) {
    try {
      results.push(dispatchScheduledScan(actor, scan, { ...options, now }));
    } catch {
      releaseLease(scan);
      scanAudit(actor, scan, SCAN_AUDIT_ACTIONS.dispatchFailed, { scheduled_for: scan.scheduled_for, reason: 'dispatch_exception' });
      persistStore();
      results.push({ scan_id: scan.id, dispatched: false, reason: 'dispatch_failed' });
    }
  }
  return results;
}

function readPathAdvance(ctx, scan, options = {}) {
  if (!canAdvanceOnRead(ctx)) return;
  const now = toDate(options.now);
  if (scan.status === 'scheduled' && scan.scheduled_for && new Date(scan.scheduled_for) <= now) {
    dispatchScheduledScan(systemCtx(scan.tenant_id), scan, { ...options, now });
    return;
  }
  if (ACTIVE_SCAN_STATUSES.includes(scan.status)) advanceScan(systemCtx(scan.tenant_id), scan.id, { ...options, now });
}

function projectScan(ctx, scan) {
  const store = getStore();
  const group = store.targetGroups.find((row) => row.id === scan.target_group_id && row.tenant_id === scan.tenant_id) ?? null;
  const targetById = new Map(
    store.targets.filter((target) => target.tenant_id === scan.tenant_id).map((target) => [target.id, target]),
  );
  const target = scan.target_id ? targetById.get(scan.target_id) ?? null : null;
  const steps = scan.steps.map((step) => {
    const run = step.test_run_id ? store.testRuns.find((row) => row.id === step.test_run_id) ?? null : null;
    const verdict = run ? store.verdicts.find((row) => row.test_run_id === run.id) ?? null : null;
    const events = run ? store.events.filter((event) => event.test_run_id === run.id) : [];
    const probeJob = run ? store.probeJobs.find((job) => job.test_run_id === run.id && !job.ownership_verification_id) ?? null : null;
    return projectScanStep({
      step,
      check: getCheckById(step.check_id),
      target: targetById.get(step.target_id) ?? null,
      run,
      verdict,
      events,
      probeJob,
    });
  });
  return {
    id: scan.id,
    tenant_id: scan.tenant_id,
    status: scan.status,
    name: scan.name ?? null,
    target_group_id: scan.target_group_id,
    target_group: group ? { id: group.id, name: group.name, environment_id: group.environment_id ?? null } : null,
    target_id: scan.target_id ?? null,
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
    summary: computeScanSummary(scan.steps),
    excluded: scan.plan_snapshot?.excluded ?? [],
    steps,
  };
}

export function createValidationScan(ctx, body = {}, runtimeConfig = undefined, options = {}) {
  const store = ensureStoreShape();
  const now = toDate(options.now);
  let input;
  try {
    input = normalizeScanInput(body, { now });
  } catch (err) {
    return scanValidationResponse(err);
  }
  const plan = buildPlan(ctx, input);
  if (plan.error) {
    if (plan.error === 'soc_gated_check' || plan.error === 'unknown_check') {
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: SCAN_AUDIT_ACTIONS.createDenied,
        resource_type: 'validation_scan',
        resource_id: input.target_group_id,
        metadata: { error_code: plan.error, check_id: plan.check_id ?? null, target_group_id: input.target_group_id },
      });
      persistStore();
    }
    return plan;
  }
  if (!input.scheduled_for && (activeScanForGroup(ctx.tenantId, plan.group.id) || activeRunForGroup(ctx.tenantId, plan.group.id))) {
    return { error: 'concurrent_scan_blocked', status: 409 };
  }
  const id = newId('scan');
  const scan = {
    id,
    tenant_id: ctx.tenantId,
    target_group_id: plan.group.id,
    target_id: input.target_id ?? null,
    name: input.name ?? null,
    status: input.scheduled_for ? 'scheduled' : 'pending',
    check_ids: input.check_ids,
    plan_snapshot: planSnapshot(plan),
    steps: materializeSteps(plan.steps, plan.checks, now),
    scheduled_for: input.scheduled_for ?? null,
    recurrence: input.recurrence ?? null,
    recurrence_series_id: id,
    occurrence_key: input.scheduled_for ? scanOccurrenceKey(ctx.tenantId, id, input.scheduled_for) : null,
    occurrence_index: 0,
    previous_scan_id: null,
    next_scan_id: null,
    dispatched_at: null,
    started_at: null,
    completed_at: null,
    abort_reason: null,
    cancel_reason: null,
    cancelled_by: null,
    cancelled_by_role: null,
    cancelled_at: null,
    created_by: ctx.userId,
    created_by_role: ctx.role,
    lease_token: null,
    lease_owner: null,
    lease_expires_at: null,
    next_eligible_at: null,
    revision: 1,
    summary: null,
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
  };
  scan.summary = computeScanSummary(scan.steps);
  store.validationScans.push(scan);
  scanAudit(ctx, scan, scan.status === 'scheduled' ? SCAN_AUDIT_ACTIONS.scheduled : SCAN_AUDIT_ACTIONS.created, {
    check_ids: scan.check_ids,
    step_count: scan.steps.length,
    excluded_count: plan.excluded.length,
    scheduled_for: scan.scheduled_for,
    recurrence: scan.recurrence?.cadence ?? null,
  });
  persistStore();
  if (scan.status === 'pending') advanceScan(ctx, scan.id, { runtimeConfig, now });
  return projectScan(ctx, scan);
}

export function listValidationScans(ctx, options = {}) {
  const store = ensureStoreShape();
  // A list read must not advance scans or start test runs. The Postgres adapter's list is a pure
  // read (readPathAdvance runs only on single-scan get and activity reads), so advancing every scan
  // here made dev behave differently from production and gave a read surprising side effects.
  let rows = store.validationScans.filter((scan) => scan.tenant_id === ctx.tenantId);
  if (options.target_group_id) rows = rows.filter((scan) => scan.target_group_id === options.target_group_id);
  if (options.status) {
    const statuses = new Set(String(options.status).split(',').map((value) => value.trim()).filter(Boolean));
    rows = rows.filter((scan) => statuses.has(scan.status));
  }
  rows = rows.sort((left, right) => String(right.created_at).localeCompare(String(left.created_at)));
  const limit = Math.max(1, Math.min(200, Number(options.limit) || 50));
  const items = rows.slice(0, limit).map((scan) => projectScan(ctx, scan));
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : options.target_group_id
          ? 'No validation scans match this target group filter.'
          : options.status
            ? 'No validation scans match this status filter.'
            : 'No validation scans have been created for this tenant yet.',
    },
  };
}

export function getValidationScan(ctx, id, options = {}) {
  const scan = scanForTenant(ctx, id);
  if (!scan) return null;
  readPathAdvance(ctx, scan, options);
  return projectScan(ctx, scan);
}

export function patchValidationScan(ctx, id, body = {}, options = {}) {
  const scan = scanForTenant(ctx, id);
  if (!scan) return null;
  const now = toDate(options.now);
  if (scan.status !== 'scheduled' || leaseHeldByOther(scan, now)) return { error: 'scan_not_editable', status: 409 };
  let input;
  try {
    input = normalizeScanInput(body, { now, partial: true });
  } catch (err) {
    return scanValidationResponse(err);
  }
  const merged = {
    target_group_id: scan.target_group_id,
    target_id: input.target_id !== undefined ? input.target_id : scan.target_id,
    check_ids: input.check_ids ?? scan.check_ids,
    name: input.name !== undefined ? input.name : scan.name,
    scheduled_for: input.scheduled_for !== undefined ? input.scheduled_for : scan.scheduled_for,
    recurrence: input.recurrence !== undefined ? input.recurrence : scan.recurrence,
  };
  if (!merged.scheduled_for) {
    return { error: 'invalid_validation_scan', status: 400, field: 'scheduled_for', message: 'A scheduled scan must keep a future scheduled_for time.' };
  }
  const plan = buildPlan(ctx, merged);
  if (plan.error) return plan;
  const changedFields = Object.keys(input).filter((key) => JSON.stringify(input[key]) !== JSON.stringify(scan[key]));
  scan.target_id = merged.target_id ?? null;
  scan.check_ids = merged.check_ids;
  scan.name = merged.name ?? null;
  scan.scheduled_for = merged.scheduled_for;
  scan.recurrence = merged.recurrence ?? null;
  scan.steps = materializeSteps(plan.steps, plan.checks, now);
  scan.plan_snapshot = planSnapshot(plan);
  scan.occurrence_key = scanOccurrenceKey(scan.tenant_id, scan.recurrence_series_id ?? scan.id, scan.scheduled_for);
  scan.revision = (scan.revision ?? 1) + 1;
  refreshSummary(scan, now);
  scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.updated, { changed_fields: changedFields, scheduled_for: scan.scheduled_for });
  persistStore();
  return projectScan(ctx, scan);
}

export function cancelValidationScan(ctx, id, options = {}) {
  const scan = scanForTenant(ctx, id);
  if (!scan) return null;
  const now = toDate(options.now);
  if (!CANCELLABLE_SCAN_STATUSES.includes(scan.status)) {
    scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.cancelDenied, { status: scan.status });
    persistStore();
    return { error: 'not_cancellable', status: 409 };
  }
  const reason = normalizeCancelReason(options.reason);
  const seriesRecurrence = scan.recurrence;
  scan.status = 'cancelled';
  scan.cancel_reason = reason;
  scan.cancelled_by = ctx.userId;
  scan.cancelled_by_role = ctx.role;
  scan.cancelled_at = now.toISOString();
  scan.completed_at = now.toISOString();
  scan.next_eligible_at = null;
  releaseLease(scan);
  const cancelledSteps = [];
  const cancelledRunIds = new Set();
  const cancelRun = (runId) => {
    if (!runId || cancelledRunIds.has(runId)) return;
    const run = getStore().testRuns.find((row) => row.id === runId && row.tenant_id === scan.tenant_id);
    if (run && ACTIVE_RUN_STATUSES.has(run.status)) cancelTestRun(ctx, runId, { reason, source: 'scan', scan_id: scan.id });
    cancelledRunIds.add(runId);
  };
  for (const step of scan.steps) {
    if (!ACTIVE_STEP_STATUSES.includes(step.status)) continue;
    cancelRun(step.test_run_id);
    step.status = 'cancelled';
    step.completed_at = now.toISOString();
    step.updated_at = now.toISOString();
    cancelledSteps.push(step.id);
  }
  for (const run of getStore().testRuns.filter((row) => row.tenant_id === scan.tenant_id && row.scan_id === scan.id)) {
    if (!ACTIVE_RUN_STATUSES.has(run.status) || cancelledRunIds.has(run.id)) continue;
    cancelRun(run.id);
    const orphanStep = scan.steps.find((step) => step.id === run.scan_step_id);
    if (orphanStep && orphanStep.status !== 'cancelled') {
      orphanStep.status = 'cancelled';
      orphanStep.test_run_id = run.id;
      orphanStep.completed_at = now.toISOString();
      orphanStep.updated_at = now.toISOString();
      cancelledSteps.push(orphanStep.id);
    }
  }
  const skipped = skipRemainingSteps(scan, 'scan_cancelled', now);
  const activeRunId = [...cancelledRunIds].at(-1) ?? null;
  let continued = null;
  if (options.cancel_series && seriesRecurrence) {
    scan.recurrence = null;
    scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.seriesStopped, { reason });
    const seriesId = scan.recurrence_series_id ?? scan.id;
    const upcoming = ensureStoreShape().validationScans.filter((row) => row.tenant_id === scan.tenant_id
      && row.id !== scan.id
      && row.status === 'scheduled'
      && (row.recurrence_series_id === seriesId || row.id === scan.next_scan_id));
    for (const next of upcoming) cancelValidationScan(ctx, next.id, { reason, cancel_series: true, now });
  } else if (seriesRecurrence && !scan.next_scan_id) {
    // Single-occurrence cancel: keep the series alive. The successor is otherwise only created at
    // dispatch, so cancelling a scheduled run that never dispatched would silently end every future
    // run. createNextOccurrence anchors from now and reuses this scan's step shape.
    continued = createNextOccurrence(ctx, scan, now);
  }
  refreshSummary(scan, now);
  scanAudit(ctx, scan, SCAN_AUDIT_ACTIONS.cancelled, {
    reason,
    cancelled_by: ctx.userId,
    cancelled_by_role: ctx.role,
    cancelled_steps: cancelledSteps.length,
    skipped_steps: skipped.length,
    active_test_run_id: activeRunId,
    ...(continued ? { series_continued_scan_id: continued.id, next_scheduled_for: continued.scheduled_for } : {}),
  });
  persistStore();
  return projectScan(ctx, scan);
}

export function getValidationScanActivity(ctx, id, options = {}) {
  const scan = scanForTenant(ctx, id);
  if (!scan) return null;
  readPathAdvance(ctx, scan, options);
  const store = getStore();
  const childRunIds = new Set(scan.steps.map((step) => step.test_run_id).filter(Boolean));
  const auditEntries = (store.auditLog ?? []).filter((entry) => {
    if (entry.tenant_id !== scan.tenant_id) return false;
    if (entry.resource_type === 'validation_scan' && entry.resource_id === scan.id) return true;
    if (entry.resource_type === 'test_run' && childRunIds.has(entry.resource_id)) return true;
    if (entry.metadata?.scan_id === scan.id) return true;
    return Boolean(entry.metadata?.test_run_id && childRunIds.has(entry.metadata.test_run_id));
  });
  const runEvents = store.events
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => event.tenant_id === scan.tenant_id && childRunIds.has(event.test_run_id))
    .map(({ event, index }) => ({ ...event, ingest_index: index }));
  const page = paginateActivity(buildActivityItems({ scan, steps: scan.steps, auditEntries, runEvents }), {
    after: options.after ?? null,
    limit: options.limit,
  });
  return {
    scan_id: scan.id,
    status: scan.status,
    items: page.items,
    count: page.items.length,
    cursor: page.cursor,
  };
}

registerRunTerminalHook((run) => {
  advanceScanForRun(run);
});
