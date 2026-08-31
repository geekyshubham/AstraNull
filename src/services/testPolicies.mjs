import { audit } from '../audit.mjs';
import { getCheckById, isCustomerRunnable } from '../contracts/checks.mjs';
import {
  nextPolicyRunAt,
  normalizePolicyInput,
  policyDispatchIdempotencyKey,
  policyValidationResponse,
} from '../contracts/testPolicyManagement.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { activeTargetGroupsForTenant, isArchivedTarget } from './targetGroups.mjs';

function ensureStoreShape() {
  const store = getStore();
  if (!Array.isArray(store.testPolicies)) store.testPolicies = [];
  if (!Array.isArray(store.testPolicyDispatches)) store.testPolicyDispatches = [];
}

function activeTargetGroup(ctx, id) {
  return activeTargetGroupsForTenant(ctx.tenantId).find((group) => group.id === id) ?? null;
}

function targetsForGroup(ctx, targetGroupId) {
  return getStore().targets.filter(
    (target) => target.tenant_id === ctx.tenantId
      && target.target_group_id === targetGroupId
      && !isArchivedTarget(target),
  );
}

function targetForGroup(ctx, targetGroupId, targetId) {
  return targetsForGroup(ctx, targetGroupId).find((target) => target.id === targetId) ?? null;
}

function targetKindCompatibilityError(check, target) {
  const kind = /^https?:\/\//i.test(String(target?.value ?? '')) ? 'url' : target?.kind;
  if (!Array.isArray(check.supported_targets) || check.supported_targets.length === 0
      || check.supported_targets.includes(kind)) return null;
  return {
    error: 'target_kind_not_supported',
    status: 400,
    check_id: check.check_id,
    target_kind: kind ?? null,
    supported_targets: check.supported_targets,
  };
}

function publicCheck(check) {
  if (!check) return null;
  return {
    check_id: check.check_id,
    name: check.name,
    vector_family: check.vector_family,
    safety_class: check.safety_class,
    risk_class: check.risk_class,
    safety_constraints: check.safety_constraints,
    default_expected_behavior: check.default_expected_behavior,
  };
}

function enrichPolicy(ctx, policy) {
  const targetGroup = activeTargetGroup(ctx, policy.target_group_id);
  const target = targetGroup ? targetForGroup(ctx, targetGroup.id, policy.target_id) : null;
  const check = getCheckById(policy.check_id);
  return {
    ...policy,
    target_group: targetGroup
      ? {
          id: targetGroup.id,
          name: targetGroup.name,
          environment_id: targetGroup.environment_id,
          expected_behavior_default: targetGroup.expected_behavior_default,
        }
      : null,
    target: target
      ? { id: target.id, kind: target.kind, value: target.value, verify_state: target.verify_state ?? null }
      : null,
    check: publicCheck(check),
    target_count: targetGroup ? targetsForGroup(ctx, targetGroup.id).length : 0,
  };
}

function activePolicy(ctx, id) {
  ensureStoreShape();
  return getStore().testPolicies.find(
    (policy) => policy.id === id && policy.tenant_id === ctx.tenantId && !policy.archived_at,
  ) ?? null;
}

function policyMaxConcurrency(check) {
  return Math.max(1, Math.min(1, Number(check?.safety_constraints?.max_concurrent_runs_per_target_group) || 1));
}

function unsupportedEventDrivenPolicy(body, current = null) {
  const cadence = String(body?.cadence ?? current?.cadence ?? 'manual').trim().toLowerCase();
  if (cadence !== 'event_driven') return null;
  return {
    error: 'unsupported_policy_cadence',
    status: 400,
    field: 'cadence',
    message: 'event_driven policies are unavailable because no durable event consumer is configured.',
  };
}

function mutationAudit(ctx, policy, action, changedFields) {
  return audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action,
    resource_type: 'test_policy',
    resource_id: policy.id,
    metadata: {
      target_group_id: policy.target_group_id,
      target_id: policy.target_id ?? null,
      check_id: policy.check_id,
      changed_fields: changedFields,
    },
  });
}

export function listTestPolicies(ctx) {
  ensureStoreShape();
  const activeGroupIds = new Set(activeTargetGroupsForTenant(ctx.tenantId).map((group) => group.id));
  return getStore().testPolicies
    .filter((policy) => policy.tenant_id === ctx.tenantId && !policy.archived_at && activeGroupIds.has(policy.target_group_id))
    .map((policy) => enrichPolicy(ctx, policy));
}

export function getTestPolicyForDispatch(ctx, id) {
  const policy = activePolicy(ctx, id);
  return policy ? enrichPolicy(ctx, policy) : null;
}

export function createTestPolicy(ctx, body = {}, options = {}) {
  ensureStoreShape();
  const unsupported = unsupportedEventDrivenPolicy(body);
  if (unsupported) return unsupported;
  const targetGroupId = String(body.target_group_id ?? '').trim();
  if (!targetGroupId) return { error: 'missing_target_group_id', status: 400 };
  const targetGroup = activeTargetGroup(ctx, targetGroupId);
  if (!targetGroup) return { error: 'target_group_not_found', status: 404 };
  const targetId = String(body.target_id ?? '').trim();
  if (!targetId) return { error: 'missing_target_id', status: 400 };
  const target = targetForGroup(ctx, targetGroupId, targetId);
  if (!target) return { error: 'target_not_found', status: 404 };

  const checkId = String(body.check_id ?? '').trim();
  const check = getCheckById(checkId);
  if (!check) return { error: 'unknown_check', status: 400 };
  if (!isCustomerRunnable(check)) {
    return {
      error: 'soc_gated_check',
      status: 403,
      message: 'This check requires a SOC-governed high-scale request, not a customer-runnable policy.',
    };
  }
  const incompatibleTarget = targetKindCompatibilityError(check, target);
  if (incompatibleTarget) return incompatibleTarget;
  const duplicate = getStore().testPolicies.find(
    (policy) => policy.tenant_id === ctx.tenantId
      && policy.target_group_id === targetGroupId
      && policy.target_id === targetId
      && policy.check_id === check.check_id
      && !policy.archived_at,
  );
  if (duplicate) return { error: 'test_policy_exists', status: 409, existing_id: duplicate.id };

  let normalized;
  try {
    normalized = normalizePolicyInput(body, { maxConcurrency: policyMaxConcurrency(check) });
  } catch (error) {
    return policyValidationResponse(error);
  }
  const now = options.now ?? new Date().toISOString();
  const record = {
    id: options.id ?? newId('policy'),
    tenant_id: ctx.tenantId,
    target_group_id: targetGroup.id,
    target_id: target.id,
    check_id: check.check_id,
    ...normalized,
    next_run_at: nextPolicyRunAt(normalized, { from: new Date(now), initial: true }),
    last_scheduled_at: null,
    last_dispatched_at: null,
    last_run_id: null,
    lease_token: null,
    lease_owner: null,
    lease_expires_at: null,
    schedule_revision: 1,
    safety_policy_snapshot: {
      target_group_safety_policy: targetGroup.safety_policy ?? null,
      check_safety_constraints: check.safety_constraints ?? null,
      check_probe_profile: check.probe_profile ?? null,
    },
    created_at: now,
    updated_at: now,
  };
  getStore().testPolicies.push(record);
  mutationAudit(ctx, record, 'test_policy.created', [
    'target_group_id', 'target_id', 'check_id', 'cadence', 'expected_verdict', 'safe_windows', 'timezone',
    'event_trigger', 'enabled', 'max_concurrent_runs', 'next_run_at', 'safety_policy_snapshot',
  ]);
  persistStore();
  return enrichPolicy(ctx, record);
}

export function patchTestPolicy(ctx, id, body = {}, options = {}) {
  const policy = activePolicy(ctx, id);
  if (!policy) return null;
  const unsupported = unsupportedEventDrivenPolicy(body, policy);
  if (unsupported) return unsupported;
  const check = getCheckById(policy.check_id);
  let normalized;
  try {
    normalized = normalizePolicyInput(body, { current: policy, maxConcurrency: policyMaxConcurrency(check) });
  } catch (error) {
    return policyValidationResponse(error);
  }

  const mutableFields = ['cadence', 'expected_verdict', 'safe_windows', 'timezone', 'event_trigger', 'state', 'enabled', 'max_concurrent_runs'];
  const changedFields = mutableFields.filter((field) => JSON.stringify(policy[field] ?? null) !== JSON.stringify(normalized[field] ?? null));
  for (const field of mutableFields) policy[field] = normalized[field];
  const now = options.now ?? new Date().toISOString();
  if (changedFields.some((field) => ['cadence', 'safe_windows', 'timezone', 'event_trigger', 'state', 'enabled'].includes(field))) {
    policy.next_run_at = nextPolicyRunAt(policy, { from: new Date(now), initial: true });
    policy.lease_token = null;
    policy.lease_owner = null;
    policy.lease_expires_at = null;
    policy.schedule_revision = Number(policy.schedule_revision ?? 0) + 1;
    changedFields.push('next_run_at', 'schedule_revision');
  }
  policy.updated_at = now;
  if (changedFields.length) mutationAudit(ctx, policy, 'test_policy.updated', [...new Set(changedFields)]);
  persistStore();
  return enrichPolicy(ctx, policy);
}

export function archiveTestPolicy(ctx, id, options = {}) {
  const policy = activePolicy(ctx, id);
  if (!policy) return null;
  const now = options.now ?? new Date().toISOString();
  policy.state = 'archived';
  policy.enabled = false;
  policy.archived_at = now;
  policy.updated_at = now;
  policy.next_run_at = null;
  policy.lease_token = null;
  policy.lease_owner = null;
  policy.lease_expires_at = null;
  mutationAudit(ctx, policy, 'test_policy.archived', ['state', 'enabled', 'archived_at', 'next_run_at']);
  persistStore();
  return { archived: true, id };
}

export function listDueTestPolicies(ctx, options = {}) {
  ensureStoreShape();
  const now = new Date(options.now ?? Date.now());
  if (Number.isNaN(now.getTime())) return { error: 'invalid_now', status: 400 };
  const limit = Math.max(1, Math.min(100, Number(options.limit) || 25));
  let disabledLegacyPolicy = false;
  for (const policy of getStore().testPolicies) {
    if (policy.tenant_id !== ctx.tenantId || policy.archived_at || String(policy.target_id ?? '').trim()) continue;
    policy.state = 'paused';
    policy.enabled = false;
    policy.next_run_at = null;
    policy.lease_token = null;
    policy.lease_owner = null;
    policy.lease_expires_at = null;
    policy.updated_at = now.toISOString();
    disabledLegacyPolicy = true;
  }
  if (disabledLegacyPolicy) persistStore();
  return getStore().testPolicies
    .filter((policy) => policy.tenant_id === ctx.tenantId
      && !policy.archived_at
      && policy.state === 'active'
      && policy.enabled === true
      && ['daily', 'weekly', 'monthly'].includes(policy.cadence)
      && policy.next_run_at
      && new Date(policy.next_run_at) <= now
      && (!policy.lease_expires_at || new Date(policy.lease_expires_at) <= now))
    .sort((left, right) => String(left.next_run_at).localeCompare(String(right.next_run_at)) || left.id.localeCompare(right.id))
    .slice(0, limit)
    .map((policy) => enrichPolicy(ctx, policy));
}

export function leaseDueTestPolicies(ctx, options = {}) {
  ensureStoreShape();
  const workerId = String(options.workerId ?? '').trim();
  if (!workerId) return { error: 'missing_worker_id', status: 400 };
  const now = new Date(options.now ?? Date.now());
  if (Number.isNaN(now.getTime())) return { error: 'invalid_now', status: 400 };
  const leaseMs = Math.max(1_000, Math.min(15 * 60_000, Number(options.leaseMs) || 60_000));
  const due = listDueTestPolicies(ctx, { now, limit: options.limit });
  if (!Array.isArray(due)) return due;
  const leased = [];

  for (const enriched of due) {
    const policy = activePolicy(ctx, enriched.id);
    if (!policy) continue;
    const scheduledFor = new Date(policy.next_run_at).toISOString();
    const idempotencyKey = policyDispatchIdempotencyKey(ctx.tenantId, policy.id, scheduledFor);
    let dispatch = getStore().testPolicyDispatches.find(
      (row) => row.tenant_id === ctx.tenantId && row.idempotency_key === idempotencyKey,
    );
    if (
      dispatch
      && !(
        dispatch.state === 'leased'
        && new Date(dispatch.lease_expires_at) <= now
      )
    ) continue;

    const leaseToken = newId('policy_lease');
    const leaseExpiresAt = new Date(now.getTime() + leaseMs).toISOString();
    if (!dispatch) {
      dispatch = {
        id: newId('policy_dispatch'),
        tenant_id: ctx.tenantId,
        policy_id: policy.id,
        scheduled_for: scheduledFor,
        idempotency_key: idempotencyKey,
        state: 'leased',
        created_at: now.toISOString(),
      };
      getStore().testPolicyDispatches.push(dispatch);
    }
    Object.assign(dispatch, {
      state: 'leased', lease_token: leaseToken, lease_owner: workerId,
      lease_expires_at: leaseExpiresAt, updated_at: now.toISOString(),
    });
    Object.assign(policy, {
      lease_token: leaseToken, lease_owner: workerId, lease_expires_at: leaseExpiresAt,
      last_scheduled_at: scheduledFor, updated_at: now.toISOString(),
    });
    leased.push({
      ...enrichPolicy(ctx, policy),
      dispatch_id: dispatch.id,
      scheduled_for: scheduledFor,
      idempotency_key: idempotencyKey,
      lease_token: leaseToken,
      lease_expires_at: leaseExpiresAt,
    });
  }
  if (leased.length) persistStore();
  return leased;
}

export function claimPolicyDispatchStart(ctx, policyId, input = {}, options = {}) {
  ensureStoreShape();
  const dispatch = getStore().testPolicyDispatches.find(
    (row) => row.id === input.dispatch_id && row.policy_id === policyId && row.tenant_id === ctx.tenantId,
  );
  if (!dispatch) return { error: 'policy_dispatch_not_found', status: 404 };
  if (dispatch.idempotency_key !== input.idempotency_key) {
    return { error: 'policy_dispatch_key_mismatch', status: 409 };
  }
  const now = new Date(options.now ?? Date.now());
  if (dispatch.start_claimed_at) {
    if (
      dispatch.state === 'leased'
      && dispatch.lease_token === input.lease_token
      && new Date(dispatch.lease_expires_at) > now
    ) return { ...dispatch };
    return { error: 'policy_dispatch_start_claimed', status: 409 };
  }
  if (
    dispatch.state !== 'leased'
    || dispatch.lease_token !== input.lease_token
    || new Date(dispatch.lease_expires_at) <= now
  ) {
    return { error: 'policy_lease_lost', status: 409 };
  }
  const policy = activePolicy(ctx, policyId);
  if (
    !policy
    || policy.state !== 'active'
    || policy.enabled !== true
    || policy.lease_token !== input.lease_token
    || !policy.lease_expires_at
    || new Date(policy.lease_expires_at) <= now
  ) {
    return { error: 'policy_lease_lost', status: 409 };
  }
  dispatch.start_claimed_at = now.toISOString();
  dispatch.updated_at = now.toISOString();
  mutationAudit(ctx, policy, 'test_policy.dispatch_start_claimed', ['start_claimed_at']);
  persistStore();
  return { ...dispatch };
}

export function completePolicyDispatch(ctx, policyId, input = {}, options = {}) {
  ensureStoreShape();
  const dispatch = getStore().testPolicyDispatches.find(
    (row) => row.id === input.dispatch_id && row.policy_id === policyId && row.tenant_id === ctx.tenantId,
  );
  if (!dispatch) return { error: 'policy_dispatch_not_found', status: 404 };
  if (dispatch.idempotency_key !== input.idempotency_key) return { error: 'policy_dispatch_key_mismatch', status: 409 };
  const runId = input.run_id == null ? null : String(input.run_id).trim();
  const state = input.state ?? (runId ? 'dispatched' : 'skipped');
  if (!['dispatched', 'skipped', 'failed'].includes(state)) return { error: 'invalid_policy_dispatch_state', status: 400 };
  if (state === 'dispatched' && !runId) return { error: 'missing_policy_run_id', status: 400 };
  if (state !== 'dispatched' && runId) return { error: 'invalid_policy_run_binding', status: 400 };
  if (state === 'dispatched') {
    const boundRun = getStore().testRuns.find(
      (run) => run.id === runId
        && run.tenant_id === ctx.tenantId
        && run.policy_id === policyId
        && run.policy_dispatch_id === dispatch.id
        && run.target_group_id === activePolicy(ctx, policyId)?.target_group_id
        && run.target_id === activePolicy(ctx, policyId)?.target_id
        && run.check_id === activePolicy(ctx, policyId)?.check_id,
    );
    if (!boundRun) return { error: 'policy_run_binding_mismatch', status: 409 };
  }
  if (dispatch.state !== 'leased') {
    if (
      dispatch.state === state
      && (dispatch.run_id ?? null) === (runId ?? null)
      && (dispatch.error_code ?? null) === (input.error_code ?? null)
    ) return { ...dispatch };
    return { error: 'policy_dispatch_already_settled', status: 409 };
  }
  const now = new Date(options.now ?? Date.now());
  if (dispatch.lease_token !== input.lease_token) return { error: 'policy_lease_lost', status: 409 };
  if (!dispatch.start_claimed_at) return { error: 'policy_dispatch_start_not_claimed', status: 409 };
  const policy = activePolicy(ctx, policyId);
  if (!policy || policy.lease_token !== input.lease_token) return { error: 'policy_lease_lost', status: 409 };
  Object.assign(dispatch, {
    state,
    run_id: runId ?? null,
    error_code: input.error_code ?? null,
    completed_at: now.toISOString(),
    updated_at: now.toISOString(),
    lease_token: null,
    lease_owner: null,
    lease_expires_at: null,
  });
  Object.assign(policy, {
    next_run_at: nextPolicyRunAt(policy, { from: new Date(dispatch.scheduled_for), initial: false }),
    last_dispatched_at: state === 'dispatched' ? now.toISOString() : policy.last_dispatched_at ?? null,
    last_run_id: runId ?? policy.last_run_id ?? null,
    lease_token: null,
    lease_owner: null,
    lease_expires_at: null,
    updated_at: now.toISOString(),
  });
  mutationAudit(ctx, policy, `test_policy.dispatch_${state}`, ['next_run_at', 'last_dispatched_at', 'last_run_id', 'lease_token']);
  persistStore();
  return { ...dispatch };
}

export async function dispatchDueTestPolicies(ctx, options = {}) {
  if (typeof options.startTestRun !== 'function') throw new Error('dispatchDueTestPolicies requires startTestRun().');
  const leases = leaseDueTestPolicies(ctx, options);
  if (!Array.isArray(leases)) return leases;
  const results = [];
  for (const lease of leases) {
    const binding = {
      dispatch_id: lease.dispatch_id,
      lease_token: lease.lease_token,
      idempotency_key: lease.idempotency_key,
      scheduled_for: lease.scheduled_for,
    };
    const claimed = claimPolicyDispatchStart(ctx, lease.id, binding, options);
    if (claimed?.error) {
      results.push({ policy_id: lease.id, run: null, error: claimed, dispatch: claimed });
      continue;
    }
    let started;
    try {
      started = await options.startTestRun(ctx, {
        target_group_id: lease.target_group_id,
        target_id: lease.target_id,
        check_id: lease.check_id,
        policy_id: lease.id,
        policy_dispatch_id: lease.dispatch_id,
      }, options.runtimeConfig, { policyDispatch: binding });
    } catch {
      started = { error: 'start_test_run_failed', status: 500 };
    }
    const failed = started?.error;
    const runId = failed ? null : (started.run?.id ?? started.id);
    const missingRunId = !failed && !runId;
    const completion = completePolicyDispatch(ctx, lease.id, {
      ...binding,
      run_id: runId,
      state: failed ? 'skipped' : missingRunId ? 'failed' : 'dispatched',
      error_code: failed ? started.error : missingRunId ? 'missing_run_id' : null,
    }, options);
    results.push({
      policy_id: lease.id,
      run: failed || missingRunId ? null : started,
      error: failed ? started : missingRunId ? { error: 'missing_run_id', status: 500 } : null,
      dispatch: completion,
    });
  }
  return results;
}
