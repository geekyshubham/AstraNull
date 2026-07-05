import { audit } from '../audit.mjs';
import { getCheckById, isCustomerRunnable } from '../contracts/checks.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { activeTargetGroupsForTenant } from './targetGroups.mjs';

const CADENCES = new Set(['manual', 'daily', 'weekly', 'monthly', 'event_driven']);
const EXPECTED_VERDICTS = new Set(['pass', 'warn', 'fail', 'manual_review']);

function ensureStoreShape() {
  const store = getStore();
  if (!Array.isArray(store.testPolicies)) store.testPolicies = [];
}

function normalizeCadence(value) {
  const cadence = String(value ?? 'manual').trim();
  return CADENCES.has(cadence) ? cadence : 'manual';
}

function normalizeExpectedVerdict(value) {
  const verdict = String(value ?? 'pass').trim();
  return EXPECTED_VERDICTS.has(verdict) ? verdict : 'pass';
}

function normalizeSafeWindows(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item) => item && typeof item === 'object' && !Array.isArray(item))
    .map((item) => ({
      day: String(item.day ?? '').trim(),
      start: String(item.start ?? '').trim(),
      end: String(item.end ?? '').trim(),
      timezone: String(item.timezone ?? 'UTC').trim() || 'UTC',
    }))
    .filter((item) => item.day && item.start && item.end)
    .slice(0, 14);
}

function activeTargetGroup(ctx, id) {
  return activeTargetGroupsForTenant(ctx.tenantId).find((group) => group.id === id) ?? null;
}

function targetsForGroup(ctx, targetGroupId) {
  return getStore().targets.filter(
    (target) => target.tenant_id === ctx.tenantId && target.target_group_id === targetGroupId,
  );
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

export function listTestPolicies(ctx) {
  ensureStoreShape();
  const activeGroupIds = new Set(activeTargetGroupsForTenant(ctx.tenantId).map((group) => group.id));
  return getStore().testPolicies
    .filter(
      (policy) =>
        policy.tenant_id === ctx.tenantId &&
        !policy.archived_at &&
        activeGroupIds.has(policy.target_group_id),
    )
    .map((policy) => enrichPolicy(ctx, policy));
}

export function createTestPolicy(ctx, body = {}) {
  ensureStoreShape();
  const targetGroupId = String(body.target_group_id ?? '').trim();
  if (!targetGroupId) return { error: 'missing_target_group_id', status: 400 };
  const targetGroup = activeTargetGroup(ctx, targetGroupId);
  if (!targetGroup) return { error: 'target_group_not_found', status: 404 };

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

  const now = new Date().toISOString();
  const record = {
    id: newId('policy'),
    tenant_id: ctx.tenantId,
    target_group_id: targetGroup.id,
    check_id: check.check_id,
    cadence: normalizeCadence(body.cadence),
    expected_verdict: normalizeExpectedVerdict(body.expected_verdict),
    safe_windows: normalizeSafeWindows(body.safe_windows),
    state: 'active',
    safety_policy_snapshot: {
      target_group_safety_policy: targetGroup.safety_policy ?? null,
      check_safety_constraints: check.safety_constraints ?? null,
      check_probe_profile: check.probe_profile ?? null,
    },
    created_at: now,
    updated_at: now,
  };
  getStore().testPolicies.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_policy.created',
    resource_type: 'test_policy',
    resource_id: record.id,
    metadata: { target_group_id: targetGroup.id, check_id: check.check_id },
  });
  persistStore();
  return enrichPolicy(ctx, record);
}

export function patchTestPolicy(ctx, id, body = {}) {
  const policy = activePolicy(ctx, id);
  if (!policy) return null;

  if (body.cadence !== undefined) policy.cadence = normalizeCadence(body.cadence);
  if (body.expected_verdict !== undefined) {
    policy.expected_verdict = normalizeExpectedVerdict(body.expected_verdict);
  }
  if (body.safe_windows !== undefined) policy.safe_windows = normalizeSafeWindows(body.safe_windows);
  if (body.state !== undefined) {
    const state = String(body.state).trim();
    if (['active', 'paused'].includes(state)) policy.state = state;
  }
  policy.updated_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_policy.updated',
    resource_type: 'test_policy',
    resource_id: policy.id,
  });
  persistStore();
  return enrichPolicy(ctx, policy);
}

export function archiveTestPolicy(ctx, id) {
  const policy = activePolicy(ctx, id);
  if (!policy) return null;
  policy.state = 'archived';
  policy.archived_at = new Date().toISOString();
  policy.updated_at = policy.archived_at;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_policy.archived',
    resource_type: 'test_policy',
    resource_id: policy.id,
  });
  persistStore();
  return { archived: true, id };
}
