import { getCheckById, isCustomerRunnable } from '../../contracts/checks.mjs';
import {
  nextPolicyRunAt,
  normalizePolicyInput,
  policyValidationResponse,
} from '../../contracts/testPolicyManagement.mjs';
import { newId } from '../../lib/ids.mjs';
import { LEAN_GROUP_LOOKUP } from './coreCatalogRepository.mjs';

/** @type {readonly string[]} */
export const TEST_POLICY_REPOSITORY_METHODS = Object.freeze([
  'listTestPolicies',
  'getActiveTestPolicy',
  'findActivePolicyByGroupCheck',
  'createTestPolicy',
  'updateTestPolicy',
  'archiveTestPolicy',
  'listDueTestPolicies',
  'leaseDueTestPolicies',
  'claimPolicyDispatchStart',
  'completePolicyDispatch',
]);

/** @type {readonly string[]} */
export const TEST_POLICY_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['getTargetGroup']);

/** @type {readonly string[]} */
export const TEST_POLICY_AUDIT_REPOSITORY_METHODS = Object.freeze(['appendAuditEvent']);

/** @type {readonly string[]} */
export const POSTGRES_TEST_POLICY_SERVICE_METHODS = Object.freeze([
  'listTestPolicies',
  'getTestPolicyForDispatch',
  'createTestPolicy',
  'patchTestPolicy',
  'archiveTestPolicy',
  'listDueTestPolicies',
  'leaseDueTestPolicies',
  'claimPolicyDispatchStart',
  'completePolicyDispatch',
  'dispatchDueTestPolicies',
]);

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

function assertRepositoryMethods(repo, label, methods) {
  if (!repo || typeof repo !== 'object') {
    throw new Error(`Postgres test policy service adapter requires repositories.${label}.`);
  }
  for (const method of methods) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres test policy service adapter requires ${label}.${method}().`);
    }
  }
}

function policyMaxConcurrency(check) {
  return Math.max(1, Math.min(1, Number(check?.safety_constraints?.max_concurrent_runs_per_target_group) || 1));
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

/**
 * @param {{
 *   testPolicies?: Record<string, unknown>,
 *   coreCatalog?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date }} [options]
 */
export function createPostgresTestPolicyServices(repositories, options = {}) {
  assertRepositoryMethods(repositories?.testPolicies, 'testPolicies', TEST_POLICY_REPOSITORY_METHODS);
  assertRepositoryMethods(repositories?.coreCatalog, 'coreCatalog', TEST_POLICY_CORE_CATALOG_REPOSITORY_METHODS);
  assertRepositoryMethods(repositories?.audit, 'audit', TEST_POLICY_AUDIT_REPOSITORY_METHODS);

  const testPolicies = repositories.testPolicies;
  const coreCatalog = repositories.coreCatalog;
  const nowFn = options.now ?? (() => new Date());

  async function loadActiveGroup(ctx, groupId, cache) {
    if (cache.has(groupId)) return cache.get(groupId);
    const group = await coreCatalog.getTargetGroup(ctx, groupId, LEAN_GROUP_LOOKUP);
    cache.set(groupId, group);
    return group;
  }

  async function enrichPolicy(ctx, policy, cache = new Map()) {
    const group = await loadActiveGroup(ctx, policy.target_group_id, cache);
    const target = group?.targets?.find((candidate) => candidate.id === policy.target_id) ?? null;
    const check = getCheckById(policy.check_id);
    return {
      ...policy,
      target_group: group
        ? {
            id: group.id,
            name: group.name,
            environment_id: group.environment_id,
            expected_behavior_default: group.expected_behavior_default,
          }
        : null,
      target: target
        ? { id: target.id, kind: target.kind, value: target.value, verify_state: target.verify_state ?? null }
        : null,
      check: publicCheck(check),
      target_count: group ? (group.targets ?? []).length : 0,
    };
  }

  const services = {
    async listTestPolicies(ctx) {
      const rows = await testPolicies.listTestPolicies(ctx);
      const cache = new Map();
      const enriched = [];
      for (const policy of rows) {
        const group = await loadActiveGroup(ctx, policy.target_group_id, cache);
        if (!group) continue;
        enriched.push(await enrichPolicy(ctx, policy, cache));
      }
      return enriched;
    },

    async getTestPolicyForDispatch(ctx, id) {
      const policy = await testPolicies.getActiveTestPolicy(ctx, id);
      return policy ? enrichPolicy(ctx, policy) : null;
    },

    async createTestPolicy(ctx, body = {}) {
      const unsupported = unsupportedEventDrivenPolicy(body);
      if (unsupported) return unsupported;
      const targetGroupId = String(body.target_group_id ?? '').trim();
      if (!targetGroupId) return { error: 'missing_target_group_id', status: 400 };
      const cache = new Map();
      const targetGroup = await loadActiveGroup(ctx, targetGroupId, cache);
      if (!targetGroup) return { error: 'target_group_not_found', status: 404 };
      const targetId = String(body.target_id ?? '').trim();
      if (!targetId) return { error: 'missing_target_id', status: 400 };
      const target = (targetGroup.targets ?? []).find((candidate) => candidate.id === targetId);
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
      const duplicate = await testPolicies.findActivePolicyByGroupCheck(
        ctx,
        targetGroupId,
        targetId,
        check.check_id,
      );
      if (duplicate) return { error: 'test_policy_exists', status: 409, existing_id: duplicate.id };

      let normalized;
      try {
        normalized = normalizePolicyInput(body, { maxConcurrency: policyMaxConcurrency(check) });
      } catch (error) {
        return policyValidationResponse(error);
      }
      const now = nowFn().toISOString();
      const record = {
        id: newId('policy'),
        tenant_id: ctx.tenantId,
        target_group_id: targetGroup.id,
        target_id: target.id,
        check_id: check.check_id,
        ...normalized,
        next_run_at: nextPolicyRunAt(normalized, { from: new Date(now), initial: true }),
        schedule_revision: 1,
        safety_policy_snapshot: {
          target_group_safety_policy: targetGroup.safety_policy ?? null,
          check_safety_constraints: check.safety_constraints ?? null,
          check_probe_profile: check.probe_profile ?? null,
        },
        created_at: now,
        updated_at: now,
      };
      const stored = await testPolicies.createTestPolicy(ctx, record);
      if (stored?.error) return stored;
      return enrichPolicy(ctx, stored, cache);
    },

    async patchTestPolicy(ctx, id, body = {}) {
      const existing = await testPolicies.getActiveTestPolicy(ctx, id);
      if (!existing) return null;
      const unsupported = unsupportedEventDrivenPolicy(body, existing);
      if (unsupported) return unsupported;
      const check = getCheckById(existing.check_id);
      let normalized;
      try {
        normalized = normalizePolicyInput(body, { current: existing, maxConcurrency: policyMaxConcurrency(check) });
      } catch (error) {
        return policyValidationResponse(error);
      }

      const mutableFields = ['cadence', 'expected_verdict', 'safe_windows', 'timezone', 'event_trigger', 'state', 'enabled', 'max_concurrent_runs'];
      const changedFields = mutableFields.filter((field) => JSON.stringify(existing[field] ?? null) !== JSON.stringify(normalized[field] ?? null));
      const now = nowFn().toISOString();
      const patch = { ...normalized, updated_at: now, changed_fields: changedFields };
      if (changedFields.some((field) => ['cadence', 'safe_windows', 'timezone', 'event_trigger', 'state', 'enabled'].includes(field))) {
        patch.next_run_at = nextPolicyRunAt(normalized, { from: new Date(now), initial: true });
        patch.lease_token = null;
        patch.lease_owner = null;
        patch.lease_expires_at = null;
        patch.schedule_revision = Number(existing.schedule_revision ?? 0) + 1;
        patch.changed_fields = [...new Set([...changedFields, 'next_run_at', 'schedule_revision'])];
      }
      const updated = await testPolicies.updateTestPolicy(ctx, id, patch);
      if (!updated || updated.error) return updated;
      return enrichPolicy(ctx, updated);
    },

    async archiveTestPolicy(ctx, id) {
      const existing = await testPolicies.getActiveTestPolicy(ctx, id);
      if (!existing) return null;
      const archived = await testPolicies.archiveTestPolicy(ctx, id, { now: nowFn().toISOString() });
      if (!archived) return null;
      return { archived: true, id };
    },

    async listDueTestPolicies(ctx, query = {}) {
      const rows = await testPolicies.listDueTestPolicies(ctx, query);
      const cache = new Map();
      const output = [];
      for (const policy of rows) {
        const group = await loadActiveGroup(ctx, policy.target_group_id, cache);
        if (group) output.push(await enrichPolicy(ctx, policy, cache));
      }
      return output;
    },

    async leaseDueTestPolicies(ctx, leaseOptions = {}) {
      const rows = await testPolicies.leaseDueTestPolicies(ctx, leaseOptions);
      if (!Array.isArray(rows)) return rows;
      const cache = new Map();
      const output = [];
      for (const policy of rows) {
        const group = await loadActiveGroup(ctx, policy.target_group_id, cache);
        if (group) output.push(await enrichPolicy(ctx, policy, cache));
      }
      return output;
    },

    async claimPolicyDispatchStart(ctx, policyId, input = {}, claimOptions = {}) {
      const policy = await testPolicies.getActiveTestPolicy(ctx, policyId);
      if (!policy) return { error: 'test_policy_not_found', status: 404 };
      return testPolicies.claimPolicyDispatchStart(ctx, policyId, input, claimOptions);
    },

    async completePolicyDispatch(ctx, policyId, input = {}, completionOptions = {}) {
      const policy = await testPolicies.getActiveTestPolicy(ctx, policyId);
      if (!policy) return { error: 'test_policy_not_found', status: 404 };
      if (!input.scheduled_for) return { error: 'missing_scheduled_for', status: 400 };
      const nextRun = nextPolicyRunAt(policy, { from: new Date(input.scheduled_for), initial: false });
      return testPolicies.completePolicyDispatch(ctx, policyId, { ...input, next_run_at: nextRun }, completionOptions);
    },

    async dispatchDueTestPolicies(ctx, dispatchOptions = {}) {
      if (typeof dispatchOptions.startTestRun !== 'function') {
        throw new Error('dispatchDueTestPolicies requires startTestRun().');
      }
      const leases = await services.leaseDueTestPolicies(ctx, dispatchOptions);
      if (!Array.isArray(leases)) return leases;
      const results = [];
      for (const lease of leases) {
        const binding = {
          dispatch_id: lease.dispatch_id,
          lease_token: lease.lease_token,
          idempotency_key: lease.idempotency_key,
          scheduled_for: lease.scheduled_for,
        };
        const claimed = await services.claimPolicyDispatchStart(
          ctx,
          lease.id,
          binding,
          dispatchOptions,
        );
        if (claimed?.error) {
          results.push({ policy_id: lease.id, run: null, error: claimed, dispatch: claimed });
          continue;
        }
        let started;
        try {
          started = await dispatchOptions.startTestRun(ctx, {
            target_group_id: lease.target_group_id,
            target_id: lease.target_id,
            check_id: lease.check_id,
            policy_id: lease.id,
            policy_dispatch_id: lease.dispatch_id,
          }, dispatchOptions.runtimeConfig, { policyDispatch: binding });
        } catch {
          started = { error: 'start_test_run_failed', status: 500, retryable: true };
        }

        const signedWorkerDispatch = dispatchOptions.runtimeConfig?.probeMode === 'signed-worker';
        if (!started?.error && signedWorkerDispatch && !started?.probe_job?.id) {
          started = {
            error: 'probe_job_dispatch_incomplete',
            status: 503,
            retryable: true,
          };
        }
        const failed = started?.error;
        const retryableFailure = failed && (
          started.retryable === true || Number(started.status) >= 500
        );
        if (retryableFailure) {
          // Do not settle or advance the occurrence. Its durable lease can expire and be
          // reclaimed, allowing startTestRun to repair the committed run/probe-job gap.
          results.push({ policy_id: lease.id, run: null, error: started, dispatch: claimed });
          continue;
        }

        const runId = failed ? null : (started.run?.id ?? started.id);
        const missingRunId = !failed && !runId;
        const completion = await services.completePolicyDispatch(ctx, lease.id, {
          ...binding,
          run_id: runId,
          state: failed ? 'skipped' : missingRunId ? 'failed' : 'dispatched',
          error_code: failed ? started.error : missingRunId ? 'missing_run_id' : null,
        }, dispatchOptions);
        results.push({
          policy_id: lease.id,
          run: failed || missingRunId ? null : started,
          error: failed ? started : missingRunId ? { error: 'missing_run_id', status: 500 } : null,
          dispatch: completion,
        });
      }
      return results;
    },
  };
  return services;
}
