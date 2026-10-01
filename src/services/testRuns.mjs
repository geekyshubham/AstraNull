import { audit } from '../audit.mjs';
import {
  customerSelectableChecks,
  evaluateCheckPrerequisites,
  getCheckById,
  isCustomerRunnable,
  resolveExpectedBehaviorForCheck,
} from '../contracts/checks.mjs';
import { targetKindCompatibilityError } from '../contracts/checkTargetCompatibility.mjs';
import { targetDedupeKey } from '../contracts/targetManagement.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { redactObject } from '../lib/redact.mjs';
import { scrubRunForCustomer } from '../lib/outsideInEvidence.mjs';
import { recordEvidence } from './evidence.mjs';
import { newId } from '../lib/ids.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../lib/wafProductCatalog.mjs';
import { getStore, persistStore } from '../store.mjs';
import { correlateExternalOnlyVerdict, correlateOpsReadinessVerdict, probeEventHasProbeIo } from './correlation.mjs';
import { upsertFindingFromVerdict } from './findings.mjs';
import { executeOpsReadinessProbe, isOpsReadinessProbeKind } from '../lib/opsReadinessValidation.mjs';
import { simulateProbeResult } from './probeStub.mjs';
import { targetOwnershipProof } from './ownershipVerification.mjs';
import { getTestPolicyForDispatch } from './testPolicies.mjs';
import { isWithinPolicySafeWindow } from '../contracts/testPolicyManagement.mjs';
import { isTrustedProducerEvent } from '../lib/trustedEventProvenance.mjs';
import { validateHostSniTargetBinding } from '../lib/probeJobs.mjs';
import { createProbeJob } from './probeCoordinator.mjs';
import { probeDispatchReady } from '../config.mjs';
import { computeReadiness } from './readiness.mjs';
import { notifyRunTerminal } from './runTerminalHooks.mjs';
import { normalizeCancelReason, withCheckSection } from '../contracts/validationScanManagement.mjs';
import { isArchivedTarget, isArchivedTargetGroup } from './targetGroups.mjs';
import {
  countCustomerRunnableRunsLastHour,
  effectiveSafetyConstraints,
  isWithinSafeTestWindow,
  lastRunForTargetGroup,
  normalizeSafetyPolicy,
  wouldExceedEventCap,
} from './safeTestPolicy.mjs';
import { isKillSwitchActiveForTenant } from './killSwitchState.mjs';
import { assertSubscriptionLimit, getTenantAccount } from './subscriptions.mjs';

export function listChecks() {
  return customerSelectableChecks(getStore().checkCatalog ?? []).map(withCheckSection);
}

const DEFAULT_TEST_RUN_LIST_LIMIT = 100;
// docs/api.md GET /v1/test-runs: limit default 100, max 100. Keep dev-json and Postgres aligned.
const MAX_TEST_RUN_LIST_LIMIT = 100;

function normalizeTestRunListLimit(limit) {
  const parsed = Number(limit);
  if (limit == null || !Number.isFinite(parsed) || parsed < 1) return DEFAULT_TEST_RUN_LIST_LIMIT;
  return Math.min(Math.floor(parsed), MAX_TEST_RUN_LIST_LIMIT);
}

export function listTestRuns(ctx, options = {}) {
  let rows = getStore().testRuns.filter((r) => r.tenant_id === ctx.tenantId);
  if (options.target_group_id) {
    rows = rows.filter((r) => r.target_group_id === options.target_group_id);
  }
  if (options.target_id) {
    rows = rows.filter((r) => r.target_id === options.target_id);
  }
  if (options.check_id) {
    rows = rows.filter((r) => r.check_id === options.check_id);
  }
  rows = rows.sort((a, b) =>
    String(b.started_at ?? b.created_at ?? '').localeCompare(
      String(a.started_at ?? a.created_at ?? ''),
    ) || String(b.id ?? '').localeCompare(String(a.id ?? '')),
  );
  rows = rows.slice(0, normalizeTestRunListLimit(options.limit));
  const verdicts = getStore().verdicts ?? [];
  return rows.map((run) =>
    // EVIDENCE-01 / ADR-0008: list items carry the same nested verdict as run detail; scrub it here too.
    scrubRunForCustomer({
      ...run,
      verdict: run.verdict ?? verdicts.find((v) => v.tenant_id === ctx.tenantId && v.test_run_id === run.id) ?? null,
    }),
  );
}

export function listTestRunsEnvelope(ctx, options = {}) {
  const items = listTestRuns(ctx, options);
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : options.target_group_id
          ? 'No test runs match this target group filter.'
          : options.target_id
            ? 'No test runs match this target filter.'
            : options.check_id
              ? 'No test runs have been recorded for this check yet.'
              : 'No test runs have been started for this tenant yet.',
    },
  };
}

function collectionDeadlineMs(check) {
  const seconds = check?.safety_constraints?.max_duration_seconds ?? 120;
  return seconds * 1000;
}

function isCollectionWindowExpired(run) {
  if (!run.collection_deadline_at) return false;
  return Date.now() >= new Date(run.collection_deadline_at).getTime();
}

function hasExternalProbeEvidence(run) {
  if (run.probe_external_result != null && run.probe_external_result !== '') return true;
  const store = getStore();
  return store.events.some(
    (e) =>
      e.test_run_id === run.id &&
      e.signal_type === 'probe_result' &&
      isTrustedProducerEvent(e) &&
      e.nonce_hash === run.correlation.nonce_hash,
  );
}

export function maybeFinalizeCollectingRun(run, { force = false } = {}) {
  if (!run || run.status !== 'collecting') return null;
  if (getStore().verdicts.some((v) => v.test_run_id === run.id)) return null;
  if (!hasExternalProbeEvidence(run)) return null;
  if (!force && !isCollectionWindowExpired(run)) return null;
  return finalizeNoObservation(run);
}

export function finalizeTestRun(ctx, id, { force = false } = {}) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  if (run.status !== 'collecting') {
    return { error: 'not_collecting', status: 409 };
  }
  if (!hasExternalProbeEvidence(run)) {
    return { error: 'external_probe_pending', status: 409 };
  }
  if (!force && !isCollectionWindowExpired(run)) {
    return { error: 'observation_window_active', status: 409 };
  }
  const verdict = maybeFinalizeCollectingRun(run, { force: true });
  if (!verdict) {
    return { error: 'cannot_finalize', status: 409 };
  }
  persistStore();
  return { run: getTestRun(ctx, id), verdict };
}

export function getTestRun(ctx, id) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  maybeFinalizeCollectingRun(run);
  const verdict = getStore().verdicts.find((v) => v.test_run_id === id);
  // EVIDENCE-01 / ADR-0008: customer run detail must read external-only. Scrub the nested verdict
  // explanation / placement_confidence at this projection seam; stored rows are untouched.
  return scrubRunForCustomer({ ...run, verdict: verdict ?? null });
}

export function getRunEvents(ctx, id) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  return getStore().events.filter((e) => e.test_run_id === id && e.tenant_id === ctx.tenantId);
}

function activeRunForGroup(tenantId, targetGroupId) {
  return getStore().testRuns.find(
    (r) =>
      r.tenant_id === tenantId &&
      r.target_group_id === targetGroupId &&
      ['running', 'collecting', 'planned'].includes(r.status),
  );
}

function validatePolicyBinding(ctx, body, group, check, options = {}) {
  const policyId = String(body.policy_id ?? '').trim();
  if (!policyId) return { policy: null };
  const policy = getTestPolicyForDispatch(ctx, policyId);
  if (!policy) return { error: 'test_policy_not_found', status: 404 };
  if (policy.state !== 'active' || policy.enabled !== true || policy.archived_at) {
    return { error: 'test_policy_disabled', status: 409 };
  }
  if (typeof policy.target_id !== 'string' || !policy.target_id.trim()) {
    return { error: 'test_policy_target_binding_missing', status: 409 };
  }
  if (policy.target_group_id !== group.id
    || policy.target_id !== body.target_id
    || policy.check_id !== check.check_id) {
    return { error: 'test_policy_binding_mismatch', status: 409 };
  }
  if (policy.max_concurrent_runs !== 1) return { error: 'unsafe_policy_concurrency', status: 409 };
  if (policy.safe_windows?.length && !isWithinPolicySafeWindow(policy)) {
    return { error: 'policy_safe_window_closed', status: 429 };
  }

  const trustedDispatch = options.policyDispatch;
  if (policy.cadence !== 'manual' && !trustedDispatch && !options.policyEvent) {
    return { error: 'trusted_policy_dispatch_required', status: 409 };
  }
  if (trustedDispatch) {
    const dispatch = (getStore().testPolicyDispatches ?? []).find(
      (row) => row.id === trustedDispatch.dispatch_id
        && row.tenant_id === ctx.tenantId
        && row.policy_id === policy.id,
    );
    if (!dispatch
      || dispatch.state !== 'leased'
      || dispatch.lease_token !== trustedDispatch.lease_token
      || dispatch.idempotency_key !== trustedDispatch.idempotency_key
      || policy.lease_token !== trustedDispatch.lease_token
      || new Date(dispatch.lease_expires_at) <= new Date()) {
      return { error: 'policy_lease_invalid', status: 409 };
    }
  }
  return { policy };
}

function validateScanBinding(ctx, body, group, check, options = {}) {
  const dispatch = options.scanDispatch;
  if (!dispatch) return { scan: null, step: null };
  if (options.policyDispatch || String(body.policy_id ?? '').trim()) {
    return { error: 'conflicting_dispatch_context', status: 409 };
  }
  const scan = (getStore().validationScans ?? []).find(
    (row) => row.id === dispatch.scan_id && row.tenant_id === ctx.tenantId,
  );
  if (!scan || !['pending', 'running'].includes(scan.status)) return { error: 'scan_dispatch_invalid', status: 409 };
  const reference = dispatch.now ? new Date(dispatch.now) : new Date();
  if (!scan.lease_token
    || scan.lease_token !== dispatch.lease_token
    || (scan.lease_expires_at && new Date(scan.lease_expires_at) <= reference)) {
    return { error: 'scan_dispatch_invalid', status: 409 };
  }
  const step = (scan.steps ?? []).find((row) => row.id === dispatch.step_id);
  if (!step
    || step.status !== 'starting'
    || step.check_id !== check.check_id
    || scan.target_group_id !== group.id
    || step.target_id !== body.target_id) {
    return { error: 'scan_dispatch_invalid', status: 409 };
  }
  return { scan, step };
}

function revalidateBeforeDispatch(ctx, body, check, initialTarget, probeWillLeaveThisHost, options = {}) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === body.target_group_id
      && candidate.tenant_id === ctx.tenantId
      && !isArchivedTargetGroup(candidate),
  );
  if (!group) return { error: 'target_group_not_found', status: 404 };
  const target = getStore().targets.find(
    (candidate) => candidate.id === initialTarget.id
      && candidate.tenant_id === ctx.tenantId
      && candidate.target_group_id === group.id
      && !isArchivedTarget(candidate),
  );
  if (!target) return { error: 'target_not_found', status: 404 };
  if (targetDedupeKey(target) !== targetDedupeKey(initialTarget)) {
    return { error: 'target_binding_changed', status: 409 };
  }
  const compatibilityError = targetKindCompatibilityError(check, target);
  if (compatibilityError) return compatibilityError;
  const binding = validatePolicyBinding(ctx, body, group, check, options);
  if (binding.error) return binding;
  if (probeWillLeaveThisHost) {
    const ownership = targetOwnershipProof(ctx, group, target.id);
    if (!ownership.verified) return { error: 'ownership_not_verified', status: 409, ownership_state: ownership.state };
  }
  return { group, target, policy: binding.policy };
}

const CANCELLABLE_STATUSES = new Set(['planned', 'running', 'collecting']);

function denySafeStart(ctx, action, resourceId, metadata, error, status = 429) {
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action,
    resource_type: 'test_run',
    resource_id: resourceId,
    metadata,
  });
  persistStore();
  return { error, status };
}

function denyEventCap(ctx, run, metadata = {}) {
  return denySafeStart(
    ctx,
    'test_run.event_cap_denied',
    run.id,
    { check_id: run.check_id, ...metadata },
    'event_cap_exceeded',
    429,
  );
}

export function maybeFinalizeRunAfterProbeIngest(ctxOrRunId, maybeRunId) {
  let ctx = null;
  let runId;
  if (typeof ctxOrRunId === 'string') {
    runId = ctxOrRunId;
  } else if (ctxOrRunId != null && typeof ctxOrRunId === 'object' && maybeRunId != null) {
    ctx = ctxOrRunId;
    runId = maybeRunId;
  } else {
    return null;
  }
  if (!runId) return null;

  const store = getStore();
  const run = store.testRuns.find((r) => {
    if (r.id !== runId) return false;
    if (ctx?.tenantId) return r.tenant_id === ctx.tenantId;
    return true;
  });
  if (!run) return null;
  run.awaiting_external_probe = false;
  if (!hasExternalProbeEvidence(run)) return null;

  // ADR-0008: verdicts are produced from external probe evidence only. The run enters
  // 'collecting'; the collection-window sweeper (or an explicit finalize) publishes the verdict.
  if (run.status === 'running') run.status = 'collecting';
  const verdict = finalizeVerdictIfReady(run);
  persistStore();
  return verdict;
}

export function startTestRun(ctx, body, runtimeConfig = { probeMode: 'simulation' }, options = {}) {
  const check = getCheckById(body.check_id);
  if (!check) return { error: 'unknown_check', status: 400 };
  if (!isCustomerRunnable(check)) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.blocked_soc_gated',
      resource_type: 'check',
      resource_id: check.check_id,
    });
    persistStore();
    return { error: 'soc_gated_check', status: 403, message: 'This check requires SOC governance.' };
  }

  const targetGroupId = body.target_group_id;
  const group = getStore().targetGroups.find(
    (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
  if (!group) return { error: 'target_group_not_found', status: 404 };

  if (isKillSwitchActiveForTenant(ctx.tenantId)) {
    return denySafeStart(
      ctx,
      'test_run.kill_switch_denied',
      targetGroupId,
      { check_id: check.check_id, target_group_id: targetGroupId },
      'kill_switch_active',
      423,
    );
  }

  const tenantAccount = getTenantAccount(ctx.tenantId);
  if (tenantAccount?.lifecycle_state === 'suspended') {
    return {
      error: 'tenant_suspended',
      status: 403,
      message: 'Tenant access is suspended.',
    };
  }

  const hourlyRuns = countCustomerRunnableRunsLastHour(ctx.tenantId);
  const subscriptionLimit = assertSubscriptionLimit(
    ctx.tenantId,
    'safe_runs_per_hour',
    hourlyRuns,
  );
  if (!subscriptionLimit.ok) {
    return {
      error: subscriptionLimit.error,
      status: 403,
      metric: subscriptionLimit.metric,
      limit: subscriptionLimit.limit,
      current: subscriptionLimit.current,
      message: 'Subscription safe-run limit reached.',
    };
  }

  if (activeRunForGroup(ctx.tenantId, targetGroupId)) {
    return { error: 'concurrent_run_blocked', status: 409 };
  }

  const targetId = typeof body.target_id === 'string' ? body.target_id.trim() : '';
  if (!targetId) return { error: 'missing_target_id', status: 400 };
  const target = getStore().targets.find(
    (candidate) => candidate.id === targetId
      && candidate.tenant_id === ctx.tenantId
      && candidate.target_group_id === targetGroupId
      && !isArchivedTarget(candidate),
  );
  if (!target) return { error: 'target_not_found', status: 404 };

  const scanBinding = validateScanBinding(ctx, body, group, check, options);
  if (scanBinding.error) return scanBinding;
  const policyBinding = validatePolicyBinding(ctx, body, group, check, options);
  if (policyBinding.error) return policyBinding;
  const policyDispatchId = options.policyDispatch?.dispatch_id ?? null;
  if (policyDispatchId) {
    const existingRun = getStore().testRuns.find(
      (run) => run.tenant_id === ctx.tenantId && run.policy_dispatch_id === policyDispatchId,
    );
    if (existingRun) return { run: getTestRun(ctx, existingRun.id), idempotent_replay: true };
  }
  const scanStepId = scanBinding.step?.id ?? null;
  if (scanStepId) {
    const existingRun = getStore().testRuns.find(
      (run) => run.tenant_id === ctx.tenantId && run.scan_step_id === scanStepId,
    );
    if (existingRun) return { run: getTestRun(ctx, existingRun.id), idempotent_replay: true };
  }

  const compatibilityError = targetKindCompatibilityError(check, target);
  if (compatibilityError) return compatibilityError;

  if ((runtimeConfig.probeMode ?? 'simulation') === 'signed-worker') {
    const targetBindingError = validateHostSniTargetBinding(check, target);
    if (targetBindingError) {
      const denied = denySafeStart(
        ctx,
        'test_run.destination_binding_denied',
        targetGroupId,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          target_id: target.id,
          reason: targetBindingError.error,
        },
        targetBindingError.error,
        targetBindingError.status,
      );
      return { ...denied, check_id: targetBindingError.check_id, message: targetBindingError.message };
    }
  }

  // Ownership gate — the last check before this run can put packets on the wire.
  //
  // Scoped to the egress path only: this is the exact condition under which the probe is
  // dispatched to an external worker instead of being computed in-process (see `inlineProbe`
  // below). Simulation and ops-readiness probes never leave the machine, so gating them would
  // block dev/CI flows without protecting anyone.
  //
  // Placed after target resolution (it needs `target.id`) but before any store mutation, so a
  // denial cannot leave a half-created run behind.
  //
  // No deadlock: the ownership challenge that *earns* verification builds its probe job
  // directly via createOwnershipChallengeJob and never passes through startTestRun.
  const probeWillLeaveThisHost =
    (runtimeConfig.probeMode ?? 'simulation') === 'signed-worker'
    && !isOpsReadinessProbeKind(check);

  if (probeWillLeaveThisHost) {
    const ownership = targetOwnershipProof(ctx, group, target.id);
    if (!ownership.verified) {
      return denySafeStart(
        ctx,
        'test_run.ownership_denied',
        targetGroupId,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          target_id: target.id,
          ownership_state: ownership.state,
        },
        'ownership_not_verified',
        409,
      );
    }
  }

  const missingPrereqs = evaluateCheckPrerequisites(check, { onlineAgents: [] });
  if (missingPrereqs.length) {
    return {
      error: 'prerequisites_not_met',
      status: 409,
      missing: missingPrereqs,
      message: `Missing prerequisites: ${missingPrereqs.join(', ')}`,
    };
  }

  const groupPolicy = normalizeSafetyPolicy(group.safety_policy);
  if ((group.safe_test_windows ?? []).length > 0 && !isWithinSafeTestWindow(group)) {
    return denySafeStart(
      ctx,
      'test_run.safe_window_denied',
      targetGroupId,
      { check_id: check.check_id, target_group_id: targetGroupId },
      'safe_window_closed',
      429,
    );
  }

  if (countCustomerRunnableRunsLastHour(ctx.tenantId) >= groupPolicy.max_runs_per_hour) {
    return denySafeStart(
      ctx,
      'test_run.safe_rate_denied',
      targetGroupId,
      {
        check_id: check.check_id,
        max_runs_per_hour: groupPolicy.max_runs_per_hour,
      },
      'safe_rate_cap_exceeded',
      429,
    );
  }

  const priorRun = lastRunForTargetGroup(ctx.tenantId, targetGroupId);
  if (priorRun && groupPolicy.min_seconds_between_runs > 0) {
    const elapsedMs = Date.now() - new Date(priorRun.created_at).getTime();
    if (elapsedMs < groupPolicy.min_seconds_between_runs * 1000) {
      return denySafeStart(
        ctx,
        'test_run.safe_interval_denied',
        priorRun.id,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          min_seconds_between_runs: groupPolicy.min_seconds_between_runs,
        },
        'safe_min_interval_active',
        429,
      );
    }
  }

  const finalValidation = revalidateBeforeDispatch(
    ctx,
    { ...body, target_group_id: targetGroupId },
    check,
    target,
    probeWillLeaveThisHost,
    options,
  );
  if (finalValidation.error) {
    if (finalValidation.error === 'ownership_not_verified') {
      return denySafeStart(
        ctx,
        'test_run.ownership_denied',
        targetGroupId,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          target_id: target.id,
          ownership_state: finalValidation.ownership_state,
          phase: 'pre_dispatch_revalidation',
        },
        finalValidation.error,
        finalValidation.status,
      );
    }
    return finalValidation;
  }

  const leavesHost = !isOpsReadinessProbeKind(check) && (runtimeConfig.probeMode ?? 'simulation') === 'signed-worker';
  if (leavesHost && !probeDispatchReady(runtimeConfig)) {
    return denySafeStart(
      ctx,
      'test_run.probe_signing_unavailable',
      targetGroupId,
      { check_id: check.check_id, target_group_id: targetGroupId, scan_id: scanBinding.scan?.id ?? null },
      'probe_signing_unavailable',
      503,
    );
  }

  const safetyConstraints = effectiveSafetyConstraints(check, group);
  const runId = newId('run');
  const run = {
    id: runId,
    tenant_id: ctx.tenantId,
    target_group_id: targetGroupId,
    target_id: target.id,
    policy_id: policyBinding.policy?.id ?? null,
    policy_dispatch_id: options.policyDispatch?.dispatch_id ?? null,
    scan_id: scanBinding.scan?.id ?? null,
    scan_step_id: scanStepId,
    check_id: check.check_id,
    vector_family: check.vector_family,
    safety_class: check.safety_class ?? check.risk_class,
    remediation_template: check.remediation_template,
    safety_constraints: safetyConstraints,
    status: 'running',
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    correlation: { nonce_hash: null, window_ms: 120000 },
    collection_deadline_at: new Date(
      Date.now() + collectionDeadlineMs(check),
    ).toISOString(),
  };
  getStore().testRuns.push(run);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_run.started',
    resource_type: 'test_run',
    resource_id: runId,
    metadata: { check_id: check.check_id, policy_id: run.policy_id, scan_id: run.scan_id, scan_step_id: run.scan_step_id },
  });

  const probeMode = runtimeConfig.probeMode ?? 'simulation';
  let probe;
  let probeEvent = null;
  let probeJob = null;

  const inlineProbe = isOpsReadinessProbeKind(check) || probeMode !== 'signed-worker';

  if (!inlineProbe) {
    if (wouldExceedEventCap(run, 1)) {
      getStore().testRuns.pop();
      return denyEventCap(ctx, run, { phase: 'probe_job' });
    }
    try {
      probeJob = createProbeJob(ctx, run, check, target, body.probe_profile, runtimeConfig);
    } catch {
      getStore().testRuns.splice(getStore().testRuns.indexOf(run), 1);
      return denySafeStart(
        ctx,
        'test_run.dispatch_failed',
        targetGroupId,
        { check_id: check.check_id, scan_id: run.scan_id, reason: 'probe_job_dispatch_failed' },
        'probe_job_dispatch_failed',
        503,
      );
    }
    run.correlation.nonce_hash = probeJob.nonce_hash;
    run.awaiting_external_probe = true;
    probe = { nonce: probeJob.nonce, nonce_hash: probeJob.nonce_hash, external_result: null };
  } else {
    probe = isOpsReadinessProbeKind(check)
      ? executeOpsReadinessProbe(ctx, check, target)
      : simulateProbeResult(check, target, body.probe_profile);
    run.correlation.nonce_hash = probe.nonce_hash;

    if (wouldExceedEventCap(run, 1)) {
      getStore().testRuns.pop();
      return denyEventCap(ctx, run, { phase: 'probe' });
    }

    const evidenceLabel = isOpsReadinessProbeKind(check)
      ? 'ops_readiness_probe_evidence'
      : 'probe_simulation_evidence';

    probeEvent = {
      id: probe.event_id,
      tenant_id: ctx.tenantId,
      test_run_id: runId,
      target_id: target.id,
      check_id: check.check_id,
      source: probe.source,
      signal_type: probe.signal_type,
      producer_kind: 'internal_simulation',
      timestamp: new Date().toISOString(),
      nonce_hash: probe.nonce_hash,
      metadata: { ...probe.metadata, external_result: probe.external_result },
    };
    getStore().events.push(probeEvent);

    recordEvidence(ctx, {
      test_run_id: runId,
      label: evidenceLabel,
      metadata: enrichProbeMetadataWithWafCatalog(
        {
          vector_family: check.vector_family,
          safety_class: check.safety_class,
          probe_event_id: probeEvent.id,
          ...(isOpsReadinessProbeKind(check)
            ? { ops_readiness: true }
            : { simulation: 'SAFE_PROBE_SIMULATION' }),
        },
        check.check_id,
      ),
      related_event_id: probeEvent.id,
    });
    run.status = 'collecting';
    run.probe_external_result = probe.external_result;

    if (isOpsReadinessProbeKind(check)) {
      // Ops-readiness runs execute inline with no agent and no external worker job.
      // Finalize to an honest verdict immediately so customer-runnable ops checks
      // never hang in 'collecting'.
      finalizeOpsReadinessVerdict(run, probe);
    }
  }

  incMetric('test_runs_started_total');
  persistStore();

  const result = { run, jobs_dispatched: 0 };
  if (probeEvent) result.probe_event = probeEvent;
  if (probeJob) {
    result.probe_job = {
      id: probeJob.id,
      status: probeJob.status,
      job_signature: probeJob.job_signature,
      nonce_hash: probeJob.nonce_hash,
    };
  }
  return result;
}


function finalizeNoObservation(run) {
  const store = getStore();
  if (wouldExceedEventCap(run, 1)) {
    audit({
      tenant_id: run.tenant_id,
      actor_user_id: 'system',
      actor_role: 'system',
      action: 'test_run.event_cap_denied',
      resource_type: 'test_run',
      resource_id: run.id,
      metadata: { phase: 'collection_window_elapsed' },
    });
    persistStore();
    return null;
  }
  return finalizeVerdictIfReady(run, { finalizedWithoutObservation: true });
}

function finalizeOpsReadinessVerdict(run, probe) {
  const store = getStore();
  const existing = store.verdicts.find((v) => v.test_run_id === run.id);
  if (existing) return existing;

  const result = correlateOpsReadinessVerdict({
    externalResult: probe.external_result,
    opsValidationOk: probe.metadata?.ops_validation_ok,
  });

  const evidenceIds = store.events
    .filter((e) => e.test_run_id === run.id)
    .map((e) => e.id);

  const verdict = {
    id: newId('evidence'),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: run.check_id,
    verdict: result.verdict,
    confidence: result.confidence,
    explanation: result.explanation,
    evidence_ids: evidenceIds,
    severity: result.severity,
    created_at: new Date().toISOString(),
  };
  store.verdicts.push(verdict);
  run.status = 'verdicted';
  run.completed_at = new Date().toISOString();

  audit({
    tenant_id: run.tenant_id,
    actor_user_id: 'system',
    actor_role: 'system',
    action: 'verdict.published',
    resource_type: 'test_run',
    resource_id: run.id,
    metadata: {
      verdict: verdict.verdict,
      confidence: verdict.confidence,
      ops_readiness: true,
    },
  });

  computeReadiness(run.tenant_id);
  notifyRunTerminal(run, { reason: 'verdicted' });
  return verdict;
}

function finalizeVerdictIfReady(run, options = {}) {
  const store = getStore();
  if (store.verdicts.some((v) => v.test_run_id === run.id)) return store.verdicts.find((v) => v.test_run_id === run.id);
  if (!hasExternalProbeEvidence(run)) return null;
  const target = store.targets.find((t) => t.id === run.target_id);
  const probeEvent = store.events.find(
    (e) =>
      e.test_run_id === run.id &&
      e.signal_type === 'probe_result' &&
      isTrustedProducerEvent(e) &&
      e.nonce_hash === run.correlation.nonce_hash,
  );

  if (
    !options.finalizedWithoutObservation
    && !isCollectionWindowExpired(run)
  ) {
    return null;
  }

  const externalResult = run.probe_external_result ?? probeEvent?.metadata?.external_result;
  const expectedBehavior = resolveExpectedBehaviorForCheck(run.check_id);
  const probeKind = getCheckById(run.check_id)?.probe_profile?.kind ?? null;
  const probeIoObserved = probeEventHasProbeIo(probeEvent);

  // ADR-0008: verdicts are produced from external probe evidence only.
  const result = correlateExternalOnlyVerdict({ externalResult, expectedBehavior, probeKind, probeIoObserved });

  const evidenceIds = store.events
    .filter((e) => e.test_run_id === run.id)
    .map((e) => e.id);

  const verdict = {
    id: newId('evidence'),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: run.check_id,
    verdict: result.verdict,
    confidence: result.confidence,
    explanation: result.explanation,
    evidence_ids: evidenceIds,
    severity: result.severity,
    created_at: new Date().toISOString(),
  };
  store.verdicts.push(verdict);
  run.status = 'verdicted';
  run.completed_at = new Date().toISOString();

  audit({
    tenant_id: run.tenant_id,
    actor_user_id: 'system',
    actor_role: 'system',
    action: options.finalizedWithoutObservation ? 'verdict.finalized_no_observation' : 'verdict.published',
    resource_type: 'test_run',
    resource_id: run.id,
    metadata: {
      verdict: verdict.verdict,
      confidence: verdict.confidence,
    },
  });

  if (result.createsFinding) {
    upsertFindingFromVerdict(
      { tenantId: run.tenant_id, userId: 'system', role: 'system' },
      verdict,
      run,
      target,
    );
  }

  computeReadiness(run.tenant_id);
  notifyRunTerminal(run, { reason: 'verdicted' });
  return verdict;
}

function revokeDispatchedJobsForRun(run) {
  const cancelledProbeJobIds = [];
  for (const job of getStore().probeJobs) {
    if (job.tenant_id !== run.tenant_id || job.test_run_id !== run.id) continue;
    if (!['pending', 'leased'].includes(job.status)) continue;
    job.status = 'cancelled';
    job.completed_at = run.completed_at;
    cancelledProbeJobIds.push(job.id);
  }
  return { cancelledProbeJobIds };
}

export function autoCancelActiveSafeRunsForKillSwitch(ctx, reason) {
  const cancelledRunIds = [];
  const cancelledRuns = [];
  for (const run of getStore().testRuns) {
    if (run.tenant_id !== ctx.tenantId) continue;
    if (!CANCELLABLE_STATUSES.has(run.status)) continue;
    run.status = 'cancelled';
    run.completed_at = new Date().toISOString();
    run.cancelled_by_kill_switch = true;
    const revoked = revokeDispatchedJobsForRun(run);
    run.summary = {
      ...(run.summary ?? {}),
      cancellation: {
        reason: reason ?? 'kill_switch',
        by: ctx.userId,
        role: ctx.role,
        source: 'kill_switch',
        scan_id: run.scan_id ?? null,
      },
    };
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.kill_switch_auto_cancel',
      resource_type: 'test_run',
      resource_id: run.id,
      metadata: {
        reason: reason ?? null,
        check_id: run.check_id,
        target_group_id: run.target_group_id,
        scan_id: run.scan_id ?? null,
        cancelled_probe_job_ids: revoked.cancelledProbeJobIds,
      },
    });
    cancelledRunIds.push(run.id);
    cancelledRuns.push(run);
  }
  if (cancelledRunIds.length) persistStore();
  for (const run of cancelledRuns) notifyRunTerminal(run, { reason: 'kill_switch' });
  return cancelledRunIds;
}

export function cancelTestRun(ctx, id, options = {}) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  if (!CANCELLABLE_STATUSES.has(run.status)) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.cancel_denied',
      resource_type: 'test_run',
      resource_id: id,
      metadata: { status: run.status },
    });
    persistStore();
    return { error: 'not_cancellable', status: 409 };
  }
  const reason = normalizeCancelReason(options.reason);
  const source = options.source ?? 'user';
  run.status = 'cancelled';
  run.completed_at = new Date().toISOString();
  const revoked = revokeDispatchedJobsForRun(run);
  run.summary = {
    ...(run.summary ?? {}),
    cancellation: {
      reason,
      by: ctx.userId,
      role: ctx.role,
      source,
      scan_id: options.scan_id ?? run.scan_id ?? null,
    },
  };
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_run.cancelled',
    resource_type: 'test_run',
    resource_id: id,
    metadata: {
      reason,
      cancelled_by: ctx.userId,
      cancelled_by_role: ctx.role,
      source,
      check_id: run.check_id,
      target_group_id: run.target_group_id,
      scan_id: options.scan_id ?? run.scan_id ?? null,
      cancelled_probe_job_ids: revoked.cancelledProbeJobIds,
    },
  });
  persistStore();
  notifyRunTerminal(run, { reason: 'cancelled', source });
  return { run };
}
